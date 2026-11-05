import Foundation
import SwiftUI

// MARK: - Reading history by time

/// Recorded history, read by time without loading whole files. In a plain file lines are in time
/// order, so the byte offset of any moment is a binary search away and the bytes between two moments
/// say how busy the Mac was. A compressed file's index gives the same per ~4 MB block.
struct HistoryArchive: Sendable {
    let directory: URL

    struct Segment: Sendable {
        let url: URL                       // the .jsonl, or the .jsonl.gz
        let size: Int64                    // uncompressed bytes
        let start: Date
        let end: Date
        var index: HistoryFiles.Index? = nil
    }

    /// History files with their first and last timestamps, oldest first.
    func segments() -> [Segment] {
        HistoryFiles.list(in: directory).compactMap { file in
            switch file {
            case .compressed(let gz, let index):
                guard let start = index.start, let end = index.end else { return nil }
                return Segment(url: gz, size: index.size, start: start, end: end, index: index)
            case .plain(let url):
                guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
                defer { try? handle.close() }
                let size = Int64((try? handle.seekToEnd()) ?? 0)
                guard size > 0, let first = Self.firstTimestamp(handle, at: 0),
                      let last = Self.lastTimestamp(handle, size: size) else { return nil }
                return Segment(url: url, size: size, start: first, end: last)
            }
        }
    }

    /// The whole recorded span.
    static func range(of segments: [Segment]) -> ClosedRange<Date>? {
        guard let first = segments.first?.start, let last = segments.map(\.end).max(), first <= last else { return nil }
        return first...last
    }

    /// Bytes recorded in each of `buckets` equal slices of `range` (0 where nothing was recorded).
    func activity(_ segments: [Segment], over range: ClosedRange<Date>, buckets: Int) -> [Double] {
        let span = range.upperBound.timeIntervalSince(range.lowerBound)
        guard buckets > 0, span > 0 else { return [] }
        var out = [Double](repeating: 0, count: buckets)
        for seg in segments {
            if let minutes = seg.index?.minutes {
                // Exact bytes per minute from the index: real gaps stay empty.
                for pair in minutes where pair.count == 2 {
                    let t = Date(timeIntervalSince1970: Double(pair[0]) * 60 + 30)
                    let i = Int(t.timeIntervalSince(range.lowerBound) / span * Double(buckets))
                    if i >= 0, i < buckets { out[i] += Double(pair[1]) }
                }
                continue
            }
            if let index = seg.index {
                // Older index without per-minute counts: spread each block over the time it covers.
                for block in index.blocks {
                    let a = block.start.timeIntervalSince(range.lowerBound) / span * Double(buckets)
                    let b = block.end.timeIntervalSince(range.lowerBound) / span * Double(buckets)
                    let first = max(0, Int(a)), last = min(buckets - 1, Int(b))
                    guard first <= last else { continue }
                    if first == last || b - a <= 0 { out[first] += Double(block.size); continue }
                    for i in first...last {
                        let overlap = min(b, Double(i + 1)) - max(a, Double(i))
                        if overlap > 0 { out[i] += Double(block.size) * overlap / (b - a) }
                    }
                }
                continue
            }
            guard let handle = try? FileHandle(forReadingFrom: seg.url) else { continue }
            defer { try? handle.close() }
            var previous: Int64?
            for i in 0...buckets {
                let t = range.lowerBound.addingTimeInterval(span * Double(i) / Double(buckets))
                let offset = t <= seg.start ? 0 : t > seg.end ? seg.size : Self.offset(of: t, in: handle, size: seg.size)
                if let previous, i > 0 { out[i - 1] += Double(offset - previous) }
                previous = offset
            }
        }
        return out
    }

    /// Events recorded in `from..<to`, newest first. When the slice is larger than `maxBytes`,
    /// only its newest part is read and `clipped` is true.
    func events(_ segments: [Segment], from: Date, to: Date, maxBytes: Int64 = 6_000_000)
        -> (events: [ActivityEvent], clipped: Bool) {
        var lines: [Data] = []
        var budget = maxBytes
        var clipped = false
        for seg in segments.reversed() where seg.end >= from && seg.start < to && budget > 0 {
            if let index = seg.index {
                // Only the blocks the slice touches, newest first, lines inside the slice.
                for block in index.blocks.reversed() where block.end >= from && block.start < to && budget > 0 {
                    guard let data = HistoryFiles.read(block, from: seg.url) else { continue }
                    var chunk: [Data] = []
                    var lineStart = data.startIndex
                    while let nl = data[lineStart...].firstIndex(of: 0x0A) {
                        let line = data[lineStart..<nl]
                        if let ts = Self.timestamp(line), ts >= from, ts < to { chunk.append(line) }
                        lineStart = nl + 1
                    }
                    var kept: [Data] = []
                    for line in chunk.reversed() {
                        guard budget > 0 else { clipped = true; break }
                        budget -= Int64(line.count + 1)
                        kept.append(line)
                    }
                    lines.insert(contentsOf: kept.reversed(), at: 0)
                }
                continue
            }
            guard let handle = try? FileHandle(forReadingFrom: seg.url) else { continue }
            defer { try? handle.close() }
            let a = from <= seg.start ? 0 : Self.offset(of: from, in: handle, size: seg.size)
            let b = to > seg.end ? seg.size : Self.offset(of: to, in: handle, size: seg.size)
            guard b > a else { continue }
            let start = max(a, b - budget)
            if start > a { clipped = true }
            try? handle.seek(toOffset: UInt64(start))
            guard var data = try? handle.read(upToCount: Int(b - start)) else { continue }
            // A clipped read starts mid-line: drop the partial first line.
            if start > a, let nl = data.firstIndex(of: 0x0A) { data = data[(nl + 1)...] }
            budget -= b - start
            var chunk: [Data] = []
            var lineStart = data.startIndex
            while let nl = data[lineStart...].firstIndex(of: 0x0A) {
                if nl > lineStart { chunk.append(data[lineStart..<nl]) }
                lineStart = nl + 1
            }
            lines.insert(contentsOf: chunk, at: 0)
        }
        let events = lines.reversed().compactMap(ActivityEvent.parse)
        return (events, clipped)
    }

    // MARK: Searching everything

    /// What a search scan reports after each chunk: new hits (newest first) and how far back it has read.
    struct SearchProgress: Sendable {
        var hits: [ActivityEvent]
        var reachedBack: Date
    }

    /// Every recorded event matching `query` (the event list's search rules), newest first, at most `limit`.
    /// Reads newest to oldest one ~4 MB chunk at a time; lines are matched as bytes first, so only matching
    /// lines are parsed. `report` gets each chunk's hits; `stop` is checked between chunks. Returns whether
    /// the scan stopped at `limit` (older matches exist or may exist).
    @discardableResult
    func search(_ segments: [Segment], query: String, limit: Int,
                stop: () -> Bool, report: (SearchProgress) -> Void) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty, limit > 0 else { return false }
        let needle = Self.searchNeedle(q)
        var found = 0
        // One chunk of whole lines in time order: its matches, newest first.
        func scan(_ data: Data, start: Date) -> Bool {
            var hits = Self.matches(in: data, needle: needle, query: q)
            hits.reverse()
            if found + hits.count > limit { hits = Array(hits.prefix(limit - found)) }
            found += hits.count
            report(SearchProgress(hits: hits, reachedBack: start))
            return found < limit && !stop()
        }
        for seg in segments.reversed() {
            if let index = seg.index {
                for block in index.blocks.reversed() {
                    guard !stop() else { return false }
                    guard let data = HistoryFiles.read(block, from: seg.url) else { continue }
                    if !scan(data, start: block.start) { return found >= limit }
                }
                continue
            }
            // The file being written: read backwards in whole-line chunks.
            guard let handle = try? FileHandle(forReadingFrom: seg.url) else { continue }
            defer { try? handle.close() }
            var end = seg.size
            while end > 0 {
                guard !stop() else { return false }
                let start = max(0, end - Int64(HistoryFiles.blockBytes))
                try? handle.seek(toOffset: UInt64(start))
                guard var data = try? handle.read(upToCount: Int(end - start)), !data.isEmpty else { break }
                var next = start
                if start > 0 {                     // begins mid-line: that line goes with the older chunk
                    guard let nl = data.firstIndex(of: 0x0A) else { end = start; continue }
                    next = start + Int64(nl - data.startIndex) + 1
                    data = data[(nl + 1)...]
                }
                let first = data.split(separator: 0x0A, maxSplits: 1).first.flatMap { Self.timestamp(Data($0)) } ?? seg.start
                if !scan(Data(data), start: first) { return found >= limit }
                end = next
            }
        }
        return false
    }

    /// Bytes to look for in the raw lines. Lines are lowercased ASCII-only before the search, so a query with
    /// other letters is found by its longest ASCII stretch and then checked exactly.
    static func searchNeedle(_ query: String) -> [UInt8] {
        if query.allSatisfy(\.isASCII) { return Array(query.utf8) }
        let pieces = query.split(whereSeparator: { !$0.isASCII }).map(String.init)
        if let longest = pieces.max(by: { $0.count < $1.count }), longest.count >= 2 { return Array(longest.utf8) }
        return Array(query.utf8)
    }

    /// Lines of `data` containing `needle` (lowercase; matched ASCII case-insensitively) that also match `query`
    /// exactly, in order. No copy and no lowercasing pass: memchr (SIMD) finds the needle's rarest byte in either
    /// case, and only those places are compared. Reads at several GB/s.
    static func matches(in data: Data, needle: [UInt8], query: String) -> [ActivityEvent] {
        guard !needle.isEmpty else { return [] }
        let pivot = needle.indices.min { rarity(needle[$0]) < rarity(needle[$1]) }!
        let lowerPivot = needle[pivot]
        let isLetter = lowerPivot >= 97 && lowerPivot <= 122
        var lines: [Range<Int>] = []                 // line ranges with a hit, offsets into the buffer
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let count = raw.count
            func equalsNeedle(at at: Int) -> Bool {
                for k in 0..<needle.count {
                    var c = base[at + k]
                    if c &- 65 < 26 { c |= 0x20 }
                    if c != needle[k] { return false }
                }
                return true
            }
            for pivotByte in isLetter ? [lowerPivot, lowerPivot - 32] : [lowerPivot] {
                var from = pivot
                while from < count, let p = memchr(base + from, Int32(pivotByte), count - from) {
                    let at = base.distance(to: p.assumingMemoryBound(to: UInt8.self)) - pivot
                    from = at + pivot + 1
                    guard at >= 0, at + needle.count <= count, equalsNeedle(at: at) else { continue }
                    var lineStart = at
                    while lineStart > 0, base[lineStart - 1] != 0x0A { lineStart -= 1 }
                    var lineEnd = at
                    while lineEnd < count, base[lineEnd] != 0x0A { lineEnd += 1 }
                    lines.append(lineStart..<lineEnd)
                    from = lineEnd + 1 + pivot
                }
            }
        }
        // Both case passes can find the same line: once each, in file order.
        lines.sort { $0.lowerBound < $1.lowerBound }
        var out: [ActivityEvent] = []
        var last = -1
        for r in lines where r.lowerBound != last {
            last = r.lowerBound
            let line = data[(data.startIndex + r.lowerBound)..<(data.startIndex + r.upperBound)]
            if let e = ActivityEvent.parse(line), e.matches(query) { out.append(e) }
        }
        return out
    }

    /// Rough frequency of a byte in recorded lines (JSON keys, paths): lower is rarer.
    private static func rarity(_ b: UInt8) -> Int {
        switch b {
        case UInt8(ascii: "\""), UInt8(ascii: "/"), UInt8(ascii: ":"), UInt8(ascii: ","): return 100
        case UInt8(ascii: "e"), UInt8(ascii: "a"), UInt8(ascii: "i"), UInt8(ascii: "r"), UInt8(ascii: "s"),
             UInt8(ascii: "t"), UInt8(ascii: "o"), UInt8(ascii: "n"), UInt8(ascii: "l"): return 60
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return 50
        case UInt8(ascii: "c"), UInt8(ascii: "p"), UInt8(ascii: "m"), UInt8(ascii: "d"), UInt8(ascii: "u"),
             UInt8(ascii: "h"), UInt8(ascii: "b"), UInt8(ascii: "."), UInt8(ascii: "-"), UInt8(ascii: "_"): return 40
        case UInt8(ascii: "f"), UInt8(ascii: "g"), UInt8(ascii: "y"), UInt8(ascii: "w"), UInt8(ascii: "k"), UInt8(ascii: "v"): return 20
        case UInt8(ascii: "j"), UInt8(ascii: "x"), UInt8(ascii: "q"), UInt8(ascii: "z"): return 5
        default: return 10
        }
    }

    // MARK: Byte offsets

    /// Offset of the first line stamped at or after `date`.
    static func offset(of date: Date, in handle: FileHandle, size: Int64) -> Int64 {
        var lo: Int64 = 0, hi = size
        // Binary search on line starts with small reads, then scan the last window in memory.
        while hi - lo > 32_768 {
            let mid = lo + (hi - lo) / 2
            guard let (lineStart, ts) = firstLine(handle, after: mid, limit: hi) else { hi = mid; continue }
            if ts < date { lo = lineStart + 1 } else { hi = lineStart }
        }
        try? handle.seek(toOffset: UInt64(lo))
        guard let data = try? handle.read(upToCount: Int(hi - lo) + 65_536), !data.isEmpty else { return hi }
        var p = data.startIndex
        if lo > 0 {                      // lo can be mid-line: start at the next line
            guard let nl = data.firstIndex(of: 0x0A) else { return hi }
            p = nl + 1
        }
        while p < data.endIndex, lo + Int64(p - data.startIndex) < hi {
            let end = data[p...].firstIndex(of: 0x0A) ?? data.endIndex
            if let ts = timestamp(data[p..<end]), ts >= date { return lo + Int64(p - data.startIndex) }
            p = end + 1
        }
        return hi
    }

    /// The first complete line starting after `offset`: its start and timestamp.
    private static func firstLine(_ handle: FileHandle, after offset: Int64, limit: Int64) -> (Int64, Date)? {
        for chunk in [4096, 131_072] {
            try? handle.seek(toOffset: UInt64(offset))
            guard let data = try? handle.read(upToCount: chunk), let nl = data.firstIndex(of: 0x0A) else { continue }
            let start = offset + Int64(nl - data.startIndex) + 1
            guard start < limit else { return nil }
            if let end = data[(nl + 1)...].firstIndex(of: 0x0A) {
                guard let ts = timestamp(data[(nl + 1)..<end]) else { return nil }
                return (start, ts)
            }
        }
        return nil
    }

    /// The line starting at `offset`: its start, timestamp and the next line's offset.
    private static func line(_ handle: FileHandle, at offset: Int64, limit: Int64) -> (Int64, Date, Int64)? {
        try? handle.seek(toOffset: UInt64(offset))
        guard let data = try? handle.read(upToCount: 131_072), !data.isEmpty else { return nil }
        let end = data.firstIndex(of: 0x0A) ?? data.endIndex
        guard let ts = timestamp(data[data.startIndex..<end]) else { return nil }
        return (offset, ts, offset + Int64(end - data.startIndex) + 1)
    }

    private static func firstTimestamp(_ handle: FileHandle, at offset: Int64) -> Date? {
        line(handle, at: offset, limit: .max)?.1
    }

    private static func lastTimestamp(_ handle: FileHandle, size: Int64) -> Date? {
        let tail = min(size, 65_536)
        try? handle.seek(toOffset: UInt64(size - tail))
        guard let data = try? handle.read(upToCount: Int(tail)) else { return nil }
        let lines = data.split(separator: 0x0A)
        return lines.reversed().lazy.compactMap { timestamp($0) }.first
    }

    /// The `"ts":"…"` value of a recorded line (written last by the collector).
    static func timestamp(_ line: Data) -> Date? {
        guard let key = line.range(of: Data(#""ts":""#.utf8), options: .backwards),
              let end = line[key.upperBound...].firstIndex(of: UInt8(ascii: "\"")) else { return nil }
        return parseISO(line[key.upperBound..<end])
    }

    /// `2026-11-01T05:41:56.360+02:00` (or `Z`), parsed directly: date formatters are far too slow
    /// for the thousands of lookups a timeline needs.
    static func parseISO(_ text: Data) -> Date? {
        let b = Array(text)
        guard b.count >= 19, b[4] == 45, b[7] == 45, b[10] == 84, b[13] == 58, b[16] == 58 else { return nil }
        func num(_ from: Int, _ len: Int) -> Int? {
            var v = 0
            for i in from..<from + len {
                guard i < b.count, b[i] >= 48, b[i] <= 57 else { return nil }
                v = v * 10 + Int(b[i] - 48)
            }
            return v
        }
        guard let y = num(0, 4), let mo = num(5, 2), let d = num(8, 2),
              let h = num(11, 2), let mi = num(14, 2), let sec = num(17, 2) else { return nil }
        var i = 19
        var fraction = 0.0
        if i < b.count, b[i] == 46 {                         // .fff
            var scale = 0.1
            i += 1
            while i < b.count, b[i] >= 48, b[i] <= 57 { fraction += Double(b[i] - 48) * scale; scale /= 10; i += 1 }
        }
        var offset = 0
        if i < b.count, b[i] == 43 || b[i] == 45 {          // ±HH:MM
            guard let oh = num(i + 1, 2), let om = num(i + 4, 2) else { return nil }
            offset = (oh * 3600 + om * 60) * (b[i] == 45 ? -1 : 1)
        }
        // Days since 1970-01-01 (civil calendar, Howard Hinnant's algorithm).
        let yy = mo <= 2 ? y - 1 : y
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        let seconds = Double(days * 86_400 + h * 3600 + mi * 60 + sec - offset) + fraction
        return Date(timeIntervalSince1970: seconds)
    }
}

// MARK: - Time travel state

/// A moment on the timeline worth a mark: a story or a new domain.
struct TimelineMarker: Identifiable {
    enum Kind { case dangerous, suspicious, newDomain }
    let id: String
    let date: Date
    let kind: Kind
    let title: String
}

@MainActor
final class TimeTravel: ObservableObject {
    @Published private(set) var active = false
    /// The end of the shown slice: "what had happened by this moment".
    @Published private(set) var playhead = Date()
    @Published var span: TimeInterval = 5 * 60 { didSet { scheduleLoad() } }
    @Published private(set) var range: ClosedRange<Date>?
    @Published private(set) var activity: [Double] = []
    @Published private(set) var events: [ActivityEvent] = []
    @Published private(set) var loading = false
    /// Older events of the shown window are still on disk (scrolling to the end of the list loads them).
    @Published private(set) var clipped = false
    /// The window is loaded as far as Hostwatch goes for one window (`maxSliceBytes`): a shorter one shows the rest.
    @Published private(set) var capped = false
    @Published private(set) var loadingMore = false
    /// A window is read a page at a time, newest first: about 3,000 events each. Reading a busy hour at once
    /// (up to ~19,000 events and their rows) made the app's memory jump by 100–250 MB.
    nonisolated static let pageBytes: Int64 = 1_000_000
    nonisolated static let maxSliceBytes: Int64 = 6_000_000
    private var loadedBytes: Int64 = 0
    private var moreTask: Task<Void, Never>?
    @Published private(set) var playing = false
    @Published var speed: Double = 1            // history seconds per real second
    @Published private(set) var markers: [TimelineMarker] = []
    /// Running Now while traveling: what was running at the playhead (nil: nothing recorded near it).
    @Published private(set) var processSnapshot: ProcessHistory.Snapshot?
    /// Set while Running Now is shown in Time Travel: the list follows the playhead.
    var processesWanted = false { didSet { if processesWanted != oldValue { loadProcesses() } } }
    /// Receives each process list loaded for the playhead (Running Now shows it).
    var onProcesses: (ProcessHistory.Snapshot?, Date) -> Void = { _, _ in }
    private let processCache = ProcessDayCache()
    private var processTask: Task<Void, Never>?

    /// Bumped whenever the listed events change (slice or search hits): the event list re-derives its rows only then.
    @Published private(set) var revision = 0
    /// CPU and memory over the whole recording, per timeline bucket (0...1; nil where nothing was recorded).
    @Published private(set) var cpuLane: [Double?] = []
    @Published private(set) var memLane: [Double?] = []
    /// Resource samples inside the shown slice, for the strip and the banner.
    @Published private(set) var windowSamples: [MetricSample] = []
    /// The launch event to select once the slice is loaded (Running Now ▸ Show Spawn in Timeline).
    @Published private(set) var focusID: UUID?
    private var pendingFocus: (pid: Int, start: Double)?
    private var pendingEvent: ActivityEvent?

    // Search across all recorded history (the toolbar search field, scope All History).
    /// Search everything (true) or only the shown window (false).
    @Published var searchAll = true { didSet { if searchAll != oldValue { revision += 1 } } }
    /// Matches, newest first; never more than `maxSearchHits`.
    @Published private(set) var searchHits: [ActivityEvent] = []
    @Published private(set) var searchQuery = ""
    @Published private(set) var searching = false
    /// The scan has read everything from now back to here.
    @Published private(set) var searchReachedBack: Date?
    /// Stopped at `maxSearchHits`: older matches may exist.
    @Published private(set) var searchCapped = false
    private var searchTask: Task<Void, Never>?
    /// Enough to scroll through and see a pattern; more would only cost memory and a slower list.
    nonisolated static let maxSearchHits = 1000
    /// One or two letters would match nearly every line.
    nonisolated static let minSearchLength = 2

    /// Whether the event list shows search hits from all history rather than the window.
    var showingSearch: Bool { active && searchAll && searchQuery.count >= Self.minSearchLength }
    /// What the event list shows while traveling.
    var listed: [ActivityEvent] { showingSearch ? searchHits : events }
    /// The last sample at or before the playhead.
    var sampleAtPlayhead: MetricSample? { windowSamples.last { $0.date <= playhead } }

    static let spans: [(String, TimeInterval)] = [("1 min", 60), ("5 min", 300), ("15 min", 900), ("1 hour", 3600)]
    static let speeds: [(String, Double)] = [("1×", 1), ("10×", 10), ("60×", 60), ("600×", 600)]
    nonisolated static let buckets = 240

    private let history: HistoryRecorder
    private let stories: StoryEngine
    private let domains: DomainRegistry
    private let metrics: MetricsStore
    private var segments: [HistoryArchive.Segment] = []
    private var loadTask: Task<Void, Never>?
    private var overviewTask: Task<Void, Never>?
    private var playTimer: Timer?
    private var refreshTimer: Timer?

    init(history: HistoryRecorder, stories: StoryEngine, domains: DomainRegistry, metrics: MetricsStore) {
        self.history = history
        self.stories = stories
        self.domains = domains
        self.metrics = metrics
    }

    private var archive: HistoryArchive { HistoryArchive(directory: history.directory) }

    var windowStart: Date { playhead.addingTimeInterval(-span) }

    // MARK: Entering and leaving

    /// Opens time travel at `date` (default: a few minutes ago).
    func enter(at date: Date? = nil) {
        let wasActive = active
        active = true
        playhead = date ?? Date().addingTimeInterval(-span)
        refreshOverview(thenLoad: true)
        if !wasActive {
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshOverview(thenLoad: false) }
            }
        }
    }

    func exit() {
        pause()
        active = false
        loadTask?.cancel()
        moreTask?.cancel()
        loadingMore = false
        overviewTask?.cancel()
        refreshTimer?.invalidate()
        refreshTimer = nil
        events = []
        pendingFocus = nil
        pendingEvent = nil
        focusID = nil
        cancelSearch()
        searchQuery = ""
        revision += 1
        processTask?.cancel()
        processSnapshot = nil
        processCache.clear()
    }

    func toggle() { active ? exit() : enter() }

    /// Opens time travel at the moment a process started, its launch event selected when it was recorded.
    func reveal(pid: Int, start: Date) {
        pause()
        focusID = nil
        pendingFocus = (pid, start.timeIntervalSince1970)
        // The slice ends a little after the launch, so it's near the top of the newest-first list.
        enter(at: start.addingTimeInterval(min(30, span / 4)))
    }

    /// Shows the window around a recorded event (a search hit) with it selected.
    func reveal(_ event: ActivityEvent) {
        guard event.ts > 0 else { return }
        pause()
        focusID = nil
        pendingEvent = event
        searchAll = false
        let at = Date(timeIntervalSince1970: event.ts)
        enter(at: at.addingTimeInterval(min(30, span / 4)))
    }

    // MARK: Running Now at the playhead

    private func loadProcesses() {
        processTask?.cancel()
        guard active, processesWanted else { return }
        let history = ProcessHistory(directory: self.history.directory), cache = processCache, at = playhead
        processTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(60))          // coalesce drags
            guard !Task.isCancelled else { return }
            let snapshot = await Task.detached(priority: .userInitiated) { history.snapshot(at: at, cache: cache) }.value
            guard let self, !Task.isCancelled, self.active else { return }
            self.processSnapshot = snapshot
            self.onProcesses(snapshot, at)
        }
    }

    // MARK: Searching all history

    /// Searches all recorded history for `text` (debounced; the same query isn't searched twice).
    func search(_ text: String) {
        let q = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard q != searchQuery else { return }
        cancelSearch()
        searchQuery = q
        searchHits = []
        searchCapped = false
        searchReachedBack = nil
        revision += 1
        guard active, q.count >= Self.minSearchLength else { return }
        searching = true
        let archive = archive
        searchTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(300))           // typing
            guard !Task.isCancelled, let self else { return }
            // Fresh file list: the search may run long after the overview was read.
            let segments = await Task.detached(priority: .userInitiated) { archive.segments() }.value
            guard !Task.isCancelled else { return }
            let stream = AsyncStream<HistoryArchive.SearchProgress> { continuation in
                let worker = Task.detached(priority: .userInitiated) {
                    archive.search(segments, query: q, limit: Self.maxSearchHits,
                                   stop: { Task.isCancelled }, report: { continuation.yield($0) })
                    continuation.finish()
                }
                continuation.onTermination = { _ in worker.cancel() }
            }
            var pending: [ActivityEvent] = []
            var lastPublish = ContinuousClock.now
            for await progress in stream {
                guard !Task.isCancelled else { return }
                pending += progress.hits
                self.searchReachedBack = progress.reachedBack
                // Publish hits a few times a second at most: each publish rebuilds the list.
                if !pending.isEmpty, ContinuousClock.now - lastPublish > .milliseconds(250) || self.searchHits.isEmpty {
                    self.searchHits += pending
                    pending = []
                    lastPublish = .now
                    self.revision += 1
                }
            }
            guard !Task.isCancelled else { return }
            if !pending.isEmpty { self.searchHits += pending; self.revision += 1 }
            self.searchCapped = self.searchHits.count >= Self.maxSearchHits
            self.searching = false
        }
    }

    private func cancelSearch() {
        searchTask?.cancel()
        searchTask = nil
        searching = false
    }

    /// The launch event of `pid` that started at `start` (s since 1970; 0 or unknown on either side: any).
    nonisolated static func launch(in events: [ActivityEvent], pid: Int, start: Double) -> ActivityEvent? {
        let execs = events.filter { $0.kind == .exec && $0.pid == pid }
        return execs.first { start > 0 && $0.pstart > 0 && abs($0.pstart - start) < 2 }
            ?? execs.first { start <= 0 || $0.pstart <= 0 }
    }

    // MARK: Moving

    func move(to date: Date) {
        guard let range else { playhead = date; return }
        playhead = min(max(date, range.lowerBound.addingTimeInterval(min(span, 1))), range.upperBound)
        scheduleLoad()
    }

    /// One slice earlier (-1) or later (+1).
    func step(_ direction: Int) {
        pause()
        move(to: playhead.addingTimeInterval(Double(direction) * span))
    }

    func togglePlay() { playing ? pause() : play() }

    private func play() {
        guard let range else { return }
        if playhead >= range.upperBound { move(to: range.lowerBound.addingTimeInterval(span)) }
        playing = true
        playTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let range = self.range else { return }
                if self.playhead >= range.upperBound { self.pause(); return }
                self.move(to: self.playhead.addingTimeInterval(self.speed * 0.5))
            }
        }
    }

    func pause() {
        playing = false
        playTimer?.invalidate()
        playTimer = nil
    }

    // MARK: Loading (off the main thread)

    private func refreshOverview(thenLoad: Bool) {
        let archive = archive
        overviewTask?.cancel()
        overviewTask = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) { () -> ([HistoryArchive.Segment], ClosedRange<Date>?, [Double]) in
                let segments = archive.segments()
                guard let range = HistoryArchive.range(of: segments) else { return (segments, nil, []) }
                return (segments, range, archive.activity(segments, over: range, buckets: TimeTravel.buckets))
            }.value
            guard let self, !Task.isCancelled, self.active else { return }
            self.segments = result.0
            self.range = result.1
            // Square root: one huge burst shouldn't flatten every other bar.
            let scaled = result.2.map { $0.squareRoot() }
            let peak = scaled.max() ?? 0
            self.activity = peak > 0 ? scaled.map { $0 / peak } : scaled
            self.markers = self.collectMarkers()
            if thenLoad { self.move(to: self.playhead) }
            if let range = result.1 { await self.loadLanes(range) }
        }
    }

    private func scheduleLoad() {
        loadProcesses()
        guard active, !segments.isEmpty else { return }
        let archive = archive, segments = segments, from = windowStart, to = playhead
        loadTask?.cancel()
        loading = true
        loadTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(90))          // coalesce drags
            guard !Task.isCancelled else { return }
            let result = await Task.detached(priority: .userInitiated) {
                archive.events(segments, from: from, to: to, maxBytes: Self.pageBytes)
            }.value
            guard let self, !Task.isCancelled else { return }
            self.moreTask?.cancel()
            self.loadingMore = false
            self.events = result.events
            self.clipped = result.clipped
            self.capped = false
            self.loadedBytes = Self.pageBytes
            self.revision += 1
            self.resolveFocus()
            self.windowSamples = await self.metrics.samples(from: from, to: to)
            self.loading = false
        }
    }

    /// The next older page of the shown window (the list scrolled to its end, or a focus not found yet).
    func loadMore() {
        guard active, clipped, !loadingMore, let oldest = events.last, oldest.ts > 0 else { return }
        guard loadedBytes < Self.maxSliceBytes else { clipped = false; capped = true; return }
        let archive = archive, segments = segments, from = windowStart
        // Up to and including the oldest loaded moment: lines sharing its timestamp may have been cut off.
        let to = Self.nextPageEnd(after: events)
        let loaded = events
        loadingMore = true
        moreTask = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) {
                archive.events(segments, from: from, to: to, maxBytes: Self.pageBytes)
            }.value
            guard let self, !Task.isCancelled, self.loadingMore else { return }
            let older = Self.newOnly(result.events, after: loaded)
            self.events += older
            self.loadedBytes += Self.pageBytes
            // Nothing new although more was said to be there (one moment busier than a page): stop here.
            self.clipped = result.clipped && !older.isEmpty
            if self.clipped && self.loadedBytes >= Self.maxSliceBytes { self.clipped = false; self.capped = true }
            self.loadingMore = false
            self.revision += 1
            self.resolveFocus()
        }
    }

    /// Where the next older page ends: at the oldest loaded moment, inclusive (lines sharing its timestamp may have
    /// been cut off by the page size).
    nonisolated static func nextPageEnd(after loaded: [ActivityEvent]) -> Date {
        Date(timeIntervalSince1970: (loaded.last?.ts ?? 0) + 0.0005)
    }

    /// The events of a next page that aren't loaded yet (it overlaps the loaded ones at the boundary moment).
    nonisolated static func newOnly(_ page: [ActivityEvent], after loaded: [ActivityEvent]) -> [ActivityEvent] {
        guard let oldest = loaded.last?.ts else { return page }
        let boundary = Set(loaded.lazy.filter { $0.ts == oldest }.map(identity))
        return page.filter { $0.ts < oldest || !boundary.contains(identity($0)) }
    }

    /// A recorded line's identity across two reads of it (each read makes new event IDs).
    nonisolated static func identity(_ e: ActivityEvent) -> String {
        "\(e.ts)|\(e.pid)|\(e.kind.rawValue)|\(e.target)|\(e.extra)"
    }

    /// Selects the event a reveal asked for once it's loaded; reads older pages until it is, or there are none.
    private func resolveFocus() {
        if let target = pendingEvent {
            if let hit = events.first(where: {
                abs($0.ts - target.ts) < 0.001 && $0.pid == target.pid && $0.kind == target.kind && $0.target == target.target
            }) {
                pendingEvent = nil
                focusID = hit.id
            } else if clipped { loadMore() } else { pendingEvent = nil }
        }
        if let f = pendingFocus {
            if let hit = Self.launch(in: events, pid: f.pid, start: f.start) {
                pendingFocus = nil
                focusID = hit.id
            } else if clipped { loadMore() } else { pendingFocus = nil }
        }
    }

    /// Average CPU and memory per timeline bucket.
    private func loadLanes(_ range: ClosedRange<Date>) async {
        let samples = await metrics.samples(from: range.lowerBound, to: range.upperBound)
        let span = range.upperBound.timeIntervalSince(range.lowerBound)
        let n = Self.buckets
        guard span > 0 else { return }
        var cpu = [Double](repeating: 0, count: n), mem = cpu, count = cpu
        for s in samples {
            let i = min(n - 1, max(0, Int(s.date.timeIntervalSince(range.lowerBound) / span * Double(n))))
            cpu[i] += s.cpu / 100
            mem[i] += s.mem
            count[i] += 1
        }
        cpuLane = (0..<n).map { count[$0] > 0 ? cpu[$0] / count[$0] : nil }
        memLane = (0..<n).map { count[$0] > 0 ? mem[$0] / count[$0] : nil }
    }

    private func collectMarkers() -> [TimelineMarker] {
        guard let range else { return [] }
        var out = stories.stories.filter { range.contains($0.firstSeen) }.map {
            TimelineMarker(id: $0.id.uuidString, date: $0.firstSeen,
                           kind: $0.severity == .dangerous ? .dangerous : .suspicious, title: $0.title)
        }
        out += domains.records.values.filter { !$0.baseline && range.contains($0.firstSeen) }.map {
            TimelineMarker(id: "d:" + $0.domain, date: $0.firstSeen, kind: .newDomain, title: "New domain \($0.domain)")
        }
        return out.sorted { $0.date < $1.date }
    }
}

// MARK: - Timeline bar

/// The floating Liquid Glass timeline: activity histogram, markers, playhead and controls.
struct TimelineBar: View {
    @ObservedObject var travel: TimeTravel
    /// Pointer over the scrubber, for the time label. Local: publishing it from the model re-rendered the
    /// whole window on every mouse move.
    @StateObject private var pointer = ScrubberPointer()
    private var hover: CGFloat? { pointer.x }

    private static let dayTime: Date.FormatStyle = .dateTime.weekday(.abbreviated).day().month(.abbreviated)
        .hour().minute()
    private static let clock: Date.FormatStyle = .dateTime.hour().minute().second()

    var body: some View {
        VStack(spacing: 8) {
            if let range = travel.range {
                scrubber(range)
                if travel.cpuLane.contains(where: { $0 != nil }) { lanes }
                HStack {
                    Text(range.lowerBound, format: Self.dayTime)
                    Spacer()
                    Text(range.upperBound, format: Self.dayTime)
                }
                .font(.system(size: 10).monospacedDigit())
                .foregroundStyle(.secondary)
            } else {
                Text(travel.loading ? "Reading history…" : "No recorded history yet. Recording is in Settings ▸ History.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 56)
            }
            controls
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .padding(.horizontal, 14)
        .padding(.bottom, 12)
    }

    // MARK: Scrubber

    private func scrubber(_ range: ClosedRange<Date>) -> some View {
        GeometryReader { geo in
            let width = geo.size.width
            let total = max(1, range.upperBound.timeIntervalSince(range.lowerBound))
            let x = { (d: Date) -> CGFloat in CGFloat(d.timeIntervalSince(range.lowerBound) / total) * width }
            let date = { (x: CGFloat) -> Date in range.lowerBound.addingTimeInterval(Double(min(max(x, 0), width) / width) * total) }
            ZStack(alignment: .topLeading) {
                Canvas { ctx, size in
                    let bars = travel.activity
                    guard !bars.isEmpty else { return }
                    let w = size.width / CGFloat(bars.count)
                    let base = size.height - 4
                    for (i, v) in bars.enumerated() where v > 0 {
                        let h = max(2, CGFloat(v) * (base - 12))
                        let rect = CGRect(x: CGFloat(i) * w + 0.5, y: base - h, width: max(1, w - 1), height: h)
                        ctx.fill(Path(roundedRect: rect, cornerRadius: min(1.5, w / 2)),
                                 with: .color(.accentColor.opacity(0.35)))
                    }
                    // The shown slice.
                    let a = x(travel.windowStart), b = x(travel.playhead)
                    ctx.fill(Path(roundedRect: CGRect(x: a, y: 8, width: max(2, b - a), height: base - 8), cornerRadius: 3),
                             with: .color(.accentColor.opacity(0.18)))
                    // Search hits along the bottom, so you see when the matches happened.
                    if travel.showingSearch {
                        var ticks = Path()
                        var lastX = -1.0
                        for e in travel.searchHits where e.ts > 0 {
                            let hx = x(Date(timeIntervalSince1970: e.ts))
                            if abs(hx - lastX) < 1 { continue }       // one tick per point is enough
                            lastX = hx
                            ticks.addRect(CGRect(x: hx - 0.5, y: base - 10, width: 1, height: 10))
                        }
                        ctx.fill(ticks, with: .color(.primary.opacity(0.7)))
                    }
                    // Story and new-domain marks along the top.
                    for m in travel.markers {
                        let color: Color = m.kind == .dangerous ? .red : m.kind == .suspicious ? .orange : .purple
                        let r: CGFloat = m.kind == .newDomain ? 2.5 : 3.5
                        ctx.fill(Path(ellipseIn: CGRect(x: x(m.date) - r, y: 4 - r, width: r * 2, height: r * 2)),
                                 with: .color(color))
                    }
                    // Playhead.
                    ctx.fill(Path(roundedRect: CGRect(x: b - 1, y: 0, width: 2, height: size.height), cornerRadius: 1),
                             with: .color(.accentColor))
                }
                if let hover {
                    Text(date(hover), format: Self.clock)
                        .font(.system(size: 10, weight: .medium).monospacedDigit())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.regularMaterial, in: Capsule())
                        .offset(x: min(max(hover - 28, 0), width - 56), y: -18)
                        .allowsHitTesting(false)
                }
            }
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0).onChanged { g in
                travel.pause()
                travel.move(to: snapped(date(g.location.x), x: x, at: g.location.x))
            })
            .onContinuousHover { phase in
                if case .active(let p) = phase { pointer.x = p.x } else { pointer.x = nil }
            }
            .help(markerHelp(near: hover, x: x) ?? "Drag to travel through recorded activity")
        }
        .frame(height: 64)
        .accessibilityElement()
        .accessibilityLabel("Timeline")
        .accessibilityValue(Text(travel.playhead, format: Self.dayTime))
        .accessibilityAdjustableAction { direction in travel.step(direction == .increment ? 1 : -1) }
    }

    /// CPU and memory over the whole recording, on the same time axis as the bars.
    private var lanes: some View {
        HStack(spacing: 8) {
            ZStack {
                Sparkline(values: travel.memLane, color: .green, width: nil, height: 22)
                Sparkline(values: travel.cpuLane, color: .blue, width: nil, height: 22)
            }
            .frame(maxWidth: .infinity)
        }
        .overlay(alignment: .topLeading) {
            HStack(spacing: 8) {
                Label("CPU", systemImage: "circle.fill").foregroundStyle(.blue)
                Label("Memory", systemImage: "circle.fill").foregroundStyle(.green)
            }
            .font(.system(size: 9, weight: .medium))
            .labelStyle(.titleAndIcon)
            .imageScale(.small)
            .padding(.leading, 2)
            .offset(y: -2)
            .allowsHitTesting(false)
        }
        .accessibilityLabel("CPU and memory over time")
    }

    /// Clicking near a marker lands just after it, so its activity is in the slice.
    private func snapped(_ date: Date, x: (Date) -> CGFloat, at position: CGFloat) -> Date {
        guard let m = travel.markers.min(by: { abs(x($0.date) - position) < abs(x($1.date) - position) }),
              abs(x(m.date) - position) < 6 else { return date }
        return m.date.addingTimeInterval(min(travel.span / 2, 60))
    }

    private func markerHelp(near position: CGFloat?, x: (Date) -> CGFloat) -> String? {
        guard let position,
              let m = travel.markers.min(by: { abs(x($0.date) - position) < abs(x($1.date) - position) }),
              abs(x(m.date) - position) < 6 else { return nil }
        return "\(m.title) · \(m.date.formatted(date: .omitted, time: .shortened))"
    }

    // MARK: Controls

    /// Transport icons get room inside their circles; play is a little larger than the steps.
    private func transportIcon(_ name: String, size: CGFloat = 10, frame: CGFloat = 15) -> some View {
        Image(systemName: name)
            .font(.system(size: size, weight: .semibold))
            .frame(width: frame, height: frame)
    }

    private var controls: some View {
        HStack(spacing: 10) {
            HStack(spacing: 2) {
                Button { travel.step(-1) } label: { transportIcon("backward.fill") }
                    .help("Earlier (⌘[)")
                Button { travel.togglePlay() } label: {
                    transportIcon(travel.playing ? "pause.fill" : "play.fill", size: 13, frame: 21)
                }
                .help(travel.playing ? "Pause" : "Play history forward")
                .disabled(travel.range == nil)
                Button { travel.step(1) } label: { transportIcon("forward.fill") }
                    .help("Later (⌘])")
            }
            .buttonStyle(.glass)
            .buttonBorderShape(.circle)
            .controlSize(.regular)
            Menu {
                Picker("Speed", selection: $travel.speed) {
                    ForEach(TimeTravel.speeds, id: \.1) { Text($0.0).tag($0.1) }
                }
                .pickerStyle(.inline)
            } label: {
                Text(TimeTravel.speeds.first { $0.1 == travel.speed }?.0 ?? "")
                    .monospacedDigit()
            }
            .menuStyle(.button)
            .buttonStyle(.glass)
            .fixedSize()
            .help("Playback speed")
            DatePicker("", selection: Binding(get: { travel.playhead }, set: { travel.pause(); travel.move(to: $0) }),
                       in: (travel.range ?? Date.distantPast...Date.distantFuture),
                       displayedComponents: [.date, .hourAndMinute])
                .labelsHidden()
                .datePickerStyle(.compact)
                .fixedSize()
                .help("Jump to a date and time")
            Picker("Window", selection: $travel.span) {
                ForEach(TimeTravel.spans, id: \.1) { Text($0.0).tag($0.1) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("How much time the event list shows, ending at the playhead")
            if travel.loading { ProgressView().controlSize(.small) }
            Spacer(minLength: 8)
            Button { travel.exit() } label: { Label("Return to Live", systemImage: "dot.radiowaves.left.and.right") }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.cancelAction)
                .help("Back to the live stream (Esc)")
        }
        .controlSize(.small)
    }
}

/// The pointer's place over the scrubber, owned by the timeline bar alone.
final class ScrubberPointer: ObservableObject {
    @Published var x: CGFloat?
}

/// Above the event list while traveling: which slice is shown, and the way back.
struct TimeTravelBanner: View {
    @ObservedObject var travel: TimeTravel
    let shown: Int
    var noun = "events"

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "clock.arrow.circlepath").foregroundStyle(.tint)
            Text("History").fontWeight(.semibold)
            Text("\(travel.windowStart.formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated).hour().minute().second())) – \(travel.playhead.formatted(.dateTime.hour().minute().second()))")
                .monospacedDigit()
            Text("·").foregroundStyle(.secondary)
            Text(noun == "events" && (travel.clipped || travel.capped) ? "newest \(shown) events" : "\(shown) \(noun)")
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .help(noun != "events" ? "" : travel.capped ? "This window is very busy; only its newest part is shown. Choose a shorter window for the rest."
                      : travel.clipped ? "Older events of this window load as you scroll to the end of the list." : "")
            if noun == "events" && travel.loadingMore { ProgressView().controlSize(.mini) }
            if let s = travel.sampleAtPlayhead {
                Text("·").foregroundStyle(.secondary)
                Text("CPU \(Int(s.cpu.rounded()))% · Memory \(Int((s.mem * 100).rounded()))%"
                     + (s.top?.first.map { " · busiest: \($0.name) \(Int($0.cpu.rounded()))%" } ?? ""))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .help("Resource use at the playhead")
            }
            Spacer()
        }
        .font(.system(size: 12))
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .background(Color.accentColor.opacity(0.08))
    }
}

/// `Hostwatch --time-travel-probe [dir]`: times the overview and a few slices on real history.
func runTimeTravelProbe(_ path: String?) -> Never {
    let dir = path.map { URL(fileURLWithPath: $0) } ?? HistoryRecorder.defaultDirectory
    let archive = HistoryArchive(directory: dir)
    let clock = ContinuousClock()
    var segments: [HistoryArchive.Segment] = []
    print("segments:", clock.measure { segments = archive.segments() }, "\(segments.count) files")
    guard let range = HistoryArchive.range(of: segments) else { print("no history"); exit(1) }
    print("range:", range.lowerBound, "–", range.upperBound)
    var bars: [Double] = []
    print("activity (240 buckets):", clock.measure { bars = archive.activity(segments, over: range, buckets: 240) })
    print("busiest bucket: \(Int((bars.max() ?? 0) / 1000)) KB, empty buckets: \(bars.filter { $0 == 0 }.count)")
    let mid = range.lowerBound.addingTimeInterval(range.upperBound.timeIntervalSince(range.lowerBound) / 2)
    for span in [60.0, 300, 900, 3600] {
        var result: (events: [ActivityEvent], clipped: Bool) = ([], false)
        let t = clock.measure { result = archive.events(segments, from: mid.addingTimeInterval(-span), to: mid) }
        print("slice \(Int(span / 60)) min:", t, "\(result.events.count) events", result.clipped ? "(clipped)" : "")
    }
    // What Time Travel reads first: one page.
    var page: (events: [ActivityEvent], clipped: Bool) = ([], false)
    let pt = clock.measure { page = archive.events(segments, from: mid.addingTimeInterval(-3600), to: mid, maxBytes: TimeTravel.pageBytes) }
    print("first page of 1 hour:", pt, "\(page.events.count) events", page.clipped ? "(more on scroll)" : "")
    // What counts toward the history size limit (read only).
    let kept = HistoryFiles.kept(in: dir, current: nil, today: MetricsArchive.dayName(Date()))
    func sum(_ prefix: String) -> String {
        HistoryRecorder.format(kept.filter { $0.url.lastPathComponent.hasPrefix(prefix) }.reduce(0) { $0 + $1.bytes })
    }
    print("counted toward the limit: \(HistoryRecorder.format(kept.reduce(0) { $0 + $1.bytes }))",
          "(activity \(sum("activity-")), metrics \(sum("metrics-")), processes \(sum("processes-")))")
    // Running Now at moments 20 s apart over the newest recorded process lists.
    let processes = ProcessHistory(directory: dir)
    let cache = ProcessDayCache()
    if let day = processes.archive.days().last {
        let lines = cache.lines(day: day, archive: processes.archive)
        if lines.count >= 2 {
            let from = lines[lines.count - 2].t - 30
            for step in 0..<5 {
                let at = Date(timeIntervalSince1970: from + Double(step) * 20)
                var snap: ProcessHistory.Snapshot?
                let t = clock.measure { snap = processes.snapshot(at: at, cache: cache) }
                let busiest = snap?.processes.max { ($0.cpu ?? 0) < ($1.cpu ?? 0) }
                let total = snap?.processes.reduce(0) { $0 + $1.cpuTime } ?? 0
                print("processes at +\(step * 20) s:", t, "\(snap?.processes.count ?? 0) running,",
                      "CPU time \(Int(total)) s, busiest \(busiest?.name ?? "–") \(Int(busiest?.cpu ?? 0))%")
            }
        }
    }
    // Search all history: a common word (stops at the cap) and one that is rarely there (reads everything).
    for query in ["curl", "zz-not-recorded-zz"] {
        var hits = 0, back: Date?
        var capped = false
        let t = clock.measure {
            capped = archive.search(segments, query: query, limit: TimeTravel.maxSearchHits, stop: { false }) {
                hits += $0.hits.count; back = $0.reachedBack
            }
        }
        print("search \"\(query)\":", t, "\(hits) hits", capped ? "(capped)" : "", "back to", back.map { "\($0)" } ?? "–")
    }
    exit(0)
}
