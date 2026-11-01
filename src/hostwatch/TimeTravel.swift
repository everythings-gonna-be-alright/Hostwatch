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
        let decoder = JSONDecoder()
        let events = lines.reversed().compactMap { try? decoder.decode(ActivityEvent.self, from: $0) }
        return (events, clipped)
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
    @Published private(set) var clipped = false
    @Published private(set) var playing = false
    @Published var speed: Double = 1            // history seconds per real second
    @Published private(set) var markers: [TimelineMarker] = []
    @Published var hoverX: CGFloat?             // pointer over the scrubber (for the time label)

    static let spans: [(String, TimeInterval)] = [("1 min", 60), ("5 min", 300), ("15 min", 900), ("1 hour", 3600)]
    static let speeds: [(String, Double)] = [("1×", 1), ("10×", 10), ("60×", 60), ("600×", 600)]
    nonisolated static let buckets = 240

    private let history: HistoryRecorder
    private let stories: StoryEngine
    private let domains: DomainRegistry
    private var segments: [HistoryArchive.Segment] = []
    private var loadTask: Task<Void, Never>?
    private var overviewTask: Task<Void, Never>?
    private var playTimer: Timer?
    private var refreshTimer: Timer?

    init(history: HistoryRecorder, stories: StoryEngine, domains: DomainRegistry) {
        self.history = history
        self.stories = stories
        self.domains = domains
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
        overviewTask?.cancel()
        refreshTimer?.invalidate()
        refreshTimer = nil
        events = []
    }

    func toggle() { active ? exit() : enter() }

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
        }
    }

    private func scheduleLoad() {
        guard active, !segments.isEmpty else { return }
        let archive = archive, segments = segments, from = windowStart, to = playhead
        loadTask?.cancel()
        loading = true
        loadTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(90))          // coalesce drags
            guard !Task.isCancelled else { return }
            let result = await Task.detached(priority: .userInitiated) {
                archive.events(segments, from: from, to: to)
            }.value
            guard let self, !Task.isCancelled else { return }
            self.events = result.events
            self.clipped = result.clipped
            self.loading = false
        }
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
    private var hover: CGFloat? { travel.hoverX }

    private static let dayTime: Date.FormatStyle = .dateTime.weekday(.abbreviated).day().month(.abbreviated)
        .hour().minute()
    private static let clock: Date.FormatStyle = .dateTime.hour().minute().second()

    var body: some View {
        VStack(spacing: 8) {
            if let range = travel.range {
                scrubber(range)
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
                if case .active(let p) = phase { travel.hoverX = p.x } else { travel.hoverX = nil }
            }
            .help(markerHelp(near: hover, x: x) ?? "Drag to travel through recorded activity")
        }
        .frame(height: 64)
        .accessibilityElement()
        .accessibilityLabel("Timeline")
        .accessibilityValue(Text(travel.playhead, format: Self.dayTime))
        .accessibilityAdjustableAction { direction in travel.step(direction == .increment ? 1 : -1) }
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

/// Above the event list while traveling: which slice is shown, and the way back.
struct TimeTravelBanner: View {
    @ObservedObject var travel: TimeTravel
    let shown: Int

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "clock.arrow.circlepath").foregroundStyle(.tint)
            Text("History").fontWeight(.semibold)
            Text("\(travel.windowStart.formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated).hour().minute().second())) – \(travel.playhead.formatted(.dateTime.hour().minute().second()))")
                .monospacedDigit()
            Text("·").foregroundStyle(.secondary)
            Text(travel.clipped ? "newest \(shown) events" : "\(shown) events")
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .help(travel.clipped ? "This slice is very busy; only its newest part is shown. Choose a shorter window." : "")
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
    exit(0)
}
