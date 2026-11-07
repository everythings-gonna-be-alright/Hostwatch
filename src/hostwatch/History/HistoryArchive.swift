import Foundation

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
