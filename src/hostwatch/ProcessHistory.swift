import Foundation

// MARK: - Process lists over time (Running Now in Time Travel)

/// Every running process, recorded about once a minute, so Time Travel can show what ran at any moment.
/// One file per day (`processes-YYYYMMDD.jsonl`), compressed when the day is over, removed with its history.
/// A line is one moment: `{"t":…,"k":1,"new":[rows],"gone":[pid],"v":[[pid,cpuTime,mem,threads]]}`.
struct ProcessHistory: Sendable {
    // Keyframes (`k:1`: the first line of each day, then every 30 minutes) list every process. Lines between
    // them list only what changed since the line before: started (`new`), ended (`gone`), or moved (`v`).
    // A moment is rebuilt from its keyframe: ~200 KB per keyframe, a few KB per minute in between.
    let directory: URL
    static let prefix = "processes"
    static let keyframeEvery: TimeInterval = 30 * 60
    /// A moment shows the last list recorded at most this long before it (Hostwatch may have been closed).
    static let maxAge: TimeInterval = 3 * 60

    var archive: MetricsArchive { MetricsArchive(directory: directory, prefix: Self.prefix) }

    /// What was running at one moment.
    struct Snapshot: Sendable, Equatable {
        var at: Date                          // the moment shown ("running for" counts to it)
        var recordedAt: Date                  // the recorded list it is built from (at or before `at`)
        var processes: [RunningProcessInfo]   // `cpu`: % of one core around `at` (nil: unknown)
    }

    // MARK: Writing

    /// What the next line is a change from.
    struct WriterState: Sendable {
        var day = ""
        var lastKeyframe: Double = 0
        var last: [Int: RunningProcessInfo] = [:]
    }

    /// The line for `list` at `t`, given what was written before (updated in place).
    static func line(for list: [RunningProcessInfo], at t: Double, day: String, state: inout WriterState) -> Data {
        let key = state.day != day || t - state.lastKeyframe >= keyframeEvery || state.last.isEmpty
        let current = Dictionary(list.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        var new: [RunningProcessInfo] = []
        var gone: [Int] = []
        var changed: [[Double]] = []
        if key {
            new = list
        } else {
            for (pid, old) in state.last {
                if let now = current[pid], now.start == old.start { continue }
                gone.append(pid)                                             // ended, or its PID was reused
            }
            for p in list {
                guard let old = state.last[p.pid], old.start == p.start else { new.append(p); continue }
                let memMoved = abs(Double(p.mem - old.mem)) > Double(max(old.mem, 1)) * 0.01
                if p.cpuTime - old.cpuTime >= 0.01 || memMoved || p.threads != old.threads {
                    changed.append([Double(p.pid), (p.cpuTime * 100).rounded() / 100, Double(p.mem), Double(p.threads)])
                }
            }
        }
        // Stored without the live CPU %: it is recomputed from CPU time between lines.
        let rows = new.map { var r = $0; r.cpu = nil; return r }
        var out = Data("{\"t\":\(Int(t.rounded())),\"k\":\(key ? 1 : 0)".utf8)
        if !rows.isEmpty, let json = try? JSONEncoder().encode(rows) { out += Data(",\"new\":".utf8) + json }
        if !gone.isEmpty { out += Data(",\"gone\":[\(gone.sorted().map(String.init).joined(separator: ","))]".utf8) }
        if !changed.isEmpty {
            let v = changed.map { r in "[\(Int(r[0])),\(r[1]),\(Int64(r[2])),\(Int(r[3]))]" }.joined(separator: ",")
            out += Data(",\"v\":[\(v)]".utf8)
        }
        out += Data("}".utf8)
        // What the reader will know after this line (stored numbers only, so later diffs match the file).
        var next = key ? [:] : state.last
        for pid in gone { next[pid] = nil }
        for r in rows { next[r.pid] = r }
        for r in changed {
            let pid = Int(r[0])
            next[pid]?.cpuTime = r[1]; next[pid]?.mem = Int64(r[2]); next[pid]?.threads = Int(r[3])
        }
        state.last = next
        state.day = day
        if key { state.lastKeyframe = t }
        return out
    }

    // MARK: Reading

    /// The process list at `date`: the last one recorded at or before it (within `maxAge`), nil when none was.
    func snapshot(at date: Date, cache: ProcessDayCache? = nil) -> Snapshot? {
        let day = MetricsArchive.dayName(date)
        let lines = cache?.lines(day: day, archive: archive) ?? Self.index(archive.data(day: day))
        return Self.rebuild(lines, at: date.timeIntervalSince1970)
    }

    /// One recorded line: its time, whether it's a keyframe, and its bytes.
    struct Line: Sendable {
        var t: Double
        var key: Bool
        var bytes: Data
    }

    /// The day's lines, time and kind read from their fixed start (`{"t":…,"k":…`), nothing else parsed.
    static func index(_ data: Data) -> [Line] {
        data.split(separator: 0x0A).compactMap { raw in
            let head = raw.prefix(40)
            guard head.starts(with: Data("{\"t\":".utf8)) else { return nil }
            let digits = head.dropFirst(5).prefix { $0 >= 48 && $0 <= 57 }
            guard let t = Double(String(decoding: digits, as: UTF8.self)) else { return nil }
            let key = head.range(of: Data("\"k\":1".utf8)) != nil
            return Line(t: t, key: key, bytes: Data(raw))
        }
    }

    /// The moment `t`, from the list recorded at or before it and the next one: processes that started in
    /// between appear at their start, CPU time and memory move between the two lists, CPU % is the rate across
    /// them. Without a next list (the newest moment, or Hostwatch was closed) the minute before is used.
    static func rebuild(_ lines: [Line], at t: Double) -> Snapshot? {
        guard let end = lines.lastIndex(where: { $0.t <= t }), t - lines[end].t <= maxAge,
              let start = lines[...end].lastIndex(where: \.key) else { return nil }
        var alive: [Int: RunningProcessInfo] = [:]
        var before: (alive: [Int: RunningProcessInfo], t: Double)?
        for i in start...end {
            before = lines[i].key ? nil : (alive, lines[i - 1].t)
            apply(lines[i], to: &alive)
        }
        let at = lines[end].t
        var out: [RunningProcessInfo] = []
        if end + 1 < lines.count, lines[end + 1].t - at <= maxAge, lines[end + 1].t > at {
            var next = alive
            apply(lines[end + 1], to: &next)
            let nextT = lines[end + 1].t
            let f = (t - at) / (nextT - at)
            for var p in alive.values {
                if let n = next[p.pid], n.start == p.start {
                    p.cpu = max(0, (n.cpuTime - p.cpuTime) / (nextT - at) * 100)
                    p.cpuTime += (n.cpuTime - p.cpuTime) * f
                    p.mem += Int64(Double(n.mem - p.mem) * f)
                } else {
                    p.cpu = before.flatMap { b in b.alive[p.pid].map { max(0, (p.cpuTime - $0.cpuTime) / (at - b.t) * 100) } }
                }
                out.append(p)
            }
            // Started after the earlier list, by now: shown from their start, CPU time growing to the next list's.
            for var n in next.values where alive[n.pid]?.start != n.start && n.start > 0 && n.start <= t {
                let lived = max(nextT - n.start, 1)
                n.cpu = n.cpuTime / lived * 100
                n.cpuTime *= min(1, max(0, t - n.start) / lived)
                out.removeAll { $0.pid == n.pid }
                out.append(n)
            }
        } else {
            for var p in alive.values {
                if let b = before, at > b.t {
                    if let old = b.alive[p.pid], old.start == p.start {
                        p.cpu = max(0, (p.cpuTime - old.cpuTime) / (at - b.t) * 100)
                    } else if p.start >= b.t, p.start < at {
                        p.cpu = max(0, p.cpuTime / (at - p.start) * 100)          // started in between
                    }
                }
                out.append(p)
            }
        }
        return Snapshot(at: Date(timeIntervalSince1970: t), recordedAt: Date(timeIntervalSince1970: at),
                        processes: out.sorted { $0.pid < $1.pid })
    }

    /// One line's changes, applied to the processes alive before it (a keyframe replaces them).
    private static func apply(_ line: Line, to alive: inout [Int: RunningProcessInfo]) {
        guard let obj = (try? JSONSerialization.jsonObject(with: line.bytes)) as? [String: Any] else { return }
        if line.key { alive = [:] }
        for pid in obj["gone"] as? [Int] ?? [] { alive[pid] = nil }
        if let new = obj["new"], let json = try? JSONSerialization.data(withJSONObject: new),
           let rows = try? JSONDecoder().decode([RunningProcessInfo].self, from: json) {
            for r in rows { alive[r.pid] = r }
        }
        for v in obj["v"] as? [[NSNumber]] ?? [] where v.count == 4 {
            let pid = v[0].intValue
            alive[pid]?.cpuTime = v[1].doubleValue
            alive[pid]?.mem = v[2].int64Value
            alive[pid]?.threads = v[3].intValue
        }
    }
}

/// The last day read, indexed, so scrubbing doesn't re-read or re-decompress it (today is re-read when stale).
final class ProcessDayCache: @unchecked Sendable {
    private let lock = NSLock()
    private var day = ""
    private var lines: [ProcessHistory.Line] = []
    private var readAt = Date.distantPast

    func lines(day: String, archive: MetricsArchive) -> [ProcessHistory.Line] {
        lock.lock()
        let today = MetricsArchive.dayName(Date())
        if day == self.day, day != today || Date().timeIntervalSince(readAt) < 30 {
            defer { lock.unlock() }
            return lines
        }
        lock.unlock()
        let fresh = ProcessHistory.index(archive.data(day: day))
        lock.lock()
        self.day = day
        lines = fresh
        readAt = Date()
        lock.unlock()
        return fresh
    }

    func clear() {
        lock.lock()
        day = ""
        lines = []
        lock.unlock()
    }
}

// MARK: - Recorder

/// Asks the collector for the process list about once a minute and writes the change since the last one.
@MainActor
final class ProcessRecorder {
    static let interval: TimeInterval = 60
    /// Whether to record (history on, not the demo).
    var enabled: () -> Bool = { false }
    /// Asks the collector for a list (its answer arrives through `receive`).
    var request: () -> Void = {}
    private let directory: () -> URL
    private var timer: Timer?
    private var lastWrite = Date.distantPast
    private var state = ProcessHistory.WriterState()
    private let writer = DispatchQueue(label: "hostwatch.processes", qos: .utility)
    private var lastMaintenanceDay = ""

    init(directory: @escaping () -> URL) {
        self.directory = directory
    }

    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        timer?.tolerance = 5
    }

    private func tick() {
        guard enabled(), Date().timeIntervalSince(lastWrite) >= Self.interval - 5 else { return }
        request()
    }

    /// Any process list from the collector (Running Now asks every 3 s while open; one a minute is kept).
    func receive(_ list: [RunningProcessInfo], at date: Date = Date()) {
        guard enabled(), !list.isEmpty, date.timeIntervalSince(lastWrite) >= Self.interval - 5 else { return }
        lastWrite = date
        let day = MetricsArchive.dayName(date)
        let line = ProcessHistory.line(for: list, at: date.timeIntervalSince1970, day: day, state: &state)
        let archive = ProcessHistory(directory: directory()).archive
        let maintain = day != lastMaintenanceDay
        lastMaintenanceDay = day
        let keepFrom = maintain ? HistoryFiles.list(in: archive.directory).first.flatMap { MetricsStore.day(ofHistory: $0.name) } : nil
        writer.async {
            archive.append(line: line, day: day)
            if maintain { archive.maintain(today: day, keepFrom: keepFrom) }
        }
    }

    /// History was deleted or moved: the next line starts a new keyframe.
    func reset() { state = ProcessHistory.WriterState() }
}
