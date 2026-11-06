import Darwin
import Foundation
import Testing
@testable import Hostwatch

// MARK: - Measuring

/// What a piece of work cost this process: CPU time, bytes written (logical writes, as the kernel counts them),
/// and how much bigger its memory footprint is afterwards.
struct ResourceCost: Codable {
    var cpu: Double            // seconds, user + system
    var writes: Int64          // bytes
    var memory: Int64          // bytes of footprint growth, kept afterwards
    var peak: Int64            // bytes of footprint growth at its highest during the work (a buffer freed at the end)

    /// Starts a new "highest footprint" interval (libproc; exported, not in the public header).
    private static let resetPeak: (@convention(c) (pid_t) -> Int32)? = {
        dlsym(dlopen(nil, RTLD_NOW), "proc_reset_footprint_interval").map { unsafeBitCast($0, to: (@convention(c) (pid_t) -> Int32).self) }
    }()

    static func sample() -> (cpu: Double, writes: Int64, footprint: Int64, peak: Int64) {
        var ru = rusage()
        getrusage(RUSAGE_SELF, &ru)
        let cpu = Double(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) + Double(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6
        var info = rusage_info_v4()
        _ = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(getpid(), RUSAGE_INFO_V4, $0) }
        }
        return (cpu, Int64(info.ri_logical_writes), Int64(info.ri_phys_footprint), Int64(info.ri_interval_max_phys_footprint))
    }

    /// Runs `work` and returns its cost; `keep` is whatever the work built, held until the memory is measured.
    static func measure<T>(_ work: () throws -> T) rethrows -> (ResourceCost, T) {
        // Performance cores when free: on efficiency cores the same work takes up to twice the CPU time.
        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)
        _ = resetPeak?(getpid())
        let a = sample()
        let kept = try work()
        let b = sample()
        return (ResourceCost(cpu: b.cpu - a.cpu, writes: b.writes - a.writes, memory: max(0, b.footprint - a.footprint),
                             peak: max(0, b.peak - a.footprint)), kept)
    }
}

/// The recorded costs (tests/perf-baseline.json) and the budget around them. `HOSTWATCH_PERF_RECORD=1 ./scripts/test.sh`
/// records new ones (each test alone): on purpose, after a change that is meant to cost more (or less).
enum PerfBaseline {
    static let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("perf-baseline.json")
    static var recording: Bool { ProcessInfo.processInfo.environment["HOSTWATCH_PERF_RECORD"] == "1" }
    private static let lock = NSLock()

    static func load() -> [String: ResourceCost] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        return (try? JSONDecoder().decode([String: ResourceCost].self, from: data)) ?? [:]
    }

    static func record(_ name: String, _ cost: ResourceCost) {
        lock.lock(); defer { lock.unlock() }
        var all = load()
        all[name] = cost
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try? encoder.encode(all).write(to: url, options: .atomic)
    }

    /// Measures and checks; when recording, measures 3 times and keeps the highest of each figure, so one lucky run
    /// (a quiet machine, memory that happened to be reused) can't set a baseline normal runs then exceed.
    static func enforce(_ name: String, _ work: () throws -> ResourceCost, sourceLocation: SourceLocation = #_sourceLocation) throws {
        guard recording else { check(name, try work(), sourceLocation: sourceLocation); return }
        var worst = try work()
        for _ in 0..<2 {
            let c = try work()
            worst = ResourceCost(cpu: max(worst.cpu, c.cpu), writes: max(worst.writes, c.writes),
                                 memory: max(worst.memory, c.memory), peak: max(worst.peak, c.peak))
        }
        check(name, worst, sourceLocation: sourceLocation)
    }

    /// Fails when the cost is over budget: writes +20% (they vary a few %; a careless rewrite costs 10× and more), memory +30%, CPU up to 2× (it depends on
    /// which cores macOS picks and what else runs; the regressions worth catching cost several times more), each with
    /// a small allowance so tiny numbers don't flap.
    static func check(_ name: String, _ cost: ResourceCost, sourceLocation: SourceLocation = #_sourceLocation) {
        print(String(format: "PERF %@: cpu %.2f s, writes %.1f MB, memory %.1f MB, peak %.1f MB", name, cost.cpu,
                     Double(cost.writes) / 1e6, Double(cost.memory) / 1e6, Double(cost.peak) / 1e6))
        if recording { record(name, cost); return }
        guard let base = load()[name] else {
            Issue.record("no baseline for \(name): run with HOSTWATCH_PERF_RECORD=1", sourceLocation: sourceLocation)
            return
        }
        let writeBudget = Int64(Double(base.writes) * 1.20) + 65_536
        let cpuBudget = base.cpu * 2.0 + 0.20
        // Kept memory can't exceed the peak: budget it from the larger of the two, so a run that happened to keep
        // nothing (memory reused) can't leave a baseline normal runs then exceed.
        let memoryBudget = Int64(Double(max(base.memory, base.peak)) * 1.3) + 16_000_000
        #expect(cost.writes <= writeBudget,
                "\(name) wrote \(cost.writes / 1000) KB, budget \(writeBudget / 1000) KB (baseline \(base.writes / 1000) KB)",
                sourceLocation: sourceLocation)
        #expect(cost.cpu <= cpuBudget,
                "\(name) used \(String(format: "%.2f", cost.cpu)) s CPU, budget \(String(format: "%.2f", cpuBudget)) s",
                sourceLocation: sourceLocation)
        #expect(cost.memory <= memoryBudget,
                "\(name) grew memory by \(cost.memory / 1_000_000) MB, budget \(memoryBudget / 1_000_000) MB",
                sourceLocation: sourceLocation)
        let peakBudget = Int64(Double(base.peak) * 1.3) + 16_000_000
        #expect(cost.peak <= peakBudget,
                "\(name) peaked \(cost.peak / 1_000_000) MB above its start, budget \(peakBudget / 1_000_000) MB",
                sourceLocation: sourceLocation)
    }
}

// MARK: - A realistic, repeatable workload

/// Collector lines like a busy Mac's: mostly file opens, connections, launches; a few hundred programs, thousands of
/// paths and hosts, timestamps a few ms apart. The same every run.
enum PerfWorkload {
    static let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    static let apps = (0..<300).map { "App\(letters($0))" }

    static func letters(_ n: Int) -> String {
        var s = "", v = n
        repeat { s.append(Character(UnicodeScalar(97 + v % 26)!)); v /= 26 } while v > 0
        return s
    }

    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static func line(_ i: Int) -> String {
        let ts = formatter.string(from: t0.addingTimeInterval(Double(i) * 0.005))
        let app = apps[(i * 7) % apps.count]
        let proc = "/Applications/\(app).app/Contents/MacOS/\(app)"
        switch i % 10 {
        case 3:                                     // a project file: one of the store's 15,000 existing patterns
            return #"{"kind":"file","time":"12:00:00","pid":\#(1000 + i % 4000),"ppid":1,"name":"\#(app)","proc":"\#(proc)","target":"\#(projectFile(i))","extra":"r","ts":"\#(ts)"}"#
        case 0:
            return #"{"kind":"exec","time":"12:00:00","pid":\#(1000 + i % 4000),"ppid":1,"name":"\#(app)","proc":"/sbin/launchd","target":"\#(proc)","parent":"/sbin/launchd","args":"\#(app) --flag","ts":"\#(ts)"}"#
        case 1, 2:
            let host = "api\(letters(i % 900)).example\(letters(i % 40)).com"
            return #"{"kind":"net","time":"12:00:00","pid":\#(1000 + i % 4000),"ppid":1,"name":"\#(app)","proc":"\#(proc)","target":"104.16.\#(i % 200).\#(i % 251):443","extra":"TCP","host":"\#(host)","host_src":"dns","ts":"\#(ts)"}"#
        default:
            let path = "/Users/alex/Library/Application Support/\(app)/cache/\(letters(i % 3000))/data.db"
            return #"{"kind":"file","time":"12:00:00","pid":\#(1000 + i % 4000),"ppid":1,"name":"\#(app)","proc":"\#(proc)","target":"\#(path)","extra":"\#(i % 3 == 0 ? "w" : "r")","ts":"\#(ts)"}"#
        }
    }

    static func lines(_ range: Range<Int>) -> Data { Data(range.map { line($0) + "\n" }.joined().utf8) }

    static let home = FileManager.default.homeDirectoryForCurrentUser.path

    /// One of 150 × 100 project folders: a pattern each ("r ~/Documents/work/<a>/<b>/*").
    static func projectFile(_ i: Int) -> String { "\(home)/Documents/work/\(letters(i % 150))/\(letters((i / 150) % 100))/notes.txt" }

    /// Chunks made before measuring: building the test data isn't the cost being measured.
    static func chunks(_ total: Int, by size: Int) -> [Data] {
        stride(from: 0, to: total, by: size).map { start in autoreleasepool { lines(start..<min(total, start + size)) } }
    }
}

// MARK: - The budget

/// Disk writes, CPU and memory of the main paths, against the recorded baseline. Runs alone (scripts/test.sh), so
/// other tests' work isn't counted.
@MainActor @Suite(.serialized) struct PerformanceBudget {
    func tempDir(_ tag: String) throws -> URL {
        _ = TestEnv.ready
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("hw-perf-\(tag)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    /// The app's event pipeline: parse, patterns, stories, domains, beacons, UI batches, with the pattern store saved
    /// as it is every 5 minutes (here every 4,000 events) and once at the end.
    @Test func appEventPipeline() throws { try PerfBaseline.enforce("app.eventPipeline", measureAppEventPipeline) }

    private func measureAppEventPipeline() throws -> ResourceCost {
        let dir = try tempDir("app")
        defer { try? FileManager.default.removeItem(at: dir) }
        let model = HUDModel(signatures: SignatureStore(directory: dir), stories: StoryEngine(persistent: false),
                             domains: DomainRegistry(replayLearningUntil: Date()))
        // A busy Mac's store first (15,000 patterns, not measured): its size is what a careless save rewrites.
        for i in 0..<15_000 {
            autoreleasepool {
                model.signatures.observe(ActivityEvent(kind: .file, time: "", pid: 1, ppid: 0, name: "tool", proc: "/usr/local/bin/tool",
                                                       target: PerfWorkload.projectFile(i), extra: "r", parent: ""))
            }
        }
        model.signatures.save(sync: true)
        let chunks = PerfWorkload.chunks(40_000, by: 200)
        let (cost, _) = ResourceCost.measure { () -> Int in
            for (n, chunk) in chunks.enumerated() {
                // A pool per batch, as the app's run loop drains one per batch of collector output.
                autoreleasepool {
                    model.receive(chunk)
                    if n % 5 == 0 { model.flushUI() }
                    if n % 20 == 0 { model.signatures.save(sync: true) }
                }
            }
            model.flushUI()
            model.signatures.save(sync: true)
            return model.history.count
        }
        #expect(model.history.count == model.historyLimit)
        return cost
    }

    /// History: 100,000 events through the compressed writer, flushed as every 30 s, then the file finished.
    @Test func historyWriting() throws { try PerfBaseline.enforce("history.write", measureHistoryWriting) }

    private func measureHistoryWriting() throws -> ResourceCost {
        let dir = try tempDir("history")
        defer { try? FileManager.default.removeItem(at: dir) }
        let stem = dir.appendingPathComponent("activity-20270115-080000-000.jsonl")
        let chunks = PerfWorkload.chunks(100_000, by: 500)
        let (cost, raw) = try ResourceCost.measure { () -> Int in
            let stream = try HistoryStream(stem: stem)
            var raw = 0
            for (n, chunk) in chunks.enumerated() {
                raw += chunk.count
                try autoreleasepool {
                    try stream.append(chunk)
                    try stream.sync()                                    // as every second
                    if n % 8 == 0 { try stream.seal() }
                }
            }
            try stream.finish()
            return raw
        }
        #expect(cost.writes < Int64(raw) / 5)                        // compressed, written once
        return cost
    }

    /// The collector's main loop: 120,000 eslogger events through the line reader, JSON and `normalize`, on a thread with no
    /// run loop (as in the collector).
    @Test func collectorEsloggerLoop() throws { try PerfBaseline.enforce("collector.esloggerLoop", measureCollectorEsloggerLoop) }

    private func measureCollectorEsloggerLoop() throws -> ResourceCost {
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        let agent = Agent()
        let input = (0..<120_000).map { i in autoreleasepool { CollectorLineLoops.esloggerLine(i) } }
        let writer = Thread {
            for d in input { d.withUnsafeBytes { _ = write(fds[1], $0.baseAddress, d.count) } }
            close(fds[1])
        }
        let (cost, events) = ResourceCost.measure { () -> Int in
            let reader = LineReader(fd: fds[0])
            var n = 0
            writer.start()
            reader.forEach { line in
                if let raw = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any], agent.normalize(raw) != nil { n += 1 }
                return true
            }
            close(fds[0])
            return n
        }
        #expect(events > 0)
        return cost
    }

    /// Time Travel on recorded history: a window's first page, then a full search through everything.
    @Test func timeTravelReading() throws { try PerfBaseline.enforce("timetravel.read", measureTimeTravelReading) }

    private func measureTimeTravelReading() throws -> ResourceCost {
        let dir = try tempDir("travel")
        defer { try? FileManager.default.removeItem(at: dir) }
        let stream = try HistoryStream(stem: dir.appendingPathComponent("activity-20270115-080000-000.jsonl"))
        for chunk in PerfWorkload.chunks(100_000, by: 2000) { try stream.append(chunk); try stream.seal() }
        try stream.finish()
        let archive = HistoryArchive(directory: dir)
        let (cost, found) = ResourceCost.measure { () -> (Int, Int) in
            let segments = archive.segments()
            let end = PerfWorkload.t0.addingTimeInterval(500)
            let page = archive.events(segments, from: end.addingTimeInterval(-3600), to: end, maxBytes: TimeTravel.pageBytes)
            var hits = 0
            archive.search(segments, query: "appqk", limit: TimeTravel.maxSearchHits, stop: { false }) { hits += $0.hits.count }
            return (page.events.count, hits)
        }
        #expect(found.0 > 1000 && found.1 > 0)
        return cost
    }
}
