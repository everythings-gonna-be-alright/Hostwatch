import Foundation
import Testing
@testable import Hostwatch

/// The collector runs for days as root: its caches must stay bounded by what they hold, never grow with traffic.
@Suite(.serialized) struct CollectorMemory {
    /// Rewriting keys already present (a PID's next connection, the next DNS answer for an IP) must not grow
    /// the map's bookkeeping. This grew by one entry per write: 300 MB → 2 GB over a few days.
    @Test func rewritingTheSameKeysStaysBounded() {
        var map = BoundedMap<String, Int>(limit: 8192)
        for i in 0..<1_000_000 { map["10.0.0.\(i % 200)"] = i }
        #expect(map.count == 200)
        #expect(map.storage <= 2 * 1024 + 1)
        #expect(map["10.0.0.7"] == 999_807)
    }

    @Test func stillForgetsTheOldestPastItsLimit() {
        var map = BoundedMap<Int, Int>(limit: 100)
        for round in 0..<50 { for k in 0..<90 { map[k] = round } }      // compacts many times
        for k in 1000..<1020 { map[k] = 1 }                               // 110 keys: the 10 written longest ago go
        #expect(map.count == 100)
        #expect(map[0] == nil && map[9] == nil && map[10] == 49 && map[1019] == 1)
        #expect(map.storage <= 2 * 1024 + 1)
    }

    /// The real thing, measured: a long stretch of collector-like churn (connections from the same programs,
    /// repeated DNS answers, file opens) through the collector's caches, then the process's footprint.
    @Test func collectorCachesDoNotLeakUnderChurn() {
        var netPids = BoundedMap<Int, TimeInterval>(limit: 8192)
        var dnsNames = BoundedMap<String, String>(limit: 50_000)
        var dnsByName = BoundedMap<String, ([String], TimeInterval)>(limit: 5000)
        let opens = RecentSet<PidKey>(ttl: 120, limit: 50_000)
        func churn(_ n: Int, from start: Int) {
            for i in start..<(start + n) {
                let pid = 400 + i % 300
                netPids[pid] = Double(i)
                let ip = "142.250.\(i % 50).\(i % 251)"
                dnsNames[ip] = "host\(i % 700).example.com"
                dnsByName["host\(i % 700).example.com"] = ([ip], Double(i))
                _ = opens.seen(PidKey(pid: pid, text: "/Users/alex/Library/Caches/app/file\(i % 5000)"), now: Double(i))
            }
        }
        churn(300_000, from: 0)                                         // warm up: caches reach their working size
        let before = MemoryFootprint.current()
        churn(800_000, from: 300_000)
        let grown = Int64(MemoryFootprint.current()) - Int64(before)
        // With the leak this grew by well over 100 MB; bounded caches stay within a few MB of noise.
        #expect(grown < 24_000_000, "collector caches grew by \(grown / 1_000_000) MB under churn")
        #expect(netPids.storage <= 2 * 1024 + 1 && dnsNames.storage <= 2 * 12_550 + 1)
    }
}

/// Foundation hands out autoreleased objects for every parsed line; the collector's loops never run a run loop,
/// so only an explicit pool per line returns that memory.
@Suite(.serialized) struct CollectorLineLoops {
    /// A file-open event as eslogger writes it (trimmed, same shape and size class).
    static func esloggerLine(_ i: Int) -> Data {
        let process: [String: Any] = [
            "audit_token": ["pid": 400 + i % 300, "euid": 501, "ruid": 501, "pidversion": i],
            "ppid": 1, "original_ppid": 1, "group_id": 400, "session_id": 400, "is_platform_binary": false,
            "executable": ["path": "/Applications/Some App.app/Contents/MacOS/Some App \(i % 50)", "path_truncated": false,
                           "stat": ["st_size": 123_456, "st_mode": 33261, "st_ino": 9_876_543 + i]],
            "signing_id": "com.example.someapp", "team_id": "ABCDE12345", "cdhash": String(repeating: "ab", count: 20),
            "start_time": "2026-11-05T21:00:00.000000Z",
        ]
        let event: [String: Any] = ["open": ["fflag": 1, "file": ["path": "/Users/alex/Library/Caches/com.example/file\(i).db",
                                                                  "path_truncated": false]]]
        let raw: [String: Any] = ["process": process, "event": event, "event_type": 10, "version": 8, "seq_num": i,
                                  "time": "2026-11-05T21:00:00.123456789Z", "mach_time": 123_456_789 + i]
        var data = try! JSONSerialization.data(withJSONObject: raw)
        data.append(0x0A)
        return data
    }

    /// Feeds `count` lines through a pipe to a LineReader on a thread with no run loop (like the collector's) and
    /// returns how much this process's footprint grew while it parsed them like the collector does.
    func growth(lines count: Int, pooled: Bool) throws -> Int64 {
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        let writer = Thread {
            for i in 0..<count { let d = Self.esloggerLine(i); d.withUnsafeBytes { _ = write(fds[1], $0.baseAddress, d.count) } }
            close(fds[1])
        }
        let done = DispatchSemaphore(value: 0)
        var grown: Int64 = 0
        let before = MemoryFootprint.current()
        Thread.detachNewThread {
            let reader = LineReader(fd: fds[0])
            func handle(_ line: Data) {
                guard let raw = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return }
                let process = raw["process"] as? [String: Any] ?? [:]
                let exe = (process["executable"] as? [String: Any])?["path"] as? String ?? ""
                _ = (exe as NSString).lastPathComponent
            }
            if pooled {
                reader.forEach { handle($0); return true }
            } else {
                while let line = reader.next() { handle(line) }
            }
            grown = Int64(MemoryFootprint.current()) - Int64(before)
            close(fds[0])
            done.signal()
        }
        writer.start()
        done.wait()
        return grown
    }

    @Test func eachLineDrainsItsAutoreleasePool() throws {
        // The measurement can see the leak: without pools these lines keep hundreds of MB (365 MB measured).
        let leaked = try growth(lines: 60_000, pooled: false)
        #expect(leaked > 100_000_000, "without pools only \(leaked / 1_000_000) MB: the test can't see a leak")
        let grown = try growth(lines: 60_000, pooled: true)
        #expect(grown < 30_000_000, "parsing 60,000 lines kept \(grown / 1_000_000) MB")
    }
}

/// The line reader under the collector's busiest stream: its buffer must stay the size of the unread part.
@Suite(.serialized) struct LineReaderMemory {
    @Test func readingHundredsOfMegabytesKeepsNoneOfThem() throws {
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        let line = Data((String(repeating: "x", count: 1999) + "\n").utf8)
        let block = Data((0..<64).map { _ in line }.joined())            // 128 KB of whole lines
        let writer = Thread {
            for _ in 0..<2400 { block.withUnsafeBytes { _ = write(fds[1], $0.baseAddress, block.count) } }   // 300 MB
            close(fds[1])
        }
        let reader = LineReader(fd: fds[0])
        var count = 0
        let before = MemoryFootprint.current()
        writer.start()
        reader.forEach { _ in count += 1; return true }
        let grown = Int64(MemoryFootprint.current()) - Int64(before)
        close(fds[0])
        #expect(count == 2400 * 64)
        #expect(grown < 40_000_000, "reading 300 MB of lines kept \(grown / 1_000_000) MB")
    }
}
