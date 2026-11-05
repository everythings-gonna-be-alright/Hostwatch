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
