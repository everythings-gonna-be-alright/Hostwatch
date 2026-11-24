import Foundation
import Testing
@testable import Hostwatch

/// The Patterns footer's line: where to start and the newest pattern, which the page doesn't say elsewhere.
@MainActor @Suite struct PatternHintLine {
    func entry(_ name: String, _ status: SignatureStatus, _ pattern: String, seen: Date) -> SignatureEntry {
        SignatureEntry(id: "net|\(name)|\(pattern)", kind: .net, process: name, pattern: pattern, count: 1, firstSeen: seen,
                       lastSeen: seen, status: status, source: nil, note: nil, exampleName: name, examplePid: 1, exampleProc: name,
                       exampleTarget: "", exampleExtra: "", exampleParent: "", exampleHost: nil, exampleHostSource: nil)
    }

    @Test func patternsNameWhereToStartAndTheNewest() {
        let now = Date()
        let line = PatternHint.make([
            entry("node", .unclassified, "a", seen: now.addingTimeInterval(-3600)),
            entry("node", .unclassified, "b", seen: now.addingTimeInterval(-3600)),
            entry("ssh", .unclassified, "c", seen: now.addingTimeInterval(-120)),
            entry("Safari", .safe, "d", seen: now.addingTimeInterval(-7200)),
        ], now: now)
        #expect(line.hasPrefix("Most to decide: node, 2 patterns · Newest: ssh, "))
    }

    @Test func allDecidedShowsOnlyTheNewest() {
        let now = Date()
        let line = PatternHint.make([entry("Safari", .safe, "d", seen: now.addingTimeInterval(-60))], now: now)
        #expect(line.hasPrefix("Newest: Safari, "))
        #expect(PatternHint.make([], now: now).hasPrefix("Nothing learned yet"))
    }
}
