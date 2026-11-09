import Foundation
import Testing
@testable import Hostwatch

/// Classify with AI, live: each pattern once, its state as it moves, and what's open when a run ends.
@MainActor @Suite struct ClassifyLiveSteps {
    func entry(_ key: String) -> SignatureEntry {
        SignatureEntry(id: key, kind: .exec, process: "/bin/zsh", pattern: "/usr/bin/\(key)", count: 1,
                       firstSeen: Date(), lastSeen: Date(), status: .unclassified, exampleName: key, examplePid: 1,
                       exampleProc: "/bin/zsh", exampleTarget: "/usr/bin/\(key)", exampleExtra: "", exampleParent: "/bin/zsh")
    }

    @Test func aPatternIsListedOnceAndMoves() {
        let live = ClassifyLive()
        live.start(engine: "Local model first, then Claude")
        live.add([entry("a"), entry("b")], as: .waiting("local model"))
        live.add([entry("a")], as: .waiting("Claude"))
        #expect(live.steps.count == 2)
        live.set("a", .asking("Apple"))
        #expect(live.asking?.id == "a")
        live.set("a", .done(.safe, by: "Local", reason: "ordinary"))
        #expect(live.asking == nil && live.count { if case .done = $0 { true } else { false } } == 1)
    }

    @Test func endingARunClosesWhatIsOpen() {
        let live = ClassifyLive()
        live.add([entry("a"), entry("b")], as: .waiting("Claude"))
        live.set("b", .done(.suspicious, by: "Claude", reason: ""))
        live.finishOpen(.left("cancelled"))
        #expect(live.steps.first { $0.id == "a" }?.state == .left("cancelled"))
        #expect(live.steps.first { $0.id == "b" }?.state == .done(.suspicious, by: "Claude", reason: ""))
    }
}
