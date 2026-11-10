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

/// Classify with AI on what the list shows or what you selected: only the New patterns among them.
@MainActor @Suite struct ClassifyScope {
    @Test func onlyNewPatternsAmongTheGivenOnes() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("scope-\(UUID().uuidString)"))
        func launch(_ target: String) -> ActivityEvent {
            ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: (target as NSString).lastPathComponent,
                          proc: target, target: target, extra: "", parent: "/bin/zsh")
        }
        let events = ["/opt/homebrew/bin/aaa", "/opt/homebrew/bin/bbb", "/opt/homebrew/bin/ccc"].map(launch)
        for e in events { _ = store.observe(e) }
        let keys = events.map(\.signatureKey)
        store.set(.safe, keys: [keys[1]])                              // decided: not classified again
        let c = PatternClassifier(store: store)
        #expect(Set(c.classifiable(in: Set(keys)).map(\.id)) == [keys[0], keys[2]])
        #expect(c.classifiable(in: [keys[0]]).map(\.id) == [keys[0]])
        #expect(c.classifiable(in: []).isEmpty)
    }

    @Test func applyingASelectionUsesSuggestionsAlreadyThere() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("apply-\(UUID().uuidString)"))
        store.autoAcceptAI = false
        let events = ["/opt/homebrew/bin/aaa", "/opt/homebrew/bin/bbb"].map {
            ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: ($0 as NSString).lastPathComponent,
                          proc: $0, target: $0, extra: "", parent: "/bin/zsh")
        }
        for e in events { _ = store.observe(e) }
        let keys = events.map(\.signatureKey)
        store.suggest(.suspicious, key: keys[0], source: "claude", note: "odd")
        store.suggest(.safe, key: keys[1], source: "on-device", note: "ordinary")
        let c = PatternClassifier(store: store)
        #expect(c.classifiable(in: Set(keys)).isEmpty && c.undecided(in: Set(keys)) == 2)   // the bug: skipped
        c.classifyAll(apply: true, only: Set(keys))
        #expect(store.status(forKey: keys[0]) == .suspicious && store.status(forKey: keys[1]) == .safe)
        #expect(c.bulk == nil)                                         // nothing left to ask: no AI call
    }

    @Test func codesignIsYoursToDecideAndOneClickDoesIt() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("yours-\(UUID().uuidString)"))
        // Reading a build folder in a project: an AI's Safe may apply (ADR 0013).
        let read = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "codesign", proc: "/usr/bin/codesign",
                                 target: NSHomeDirectory() + "/Documents/Proj/.build/out/Products/Debug/App", extra: "r", parent: "/usr/bin/swift-package")
        _ = store.observe(read)
        #expect(!PatternClassifier.staysYours(store.entry(read.signatureKey)!))
        // Writing into Downloads: yours, with the reason.
        let e = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "codesign", proc: "/usr/bin/codesign",
                              target: NSHomeDirectory() + "/Downloads/Tool.app/Contents/MacOS/Tool", extra: "w", parent: "/bin/zsh")
        _ = store.observe(e)
        let entry = store.entry(e.signatureKey)!
        #expect(PatternClassifier.staysYours(entry))
        #expect(PatternClassifier.yoursBecause(entry).hasSuffix("so only you can mark it Safe"))
        let c = PatternClassifier(store: store)
        c.live.add([entry], as: .asking("Claude"))
        c.decide(entry.id, .safe)
        #expect(store.status(forKey: entry.id) == .safe && store.entry(entry.id)?.source == "you")
        #expect(c.live.steps.first?.state == .done(.safe, by: "You", reason: ""))
    }
}
