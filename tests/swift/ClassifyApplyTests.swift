import Foundation
import Testing
@testable import Hostwatch

/// A local model that calls everything Safe with high confidence: the pipeline, not the model, is under test.
struct AlwaysSafe: LocalTriageModel {
    func status() -> LocalModelStatus { .ready }
    func triage(_ prompt: String) async throws -> LocalVerdict { LocalVerdict(verdict: .safe, confidence: .high, reason: "fine") }
}

/// Classify with AI ▸ Apply the Verdicts, end to end: the answers change the patterns' status.
@MainActor @Suite struct ClassifyApply {
    @Test func applyChangesStatus() async throws {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("pipe-\(UUID().uuidString)"))
        store.autoAcceptAI = false
        let events = ["/go/bin/aaa", "/go/bin/bbb", "/go/bin/ccc"].map { NSHomeDirectory() + $0 }.map {
            ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: ($0 as NSString).lastPathComponent,
                          proc: $0, target: $0, extra: "", parent: "/bin/bash", args: ($0 as NSString).lastPathComponent + " -r x")
        }
        for e in events { _ = store.observe(e) }
        let keys = events.map(\.signatureKey)
        let c = PatternClassifier(store: store, localModel: AlwaysSafe())
        c.engine = .onDevice
        #expect(keys.allSatisfy { store.status(forKey: $0) == .unclassified })
        c.classifyAll(apply: true, only: Set(keys))
        for _ in 0..<40 where c.bulk != nil || c.running { try await Task.sleep(for: .milliseconds(50)) }
        #expect(keys.allSatisfy { store.status(forKey: $0) == .safe })
        #expect(c.lastMessage.hasPrefix("Classified 3 patterns, verdicts applied"))
    }

    @Test func applyTheVerdictsAppliesASafeForARunAnythingToolAsYourDecision() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("yoursapply-\(UUID().uuidString)"))
        let previous = store.autoAcceptAI                 // a saved preference: put it back for the other tests
        store.autoAcceptAI = true
        defer { store.autoAcceptAI = previous }
        let e = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "codesign", proc: "/usr/bin/codesign",
                              target: NSHomeDirectory() + "/Downloads/Tool.app/Contents/MacOS/Tool", extra: "w", parent: "/bin/zsh")
        _ = store.observe(e)
        store.suggest(.safe, key: e.signatureKey, source: "claude", note: "re-signing a tool you downloaded")
        #expect(store.status(forKey: e.signatureKey) == .unclassified)       // never by itself
        let c = PatternClassifier(store: store, localModel: AlwaysSafe())
        c.classifyAll(apply: true, only: [e.signatureKey])
        #expect(store.status(forKey: e.signatureKey) == .safe)               // your Apply decides it
        #expect(store.entry(e.signatureKey)?.source == "you")
        #expect(store.entry(e.signatureKey)?.note?.contains("normally yours") == true)
    }

    @Test func reopenedPatternsAreClassifiedWhenYouAskAndTheAIIsToldWhy() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("reopen-\(UUID().uuidString)"))
        let e = ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: "aaa", proc: NSHomeDirectory() + "/go/bin/aaa",
                              target: NSHomeDirectory() + "/go/bin/aaa", extra: "", parent: "/bin/bash")
        _ = store.observe(e)
        let key = e.signatureKey
        store.set(.safe, keys: [key])
        #expect(store.reopen(keys: [key], reason: "part of a story: download then run") == 1)
        let c = PatternClassifier(store: store, localModel: AlwaysSafe())
        #expect(!c.classifiable.contains { $0.id == key })                    // automatic runs leave it to you
        #expect(c.classifiable(in: [key]).map(\.id) == [key] && c.undecided(in: [key]) == 1)   // asked: included
        let entry = store.entry(key)!
        let prompt = TriagePrompt.pattern(entry, context: nil)
        #expect(prompt.contains("Reopened: decided before, sent back because part of a story: download then run"))
        #expect(TriagePrompt.warningSigns(entry, context: nil).contains { $0.hasPrefix("reopened because") })
    }
}

/// A local model that takes a moment, so a run can be cancelled while it's asking.
struct SlowSafe: LocalTriageModel {
    func status() -> LocalModelStatus { .ready }
    func triage(_ prompt: String) async throws -> LocalVerdict {
        try await Task.sleep(for: .milliseconds(30))
        return LocalVerdict(verdict: .safe, confidence: .high, reason: "fine")
    }
}

/// Cancelling Classify with AI never blocks the next one (it used to stop before asking anything, on "Cancelled.").
@MainActor @Suite struct ClassifyAfterCancel {
    @Test func theNextRunAfterACancelClassifies() async throws {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("cancel-\(UUID().uuidString)"))
        store.autoAcceptAI = false
        let events = ["/go/bin/aaa", "/go/bin/bbb"].map { NSHomeDirectory() + $0 }.map {
            ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: ($0 as NSString).lastPathComponent,
                          proc: $0, target: $0, extra: "", parent: "/bin/bash", args: ($0 as NSString).lastPathComponent + " -r x")
        }
        for e in events { _ = store.observe(e) }
        let keys = Set(events.map(\.signatureKey))
        let c = PatternClassifier(store: store, localModel: SlowSafe())
        c.engine = .onDevice
        c.classifyAll(apply: true, only: keys)
        #expect(c.running)
        c.cancelAll()
        #expect(!c.running && c.bulk == nil && c.lastMessage == "Cancelled.")

        c.classifyAll(apply: true, only: keys)
        #expect(c.bulk != nil && c.running)                        // it starts, instead of stopping at once
        for _ in 0..<60 where c.bulk != nil || c.running { try await Task.sleep(for: .milliseconds(50)) }
        #expect(keys.allSatisfy { store.status(forKey: $0) == .safe })
        #expect(c.lastMessage.hasPrefix("Classified 2 patterns, verdicts applied"))
    }
}
