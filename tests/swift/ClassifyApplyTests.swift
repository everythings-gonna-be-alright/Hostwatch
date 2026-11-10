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
}
