import Foundation
import Testing
@testable import Hostwatch

/// The UI gets events in batches (and none while hidden); detection still sees every event at once.
@MainActor @Suite(.serialized) struct UIBatching {
    let model: HUDModel
    let dir: URL

    init() throws {
        _ = TestEnv.ready
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        model = HUDModel(signatures: SignatureStore(directory: dir), stories: StoryEngine(persistent: false),
                         domains: DomainRegistry(replayLearningUntil: Date()))
    }

    func line(_ pid: Int, _ name: String) -> Data {
        Data((#"{"kind":"exec","time":"12:00:00","pid":\#(pid),"ppid":1,"name":"\#(name)","proc":"/usr/bin/\#(name)","target":"/usr/bin/\#(name)","parent":"/bin/zsh","args":"\#(name)"}"# + "\n").utf8)
    }

    @Test func hiddenUIBuffersAndCatchesUpNewestFirst() {
        model.uiVisible = false
        model.receive(line(1, "one") + line(2, "two"))
        model.receive(line(3, "three"))
        #expect(model.history.isEmpty)                                   // nothing drawn while hidden
        #expect(model.signatures.entry(model.signatures.allEntries.first?.id ?? "") != nil)   // detection saw them
        model.uiVisible = true                                           // shown: catches up at once
        #expect(model.history.map(\.pid) == [3, 2, 1])
        #expect(model.counts[.exec] == 3)
    }

    @Test func visibleUIUpdatesInOneBatch() {
        model.receive(line(1, "a"))
        model.receive(line(2, "b"))
        #expect(model.history.isEmpty)                                   // waits for the batch
        model.flushUI()
        #expect(model.history.map(\.pid) == [2, 1])
        model.receive(line(3, "c"))
        model.flushUI()
        #expect(model.history.map(\.pid) == [3, 2, 1])
    }

    @Test func partialLinesAreJoined() {
        let full = line(7, "split")
        model.receive(full.prefix(30))
        model.receive(full.dropFirst(30))
        model.flushUI()
        #expect(model.history.map(\.pid) == [7])
    }

    // MARK: After a restart

    @Test func restartShowsTheNewestRecordedEventsBelowLiveOnes() async throws {
        let history = dir.appendingPathComponent("History")
        try FileManager.default.createDirectory(at: history, withIntermediateDirectories: true)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let t0 = Date().addingTimeInterval(-3600)
        let lines = (0..<6000).map { i in
            #"{"kind":"exec","time":"12:00:00","pid":\#(i),"ppid":1,"name":"old\#(i)","proc":"/usr/bin/true","target":"/usr/bin/true","ts":"\#(f.string(from: t0.addingTimeInterval(Double(i) * 0.5)))"}"#
        }.joined(separator: "\n") + "\n"
        try lines.write(to: history.appendingPathComponent("activity-20270115-080000-000.jsonl"), atomically: true, encoding: .utf8)

        model.receive(line(99_999, "live"))                                // a live event arrives first
        model.flushUI()
        await withCheckedContinuation { done in model.restoreRecent(from: history) { done.resume() } }

        #expect(model.history.count == model.historyLimit)                 // capped at the list's limit
        #expect(model.history.first?.pid == 99_999)                       // live stays on top
        #expect(model.history[1].pid == 5999 && model.history[2].pid == 5998)   // then newest recorded first
        #expect(model.history.dropFirst().allSatisfy { $0.seq < 0 })      // sorted below live events
        #expect(model.restoredCount == model.historyLimit)
    }

    @Test func noHistoryMeansNothingRestored() async {
        await withCheckedContinuation { done in
            model.restoreRecent(from: dir.appendingPathComponent("nothing-here")) { done.resume() }
        }
        #expect(model.history.isEmpty && model.restoredCount == 0)
    }
}

/// Show: three choices; the count on each is what that tab would list.
@MainActor @Suite struct ShowFilterChoices {
    @Test func earlierChoicesMapOntoTheThree() {
        #expect(SignatureFilter.allCases.map(\.short) == ["All", "New", "Important"])
        #expect(SignatureFilter(stored: "hideSafe") == .unclassified)
        #expect(SignatureFilter(stored: "flagged") == .important)
    }

    @Test func aCountIsWhatTheListShows() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-show-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = HUDModel(signatures: SignatureStore(directory: dir), stories: StoryEngine(persistent: false),
                             domains: DomainRegistry(replayLearningUntil: Date()))
        let events = [exec("/bin/sh", pid: 1, ppid: 0, parent: "/Applications/Slack.app/Contents/MacOS/Slack", args: "sh -c id"),
                      net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 2, to: "45.1.2.3:443")]
        for f in SignatureFilter.allCases where f != .all {
            #expect(model.showCounts(events)[f] == model.filtered(events, show: f).count)
        }
        #expect(model.showCounts(events)[.important] == 1)                       // the app's shell: high risk
    }
}

/// Classify with AI: every New pattern in batches, verdicts applied (never Safe for high risk) or kept as suggestions.
@MainActor @Suite(.serialized) struct ClassifyEverything {
    struct FakeModel: LocalTriageModel {
        func status() -> LocalModelStatus { .ready }
        func triage(_ prompt: String) async throws -> LocalVerdict {
            LocalVerdict(verdict: .safe, confidence: .high, reason: "ordinary")
        }
    }

    func make() throws -> (PatternClassifier, SignatureStore) {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-classify-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = SignatureStore(directory: dir)
        func name(_ i: Int) -> String {                                         // letters only: digits normalise to #
            String(UnicodeScalar(65 + i / 26)!) + String(UnicodeScalar(97 + i % 26)!) + "app"
        }
        for i in 0..<95 { store.observe(net("/Applications/\(name(i)).app/Contents/MacOS/\(name(i))", pid: i, to: "45.1.2.3:443")) }
        store.observe(exec("/bin/sh", pid: 500, ppid: 0, parent: "/Applications/Slack.app/Contents/MacOS/Slack", args: "sh -c id"))  // high risk
        let classifier = PatternClassifier(store: store, localModel: FakeModel())
        classifier.engine = .onDevice
        return (classifier, store)
    }

    func waitUntilDone(_ c: PatternClassifier) async throws {
        for _ in 0..<300 where c.bulk != nil || c.running { try await Task.sleep(nanoseconds: 20_000_000) }
    }

    @Test func allBatchesAndVerdictsAppliedButNeverSafeForHighRisk() async throws {
        let (classifier, store) = try make()
        let total = classifier.classifiable.count
        #expect(total == 96)
        classifier.classifyAll(apply: true)
        #expect(classifier.bulk?.total == 96)
        try await waitUntilDone(classifier)
        #expect(classifier.bulk == nil)
        #expect(store.count(.safe) >= 95)                                          // three batches of 40
        let shell = try #require(store.allEntries.first { $0.risk == .high })
        #expect(store.status(forKey: shell.id) == .unclassified)                  // high risk stays yours
    }

    @Test func orKeptAsSuggestions() async throws {
        let (classifier, store) = try make()
        classifier.classifyAll(apply: false)
        try await waitUntilDone(classifier)
        #expect(store.count(.safe) == 0)
        #expect(store.allEntries.filter { $0.suggestion?.status == .safe }.count >= 95)
    }
}
