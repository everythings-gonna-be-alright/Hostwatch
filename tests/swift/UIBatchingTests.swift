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
