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
}
