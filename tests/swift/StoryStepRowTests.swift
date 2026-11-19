import Foundation
import Testing
@testable import Hostwatch

/// The Stories card shows one connection once, with every stage it counted for.
@Suite struct StoryStepRows {
    func step(_ time: String, _ host: String, _ stage: StoryStage, pid: Int = 7) -> StoryStep {
        let e = ActivityEvent(kind: .net, time: time, pid: pid, ppid: 1, name: "Google Chrome Helper", proc: "/x/Helper",
                              target: "142.251.153.2:443", extra: "UDP", parent: "/x/Chrome")
        var s = StoryStep(e, stage: stage, note: "")
        s.host = host
        return s
    }

    @Test func oneConnectionTwiceIsOneRow() {
        let rows = StoryStepRow.rows([
            step("00:48:12", "gemini.google.com", .network), step("00:48:12", "gemini.google.com", .newDomain),
            step("00:48:18", "ssl.gstatic.com", .network),
            step("00:48:18", "ssl.gstatic.com", .network, pid: 8),                  // another process: its own row
        ])
        #expect(rows.count == 3)
        #expect(rows[0].steps.map(\.stage) == [.network, .newDomain])
    }
}
