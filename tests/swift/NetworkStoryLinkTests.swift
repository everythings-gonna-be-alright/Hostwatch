import Foundation
import Testing
@testable import Hostwatch

/// The network map's "Tried to reach this Mac" links to its story only while that story is there.
@Suite struct NetworkStoryLink {
    func story(_ target: String, network: Bool = true, dismissed: Bool = false) -> Story {
        let e = ActivityEvent(kind: .net, time: "", pid: 0, ppid: 0, name: "TV", proc: "", target: target,
                              extra: "TCP", parent: "", host: "", hostSource: "")
        var s = Story(rootPid: 0, originName: "TV (\(target))", originPath: network ? "network:TV" : "/bin/sh",
                      origin: .background, steps: [StoryStep(e, stage: .portScan, note: "", date: Date())],
                      firstSeen: Date(), lastSeen: Date())
        s.dismissed = dismissed
        return s
    }

    @Test func findsTheOpenStoryByAnyAddress() {
        let s = story("192.168.1.40:22")
        #expect(StoryEngine.networkStory(about: ["fe80::1", "192.168.1.40"], in: [s])?.id == s.id)
        #expect(StoryEngine.networkStory(about: ["192.168.1.4"], in: [s]) == nil)        // not a prefix of another address
    }

    @Test func deletedOrDismissedMeansNoLink() {
        #expect(StoryEngine.networkStory(about: ["192.168.1.40"], in: []) == nil)
        #expect(StoryEngine.networkStory(about: ["192.168.1.40"], in: [story("192.168.1.40", dismissed: true)]) == nil)
        #expect(StoryEngine.networkStory(about: ["192.168.1.40"], in: [story("192.168.1.40", network: false)]) == nil)
    }
}
