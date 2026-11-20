import Foundation
import Testing
@testable import Hostwatch

/// The native Endpoint Security client hands `Agent.normalize` the same shape eslogger printed, so both sources
/// give the same events.
@Suite struct ESSourceShape {
    let shell = ESShape.Process(path: "/bin/zsh", pid: 900, ppid: 1)

    @Test func execBecomesTheSameEventAsEsloggers() throws {
        let agent = Agent()
        let raw = ESShape.exec(caller: shell, target: .init(path: "/usr/bin/curl", pid: 901, ppid: 900),
                               args: ["curl", "-s", "https://example.com"])
        let ev = try #require(agent.normalize(raw))
        #expect(ev.kind == "exec")
        #expect(ev.string("proc") == "/usr/bin/curl" && ev.string("parent") == "/bin/zsh")
        #expect(ev.int("pid") == 901 && ev.int("ppid") == 900)
        #expect(ev.string("args").contains("https://example.com"))
    }

    @Test func openCarriesItsMode() throws {
        let agent = Agent()
        let write = try #require(agent.normalize(ESShape.open(caller: shell, path: "/tmp/hw-es-a", fflag: 2)))
        #expect(write.kind == "file" && write.string("target") == "/tmp/hw-es-a" && write.string("extra") == "w")
        let read = try #require(agent.normalize(ESShape.open(caller: shell, path: "/tmp/hw-es-b", fflag: 1)))
        #expect(read.string("extra") == "r")
    }

    @Test func exitIsNeverPublished() {
        #expect(Agent().normalize(ESShape.exit(caller: shell)) == nil)
    }

    @Test func onlyTheThreeEventsAreSubscribed() {
        #expect(["exec", "exit", "open", "fork"].allSatisfy { ESSource.eventType($0) != nil })
        #expect(ESSource.eventType("mmap") == nil)
    }
}

/// The entitled collector lives in its own bundle inside the app, and answers to the app's identity.
@Suite struct EntitledCollectorBundle {
    @Test func theHelperKnowsItsApp() {
        let app = "/Applications/Hostwatch.app"
        #expect(AppPaths.outerApp(ofBundle: app + "/" + AppPaths.collectorHelper).path == app)
        #expect(AppPaths.outerApp(ofBundle: app).path == app)
    }

    @Test func noHelperMeansTheAppItself() {
        let none = FileManager.default.temporaryDirectory.appendingPathComponent("hw-nohelper-\(UUID().uuidString).app")
        #expect(AppPaths.entitledCollector(in: none) == nil)
    }
}

/// The app notices it's talking to another copy's collector (an older Hostwatch elsewhere), and says which.
@Suite struct CollectorCopyCheck {
    @Test func ownCopyIsFineOthersAreNamed() {
        let mine = "/Applications/Hostwatch.app"
        #expect(AppDelegate.collectorCopyProblem(mine: mine, theirs: mine, version: "0.19.0") == nil)
        #expect(AppDelegate.collectorCopyProblem(mine: mine, theirs: nil, version: nil) == "")          // an older version
        let other = AppDelegate.collectorCopyProblem(mine: mine, theirs: NSHomeDirectory() + "/Downloads/Hostwatch.app", version: "0.19.0")
        #expect(other == "The old one belongs to the copy of Hostwatch in ~/Downloads. You can delete that copy afterwards.")
    }
}
