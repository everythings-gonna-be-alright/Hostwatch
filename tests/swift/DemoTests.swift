import Foundation
import Testing
@testable import Hostwatch

/// Demo mode: the made-up activity parses like the collector's and tells its story.
@MainActor @Suite struct DemoData {
    @Test func linesAreCollectorEventsOfTheMadeUpUser() throws {
        let decoder = JSONDecoder()
        let events = try Demo.lines().map { try decoder.decode(ActivityEvent.self, from: $0.dropLast()) }
        #expect(events.count > 30)
        #expect(Set(events.map(\.kind)) == [.exec, .net, .file])
        let paths = events.flatMap { [$0.proc, $0.target, $0.args] }.joined(separator: " ")
        #expect(!paths.contains(FileManager.default.homeDirectoryForCurrentUser.path))
        #expect(paths.contains(Demo.home + "/Downloads/CleanMyDisk.app"))
    }

    @Test func runningListMatchesTheLaunches() {
        let list = Demo.runningList(jitter: false)
        let launches = Demo.lines().compactMap { try? JSONDecoder().decode(ActivityEvent.self, from: $0.dropLast()) }
        let cleaner = list.first { $0.name == "CleanMyDisk" }!
        #expect(TimeTravel.launch(in: launches, pid: cleaner.pid, start: cleaner.start) != nil)
        #expect(list.contains { $0.user == "root" } && list.allSatisfy { $0.uid == ($0.user == "root" ? 0 : 501) })
    }

    @Test func watchProfileShowsTheRiskyThings() {
        let p = Demo.watchProfile()
        let risky = p.highlights(home: Demo.home).filter { $0.level == .risky }.map(\.text)
        #expect(risky.contains { $0.contains("LaunchAgents/com.cleanmydisk.update.plist") })
        #expect(p.network.count == 3 && p.processes.count == 3)
    }
}
