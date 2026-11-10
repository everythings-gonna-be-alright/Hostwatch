import Foundation
import Testing
@testable import Hostwatch

/// The overlay folds repeats into one row with a summary, and never folds an exception.
@Suite struct HUDFolding {
    func file(_ proc: String, _ path: String, _ mode: String = "r") -> ActivityEvent {
        ActivityEvent(kind: .file, time: "04:58:30", pid: 1, ppid: 1, name: (proc as NSString).lastPathComponent, proc: proc,
                      target: path, extra: mode, parent: "")
    }

    @Test func repeatsFoldIntoOneRowWithASummary() {
        let app = "/System/Applications/Shortcuts.app/Contents/Resources"
        let events = (0..<12).map { file("/usr/libexec/BackgroundShortcuts", "\(app)/\($0).lproj/x.strings") }
            + [file("/bin/sleep", "/bin/sleep")]
        let items = HUDFold.fold(events, limit: 10) { "\($0.kind)|\($0.proc)" }
        #expect(items.count == 2 && items[0].count == 12)
        #expect(HUDFold.summary(items[0].events) == "read 12 files in Shortcuts.app")
    }

    @Test func anExceptionKeepsItsOwnRowAndTheLimitCountsRows() {
        let events = (0..<5).map { file("/usr/bin/x", "/tmp/\($0)") }
        let items = HUDFold.fold(events, limit: 3) { $0.target == "/tmp/2" ? nil : "same" }
        #expect(items.count == 2 && items[0].count == 4 && items[1].event.target == "/tmp/2")
        #expect(HUDFold.fold((0..<9).map { file("/p\($0)", "/x") }, limit: 3) { "\($0.proc)" }.count == 3)
    }

    @Test func summariesForLaunchesAndConnections() {
        let launches = ["sleep", "cat", "jq", "sed"].map {
            ActivityEvent(kind: .exec, time: "", pid: 1, ppid: 1, name: $0, proc: "/bin/\($0)", target: "/bin/\($0)", extra: "", parent: "/bin/zsh")
        }
        #expect(HUDFold.summary(launches) == "started 4 programs: sleep, cat, jq…")
        #expect(HUDFold.place([AppPaths.userHome + "/Library/Preferences/a.plist", AppPaths.userHome + "/Library/Preferences/b.plist"])
                == "~/Library/Preferences")
    }

    @Test func onlyABurstFolds() {
        let a = ActivityEvent(kind: .file, time: "04:58:30.10", pid: 1, ppid: 1, name: "x", proc: "/x", target: "/a", extra: "r", parent: "")
        let b = ActivityEvent(kind: .file, time: "04:58:28.00", pid: 1, ppid: 1, name: "x", proc: "/x", target: "/b", extra: "r", parent: "")
        let c = ActivityEvent(kind: .file, time: "04:58:10.00", pid: 1, ppid: 1, name: "x", proc: "/x", target: "/c", extra: "r", parent: "")
        let items = HUDFold.fold([a, b, c], limit: 5) { _ in "same" }
        #expect(items.map(\.count) == [2, 1])                         // c is 20 s older: its own row
    }

    @Test func singleRowsRead() {
        let f = file("/usr/sbin/cfprefsd", AppPaths.userHome + "/Library/Preferences/com.apple.x.plist")
        #expect(HUDFold.detail(f) == "com.apple.x.plist in ~/Library/Preferences")
        let launch = ActivityEvent(kind: .exec, time: "", pid: 1, ppid: 1, name: "sleep", proc: "/bin/sleep", target: "/bin/sleep",
                                   extra: "", parent: "/bin/zsh")
        #expect(HUDFold.detail(launch) == "started by zsh")
    }
}
