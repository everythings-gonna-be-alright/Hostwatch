import Darwin
import Foundation
import Testing
@testable import Hostwatch

/// Events ▸ Running Now: the collector's process list, the rows, and the jump to a launch in Time Travel.
@Suite struct RunningNow {
    func info(_ pid: Int, _ name: String, ppid: Int = 1, start: Double = 1_800_000_000, cpu: Double? = 1,
              args: String = "", user: String = "someone") -> RunningProcessInfo {
        RunningProcessInfo(pid: pid, ppid: ppid, start: start, uid: 501, user: user, name: name, path: "/usr/bin/\(name)",
                           args: args, cpu: cpu, cpuTime: 2, mem: 1_000_000, threads: 3)
    }

    @Test func commandLineIsReadFromTheKernel() {
        let argv = ProcessTable.commandLine(Int(getpid()))
        #expect(!argv.isEmpty)
        #expect(argv.first.map { Agent.base($0) } == Agent.base(ProcessList.path(Int(getpid()))))
    }

    @Test func cpuIsMeasuredBetweenTwoListsOfTheSameProcess() {
        let me = Int(getpid())
        let key = ProcessInstance(pid: me, start: 7)
        let before = [key: ProcessUsage(cpuNanos: 1e9, footprint: 1, read: 0, written: 0)]
        let now = [key: ProcessUsage(cpuNanos: 2e9, footprint: 5_000_000, read: 0, written: 0),
                   ProcessInstance(pid: 1, start: 1): ProcessUsage(cpuNanos: 3e9, footprint: 1, read: 0, written: 0)]
        let rows = ProcessTable.rows(now: now, before: before, seconds: 2) { _ in nil }
        let mine = rows.first { $0.pid == me }
        #expect(mine?.cpu == 50)                    // 1 s of CPU in 2 s
        #expect(mine?.cpuTime == 2 && mine?.mem == 5_000_000 && (mine?.threads ?? 0) >= 1)
        #expect(rows.first { $0.pid == 1 }?.cpu == nil)   // nothing to compare with
        #expect(ProcessTable.rows(now: now, before: nil, seconds: 0) { _ in nil }.allSatisfy { $0.cpu == nil })
    }

    @Test func theListIsSentWithItsKindFirst() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(ProcessListMessage(list: [info(5, "zsh")]))
        #expect(String(decoding: data.prefix(20), as: UTF8.self).hasPrefix(#"{"kind":"proc_list""#))
        #expect(try JSONDecoder().decode(ProcessListMessage.self, from: data).list == [info(5, "zsh")])
    }

    @MainActor @Test func theModelPassesTheListOnEvenWhenPaused() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-run-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = HUDModel(signatures: SignatureStore(directory: dir), stories: StoryEngine(persistent: false),
                             domains: DomainRegistry(replayLearningUntil: Date()))
        var got: [RunningProcessInfo] = []
        model.onProcessList = { got = $0 }
        model.paused = true
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        var line = try encoder.encode(ProcessListMessage(list: [info(5, "zsh"), info(6, "vim", ppid: 5)]))
        line.append(0x0A)
        model.receive(line)
        #expect(got.map(\.pid) == [5, 6] && model.history.isEmpty)
    }

    @Test func rowsKnowTheirParentAndMatchSearch() {
        let rows = RunningRow.rows([info(5, "zsh"), info(6, "vim", ppid: 5, args: "vim notes.txt"), info(7, "kernel_task", ppid: 0)])
        #expect(rows.first { $0.pid == 6 }?.parentName == "zsh")
        #expect(rows.first { $0.pid == 7 }?.parentName == "kernel")
        let vim = rows.first { $0.pid == 6 }!
        #expect(vim.matches("notes") && vim.matches("vim") && vim.matches("6") && vim.matches("someone") && !vim.matches("emacs"))
    }

    @Test func theLaunchIsFoundByPidAndStartTime() {
        var old = ActivityEvent(kind: .exec, time: "10:00:00", pid: 42, ppid: 1, name: "tool", proc: "/bin/zsh",
                                target: "/tmp/tool", extra: "", parent: "zsh")
        old.pstart = 1_700_000_000                              // an earlier process with the same pid
        var current = ActivityEvent(kind: .exec, time: "11:00:00", pid: 42, ppid: 1, name: "tool", proc: "/bin/zsh",
                                    target: "/tmp/tool", extra: "", parent: "zsh")
        current.pstart = 1_800_000_000.25
        let net = ActivityEvent(kind: .net, time: "11:00:01", pid: 42, ppid: 1, name: "tool", proc: "/tmp/tool",
                                target: "1.2.3.4:443", extra: "TCP", parent: "")
        let events = [net, old, current]
        #expect(TimeTravel.launch(in: events, pid: 42, start: 1_800_000_000)?.id == current.id)
        #expect(TimeTravel.launch(in: events, pid: 43, start: 1_800_000_000) == nil)
        #expect(TimeTravel.launch(in: events, pid: 42, start: 1_900_000_000) == nil)   // that process wasn't recorded
    }

    @MainActor @Test func aLaunchBeforeTheRecordingCantBeShown() {
        let running = RunningProcesses()
        let row = RunningRow.rows([info(5, "zsh", start: 1_800_000_000)])[0]
        #expect(running.launchRecorded(row))                   // recording start not known yet: try
        #expect(!running.launchRecorded(RunningRow.rows([info(5, "zsh", start: 0)])[0]))
    }

    @Test func durationsReadLikeActivityMonitor() {
        #expect(RunningFormat.duration(42) == "42 s")
        #expect(RunningFormat.duration(3 * 3600 + 5 * 60) == "3 h 5 min")
        #expect(RunningFormat.duration(2 * 86_400 + 3600) == "2 d 1 h")
        #expect(RunningFormat.cpuTime(1.5) == "1.50 s")
        #expect(RunningFormat.cpuTime(3725) == "1:02:05")
        #expect(RunningFormat.cpu(nil) == "–")
    }

    @MainActor @Test func watchCloselyGetsTheProcessAsALaunch() {
        let row = RunningRow.rows([info(9, "node", args: "node server.js")])[0]
        let e = RunningProcessesView.event(for: row)
        #expect(e.kind == .exec && e.pid == 9 && e.target == "/usr/bin/node" && e.args == "node server.js" && e.pstart == 1_800_000_000)
    }
}

/// Running Now's Writing column, live: bytes per second between two lists of the same process.
@MainActor @Suite struct RunningNowWriteRate {
    func info(_ pid: Int, start: Double, written: Int64?) -> RunningProcessInfo {
        RunningProcessInfo(pid: pid, ppid: 1, start: start, uid: 501, user: "alex", name: "p\(pid)", path: "/bin/p\(pid)",
                           args: "", cpu: nil, cpuTime: 1, mem: 1, threads: 1, written: written)
    }

    @Test func rateFromTwoLists() {
        let running = RunningProcesses()
        running.showing = true
        defer { running.showing = false }
        let t = Date(timeIntervalSince1970: 1_800_000_000)
        running.receive([info(1, start: 10, written: 1000), info(2, start: 10, written: nil)], at: t)
        #expect(running.rows.allSatisfy { $0.info.writeRate == nil })               // nothing to compare yet
        running.receive([info(1, start: 10, written: 7000), info(2, start: 10, written: nil), info(3, start: 20, written: 50)],
                        at: t.addingTimeInterval(3))
        #expect(running.rows.first { $0.pid == 1 }?.info.writeRate == 2000)
        #expect(running.rows.first { $0.pid == 2 }?.info.writeRate == nil)          // not known (older collector)
        #expect(running.rows.first { $0.pid == 3 }?.info.writeRate == nil)          // new: next refresh
        running.receive([info(1, start: 99, written: 10)], at: t.addingTimeInterval(6))   // PID reused
        #expect(running.rows.first?.info.writeRate == nil)
    }
}
