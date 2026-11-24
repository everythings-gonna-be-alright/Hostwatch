import Foundation
import Testing
@testable import Hostwatch

/// Show Launch Chain and Ask AI's "Launch chain": rebuilt from what was recorded, not from what is still running.
@Suite struct LaunchChains {
    func step(_ pid: Int, _ ppid: Int, _ path: String, _ args: String = "", _ source: LaunchStep.Source = .launch) -> LaunchStep {
        LaunchStep(pid: pid, ppid: ppid, path: path, args: args, source: source)
    }

    @Test func reachesLaunchdThroughExitedProcesses() {
        let known: [Int: LaunchStep] = [
            9961: step(9961, 9950, "/bin/sh", "/bin/sh -c 'swift test'"),
            9950: step(9950, 9900, "/Users/me/.local/share/claude/versions/2.1.318", "", .list),
            9900: step(9900, 1, "/bin/zsh", "", .list),
        ]
        let chain = LaunchChain.build(from: 9961) { known[$0] }
        #expect(chain.steps.map(\.pid) == [9961, 9950, 9900] && !chain.broken)
        let text = LaunchChain.text(chain)
        #expect(text.hasPrefix("origin: AI agent"))                       // the shell is skipped, the agent counts
        #expect(text.contains("← 1 launchd"))
    }

    @Test func aGapInTheRecordSaysSo() {
        let known: [Int: LaunchStep] = [500: step(500, 400, "/bin/bash")]
        let chain = LaunchChain.build(from: 500) { known[$0] }
        #expect(chain.broken && chain.steps.count == 1)
        #expect(LaunchChain.text(chain).contains("started before anything was recorded"))
    }

    @Test func aPidLoopEnds() {
        let known: [Int: LaunchStep] = [10: step(10, 20, "/bin/sh"), 20: step(20, 10, "/bin/sh")]
        #expect(LaunchChain.build(from: 10) { known[$0] }.steps.count == 2)
    }

    @Test func theReportNamesTheProgramPastTheShells() {
        let report = LaunchChainReport(process: step(54973, 54970, "/usr/bin/curl"),
                                       steps: [step(54970, 54955, "/bin/sh"), step(54955, 1, "/usr/sbin/auditd", "auditd -l", .list)],
                                       broken: false, session: nil)
        #expect(report.origin == .other && report.originIndex == 1)
        #expect(report.summary == "Started by auditd")
    }

    @Test func aGapSaysRecordingStartedLater() {
        let report = LaunchChainReport(process: step(9, 8, "/bin/ls"), steps: [step(8, 7, "/bin/zsh")], broken: true, session: nil)
        #expect(report.origin == .unknown && report.originIndex == nil)
        #expect(report.summary.contains("before Hostwatch was recording"))
    }
    @Test func theCauseIsTheCommandItCameFrom() {
        // git ran ssh through a shell: git's command says why, not the shell's.
        let ssh = step(30, 20, "/usr/bin/ssh", "ssh git@gitlab.example.org git-upload-pack 'team/app.git'")
        let report = LaunchChainReport(process: ssh,
                                       steps: [step(20, 10, "/bin/bash", "bash -c 'ssh git@gitlab.example.org'"),
                                               step(10, 5, "/usr/bin/git", "git clone git@gitlab.example.org:team/app.git"),
                                               step(5, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", "iTerm2")],
                                       broken: false, session: nil)
        #expect(report.cause?.args == "git clone git@gitlab.example.org:team/app.git")
    }

    @Test func aTerminalsOwnCommandIsNoCause() {
        let report = LaunchChainReport(process: step(9, 8, "/usr/bin/ssh", "ssh host"),
                                       steps: [step(8, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", "iTerm2")],
                                       broken: false, session: nil)
        #expect(report.cause == nil)
    }
}
