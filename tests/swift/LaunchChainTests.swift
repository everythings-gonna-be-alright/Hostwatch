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
}
