import Foundation
import Testing
@testable import Hostwatch

/// `--origin-report`'s notion of where a process came from: the nearest ancestor that isn't a shell or wrapper.
@Suite struct ProcessOrigins {
    @Test func shellsAndWrappersAreSkipped() {
        let iterm = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        #expect(ProcessOrigin.classify(ancestors: ["/bin/zsh", "/usr/bin/login", iterm], brokenAt: false) == .terminal)
        #expect(ProcessOrigin.classify(ancestors: ["/bin/sh", "/usr/bin/env", "/Applications/Slack.app/Contents/MacOS/Slack"],
                                       brokenAt: false) == .app)
        #expect(ProcessOrigin.classify(ancestors: ["/bin/bash", "/usr/sbin/cron"], brokenAt: false) == .scheduled)
        #expect(ProcessOrigin.classify(ancestors: ["/bin/zsh", "/usr/sbin/sshd"], brokenAt: false) == .ssh)
        #expect(ProcessOrigin.classify(ancestors: ["/Users/me/Downloads/updater"], brokenAt: false) == .other)
    }

    @Test func anAgentAnywhereUpTheChainCounts() {
        let claude = "/Users/me/.local/share/claude/versions/2.1.318"
        #expect(ProcessOrigin.classify(ancestors: ["/bin/zsh", claude, "/bin/zsh", "/Applications/iTerm.app/Contents/MacOS/iTerm2"],
                                       brokenAt: false) == .agent)
    }

    @Test func theEndOfTheChainSaysLaunchdOrUnknown() {
        #expect(ProcessOrigin.classify(ancestors: [], brokenAt: false) == .launchd)          // reached pid 1
        #expect(ProcessOrigin.classify(ancestors: ["/bin/zsh"], brokenAt: true) == .unknown)  // started before recording
        #expect(ProcessOrigin.classify(ancestors: ["/sbin/launchd"], brokenAt: false) == .launchd)
    }

    @Test func onlyToolsAndInterpretersAreInScope() {
        #expect(ProcessOrigin.isToolLike("/usr/bin/curl"))
        #expect(ProcessOrigin.isToolLike("/usr/bin/python3"))
        #expect(ProcessOrigin.isToolLike("/bin/zsh"))
        #expect(!ProcessOrigin.isToolLike("/Applications/Slack.app/Contents/MacOS/Slack"))
    }
}
