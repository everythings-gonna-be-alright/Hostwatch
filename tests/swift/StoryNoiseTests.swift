import Foundation
import Testing
@testable import Hostwatch

/// Every case here was a false story on a real Mac (November 2026): what made it, and that it no longer does,
/// beside the real thing it must still catch.
@MainActor @Suite(.serialized) struct StoryNoise {
    let python = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"
    let chrome = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"

    func engine() -> StoryEngine {
        _ = TestEnv.ready
        let e = StoryEngine(persistent: false)
        e.liveLookups = false
        return e
    }

    // MARK: Threat lists

    @Test func localAndCDNAddressesAreNobodysServer() {
        for ip in ["169.254.169.254", "192.168.1.5", "10.0.0.1", "127.0.0.1", "100.64.1.1", "0.0.0.0", "224.0.0.251", "fe80::1", "[::1]"] {
            #expect(FeedCheck.localAddress(ip), "\(ip)")
        }
        #expect(!FeedCheck.localAddress("45.33.12.7") && !FeedCheck.localAddress("2a00:1450::1"))
        #expect(!FeedCheck.matchableIP("169.254.169.254:80") && FeedCheck.matchableIP("45.33.12.7:443"))
        for ip in ["162.159.134.234", "104.18.39.21", "172.67.1.1", "151.101.1.1", "2606:4700::6810:84e5"] {
            #expect(FeedCheck.sharedNetwork(ip), "\(ip)")
        }
        #expect(!FeedCheck.sharedNetwork("45.33.12.7") && !FeedCheck.sharedNetwork("162.160.0.1"))
    }

    @Test func discordIsAPlatform() {
        #expect(FeedCheck.neverFlag("gateway-us-east1-c.discord.gg") && FeedCheck.platformHost("gateway-us-east1-c.discord.gg"))
        #expect(!FeedCheck.neverFlag("discord-nitro-gift.example"))
    }

    // MARK: Evidence

    /// A listed connection is one sign, and its "outbound connection" isn't a second: HaGeZi's mgid.com no longer
    /// makes a story alone. A malware tracker's match still does.
    @Test func oneEventIsOneSign() {
        let s = engine()
        s.ingest(net(chrome, pid: 700, to: "1.2.3.4:443", host: "mgid.com"), decidedSafe: false,
                 extra: [(.knownBad, "HaGeZi Threat Intelligence: malware or phishing domain"), (.network, "connected to mgid.com:443")])
        #expect(s.stories.isEmpty)
        s.ingest(net("/tmp/x/evil", pid: 701, to: "45.33.12.7:443", host: "bad.example"), decidedSafe: false,
                 extra: [(.knownBad, "ThreatFox: botnet command server")])
        #expect(s.stories.count == 1 && s.stories[0].severity == .dangerous)
    }

    @Test func contextNeverAddsToTheScore() {
        let step = { (stage: StoryStage, pid: Int) in
            StoryStep(net(self.chrome, pid: pid, to: "1.2.3.4:443"), stage: stage, note: "", date: Date())
        }
        let story = Story(rootPid: 1, originName: "x", originPath: "/x", origin: .app,
                          steps: [step(.knownBad, 1), step(.network, 1), step(.network, 2)])
        #expect(story.score == 8)
        #expect(!StoryEvidence.independent(story.steps))
        #expect(StoryEvidence.independent(story.steps + [step(.rawIP, 3)]))
    }

    /// One listing for one program: one story a day, not a new one every 40 minutes.
    @Test func theSameListingJoinsTheStoryAlreadyTold() {
        let s = engine()
        for (i, pid) in [800, 810, 820].enumerated() {
            s.ingest(net("/tmp/x/evil", pid: pid, to: "45.33.12.\(i + 7):443", host: "bad.example"), decidedSafe: false,
                     extra: [(.knownBad, "ThreatFox: botnet command server")])
        }
        #expect(s.stories.count == 1)
        #expect(s.stories[0].steps.filter { $0.stage == .knownBad }.count >= 2)
    }

    // MARK: Commands

    @Test func readingJSONInlineIsNotEncoded() {
        let json = #"python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("KEY") is None)'"#
        #expect(!StoryEvidence.riskyInline(json))
        #expect(StoryEvidence.riskyInline(#"python3 -c 'import base64,os; os.system(base64.b64decode("Y3VybA=="))'"#))
        #expect(StoryEvidence.riskyInline(#"python3 -c 'import socket,pty; s=socket.socket()'"#))
        #expect(StoryEvidence.riskyInline(#"perl -e 'system("id")'"#))
        let s = engine()
        let found = s.ingest(exec("/usr/bin/python3", pid: 900, ppid: 899, parent: "/bin/bash", args: json), decidedSafe: false)
        #expect(!found.contains { $0.0 == .encodedCommand })
    }

    /// python3 → python3.9 → Python.app pass one command on: one step, not three.
    @Test func oneCommandThroughLaunchersIsOneStep() {
        let code = #"'import base64; exec(base64.b64decode("cHJpbnQoMSk="))'"#
        let s = engine()
        s.ingest(exec("/usr/bin/python3", pid: 950, ppid: 949, parent: "/bin/bash", args: "python3 -c \(code)"), decidedSafe: false)
        s.ingest(exec("/Library/Developer/CommandLineTools/usr/bin/python3", pid: 950, ppid: 949, parent: "/usr/bin/python3",
                      args: "/Library/Developer/CommandLineTools/usr/bin/python3 -c \(code)"), decidedSafe: false)
        s.ingest(exec(python, pid: 950, ppid: 949, parent: "/Library/Developer/CommandLineTools/usr/bin/python3",
                      args: "\(python) -c \(code)"), decidedSafe: false)
        let steps = s.openChains.flatMap(\.steps).filter { $0.stage == .encodedCommand }
        #expect(steps.count == 1)
    }

    // MARK: Credentials

    @Test func aToolReadingItsOwnSignInIsNotTheft() {
        #expect(StoryEvidence.ownsCredential(program: python, args: "\(python) /opt/homebrew/bin/aws sso login",
                                             file: "\(home)/.aws/cli/cache/session.db", home: home))
        #expect(StoryEvidence.ownsCredential(program: "/opt/homebrew/bin/kubectl", args: "kubectl get pods",
                                             file: "\(home)/.kube/config", home: home))
        // Another tool's folder, or "aws" from Downloads: still credential access.
        #expect(!StoryEvidence.ownsCredential(program: "/opt/homebrew/bin/kubectl", args: "", file: "\(home)/.aws/credentials", home: home))
        #expect(!StoryEvidence.ownsCredential(program: python, args: "\(python) \(home)/Downloads/aws",
                                              file: "\(home)/.aws/credentials", home: home))
        #expect(!StoryEvidence.ownsCredential(program: python, args: "\(python) -c 'print(1)'",
                                              file: "\(home)/.aws/credentials", home: home))
    }

    @Test func theAWSSignInMakesNoCredentialStep() {
        let s = engine()
        s.ingest(exec(python, pid: 1000, ppid: 999, parent: "/opt/homebrew/bin/fish", args: "\(python) /opt/homebrew/bin/aws sso login"),
                 decidedSafe: false)
        let own = s.ingest(file(python, pid: 1000, "r", "\(home)/.aws/credentials"), decidedSafe: false)
        #expect(!own.contains { $0.0 == .credential })
        s.ingest(exec(python, pid: 1001, ppid: 999, parent: "/opt/homebrew/bin/fish", args: "\(python) \(home)/Downloads/aws"),
                 decidedSafe: false)
        let stolen = s.ingest(file(python, pid: 1001, "r", "\(home)/.aws/credentials"), decidedSafe: false)
        #expect(stolen.contains { $0.0 == .credential })
    }

    // MARK: Uploads on your network

    @Test func uploadsToADeviceThatIsntYoursCount() {
        let now = Date(), started = now.addingTimeInterval(-10 * 86400), first = now.addingTimeInterval(-3600)
        func rule(yours: Bool, system: Bool = false, mb: Int64 = 150) -> Bool {
            NetworkMapPolicy.isLargeUpload(sentLastHour: mb * 1_000_000, pairFirstSeen: first, mapStarted: started, now: now,
                                           yourNetwork: true, deviceYours: yours, systemProgram: system)
        }
        #expect(rule(yours: false))
        #expect(!rule(yours: true))                     // your NAS, your Time Machine disk
        #expect(!rule(yours: false, system: true))      // AirDrop, AirPlay: macOS itself
        #expect(!rule(yours: false, mb: 50))
    }
}
