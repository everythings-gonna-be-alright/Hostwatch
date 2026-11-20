import Foundation
import Testing
@testable import Hostwatch

/// Network Firewall ▸ Your destinations ▸ Everywhere ▸ Always block: every connection of the app's programs is blocked,
/// before any other rule.
@MainActor @Suite struct AppWithoutNetwork {
    let slack = "/Applications/Slack.app"
    let helper = "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper"

    func facts(_ program: String, ip: String = "93.184.216.34") -> FirewallFacts {
        FirewallFacts(program: program, proto: "TCP", ip: ip, port: "443", host: "slack.com", risk: .routine, riskReason: "",
                      knownBad: "", patternKey: "net|\(program)|TCP internet:443")
    }

    func firewall(_ file: URL) -> FirewallMonitor {
        FirewallMonitor(defaults: scratchDefaults("hw-appblock"), fileURL: file)
    }

    @Test func itWinsOverEverythingElse() {
        // A Safe pattern, a routine risk, your own Allow, and the local network: all lose to the app's block.
        let yours = FirewallDecision(verdict: .allow, reason: "you allowed slack.com")
        for f in [facts(helper), facts(helper, ip: "192.168.1.19")] {
            let d = FirewallPolicy.decide(f, status: .safe, yours: yours, blockedApp: slack)
            #expect(d.verdict == .block && d.reason == "you block Slack everywhere")
        }
    }

    @Test func anAppCoversItsProgramsAndNothingElse() {
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID()).json"))
        fw.setNoNetwork(true, app: slack)
        #expect(fw.blockedApp(facts(helper)) == slack)
        #expect(fw.blockedApp(facts("/Applications/Slack.app/Contents/MacOS/Slack")) == slack)
        #expect(fw.blockedApp(facts("/Applications/Slack Beta.app/Contents/MacOS/Slack")) == nil)   // a name alike isn't it
        #expect(fw.rules.contains { $0.kind == .appBlock && $0.key == slack })
        fw.setNoNetwork(false, app: slack)
        #expect(fw.blockedApp(facts(helper)) == nil && fw.appBlocks.isEmpty)
    }

    @Test func hostwatchCantBeBlocked() {
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID()).json"))
        guard let own = Bundle.main.executablePath else { return }
        fw.setNoNetwork(true, app: own)
        #expect(fw.appBlocks.isEmpty)
    }

    @Test func itIsKept() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fw = firewall(dir.appendingPathComponent("fw.json"))
        fw.setNoNetwork(true, app: slack)
        let again = firewall(dir.appendingPathComponent("fw.json"))
        #expect(again.appBlocks == [slack])
        // Removing it as a rule (Allow Again in Your rules) gives the network back.
        if let rule = again.rules.first(where: { $0.kind == .appBlock }) { again.remove(rule) }
        #expect(again.appBlocks.isEmpty)
    }




    @Test func everywheresBlockStopsAllButTheAllowed() {
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("everywhere-\(UUID()).json"))
        fw.setEverywhereBlocked(true)
        fw.setAllowedEverywhere(true, app: slack)
        #expect(fw.blockedEverywhere(facts("/usr/bin/curl")))
        #expect(!fw.blockedEverywhere(facts(helper)))                          // always allowed: kept out of the block
        let d = FirewallPolicy.decide(facts("/usr/bin/curl"), status: .safe, blockedEverywhere: true)
        #expect(d.verdict == .block && d.reason == "you block every program everywhere, but the ones you allow")
        // Hostwatch itself still connects.
        let own = FirewallPolicy.decide(facts("/x/Hostwatch"), status: .unclassified, blockedEverywhere: true, hostwatch: "/x/Hostwatch")
        #expect(own.verdict == .allow)
    }

    @Test func alwaysAllowEverywhereIsNoWayPastAThreatList() {
        var bad = facts(helper)
        bad.knownBad = "ThreatFox: a command server"
        // Kept out of Everywhere's block, so blockedEverywhere is false: the threat list still decides.
        let d = FirewallPolicy.decide(bad, status: .safe, blockedEverywhere: false)
        #expect(d.verdict == .block)
    }

    @Test func aChangeIsInEffectAtOnce() {
        // The collector remembers answers (a block for a minute): every rule change tells it to forget them, so an app
        // you unblock connects at once.
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("flush-\(UUID()).json"))
        var flushed = 0
        fw.flushAnswers = { flushed += 1 }
        fw.setNoNetwork(true, app: slack)
        fw.setNoNetwork(false, app: slack)
        fw.setEverywhereBlocked(true)
        fw.setAllowedEverywhere(true, app: slack)
        fw.setBlocked(true, domain: "example.com", program: "/usr/bin/curl")
        #expect(flushed == 5)
    }
}
