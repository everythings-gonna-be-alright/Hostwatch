import Foundation
import Testing
@testable import Hostwatch

/// Network Firewall ▸ Apps ▸ an app's Everywhere ▸ Block: every connection of the app's programs is blocked, your
/// network too, but the destinations its own card allows.
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

    @Test func itWinsOverGeneralAndTheLocalNetwork() {
        // A Safe pattern, a routine risk, a General Allow, and the local network: all lose to the app's block.
        let yours = FirewallDecision(verdict: .allow, reason: "you allowed slack.com")
        let card = AppRules(app: slack, everywhere: .block)
        for f in [facts(helper), facts(helper, ip: "192.168.1.19")] {
            let d = FirewallPolicy.decide(f, status: .safe, yours: yours, app: card)
            #expect(d.verdict == .block && d.reason == "you block Slack everywhere")
        }
    }

    @Test func anAppCoversItsProgramsAndNothingElse() {
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID()).json"))
        fw.setEverywhere(.block, app: slack)
        #expect(fw.appRules(for: helper)?.everywhere == .block)
        #expect(fw.appRules(for: "/Applications/Slack.app/Contents/MacOS/Slack")?.app == slack)
        #expect(fw.appRules(for: "/Applications/Slack Beta.app/Contents/MacOS/Slack") == nil)   // a name alike isn't it
        fw.setEverywhere(.firewall, app: slack)
        #expect(fw.appRules(for: helper)?.everywhere == .firewall)              // the card stays until you remove it
        fw.removeApp(slack)
        #expect(fw.apps.isEmpty)
    }

    @Test func hostwatchCantBeBlocked() {
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID()).json"))
        guard let own = Bundle.main.executablePath else { return }
        fw.setEverywhere(.block, app: own)
        #expect(fw.apps.isEmpty)
    }

    @Test func itIsKept() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("appblock-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fw = firewall(dir.appendingPathComponent("fw.json"))
        fw.setEverywhere(.block, app: slack)
        let again = firewall(dir.appendingPathComponent("fw.json"))
        #expect(again.apps == [AppRules(app: slack, everywhere: .block)])
    }

    @Test func everywheresBlockStopsAllButTheAppsAllowedEverywhere() {
        let allowed = AppRules(app: slack, everywhere: .allow)
        let d = FirewallPolicy.decide(facts("/usr/bin/curl"), status: .safe, blockedEverywhere: true)
        #expect(d.verdict == .block && d.reason == "you block every program everywhere, but the ones you allow")
        let ok = FirewallPolicy.decide(facts(helper), status: .unclassified, app: allowed, blockedEverywhere: true)
        #expect(ok.verdict == .allow && ok.reason == "you allow Slack everywhere")
        // Hostwatch itself still connects.
        let own = FirewallPolicy.decide(facts("/x/Hostwatch"), status: .unclassified, blockedEverywhere: true, hostwatch: "/x/Hostwatch")
        #expect(own.verdict == .allow)
    }

    @Test func allowEverywhereIsNoWayPastAThreatListOrAGeneralBlock() {
        var bad = facts(helper)
        bad.knownBad = "ThreatFox: a command server"
        let allowed = AppRules(app: slack, everywhere: .allow)
        #expect(FirewallPolicy.decide(bad, status: .safe, app: allowed).verdict == .block)
        #expect(FirewallPolicy.decide(bad, status: .safe, threatException: true, app: allowed).verdict == .allow)
        let general = FirewallDecision(verdict: .block, reason: "you block slack.com")
        #expect(FirewallPolicy.decide(facts(helper), status: .safe, yours: general, app: allowed).verdict == .block)
    }

    @Test func aChangeIsInEffectAtOnce() {
        // The collector remembers answers (a block for a minute): every rule change tells it to forget them, so an app
        // you unblock connects at once.
        let fw = firewall(FileManager.default.temporaryDirectory.appendingPathComponent("flush-\(UUID()).json"))
        var flushed = 0
        fw.flushAnswers = { flushed += 1 }
        fw.setEverywhere(.block, app: slack)
        fw.setEverywhere(.firewall, app: slack)
        fw.setEverywhereBlocked(true)
        fw.setEverywhere(.allow, app: slack)
        fw.setBlocked(true, domain: "example.com", program: "/usr/bin/curl")
        fw.removeApp(slack)
        #expect(flushed == 6)
    }
}
