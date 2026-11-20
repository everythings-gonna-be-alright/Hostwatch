import Foundation
import Testing
@testable import Hostwatch

/// Rules per app (ADR 0020): an app's own destinations, then its Everywhere ▸ Block, then General's destinations, then
/// its Everywhere ▸ Allow, then General's Everywhere. Older blocks become cards.
@MainActor @Suite struct AppRulesOrder {
    let cursor = "/Applications/Cursor.app"
    let helper = "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper"

    func facts(_ program: String, host: String = "example.com", ip: String = "93.184.216.34") -> FirewallFacts {
        FirewallFacts(program: program, proto: "TCP", ip: ip, port: "443", host: host, risk: .normal, riskReason: "",
                      knownBad: "", patternKey: "net|\(program)|TCP internet:443")
    }

    @Test func theAppsOwnDestinationWinsOverGeneral() {
        let card = AppRules(app: cursor, destinations: [Destination(target: "example.com", others: .allow)])
        let general = FirewallDecision(verdict: .block, reason: "you block example.com")
        let d = FirewallPolicy.decide(facts(helper, host: "api.example.com"), status: .unclassified, yours: general, app: card)
        #expect(d.verdict == .allow && d.reason == "you allow Cursor to example.com")
        // Another program still meets General's block.
        #expect(FirewallPolicy.decide(facts("/usr/bin/curl"), status: .unclassified, yours: general).verdict == .block)
    }

    @Test func aBlockedAppStillReachesWhatItsOwnCardAllows() {
        let card = AppRules(app: cursor, everywhere: .block, destinations: [Destination(target: "cursor.sh", others: .allow)])
        #expect(FirewallPolicy.decide(facts(helper, host: "api2.cursor.sh"), status: .unclassified, app: card).verdict == .allow)
        #expect(FirewallPolicy.decide(facts(helper, host: "other.org"), status: .safe, app: card).verdict == .block)
    }

    @Test func theMostSpecificDestinationAndCardDecide() {
        let card = AppRules(app: cursor, destinations: [Destination(target: "example.com", others: .block),
                                                        Destination(target: "api.example.com", others: .allow),
                                                        Destination(target: "off.example.com", on: false, others: .allow)])
        #expect(card.decision(host: "api.example.com", ip: "1.2.3.4")?.verdict == .allow)
        #expect(card.decision(host: "www.example.com", ip: "1.2.3.4")?.verdict == .block)
        #expect(card.decision(host: "off.example.com", ip: "1.2.3.4")?.verdict == .block)         // turned off: the parent
        // A card for the helper itself is more specific than the app's.
        #expect(AppRulesList.rules(for: helper, in: [AppRules(app: cursor), AppRules(app: helper)])?.app == helper)
    }

    @Test func aQuestionsBlockGoesToTheAppsCard() {
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-apprules"),
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("apprules-\(UUID()).json"))
        fw.setBlocked(true, domain: "tracker.example", program: helper)
        #expect(fw.apps.map(\.app) == [cursor])                          // the app, not its helper: every program in it
        fw.setBlocked(true, domain: "ads.example", program: "/Applications/Cursor.app/Contents/MacOS/Cursor")
        #expect(fw.apps.count == 1 && fw.apps[0].destinations.map(\.target) == ["tracker.example", "ads.example"])
        fw.setBlocked(false, domain: "tracker.example", program: helper)
        fw.setBlocked(false, domain: "ads.example", program: helper)
        #expect(fw.apps.isEmpty)                                         // a card made only by blocks goes with them
    }

    @Test func olderBlocksBecomeCards() {
        let general = Destination(target: "github.com", exceptions: PlaceExceptions(allowed: [cursor], blocked: ["/usr/bin/curl"]))
        let cards = AppRulesList.migrated(appBlocks: ["/Applications/Slack.app"], everywhereAllowed: [cursor],
                                          domainBlocks: ["kubescape|tracker.example"], destinations: [general])
        #expect(cards.map(\.app) == [cursor, "/Applications/Slack.app", "kubescape", "/usr/bin/curl"])
        #expect(cards[0].everywhere == .allow && cards[0].destinations.map(\.target) == ["github.com"])
        #expect(cards[1].everywhere == .block)
        #expect(cards[2].runs("/opt/homebrew/bin/kubescape") && cards[2].destinations.first?.others == .block)
        #expect(cards[3].destinations.first?.others == .block)
    }

    @Test func aGeneralDestinationsChipsMoveToTheApps() {
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-apprules"),
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("apprules-\(UUID()).json"))
        let general = Destination(target: "github.com", others: .block, exceptions: PlaceExceptions(allowed: [cursor]))
        let left = fw.adoptPrograms(from: [general])
        #expect(left.count == 1 && left[0].exceptions.isEmpty && left[0].others == .block)
        #expect(fw.appRules(for: helper)?.decision(host: "github.com", ip: "")?.verdict == .allow)
    }

    @Test func anOldFileIsReadIntoCards() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("apprules-old-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("fw.json")
        let old = #"{"entries":{},"allowed":0,"domainBlocks":["kubescape|tracker.example"],"appBlocks":["/Applications/Slack.app"],"everywhereBlocked":true,"everywhereAllowed":["/Applications/Cursor.app"]}"#
        try Vault.shared.write(Data(old.utf8), to: file)
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-apprules"), fileURL: file)
        #expect(fw.everywhereBlocked && fw.apps.count == 3)
        #expect(fw.isBlocked(domain: "tracker.example", program: "/opt/homebrew/bin/kubescape"))
    }
}
