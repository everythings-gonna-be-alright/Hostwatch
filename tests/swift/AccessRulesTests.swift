import Foundation
import Testing
@testable import Hostwatch

/// Your Allow and Block rules: matched most specific first (Block on a tie), refused where allowing every program
/// would open a whole area or a secret, and applied by Protection and the firewall before anything automatic.
@MainActor @Suite struct AccessRuleMatching {
    @Test func aFolderCoversWhatsInsideAndAnAppItsPrograms() {
        #expect(AccessRules.covers("/tmp/contracts", "/tmp/contracts/nda.pdf"))
        #expect(!AccessRules.covers("/tmp/contracts", "/tmp/contracts-old/x"))
        #expect(AccessRules.covers("/var/tmp/x", "/private/var/tmp/x/y"))
        #expect(AccessRules.runs("/Applications/Preview.app", "/Applications/Preview.app/Contents/MacOS/Preview"))
        #expect(!AccessRules.runs("/Applications/Preview.app", "/Applications/Preview.application"))
    }
}

/// Network destinations, shaped like places: a domain covers its subdomains, the most specific decides, its program
/// exceptions first (Block when on both), then its choice for any other program, before threat lists and patterns.
@MainActor @Suite struct DestinationsDecide {
    @Test func theMostSpecificDestinationAndItsExceptionsDecide() {
        var wide = Destination(target: "example.com"); wide.others = .block
        var narrow = Destination(target: "api.example.com"); narrow.exceptions.allowed = ["/Applications/Slack.app"]
        let list = [wide, narrow]
        #expect(Destinations.decide(list, host: "cdn.example.com", ip: "1.2.3.4", program: "/x")?.verdict == .block)
        #expect(Destinations.decide(list, host: "api.example.com", ip: "1.2.3.4",
                                    program: "/Applications/Slack.app/Contents/MacOS/Slack")?.verdict == .allow)
        #expect(Destinations.decide(list, host: "api.example.com", ip: "1.2.3.4", program: "/x") == nil)   // firewall decides
        #expect(Destinations.decide(list, host: "notexample.com", ip: "1.2.3.4", program: "/x") == nil)
        var both = Destination(target: "203.0.113.9"); both.exceptions = PlaceExceptions(allowed: ["/x"], blocked: ["/x"])
        #expect(Destinations.decide([both], host: "", ip: "203.0.113.9", program: "/x")?.verdict == .block)
    }

    @Test func onlyWholeDomainsAndIPs() {
        #expect(Destinations.refusal("example.com") == nil && Destinations.refusal("203.0.113.9") == nil)
        #expect(Destinations.refusal("com") != nil && Destinations.refusal("https://example.com/x") != nil)
    }

    @Test func yourDecisionComesBeforeThreatListsAndOldRulesMoveIn() {
        let suite = "dest-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
        m.accessRules = [AccessRule(kind: .network, target: "Example.com", program: nil, action: .allow),
                         AccessRule(kind: .network, target: "example.com", program: "/usr/bin/curl", action: .block)]
        m.moveNetworkRulesIntoDestinations()
        #expect(m.accessRules.isEmpty && m.destinations.count == 1)
        #expect(m.destinations[0].others == .allow && m.destinations[0].exceptions.blocked == ["/usr/bin/curl"])
        let facts = FirewallFacts(program: "/x", proto: "TCP", ip: "93.184.216.34", port: "443", host: "api.example.com",
                                  risk: .high, riskReason: "downloaded", knownBad: "ThreatFox", patternKey: "k")
        let yours = m.networkDecision(host: facts.host, ip: facts.ip, program: facts.program)
        #expect(FirewallPolicy.decide(facts, status: .dangerous, yours: yours).verdict == .allow)
        #expect(FirewallPolicy.decide(facts, status: .dangerous).verdict == .block)
    }
}

/// Folders and files: older program chips and file rules become places on the apps' cards (ADR 0021).
@MainActor @Suite struct PlaceExceptionsMoveIntoApps {
    func monitor() -> ProtectionMonitor {
        let suite = "places-\(UUID().uuidString)"
        return ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
    }
    func open(_ path: String, by program: String) -> ActivityEvent {
        ActivityEvent(kind: .file, time: "1", pid: 5, ppid: 1, name: (program as NSString).lastPathComponent, proc: program,
                      target: path, extra: "r", parent: "/bin/zsh")
    }

    @Test func chipsBecomeCardsAndBlockWinsBoth() {
        let m = monitor()
        let preview = "/System/Applications/Preview.app"
        var place = CustomPlace(path: "/tmp/contracts", isFolder: true)
        place.exceptions = PlaceExceptions(allowed: [preview, "/usr/bin/curl"], blocked: ["/usr/bin/curl"])
        m.customPlaces = [place]
        m.groups = ["ssh": ProtectedGroupSetting(exceptions: PlaceExceptions(blocked: ["/Applications/Slack.app"]))]
        m.moveExceptionsIntoApps()
        #expect(m.customPlaces[0].exceptions.isEmpty && m.groups["ssh"]?.exceptions.isEmpty == true)
        #expect(Set(m.appFiles.map(\.app)) == ["/System/Applications/Preview.app", "/usr/bin/curl", "/Applications/Slack.app"])
        #expect(m.appFiles.first { $0.app == "/usr/bin/curl" }?.places.map(\.verdict) == [.block])   // on both: Block
        #expect(m.appFiles.first { $0.app == "/Applications/Slack.app" }?.places.map(\.place) == ["group:ssh"])
        m.fileMode = .watch
        #expect(m.decide(open("/tmp/contracts/a.pdf", by: preview + "/Contents/MacOS/Preview"), status: .dangerous)?.1.verdict == .allow)
        #expect(m.decide(open("/tmp/contracts/a.pdf", by: "/usr/bin/curl"), status: .safe)?.1.verdict == .block)
    }

    @Test func settingsSavedBeforeExceptionsStillRead() throws {
        let old = #"{"on":true,"others":"block"}"#
        let s = try JSONDecoder().decode(ProtectedGroupSetting.self, from: Data(old.utf8))
        #expect(s.others == .block && s.exceptions.isEmpty)
        let place = #"{"id":"a","path":"/tmp/x","isFolder":true,"on":true,"others":"ask"}"#
        #expect(try JSONDecoder().decode(CustomPlace.self, from: Data(place.utf8)).exceptions.isEmpty)
    }

    @Test func oldFileRulesMoveIntoTheCards() {
        let m = monitor()
        m.customPlaces = [CustomPlace(path: "/tmp/contracts", isFolder: true)]
        m.accessRules = [
            AccessRule(kind: .files, target: "/tmp/contracts/2026", program: "/usr/bin/curl", action: .block),   // curl's card
            AccessRule(kind: .files, target: "/tmp/private", program: nil, action: .block),                      // a blocked place
            AccessRule(kind: .network, target: "example.com", program: nil, action: .block),                     // stays
        ]
        m.moveFileRulesIntoPlaces(home: "/Users/someone")
        #expect(m.appFiles.first?.app == "/usr/bin/curl" && m.appFiles.first?.places.first?.place == "/tmp/contracts/2026")
        #expect(m.customPlaces.first { $0.path == "/tmp/private" }?.others == .block)
        #expect(m.accessRules.map(\.kind) == [.network])
        m.fileMode = .watch
        #expect(m.decide(open("/tmp/contracts/2026/a", by: "/usr/bin/curl"), status: .safe)?.1.verdict == .block)
    }
}

private extension AccessRule {
    func with(_ change: (inout AccessRule) -> Void) -> AccessRule { var r = self; change(&r); return r }
}
