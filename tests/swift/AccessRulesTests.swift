import Foundation
import Testing
@testable import Hostwatch

/// Your Allow and Block rules: matched most specific first (Block on a tie), refused where allowing every program
/// would open a whole area or a secret, and applied by Protection and the firewall before anything automatic.
@MainActor @Suite struct AccessRuleMatching {
    let home = "/Users/someone"
    func file(_ target: String, _ action: AccessRule.Action, program: String? = nil) -> AccessRule {
        AccessRule(kind: .files, target: target, program: program, action: action)
    }

    @Test func aFolderCoversWhatsInsideAndAnAppItsPrograms() {
        let rules = [file("\(home)/Documents/contracts", .block)]
        #expect(AccessRules.matchFile(rules, path: "\(home)/Documents/contracts/nda.pdf", program: "/usr/bin/cat") != nil)
        #expect(AccessRules.matchFile(rules, path: "\(home)/Documents/contracts-old/x", program: "/usr/bin/cat") == nil)
        #expect(AccessRules.runs("/Applications/Preview.app", "/Applications/Preview.app/Contents/MacOS/Preview"))
        #expect(!AccessRules.runs("/Applications/Preview.app", "/Applications/Preview.application"))
        #expect(AccessRules.covers("/var/tmp/x", "/private/var/tmp/x/y"))
    }

    @Test func theMostSpecificWinsAndBlockWinsATie() {
        let preview = "/Applications/Preview.app"
        let rules = [file("\(home)/Documents", .block), file("\(home)/Documents/contracts", .allow, program: preview),
                     file("\(home)/Documents/contracts", .block)]
        #expect(AccessRules.matchFile(rules, path: "\(home)/Documents/contracts/a", program: preview + "/Contents/MacOS/Preview")?.action == .allow)
        #expect(AccessRules.matchFile(rules, path: "\(home)/Documents/contracts/a", program: "/usr/bin/curl")?.action == .block)
        let tie = [file("\(home)/x", .allow), file("\(home)/x", .block)]
        #expect(AccessRules.matchFile(tie, path: "\(home)/x/y", program: "/bin/cat")?.action == .block)
        #expect(AccessRules.matchFile([file("\(home)/x", .block).with { $0.on = false }], path: "\(home)/x/y", program: "/bin/cat") == nil)
    }

    @Test func aDomainCoversItsSubdomains() {
        let rules = [AccessRule(kind: .network, target: "example.com", program: nil, action: .block),
                     AccessRule(kind: .network, target: "203.0.113.9", program: nil, action: .allow)]
        #expect(AccessRules.matchNetwork(rules, host: "api.example.com", ip: "1.2.3.4", program: "/x")?.action == .block)
        #expect(AccessRules.matchNetwork(rules, host: "notexample.com", ip: "1.2.3.4", program: "/x") == nil)
        #expect(AccessRules.matchNetwork(rules, host: "", ip: "203.0.113.9", program: "/x")?.action == .allow)
    }

    @Test func allowingEveryProgramAWholeAreaOrASecretIsRefused() {
        let sensitive = ["\(home)/.ssh"]
        func refused(_ r: AccessRule) -> Bool { AccessRules.refusal(r, home: home, sensitive: sensitive) != nil }
        #expect(refused(file(home, .allow)))
        #expect(refused(file("\(home)/Documents", .allow)))
        #expect(refused(file("/tmp", .allow)))
        #expect(refused(file("\(home)/.ssh", .allow)))
        #expect(!refused(file("\(home)/Documents/site", .allow)))                      // a project folder: fine
        #expect(!refused(file("\(home)/.ssh", .allow, program: "/usr/bin/ssh")))         // one program: your call
        #expect(!refused(file(home, .block)))                                            // Block may be broad
        #expect(refused(AccessRule(kind: .network, target: "com", program: nil, action: .allow)))
        #expect(!refused(AccessRule(kind: .network, target: "github.com", program: nil, action: .allow)))
    }

    @Test func theFirewallAppliesNetworkRulesFirst() {
        let suite = "rules-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
        m.accessRules = [AccessRule(kind: .network, target: "example.com", program: nil, action: .allow)]
        let facts = FirewallFacts(program: "/x", proto: "TCP", ip: "93.184.216.34", port: "443", host: "api.example.com",
                                  risk: .high, riskReason: "downloaded", knownBad: "ThreatFox", patternKey: "k")
        let rule = m.networkRule(host: facts.host, ip: facts.ip, program: facts.program)
        #expect(FirewallPolicy.decide(facts, status: .dangerous, rule: rule).verdict == .allow)   // your rule first
        #expect(FirewallPolicy.decide(facts, status: .dangerous).verdict == .block)
    }
}

/// Folders and files: one model, places with exceptions. A program you always allow or always block in a place is
/// decided there before its pattern, Block when it's on both lists, the deepest place first.
@MainActor @Suite struct PlaceExceptionsDecide {
    func monitor() -> ProtectionMonitor {
        let suite = "places-\(UUID().uuidString)"
        return ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
    }
    func open(_ path: String, by program: String) -> ActivityEvent {
        ActivityEvent(kind: .file, time: "1", pid: 5, ppid: 1, name: (program as NSString).lastPathComponent, proc: program,
                      target: path, extra: "r", parent: "/bin/zsh")
    }

    @Test func exceptionsComeBeforeThePatternAndBlockWinsBoth() {
        let preview = "/System/Applications/Preview.app"
        var place = CustomPlace(path: "/tmp/contracts", isFolder: true)
        place.exceptions = PlaceExceptions(allowed: [preview, "/usr/bin/curl"], blocked: ["/usr/bin/curl"])
        let d1 = ProtectionPolicy.decideCustom(path: "/tmp/contracts/a.pdf", actor: preview + "/Contents/MacOS/Preview",
                                               status: .dangerous, places: [place])
        #expect(d1?.verdict == .allow)                                        // your exception over the pattern
        let d2 = ProtectionPolicy.decideCustom(path: "/tmp/contracts/a.pdf", actor: "/usr/bin/curl", status: .safe, places: [place])
        #expect(d2?.verdict == .block)                                        // on both lists: blocked
    }

    @Test func theDeepestPlaceDecides() {
        let outer = CustomPlace(path: "/tmp/work", isFolder: true, others: .block)
        var inner = CustomPlace(path: "/tmp/work/site", isFolder: true, others: .ask)
        inner.exceptions.allowed = ["/usr/local/bin/hugo"]
        let d = ProtectionPolicy.decideCustom(path: "/tmp/work/site/index.md", actor: "/usr/local/bin/hugo",
                                              status: .unclassified, places: [outer, inner])
        #expect(d?.verdict == .allow)
    }

    @Test func settingsSavedBeforeExceptionsStillRead() throws {
        let old = #"{"on":true,"others":"block"}"#
        let s = try JSONDecoder().decode(ProtectedGroupSetting.self, from: Data(old.utf8))
        #expect(s.others == .block && s.exceptions.isEmpty)
        let place = #"{"id":"a","path":"/tmp/x","isFolder":true,"on":true,"others":"ask"}"#
        #expect(try JSONDecoder().decode(CustomPlace.self, from: Data(place.utf8)).exceptions.isEmpty)
    }

    @Test func oldFileRulesMoveIntoThePlaces() {
        let m = monitor()
        m.customPlaces = [CustomPlace(path: "/tmp/contracts", isFolder: true)]
        m.accessRules = [
            AccessRule(kind: .files, target: "/tmp/contracts/2026", program: "/usr/bin/curl", action: .block),   // into the place
            AccessRule(kind: .files, target: "/tmp/private", program: nil, action: .block),                      // a blocked place
            AccessRule(kind: .network, target: "example.com", program: nil, action: .block),                     // stays
        ]
        m.moveFileRulesIntoPlaces(home: "/Users/someone")
        #expect(m.customPlaces.first { $0.path == "/tmp/contracts" }?.exceptions.blocked == ["/usr/bin/curl"])
        #expect(m.customPlaces.first { $0.path == "/tmp/private" }?.others == .block)
        #expect(m.accessRules.map(\.kind) == [.network])
        m.fileMode = .watch
        #expect(m.decide(open("/tmp/contracts/2026/a", by: "/usr/bin/curl"), status: .safe)?.1.verdict == .block)
    }
}

private extension AccessRule {
    func with(_ change: (inout AccessRule) -> Void) -> AccessRule { var r = self; change(&r); return r }
}
