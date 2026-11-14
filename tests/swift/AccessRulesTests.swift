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

    @Test func protectionAndTheFirewallApplyThemFirst() {
        let suite = "rules-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
        m.fileMode = .watch
        m.accessRules = [file("/tmp/secret-project", .block)]
        let open = ActivityEvent(kind: .file, time: "1", pid: 5, ppid: 1, name: "cat", proc: "/bin/cat",
                                 target: "/tmp/secret-project/plan.txt", extra: "r", parent: "/bin/zsh")
        #expect(m.decide(open, status: .safe)?.1.verdict == .block)             // before the pattern's Safe
        m.accessRules = [AccessRule(kind: .network, target: "example.com", program: nil, action: .allow)]
        let facts = FirewallFacts(program: "/x", proto: "TCP", ip: "93.184.216.34", port: "443", host: "api.example.com",
                                  risk: .high, riskReason: "downloaded", knownBad: "ThreatFox", patternKey: "k")
        let rule = m.networkRule(host: facts.host, ip: facts.ip, program: facts.program)
        #expect(FirewallPolicy.decide(facts, status: .dangerous, rule: rule).verdict == .allow)   // your rule first
        #expect(FirewallPolicy.decide(facts, status: .dangerous).verdict == .block)
    }
}

private extension AccessRule {
    func with(_ change: (inout AccessRule) -> Void) -> AccessRule { var r = self; change(&r); return r }
}
