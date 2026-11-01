import Foundation
import Testing
@testable import Hostwatch

/// Rules learned from your decisions: matching, checking proposals, regression, precedence.
@MainActor @Suite(.serialized) struct LearnedRules {
    let dir: URL
    let store: SignatureStore
    let git = "/opt/homebrew/Cellar/git/2.54.0/libexec/git-core/git-credential-osxkeychain"

    init() throws {
        _ = TestEnv.ready
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-rules-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        store = SignatureStore(directory: dir)            // never the real signatures file
    }

    /// A pattern seen once, keyed like the app does.
    @discardableResult
    func seen(_ e: ActivityEvent) -> String { store.observe(e); return e.signatureKey }

    func keychainRead(parent: String) -> ActivityEvent {
        exec("/usr/bin/security", pid: Int.random(in: 1000...9999), ppid: 1, parent: parent,
             args: "security find-internet-password -s github.com -w")
    }

    var gitRule: LearnedRule {
        LearnedRule(name: "git credential helper reads keychain", rationale: "you marked these safe",
                    kind: .exec, process: "*/git-credential-osxkeychain", pattern: "/usr/bin/security", action: .safe)
    }

    @Test func globMatching() {
        #expect(Glob.match("*/git-credential-*", "/opt/homebrew/libexec/git-core/git-credential-osxkeychain"))
        #expect(Glob.match("TCP INTERNET:443", "tcp internet:443"))
        #expect(Glob.match("r ~/documents/*", "r ~/Documents/**"))
        #expect(Glob.match("/usr/bin/?url", "/usr/bin/curl"))
        #expect(!Glob.match("/usr/bin/curl", "/usr/bin/curl2"))
        #expect(Glob.literalCount("*/*") == 0 && Glob.literalCount("*/git-*") == 3)
    }

    @Test func proposalIsCheckedAgainstYourDecisions() {
        let a = seen(keychainRead(parent: git))
        store.set(.safe, keys: [a])                                         // your decision
        seen(keychainRead(parent: "/opt/homebrew/Cellar/git/2.55.0/libexec/git-core/git-credential-osxkeychain"))
        let e = RuleEvaluation.evaluate(gitRule, entries: store.allEntries)
        #expect(e.approvable)
        #expect(e.agreeing == [a])
        #expect(e.totalMatches >= 1)
    }

    @Test func conflictingTooBroadAndEmptyRulesAreRefused() {
        let a = seen(keychainRead(parent: git))
        store.set(.suspicious, keys: [a])                                   // you said suspicious
        #expect(!RuleEvaluation.evaluate(gitRule, entries: store.allEntries).approvable)   // rule says safe
        var broad = gitRule; broad.process = "*"; broad.pattern = "*"
        #expect(RuleEvaluation.evaluate(broad, entries: store.allEntries).problems.contains { $0.contains("too general") })
        var none = gitRule; none.process = "/nothing/like/this"
        #expect(RuleEvaluation.evaluate(none, entries: store.allEntries).problems.contains("matches no pattern"))
    }

    @Test func precedenceYouThenRulesThenAI() {
        let mine = seen(keychainRead(parent: git))
        store.set(.suspicious, keys: [mine])                                // you
        let other = seen(keychainRead(parent: "/usr/local/libexec/git-core/git-credential-osxkeychain"))
        store.suggest(.dangerous, key: other, source: "claude", note: "AI said so")
        var rule = gitRule; rule.pausedReason = nil
        store.applyRules([rule])
        #expect(store.entry(mine)?.status == .suspicious && store.entry(mine)?.source == "you")   // you win
        #expect(store.entry(other)?.status == .safe && store.entry(other)?.source == "rule")       // rule beats AI
        store.applyRules([])                                                                         // rule removed
        #expect(store.entry(other)?.source != "rule")
    }

    @Test func ruleAppliesToNewPatternsAndCountsAsYours() {
        store.applyRules([gitRule])
        let e = keychainRead(parent: "/opt/x/git-credential-osxkeychain")
        seen(e)
        #expect(store.entry(e.signatureKey)?.source == "rule")
        #expect(store.markedSafeByYou(e))                                  // so Stories skip the step
        #expect(store.reviewedByYou(e.signatureKey))
    }

    @Test func regressionPausesARuleThatStartsContradictingYou() throws {
        let book = RuleBook(store: store, fileURL: dir.appendingPathComponent("rules.json"))
        let a = seen(keychainRead(parent: git))
        store.set(.safe, keys: [a])
        let proposal = RuleProposal(rule: gitRule, evaluation: RuleEvaluation.evaluate(gitRule, entries: store.allEntries))
        book.approve(proposal)
        #expect(book.activeCount == 1)
        let rule = try #require(book.rules.first)
        #expect(rule.examples == [a])
        // You later decide a matching pattern differently: the rule pauses itself.
        let b = seen(keychainRead(parent: "/usr/local/bin/git-credential-osxkeychain"))
        store.set(.dangerous, keys: [b])
        #expect(book.activeCount == 0)
        #expect(book.rules.first?.pausedReason?.contains("contradicts your decision") == true)
        // Rules are saved for the next launch.
        let reloaded = RuleBook(store: store, fileURL: dir.appendingPathComponent("rules.json"))
        #expect(reloaded.rules.count == 1)
    }

    @Test func parsesClaudeProposalsAndIgnoresJunk() {
        let text = """
        Here you go:
        [{"name":"git helper","rationale":"r","kind":"exec","process":"*/git-credential-*","pattern":"/usr/bin/security","action":"SAFE"},
         {"name":"bad action","process":"x","pattern":"y","action":"MAYBE"},
         {"name":"any kind","kind":"any","process":"/usr/bin/curl","pattern":"TCP internet:443","action":"suspicious"}]
        """
        let rules = RuleProposalParser.parse(text)
        #expect(rules.count == 2)
        #expect(rules[0].kind == .exec && rules[0].action == .safe)
        #expect(rules[1].kind == nil && rules[1].action == .suspicious)
        #expect(RuleProposalParser.parse("no json here").isEmpty)
    }

    @Test func promptMasksSecrets() {
        var e = store.allEntries.first ?? SignatureEntry(id: "x", kind: .exec, process: "/bin/sh", pattern: "p", count: 1,
            firstSeen: Date(), lastSeen: Date(), status: .safe, source: "you", note: nil, exampleName: "sh", examplePid: 1,
            exampleProc: "/bin/sh", exampleTarget: "/bin/sh", exampleExtra: "", exampleParent: "")
        e.pattern = "curl https://h/x?token=s3cret"
        let p = RuleBook.prompt(decisions: [e], rules: [], ignoredChains: ["/bin/fish|lolbin"])
        #expect(p.contains("Decisions made by the user (1)") && p.contains("always ignore"))
        #expect(!p.contains("s3cret"))
    }
}
