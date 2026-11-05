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

    /// The pattern made regular behaviour: seen 6 times over two hours (Safe rules are learned only from those).
    func makeRegular(_ key: String) {
        guard var e = store.entry(key) else { return }
        e.count = 6
        e.firstSeen = Date().addingTimeInterval(-7200)
        store.restore(e)
    }

    func keychainRead(parent: String) -> ActivityEvent {
        exec("/usr/bin/security", pid: Int.random(in: 1000...9999), ppid: 1, parent: parent,
             args: "security find-internet-password -s github.com -w")
    }

    var gitRule: LearnedRule {
        LearnedRule(name: "git credential helper reads keychain", rationale: "you marked these safe",
                    kind: .exec, process: "*/git-credential-osxkeychain", pattern: "/usr/bin/security find-internet-password*", action: .safe)
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
        makeRegular(a)
        store.set(.safe, keys: [a])                                         // your decision
        seen(keychainRead(parent: "/opt/homebrew/Cellar/git/2.55.0/libexec/git-core/git-credential-osxkeychain"))
        let e = RuleEvaluation.evaluate(gitRule, entries: store.allEntries)
        #expect(e.approvable)
        #expect(e.agreeing == [a])
        #expect(e.totalMatches >= 1)
    }

    /// A Safe rule stops questions for good: never from patterns seen a few times; Dangerous ones may be one-offs.
    @Test func safeRulesNeedRegularBehaviour() {
        let once = seen(keychainRead(parent: git))
        store.set(.safe, keys: [once])
        let e = RuleEvaluation.evaluate(gitRule, entries: store.allEntries)
        #expect(!e.approvable && e.problems.contains { $0.contains("regular behaviour") })
        // Five times within a minute (a loop) is still not regular; over two hours it is.
        guard var entry = store.entry(once) else { Issue.record("no entry"); return }
        entry.count = 50
        entry.firstSeen = entry.lastSeen.addingTimeInterval(-30)
        store.restore(entry)
        #expect(!RuleEvaluation.evaluate(gitRule, entries: store.allEntries).approvable)
        makeRegular(once)
        #expect(RuleEvaluation.evaluate(gitRule, entries: store.allEntries).approvable)
        // What Claude learns from: one-off Safe decisions left out, one-off Dangerous ones kept.
        let book = RuleBook(store: store, fileURL: dir.appendingPathComponent("rules.json"))
        let oneOffSafe = seen(exec("/usr/bin/zip", pid: 7, ppid: 1, parent: "/Applications/Archiver.app/Contents/MacOS/Archiver", args: "zip -r a.zip b"))
        let oneOffBad = seen(exec("/usr/bin/nc", pid: 8, ppid: 1, parent: "/tmp/x/dropper", args: "nc 1.2.3.4 4444"))
        store.set(.safe, keys: [oneOffSafe])
        store.set(.dangerous, keys: [oneOffBad])
        let taught = Set(book.teachingDecisions.map(\.id))
        #expect(taught.contains(once) && taught.contains(oneOffBad) && !taught.contains(oneOffSafe))
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
        makeRegular(a)
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

    // MARK: AI verdicts

    @Test func aiSuggestsAndYouDecide() {
        let key = seen(net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 4101, to: "5.6.7.8:443"))
        #expect(store.status(forKey: key) == .unclassified)
        store.suggest(.safe, key: key, source: "claude", note: "routine archive")
        #expect(store.status(forKey: key) == .unclassified)                  // only a suggestion
        #expect(store.entry(key)?.suggestion?.status == .safe && store.decidedBy(key) == "AI suggests Safe")
        #expect(store.acceptSuggestions(keys: [key]) == 1)
        #expect(store.status(forKey: key) == .safe && store.entry(key)?.source == "claude")
        #expect(store.decidedBy(key) == "AI (Claude)")
    }

    @Test func acceptingByItselfIsOptInAndSkipsHighRisk() {
        store.autoAcceptAI = true
        defer { store.autoAcceptAI = false }
        let shell = exec("/bin/sh", pid: 4100, ppid: 5, parent: "/Applications/Slack.app/Contents/MacOS/Slack")
        #expect(shell.signatureRisk == .high)
        let high = seen(shell)
        store.suggest(.suspicious, key: high, source: "claude", note: "app shell")
        #expect(store.status(forKey: high) == .unclassified && store.entry(high)?.suggestion?.status == .suspicious)
        let curl = seen(net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 4101, to: "5.6.7.8:443"))
        store.suggest(.safe, key: curl, source: "on-device", note: nil)
        #expect(store.status(forKey: curl) == .safe)
    }

    @Test func aiNeverSuggestsSafeForHighRiskOrInterpreters() {
        let shell = seen(exec("/bin/sh", pid: 4100, ppid: 5, parent: "/Applications/Slack.app/Contents/MacOS/Slack"))
        let python = seen(net("/opt/homebrew/bin/python3.12", pid: 4102, to: "5.6.7.8:443"))
        for key in [shell, python] {
            for source in ["claude", "on-device"] { store.suggest(.safe, key: key, source: source, note: "looks routine") }
            #expect(store.entry(key)?.suggestion == nil && store.status(forKey: key) == .unclassified)
        }
        store.suggest(.suspicious, key: python, source: "claude", note: nil)          // other verdicts are fine
        #expect(store.entry(python)?.suggestion?.status == .suspicious)
    }

    @Test func interpretersCantBeTrustedWholesale() {
        let python = "/opt/homebrew/bin/python3.12"
        let key = seen(net(python, pid: 4103, to: "5.6.7.8:443"))
        store.setProcessRule(.safe, kind: .net, process: python)                       // "python: everything Safe"
        #expect(store.status(forKey: key) == .unclassified)
        store.setProcessRule(.suspicious, kind: .net, process: python)                 // flagging is fine
        #expect(store.status(forKey: key) == .suspicious)

        let rule = LearnedRule(name: "python is fine", rationale: "", kind: .net,
                               process: "*/python3.12", pattern: "*", action: .safe)
        #expect(RuleEvaluation.evaluate(rule, entries: store.allEntries).problems.contains { $0.contains("interpreter") })
    }

    @Test func wideInterpreterPatternsAreDroppedUnlessYouDecided() throws {
        let zsh = "/bin/zsh"
        func wide(_ pattern: String, _ source: String?, _ status: SignatureStatus) -> String {
            let key = "file|\(zsh)|\(pattern)"
            store.restore(SignatureEntry(id: key, kind: .file, process: zsh, pattern: pattern, count: 1, firstSeen: Date(),
                                         lastSeen: Date(), status: status, source: source, note: nil, exampleName: "zsh",
                                         examplePid: 1, exampleProc: zsh, exampleTarget: "/x", exampleExtra: "r", exampleParent: ""))
            return key
        }
        let auto = wide("r /*", "auto", .safe)
        let new = wide("r /Users/**", nil, .unclassified)
        let mine = wide("r ~/Documents/**", "you", .safe)
        store.save(sync: true)
        let reopened = SignatureStore(directory: dir)
        #expect(reopened.entry(auto) == nil && reopened.entry(new) == nil)
        #expect(reopened.status(forKey: mine) == .safe)                                // your decision stays
    }

    @Test func blanketTrustInInterpretersIsUndoneAtLaunch() throws {
        let python = seen(net("/opt/homebrew/bin/python3.12", pid: 4104, to: "5.6.7.8:443"))
        let curlKey = seen(net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 4105, to: "5.6.7.8:443"))
        let mine = seen(net("/opt/homebrew/bin/node", pid: 4106, to: "5.6.7.8:443"))
        store.set(.safe, keys: [python], source: "claude")
        store.set(.safe, keys: [curlKey], source: "claude")
        store.set(.safe, keys: [mine])                                                  // your own decision
        store.save(sync: true)
        let reopened = SignatureStore(directory: dir)
        #expect(reopened.status(forKey: python) == .unclassified)
        #expect(reopened.status(forKey: curlKey) == .safe && reopened.status(forKey: mine) == .safe)
    }
}
