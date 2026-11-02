import Foundation
import Testing
@testable import Hostwatch

/// The first-run baseline: trust only what's clearly ordinary, never what could be malware already
/// on the Mac; waves at 5, 15 and 60 minutes; undoable; stories still alert.
@MainActor @Suite(.serialized) struct Baseline {
    let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
    let dropper = FileManager.default.homeDirectoryForCurrentUser.path + "/Downloads/Setup"
    let zoom = "/Applications/zoom.us.app/Contents/MacOS/zoom.us"

    func entry(_ kind: EventKind = .net, risk: PatternRisk = .normal, pattern: String = "TCP internet:443",
               proc: String, target: String = "1.2.3.4:443", parent: String = "") -> SignatureEntry {
        SignatureEntry(id: "\(kind.rawValue)|\(proc)|\(pattern)|\(target)", kind: kind, process: proc, pattern: pattern,
                       count: 3, risk: risk, firstSeen: Date(), lastSeen: Date(), status: .unclassified, source: nil,
                       note: nil, exampleName: (proc as NSString).lastPathComponent, examplePid: 1, exampleProc: proc,
                       exampleTarget: target, exampleExtra: "", exampleParent: parent, exampleHost: nil, exampleHostSource: nil)
    }

    /// Fake signing facts: Apple binaries and Slack are trusted; "signed" is signed but not trusted.
    func identify(_ path: String) -> (identity: CodeIdentity?, trusted: Bool) {
        if path.hasPrefix("/usr/") || path.hasPrefix("/bin/") || path.hasPrefix("/System/") {
            return (CodeIdentity(signed: true, apple: true), true)
        }
        if path == slack { return (CodeIdentity(signed: true, teamID: "BQR82RBBHL", organization: "Slack Technologies"), true) }
        if path == zoom { return (CodeIdentity(signed: true, teamID: "BJ4HAAB9B3", organization: "Zoom"), true) }
        if path.contains("/signed/") { return (CodeIdentity(signed: true, teamID: "ABCDE12345", organization: "Someone"), false) }
        if path.contains("/quarantined/") { return (CodeIdentity(signed: true, teamID: "Q", organization: "Q", quarantined: true), true) }
        if path.contains("/adhoc/") { return (CodeIdentity(signed: true, adhoc: true), false) }
        return (nil, false)
    }

    // MARK: Policy

    let slackKey = "app:/Applications/Slack.app|team:BQR82RBBHL"

    func key(_ d: BaselineDecision) -> String? {
        if case .trust(let k) = d { return k.id }
        return nil
    }

    @Test func ordinaryActivityIsTrustedPerApp() {
        let d = BaselinePolicy.decide(entry(proc: slack), identify: identify)
        #expect(d == .trust(BaselineKey(id: slackKey, name: "Slack", signer: "Slack Technologies")))
        let ls = entry(.exec, pattern: "/bin/ls", proc: "/bin/zsh", target: "/bin/ls", parent: "/bin/zsh")
        #expect(key(BaselinePolicy.decide(ls, identify: identify)) == "system")       // one rule for macOS itself
    }

    @Test func systemServicesMayTouchSensitivePlacesButToolsMayNot() {
        let mds = entry(.file, pattern: "r ~/Library/Keychains/*  [keychain]", proc: "/System/Library/Frameworks/CoreServices.framework/mds",
                        target: "/k.db")
        #expect(key(BaselinePolicy.decide(mds, identify: identify)) == "system")
        let cat = entry(.file, pattern: "r ~/.ssh/*  [ssh keys]", proc: "/bin/cat", target: "/id_rsa")
        #expect(BaselinePolicy.decide(cat, identify: identify) == .review(app: "cat", reason: "reads ssh keys"))
        let sqlite = entry(.file, pattern: "r ~/Library/Messages/*  [messages]", proc: "/usr/libexec/sqlite3", target: "/c.db")
        #expect(BaselinePolicy.decide(sqlite, identify: identify) == .ignore)  // interpreter: stays New, not listed
    }

    @Test func appsYouTrustedMayTouchTheirSensitivePlaces() {
        let e = entry(.file, pattern: "r ~/Library/Keychains/*  [keychain]", proc: slack, target: "/k.db")
        guard case .review = BaselinePolicy.decide(e, identify: identify) else { Issue.record("automatic"); return }
        #expect(key(BaselinePolicy.decide(e, identify: identify, allowSensitive: true)) == slackKey)
        let high = entry(risk: .high, proc: slack)
        guard case .review = BaselinePolicy.decide(high, identify: identify, allowSensitive: true) else { Issue.record("high"); return }
    }

    @Test func hostwatchItselfIsNeverListed() {
        let own = Bundle.main.bundlePath + "/Contents/MacOS/Hostwatch"
        #expect(BaselinePolicy.decide(entry(proc: own), identify: identify) == .ignore)
    }

    @Test func homebrewToolsAreGroupedAndTrustedOnlyWhenYouSaySo() {
        let git = "/opt/homebrew/Cellar/git/2.50.0/bin/git"
        let adhoc: BaselinePolicy.Identify = { _ in (CodeIdentity(signed: true, adhoc: true), false) }
        #expect(BaselinePolicy.decide(entry(proc: git), identify: adhoc)
                == .review(app: "git", reason: "Homebrew tool (ad-hoc signed by Homebrew)", homebrew: true))
        let trusted: BaselinePolicy.Identify = { _ in (CodeIdentity(signed: true, adhoc: true), true) }
        #expect(key(BaselinePolicy.decide(entry(proc: git), identify: trusted)) == "homebrew")
    }

    @Test(arguments: ["high", "sensitive", "downloads", "temp", "adhoc", "quarantined", "missing", "untrustedParent"])
    func whatCouldBeMalwareIsLeftForYou(_ kind: String) {
        let e: SignatureEntry
        switch kind {
        case "high": e = entry(risk: .high, proc: slack)
        case "sensitive": e = entry(.file, pattern: "~/Library/LaunchAgents [persistence]", proc: slack, target: "/x.plist")
        case "downloads": e = entry(proc: dropper)
        case "temp": e = entry(proc: "/private/tmp/payload")
        case "adhoc": e = entry(proc: "/opt/adhoc/tool")
        case "quarantined": e = entry(proc: "/Applications/quarantined/App")
        case "missing": e = entry(proc: "/opt/gone/tool")
        default: e = entry(.exec, pattern: "/bin/sh", proc: "/bin/sh", target: "/bin/sh", parent: "/opt/adhoc/launcher")
        }
        switch BaselinePolicy.decide(e, identify: identify) {
        case .review: break
        case .ignore where kind == "untrustedParent": break                    // a shell: stays New, not listed
        case let d: Issue.record("\(kind) must stay New, got \(d)")
        }
    }

    @Test func signedButUntrustedGoesToTheOnDeviceModel() {
        #expect(BaselinePolicy.decide(entry(proc: "/Applications/signed/Tool"), identify: identify) == .onDevice(app: "Tool"))
    }

    @Test func appNamesGroupHelpersUnderTheirApp() {
        #expect(BaselinePolicy.appName("/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper") == "Cursor")
        #expect(BaselinePolicy.appName("/usr/bin/curl") == "curl")
        #expect(BaselinePolicy.appRoot("/Applications/Cursor.app/Contents/MacOS/Cursor") == "/Applications/Cursor.app")
    }

    @Test func reviewHasOneRowPerAppWithAllItsReasons() {
        var report = BaselineReport()
        report.add(.review(app: "file", reason: "reads keychains"), key: "a")
        report.add(.review(app: "file", reason: "reads mail"), key: "b")
        report.add(.review(app: "file", reason: "reads keychains"), key: "c")
        #expect(report.review.count == 1 && report.review[0].reasons == ["reads keychains", "reads mail"])
        #expect(report.reviewCount == 3)
    }

    // MARK: Waves

    func makeLearner(fresh: Bool = true) throws -> (BaselineLearner, SignatureStore, UserDefaults) {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-base-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = SignatureStore(directory: dir)
        let defaults = scratchDefaults("hw-base")
        let learner = BaselineLearner(store: store, classifier: nil, defaults: defaults, freshInstall: fresh)
        learner.identify = { self.identify($0) }
        return (learner, store, defaults)
    }

    @Test func wavesAtFiveFifteenAndSixtyMinutes() async throws {
        let (learner, _, defaults) = try makeLearner()
        let start = try #require(defaults.object(forKey: "baselineStartedAt") as? Date)
        for (i, minutes) in [5.0, 15, 60].enumerated() {
            guard case .learning(let wave, let at) = learner.phase else { Issue.record("not learning"); return }
            #expect(wave == i + 1 && abs(at.timeIntervalSince(start) - minutes * 60) < 1)
            await learner.runWave()
        }
        #expect(learner.phase == .done)
    }

    @Test func existingInstallsDontStartByThemselves() throws {
        let (learner, _, _) = try makeLearner(fresh: false)
        #expect(learner.phase == .idle)
    }

    @Test func waveTrustsOrdinaryLeavesTheRestAndUndoes() async throws {
        let (learner, store, _) = try makeLearner()
        let slackNet = net(slack, pid: 10, to: "3.68.170.153:443", host: "app.slack.com")
        let dropperNet = net(dropper, pid: 11, to: "45.1.1.1:8443")
        store.observe(slackNet)
        store.observe(dropperNet)
        await learner.runWave()

        #expect(store.status(for: slackNet) == .safe)
        #expect(store.entry(slackNet.signatureKey)?.source == "baseline")
        #expect(store.status(for: dropperNet) == .unclassified)                 // left for you
        let report = try #require(learner.report)
        #expect(learner.trustedCount == 1 && report.reviewCount == 1)
        #expect(report.review.first?.app == "Setup")
        #expect(!store.markedSafeByYou(slackNet))                               // stories still alert on it
        #expect(learner.rules.map(\.id) == [slackKey])                         // one rule per app
        #expect(learner.rules.first?.name == "Slack" && learner.rules.first?.signer == "Slack Technologies")

        learner.undo()
        #expect(store.status(for: slackNet) == .unclassified)
        #expect(learner.trustedCount == 0 && learner.rules.isEmpty)
    }

    @Test func trustingAnAppMakesARuleYouCanSee() async throws {
        let (learner, store, _) = try makeLearner()
        let keychain = file(slack, pid: 12, "r", home + "/Library/Keychains/login.keychain-db")
        store.observe(keychain)
        await learner.runWave()
        let group = try #require(learner.report?.review.first { $0.app == "Slack" })
        await learner.trustApp(group)
        #expect(store.status(for: keychain) == .safe && store.entry(keychain.signatureKey)?.source == "you")
        let rule = try #require(learner.rules.first { $0.id == slackKey })
        #expect(rule.approvedByYou && learner.patternCount(rule) == 1)
        #expect(learner.report?.review.isEmpty == true)

        let later = file(slack, pid: 12, "r", home + "/Library/Cookies/Cookies.binarycookies")   // its own sensitive reads
        store.observe(later)
        await learner.applyRules()
        if store.entry(later.signatureKey)?.risk != .high { #expect(store.status(for: later) == .safe) }
    }

    @Test func unsignedAppsAreTrustedPatternByPatternWithoutARule() async throws {
        let (learner, store, _) = try makeLearner()
        let e = net(dropper, pid: 13, to: "5.6.7.8:443")
        store.observe(e)
        await learner.runWave()
        let group = try #require(learner.report?.review.first)
        await learner.trustApp(group)
        #expect(store.status(for: e) == .safe && learner.rules.isEmpty)
    }

    @Test func interpretersAndShellsAreNotListedAndCantBeTrusted() async throws {
        let (learner, store, _) = try makeLearner()
        let python = "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12"
        let e = net(python, pid: 17, to: "5.6.7.8:443")
        store.observe(e)
        await learner.runWave()
        #expect(learner.report?.review.isEmpty == true && store.status(for: e) == .unclassified)   // stays New
        let group = BaselineReport.Group(app: "python3.12", reasons: [], keys: [e.signatureKey])
        #expect(learner.runsAnyCode(group))
        await learner.trustApp(group)                                           // refused even if asked
        #expect(store.status(for: e) == .unclassified && learner.rules.isEmpty)
    }

    @Test func showInPatternsOpensExactlyThosePatterns() async throws {
        let (learner, store, _) = try makeLearner()
        let py312 = net("/opt/adhoc/tool3.12", pid: 18, to: "5.6.7.8:443")
        let py3 = net("/opt/adhoc/tool3", pid: 19, to: "5.6.7.8:8443")
        store.observe(py312)
        store.observe(py3)
        await learner.runWave()
        let group = try #require(learner.report?.review.first { $0.app == "tool3.12" })
        store.search = "tool3"                                                // a text search matches both
        #expect(store.patternItems(filter: .all).count == 2)
        store.search = ""
        store.scope = .init(title: group.app, keys: Set(group.keys))
        #expect(store.patternItems(filter: .flagged).map(\.entry.id) == [py312.signatureKey])
        #expect(learner.entries(group).map(\.id) == [py312.signatureKey])
    }

    @Test func dismissedStaysNewAndIsNotListedAgain() async throws {
        let (learner, store, _) = try makeLearner()
        let e = net(dropper, pid: 14, to: "5.6.7.8:443")
        store.observe(e)
        await learner.runWave()
        learner.dismiss(try #require(learner.report?.review.first))
        #expect(learner.report?.review.isEmpty == true && store.status(for: e) == .unclassified)
        await learner.buildNow()
        #expect(learner.report?.review.isEmpty == true)
    }

    @Test func markSuspiciousFromTheReview() async throws {
        let (learner, store, _) = try makeLearner()
        let e = net(dropper, pid: 15, to: "5.6.7.8:443")
        store.observe(e)
        await learner.runWave()
        learner.markSuspicious(try #require(learner.report?.review.first))
        #expect(store.status(for: e) == .suspicious && learner.report?.review.isEmpty == true)
    }

    @Test func theFirstVersionsRulesAreUndone() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-base-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = SignatureStore(directory: dir)
        let e = net(slack, pid: 16, to: "3.68.170.153:443")
        store.observe(e)
        store.set(.safe, keys: [e.signatureKey], source: "baseline", note: "Baseline: Slack Technologies")
        let defaults = scratchDefaults("hw-base")
        defaults.set(Data("[]".utf8), forKey: "baselineRules")
        _ = BaselineLearner(store: store, classifier: nil, defaults: defaults, freshInstall: false)
        #expect(store.status(for: e) == .unclassified && defaults.object(forKey: "baselineRules") == nil)
    }

    // MARK: Domains

    @Test func domainsFirstReachedByUntrustedProgramsStayNewWhileLearning() {
        let domains = DomainRegistry(replayLearningUntil: Date().addingTimeInterval(3600))
        #expect(domains.observe(net(slack, pid: 20, to: "3.68.170.153:443", host: "app.slack.com")) == nil)   // usual
        #expect(domains.observe(net(dropper, pid: 21, to: "45.1.1.1:443", host: "c2.evil-cdn.xyz")) == "evil-cdn.xyz")
    }

    // MARK: Baseline rules keep working

    @Test func rulesTrustFutureNormalPatternsButNeverHighRisk() async throws {
        let (learner, store, _) = try makeLearner()
        store.observe(net(slack, pid: 30, to: "3.68.170.153:443", host: "app.slack.com"))
        await learner.buildNow()                                                // learning done, Slack rule made
        #expect(learner.phase == .done)

        let later = net(slack, pid: 30, to: "52.1.1.1:5222", host: "chat.slack.com")   // a new behaviour
        let risky = exec("/bin/sh", pid: 31, ppid: 30, parent: slack)          // app spawning a shell: high risk
        store.observe(later)
        store.observe(risky)
        #expect(risky.signatureRisk == .high)
        #expect(store.status(for: later) == .unclassified && later.signatureRisk != .high)   // new, normal risk
        await learner.applyRules()
        #expect(store.status(for: later) == .safe && store.entry(later.signatureKey)?.note == "Baseline: Slack (Slack Technologies)")
        #expect(store.status(for: risky) == .unclassified)                      // never high risk
    }

    @Test func newDevelopersAfterLearningWaitForYou() async throws {
        let (learner, store, _) = try makeLearner()
        store.observe(net(slack, pid: 40, to: "3.68.170.153:443", host: "app.slack.com"))
        await learner.buildNow()
        let zoomNet = net(zoom, pid: 41, to: "170.114.52.2:443", host: "zoom.us")   // trusted developer, no rule yet
        store.observe(zoomNet)
        await learner.applyRules()
        #expect(store.status(for: zoomNet) == .unclassified)
        await learner.buildNow()                                                // Update Baseline adds it
        #expect(store.status(for: zoomNet) == .safe && learner.rules.contains { $0.name == "zoom.us" })
    }

    @Test func pauseResumeAndDeleteOneRule() async throws {
        let (learner, store, _) = try makeLearner()
        let slackNet = net(slack, pid: 50, to: "3.68.170.153:443", host: "app.slack.com")
        let zoomNet = net(zoom, pid: 51, to: "170.114.52.2:443", host: "zoom.us")
        store.observe(slackNet)
        store.observe(zoomNet)
        await learner.buildNow()
        let slackRule = try #require(learner.rules.first { $0.id == slackKey })

        learner.setPaused(slackRule, true)
        #expect(store.status(for: slackNet) == .unclassified && store.status(for: zoomNet) == .safe)
        await learner.buildNow()                                                // a paused rule isn't recreated or applied
        #expect(store.status(for: slackNet) == .unclassified)

        learner.setPaused(slackRule, false)
        await learner.applyRules()
        #expect(store.status(for: slackNet) == .safe)

        learner.delete(slackRule)
        #expect(store.status(for: slackNet) == .unclassified && !learner.rules.contains { $0.id == slackRule.id })
        #expect(store.status(for: zoomNet) == .safe)                            // other rules untouched
    }

    @Test func yourDecisionsWin() async throws {
        let (learner, store, _) = try makeLearner()
        let slackNet = net(slack, pid: 60, to: "3.68.170.153:443", host: "app.slack.com")
        store.observe(slackNet)
        store.set(.suspicious, keys: [slackNet.signatureKey])                   // you decided first
        await learner.buildNow()
        #expect(store.status(for: slackNet) == .suspicious)
    }
}
