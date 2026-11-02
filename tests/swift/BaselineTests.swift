import Foundation
import Testing
@testable import Hostwatch

/// The first-run baseline: trust only what's clearly ordinary, never what could be malware already
/// on the Mac; waves at 5, 15 and 60 minutes; undoable; stories still alert.
@MainActor @Suite(.serialized) struct Baseline {
    let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
    let dropper = FileManager.default.homeDirectoryForCurrentUser.path + "/Downloads/Installer"

    func entry(_ kind: EventKind = .net, risk: PatternRisk = .normal, pattern: String = "TCP internet:443",
               proc: String, target: String = "1.2.3.4:443", parent: String = "") -> SignatureEntry {
        SignatureEntry(id: "\(kind.rawValue)|\(proc)|\(pattern)|\(target)", kind: kind, process: proc, pattern: pattern,
                       count: 3, risk: risk, firstSeen: Date(), lastSeen: Date(), status: .unclassified, source: nil,
                       note: nil, exampleName: (proc as NSString).lastPathComponent, examplePid: 1, exampleProc: proc,
                       exampleTarget: target, exampleExtra: "", exampleParent: parent, exampleHost: nil, exampleHostSource: nil)
    }

    /// Fake signing facts: Apple binaries and Slack are trusted; "signed" is signed but not trusted.
    func identify(_ path: String) -> (identity: CodeIdentity?, trusted: Bool) {
        if path.hasPrefix("/usr/bin/") || path.hasPrefix("/bin/") {
            return (CodeIdentity(signed: true, apple: true), true)
        }
        if path == slack { return (CodeIdentity(signed: true, teamID: "BQR82RBBHL", organization: "Slack Technologies"), true) }
        if path.contains("/signed/") { return (CodeIdentity(signed: true, teamID: "ABCDE12345", organization: "Someone"), false) }
        if path.contains("/quarantined/") { return (CodeIdentity(signed: true, teamID: "Q", organization: "Q", quarantined: true), true) }
        if path.contains("/adhoc/") { return (CodeIdentity(signed: true, adhoc: true), false) }
        return (nil, false)
    }

    // MARK: Policy

    @Test func ordinarySignedActivityIsTrusted() {
        #expect(BaselinePolicy.decide(entry(proc: slack), identify: identify) == .trust(app: "Slack", signer: "Slack Technologies"))
        let ls = entry(.exec, pattern: "/bin/ls", proc: "/bin/zsh", target: "/bin/ls", parent: "/bin/zsh")
        #expect(BaselinePolicy.decide(ls, identify: identify) == .trust(app: "ls", signer: "Apple"))
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
        guard case .review = BaselinePolicy.decide(e, identify: identify) else {
            Issue.record("\(kind) must need review, got \(BaselinePolicy.decide(e, identify: identify))")
            return
        }
    }

    @Test func signedButUntrustedGoesToTheOnDeviceModel() {
        #expect(BaselinePolicy.decide(entry(proc: "/Applications/signed/Tool"), identify: identify) == .onDevice(app: "Tool"))
    }

    @Test func appNamesGroupHelpersUnderTheirApp() {
        #expect(BaselinePolicy.appName("/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper") == "Cursor")
        #expect(BaselinePolicy.appName("/usr/bin/curl") == "curl")
    }

    // MARK: Waves

    func makeLearner(fresh: Bool = true) throws -> (BaselineLearner, SignatureStore, UserDefaults) {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-base-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = SignatureStore(directory: dir)
        let defaults = UserDefaults(suiteName: "hw-base-\(UUID().uuidString)")!
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
        #expect(report.trustedCount == 1 && report.reviewCount == 1)
        #expect(report.review.first?.app == "Installer")
        #expect(!store.markedSafeByYou(slackNet))                               // stories still alert on it

        learner.undo()
        #expect(store.status(for: slackNet) == .unclassified)
        #expect(learner.report?.trustedCount == 0)
    }

    @Test func trustingAnAppFromTheReportIsYourDecision() async throws {
        let (learner, store, _) = try makeLearner()
        let e = net("/Applications/signed/Tool", pid: 12, to: "5.6.7.8:443")
        store.observe(e)
        await learner.runWave()
        let group = try #require(learner.report?.onDevice.first)                // no model in tests: stays New
        learner.trust(group)
        #expect(store.status(for: e) == .safe && store.entry(e.signatureKey)?.source == "you")
    }

    // MARK: Domains

    @Test func domainsFirstReachedByUntrustedProgramsStayNewWhileLearning() {
        let domains = DomainRegistry(replayLearningUntil: Date().addingTimeInterval(3600))
        #expect(domains.observe(net(slack, pid: 20, to: "3.68.170.153:443", host: "app.slack.com")) == nil)   // usual
        #expect(domains.observe(net(dropper, pid: 21, to: "45.1.1.1:443", host: "c2.evil-cdn.xyz")) == "evil-cdn.xyz")
    }
}
