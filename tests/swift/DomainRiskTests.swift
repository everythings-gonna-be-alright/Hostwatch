import Foundation
import Testing
@testable import Hostwatch

/// Domain details: the local risk score and the AI's risk line.
@MainActor @Suite struct DomainRiskScore {
    let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
    let dropper = FileManager.default.homeDirectoryForCurrentUser.path + "/Downloads/Updater"

    func record(_ domain: String, baseline: Bool = false, known: Bool = false, programs: [String] = ["Slack"],
                firstSeen: Date = Date().addingTimeInterval(-3 * 86_400)) -> DomainRecord {
        var r = DomainRecord(domain: domain, firstSeen: firstSeen, lastSeen: Date(), count: 5, programs: programs,
                             hosts: ["www." + domain], baseline: baseline)
        r.known = known
        return r
    }

    @Test func usualDomainOfATrustedAppIsLow() {
        let a = DomainRisk.assess(record("slack.com", baseline: true), connections: [net(slack, pid: 1, to: "3.1.1.1:443", host: "app.slack.com")],
                                  untrusted: { _ in false })
        #expect(a.score == 0)
        #expect(RiskScale.word(a.score) == "Low")
    }

    @Test func newRandomAbusedDomainFromDownloadsBeaconingIsCritical() {
        var beacon = net(dropper, pid: 2, to: "45.33.12.7:443", host: "cdn.x7k2qz9pv4lm8r.xyz")
        beacon.beacon = "every ~60s"
        let a = DomainRisk.assess(record("x7k2qz9pv4lm8r.xyz", programs: ["Updater"], firstSeen: Date().addingTimeInterval(-600)),
                                  connections: [beacon], untrusted: { $0.contains("/Downloads/") })
        #expect(a.score == 100)
        let reasons = a.reasons.map(\.text).joined(separator: " | ")
        for word in ["unsigned or downloaded", "beaconing", "usual domains", ".xyz", "Random-looking", "24 hours"] {
            #expect(reasons.contains(word), "missing: \(word)")
        }
        #expect(a.reasons.first?.points == 30)                                   // biggest reason first
    }

    @Test func knownAndWidelyUsedLowerTheScore() {
        let a = DomainRisk.assess(record("example.xyz", known: true, programs: ["A", "B", "C"]), connections: [],
                                  untrusted: { _ in false })
        #expect(a.score == 0)                                                    // +15 .xyz, -30 known, -10 widely used
        #expect(a.reasons.contains { $0.points < 0 })
    }

    @Test func lookalikesAndGeneratedNames() {
        #expect(DomainRisk.assess(record("xn--pple-43d.com"), connections: [], untrusted: { _ in false })
            .reasons.contains { $0.text.contains("xn--") })
        #expect(DomainRisk.looksRandom("x7k2qz9pv4lm8r"))
        #expect(DomainRisk.looksRandom("q1w2e3r4t5y6u7"))
        #expect(!DomainRisk.looksRandom("googleusercontent"))
        #expect(!DomainRisk.looksRandom("slack"))                                // short names never count
    }

    @Test func aiRiskLineIsRead() {
        #expect(AIAnalysis.risk(in: "VERDICT: SAFE\nCONFIDENCE: high\nRISK: 12\n\n**What it is:** x") == 12)
        #expect(AIAnalysis.risk(in: "**RISK:** 85/100") == 85)
        #expect(AIAnalysis.risk(in: "RISK: 250") == 100)
        #expect(AIAnalysis.risk(in: "VERDICT: SAFE\nno risk line") == nil)
    }

    @Test func promptsAskForTheRiskLine() {
        #expect(AIAnalysis.systemPrompt.contains("RISK:") && DomainEvidence.instructions.contains("RISK:"))
    }
}
