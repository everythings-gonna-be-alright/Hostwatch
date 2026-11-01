import Foundation
import Testing
@testable import Hostwatch

/// On-device first pass: routing rules (pure), the prompt, and the real model when it is ready.
@Suite struct OnDeviceTriage {
    let safeHigh = LocalVerdict(verdict: .safe, confidence: .high, reason: "app reads its own data")
    let safeMedium = LocalVerdict(verdict: .safe, confidence: .medium, reason: "probably fine")
    let suspicious = LocalVerdict(verdict: .suspicious, confidence: .high, reason: "shell from an app")
    let unsure = LocalVerdict(verdict: .unknown, confidence: .low, reason: "not enough context")

    @Test func confidentSafeOnNormalRiskIsSettled() {
        #expect(TriageRouter.route(risk: .normal, local: safeHigh, claudeEnabled: true) == .settle(.safe, note: safeHigh.reason))
        #expect(TriageRouter.route(risk: .normal, local: safeHigh, claudeEnabled: false) == .settle(.safe, note: safeHigh.reason))
    }

    @Test func highRiskIsNeverSettledOnDevice() {
        #expect(TriageRouter.route(risk: .high, local: safeHigh, claudeEnabled: true) == .escalate)
        #expect(TriageRouter.route(risk: .high, local: safeHigh, claudeEnabled: false) == .leave)
    }

    @Test func lessThanCertainGoesToClaudeOrStaysForYou() {
        for local in [safeMedium, unsure] {
            #expect(TriageRouter.route(risk: .normal, local: local, claudeEnabled: true) == .escalate)
            #expect(TriageRouter.route(risk: .normal, local: local, claudeEnabled: false) == .leave)
        }
    }

    @Test func flaggedGoesToClaudeOrIsAppliedWhenClaudeIsOff() {
        #expect(TriageRouter.route(risk: .normal, local: suspicious, claudeEnabled: true) == .escalate)
        #expect(TriageRouter.route(risk: .high, local: suspicious, claudeEnabled: false)
                == .settle(.suspicious, note: suspicious.reason))
    }

    @Test func unavailableModelFallsBackToClaude() {
        #expect(TriageRouter.route(risk: .normal, local: nil, claudeEnabled: true) == .escalate)
        #expect(TriageRouter.route(risk: .normal, local: nil, claudeEnabled: false) == .leave)
    }

    @Test func promptCarriesTheFactsAndMasksSecrets() {
        let e = entry(kind: .net, process: "/usr/bin/curl", pattern: "TCP internet:443", risk: .normal,
                      target: "https://api.example.com/x?token=s3cr3t", host: "api.example.com")
        let p = AppleOnDeviceModel.prompt(for: e, signer: nil, trusted: false)
        #expect(p.contains("Program: curl"))
        #expect(p.contains("connected to TCP internet:443 (host api.example.com)"))
        #expect(p.contains("Local risk heuristic: normal"))
        #expect(!p.contains("s3cr3t"))
    }

    /// Runs only when Apple's on-device model is ready on this Mac.
    @Test(.enabled(if: AppleOnDeviceModel().status().isReady))
    func realModelNeverCallsADropperConfidentlySafe() async throws {
        let e = entry(kind: .file, process: "/private/tmp/x/updater", pattern: "w ~/Library/LaunchAgents/*.plist  [persistence]",
                      risk: .high, target: "\(home)/Library/LaunchAgents/com.update.helper.plist")
        var unsigned = CodeIdentity(); unsigned.quarantined = true
        let verdict = try await AppleOnDeviceModel().triage(AppleOnDeviceModel.prompt(for: e, signer: unsigned, trusted: false))
        #expect(!(verdict.verdict == .safe && verdict.confidence == .high))
    }

    func entry(kind: EventKind, process: String, pattern: String, risk: PatternRisk, target: String,
               host: String? = nil) -> SignatureEntry {
        SignatureEntry(id: "\(kind.rawValue)|\(process)|\(pattern)", kind: kind, process: process, pattern: pattern,
                       count: 3, risk: risk, firstSeen: Date(), lastSeen: Date(), status: .unclassified, source: nil,
                       note: nil, exampleName: (process as NSString).lastPathComponent, examplePid: 1,
                       exampleProc: process, exampleTarget: target, exampleExtra: "", exampleParent: "",
                       exampleHost: host, exampleHostSource: host == nil ? nil : "dns")
    }
}
