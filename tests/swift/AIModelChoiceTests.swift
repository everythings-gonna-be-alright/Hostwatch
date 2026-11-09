import Foundation
import Testing
@testable import Hostwatch

/// Settings ▸ AI: a custom server's answers, where it is, and the Claude model flag.
@Suite struct AIModelChoices {
    @Test func aReasoningReplyGivesItsLastAnswer() {
        let reply = "<think>Finder reading Documents… {\"verdict\": \"DANGEROUS\"} no wait</think>\n{\"verdict\": \"SAFE\", \"confidence\": \"high\", \"reason\": \"Finder browsing\"}"
        let v = CustomAIModel.verdict(from: reply)
        #expect(v.verdict == .safe && v.confidence == .high && v.reason == "Finder browsing")
    }

    @Test func anUnreadableReplyIsUnsure() {
        let v = CustomAIModel.verdict(from: "I think it's fine.")
        #expect(v.verdict == .unknown && v.confidence == .low)
        #expect(CustomAIModel.verdict(from: #"{"verdict": "UNSURE", "confidence": "medium"}"#).verdict == .unknown)
    }

    @Test func whereTheEvidenceGoes() {
        #expect(CustomAIConfig(baseURL: "http://127.0.0.1:11434/v1").isLocal)
        #expect(CustomAIConfig(baseURL: "http://localhost:1234/v1").isLocal)
        #expect(!CustomAIConfig(baseURL: "https://api.example.com/v1").isLocal)
        #expect(CustomAIConfig(baseURL: "https://api.example.com/v1").host == "api.example.com")
    }

    @Test func aCustomModelNeedsAModel() {
        #expect(!CustomAIModel(config: CustomAIConfig(baseURL: "http://127.0.0.1:11434/v1", model: "")).status().isReady)
        #expect(CustomAIModel(config: CustomAIConfig(baseURL: "http://127.0.0.1:11434/v1", model: "m")).status().isReady)
    }

    @Test func claudeCodesDefaultAddsNoFlag() {
        #expect(ClaudeModelChoice.cliDefault.rawValue.isEmpty)
        #expect(ClaudeModelChoice.allCases.filter { $0 != .cliDefault }.allSatisfy { !$0.rawValue.isEmpty })
    }
}
