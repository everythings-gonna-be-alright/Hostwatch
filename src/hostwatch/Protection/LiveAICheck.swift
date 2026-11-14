import Foundation

/// A paused launch or file access checked by AI before you are asked. Only a clear Safe lets it go on, and only this
/// time: the pattern stays New for your own decision. Pure, so the rule is tested without a model. source:
/// docs/adr/0014-ai-checks-paused-programs.md
enum LiveAICheck {
    /// The setting (Settings ▸ AI): on unless you turn it off.
    static let settingKey = "protectionAICheck"
    /// How long a paused program waits for the AI before you are asked: it waits 30 s in all, you need the rest.
    static let timeLimit: TimeInterval = 12

    enum Outcome: Equatable {
        /// Goes on this time. The note says why, for the notice and Found.
        case allow(String)
        /// You decide. The note is the AI's view in a sentence; the verdict and why the AI couldn't allow it alone
        /// (the limit) let the question show the conclusion as a card.
        case ask(String, verdict: LocalVerdict? = nil, limit: String? = nil)
    }

    static func enabled(_ defaults: UserDefaults = .standard) -> Bool {
        defaults.object(forKey: settingKey) as? Bool ?? true
    }

    /// The rule. - refusal: why no AI may allow this pattern by itself (SignatureBuilder.aiSafeRefusal: shells,
    /// interpreters, sensitive files, high risk), nil when it may. - warned: Hostwatch found a warning sign itself.
    static func outcome(verdict: LocalVerdict?, risk: PatternRisk, warned: Bool, refusal: String?) -> Outcome {
        guard let v = verdict else { return .ask("The AI didn't answer in time.") }
        let said = "AI: \(v.verdict.rawValue.lowercased()), \(v.confidence.rawValue) confidence. \(v.reason)"
        guard v.verdict == .safe, v.confidence == .high else { return .ask(said, verdict: v) }
        if let refusal { return .ask(said + " Not allowed by AI alone: \(refusal).", verdict: v, limit: refusal) }
        if risk == .high { return .ask(said + " Not allowed by AI alone: it's a high-risk pattern.", verdict: v, limit: "it's a high-risk pattern") }
        if warned { return .ask(said + " Not allowed by AI alone: Hostwatch found a warning sign.", verdict: v, limit: "Hostwatch found a warning sign") }
        return .allow(v.reason.isEmpty ? "The AI rated it safe." : v.reason)
    }
}
