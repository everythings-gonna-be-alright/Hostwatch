import Foundation
import FoundationModels

// Which model each engine uses (Settings ▸ AI): Apple's on-device model or a custom server for the local pass, and
// which Claude model the Claude engine runs. A custom server speaks the OpenAI chat format (Ollama, LM Studio,
// llama.cpp, vLLM or a cloud endpoint): on this Mac nothing leaves it, elsewhere the evidence (secrets masked) goes
// there, which Settings says.

/// The model behind "local" (classifying new patterns first, and Ask AI with the local engine).
enum LocalModelChoice: String, CaseIterable, Sendable {
    case apple, custom

    var title: String { self == .apple ? "Apple On-Device" : "Custom Server (OpenAI-compatible)" }

    static let key = "localModelChoice"
    static var current: LocalModelChoice {
        UserDefaults.standard.string(forKey: key).flatMap(LocalModelChoice.init) ?? .apple
    }

    /// The model to use now: the choice is read at each use, so Settings applies at once.
    static func model() -> any LocalAIModel {
        current == .custom ? CustomAIModel(config: CustomAIConfig.load()) : AppleOnDeviceModel()
    }
}

/// Apple's on-device models: the general one, or the one tuned for tagging and classifying text.
enum AppleModelChoice: String, CaseIterable, Sendable {
    case general, contentTagging

    var title: String { self == .general ? "General" : "Content Tagging" }
    var help: String {
        self == .general ? "Apple's general model: broader knowledge, the default."
            : "Apple's model tuned for classifying and tagging text: steadier labels, less general knowledge."
    }

    static let key = "appleModelChoice"
    static var current: AppleModelChoice {
        UserDefaults.standard.string(forKey: key).flatMap(AppleModelChoice.init) ?? .general
    }

    var model: SystemLanguageModel {
        self == .general ? .default : SystemLanguageModel(useCase: .contentTagging)
    }
}

/// The Claude model the Claude engine asks (the Claude Code CLI's `--model`).
enum ClaudeModelChoice: String, CaseIterable, Sendable {
    case cliDefault = "", opus, sonnet, haiku

    var title: String {
        switch self {
        case .cliDefault: "Claude Code's Default"
        case .opus: "Opus (strongest)"
        case .sonnet: "Sonnet (balanced)"
        case .haiku: "Haiku (fastest, cheapest)"
        }
    }

    static let key = "claudeModel"
    static var current: ClaudeModelChoice {
        UserDefaults.standard.string(forKey: key).flatMap(ClaudeModelChoice.init) ?? .cliDefault
    }

    /// Added to every Claude CLI call: nothing when Claude Code's own setting decides.
    static var arguments: [String] { current == .cliDefault ? [] : ["--model", current.rawValue] }
}

/// A local model: the pattern triage plus free-text analysis for Ask AI.
protocol LocalAIModel: LocalTriageModel {
    func explain(_ prompt: String, instructions: String) async throws -> String
    /// Where answers come from, for the Ask AI footer ("on-device", "Ollama on this Mac", "api.example.com").
    var origin: String { get }
    /// Whether the evidence stays on this Mac.
    var staysOnMac: Bool { get }
}

extension AppleOnDeviceModel: LocalAIModel {
    var origin: String { "on-device (\(AppleModelChoice.current.title))" }
    var staysOnMac: Bool { true }
}

// MARK: - Custom server

struct CustomAIConfig: Equatable, Sendable {
    var baseURL = "http://127.0.0.1:11434/v1"
    var model = ""
    var apiKey = ""

    static let urlKey = "customAIBaseURL", modelKey = "customAIModel"
    /// The key is a secret: sealed through the Vault like every Hostwatch file, never in preferences.
    static var keyFile: URL { AppPaths.support.appendingPathComponent("custom-ai-key") }

    static func load() -> CustomAIConfig {
        let d = UserDefaults.standard
        let key = Vault.shared.read(keyFile).map { String(decoding: $0, as: UTF8.self) } ?? ""
        return CustomAIConfig(baseURL: d.string(forKey: urlKey) ?? CustomAIConfig().baseURL,
                              model: d.string(forKey: modelKey) ?? "", apiKey: key)
    }

    func save() {
        UserDefaults.standard.set(baseURL, forKey: Self.urlKey)
        UserDefaults.standard.set(model, forKey: Self.modelKey)
        if apiKey.isEmpty { try? FileManager.default.removeItem(at: Self.keyFile) }
        else { try? Vault.shared.write(Data(apiKey.utf8), to: Self.keyFile) }
    }

    var host: String { URL(string: baseURL)?.host ?? baseURL }

    /// Loopback: the evidence stays on this Mac.
    var isLocal: Bool { ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host) }

    var endpoint: URL? {
        URL(string: baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL)
    }
}

/// A model behind an OpenAI-compatible chat endpoint (`/chat/completions`, `/models`).
struct CustomAIModel: LocalAIModel {
    let config: CustomAIConfig

    var origin: String { config.model + (config.isLocal ? " on this Mac" : " at \(config.host)") }
    var staysOnMac: Bool { config.isLocal }

    func status() -> LocalModelStatus {
        if config.endpoint == nil { return .unavailable("the server address isn't a URL") }
        if config.model.isEmpty { return .unavailable("choose a model") }
        return .ready
    }

    func triage(_ prompt: String) async throws -> LocalVerdict {
        let system = AppleOnDeviceModel.instructions + "\n\nAnswer with one JSON object only: "
            + #"{"verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "UNSURE", "confidence": "low" | "medium" | "high", "reason": "at most 15 words"}"#
        let text = try await chat(system: system, user: prompt, maxTokens: 2_000)
        return Self.verdict(from: text)
    }

    func explain(_ prompt: String, instructions: String) async throws -> String {
        let text = try await chat(system: instructions, user: prompt, maxTokens: 1_500)
        // A reasoning model thinks out loud first: the answer is what follows its thinking.
        return text.components(separatedBy: "</think>").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? text
    }

    /// The last JSON object in a reply (reasoning models think first), as a verdict. Unreadable means unsure.
    static func verdict(from reply: String) -> LocalVerdict {
        let text = reply.components(separatedBy: "</think>").last ?? reply
        guard let open = text.range(of: "{", options: .backwards), let close = text.range(of: "}", options: .backwards),
              open.lowerBound < close.upperBound,
              let json = (try? JSONSerialization.jsonObject(with: Data(text[open.lowerBound..<close.upperBound].utf8))) as? [String: Any]
        else { return LocalVerdict(verdict: .unknown, confidence: .low, reason: "no readable answer") }
        let word = (json["verdict"] as? String ?? "").uppercased()
        return LocalVerdict(verdict: Verdict(rawValue: word == "UNSURE" ? "UNKNOWN" : word) ?? .unknown,
                            confidence: LocalVerdict.Confidence(rawValue: (json["confidence"] as? String ?? "").lowercased()) ?? .low,
                            reason: String((json["reason"] as? String ?? "").prefix(160)))
    }

    private func chat(system: String, user: String, maxTokens: Int) async throws -> String {
        guard let base = config.endpoint else { throw URLError(.badURL) }
        var request = URLRequest(url: base.appendingPathComponent("chat/completions"))
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !config.apiKey.isEmpty { request.setValue("Bearer \(config.apiKey)", forHTTPHeaderField: "Authorization") }
        let body: [String: Any] = ["model": config.model, "temperature": 0, "max_tokens": maxTokens, "stream": false,
                                   "messages": [["role": "system", "content": system],
                                                ["role": "user", "content": Secrets.mask(user)]]]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw CustomAIError.server(http.statusCode, String(decoding: data.prefix(300), as: UTF8.self))
        }
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let message = ((obj["choices"] as? [[String: Any]])?.first?["message"]) as? [String: Any],
              let content = message["content"] as? String
        else { throw CustomAIError.unreadable(String(decoding: data.prefix(200), as: UTF8.self)) }
        return content
    }

    /// The server's models, for the Settings picker.
    static func models(_ config: CustomAIConfig) async throws -> [String] {
        guard let base = config.endpoint else { throw URLError(.badURL) }
        var request = URLRequest(url: base.appendingPathComponent("models"))
        request.timeoutInterval = 10
        if !config.apiKey.isEmpty { request.setValue("Bearer \(config.apiKey)", forHTTPHeaderField: "Authorization") }
        let (data, _) = try await URLSession.shared.data(for: request)
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return ((obj?["data"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String }.sorted()
    }
}

enum CustomAIError: LocalizedError {
    case server(Int, String), unreadable(String)

    var errorDescription: String? {
        switch self {
        case .server(let code, let text): "The server answered \(code): \(text)"
        case .unreadable(let text): "The server's answer wasn't an OpenAI-style chat reply: \(text)"
        }
    }
}
