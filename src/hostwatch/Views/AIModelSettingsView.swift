import SwiftUI

/// Settings ▸ AI: which model each engine uses. The local model (Apple's or a custom server), Apple's model, and the
/// Claude model. A custom server is tested from here before it classifies anything.
struct AIModelSettings: View {
    @StateObject private var state = AIModelSettingsState()

    var body: some View {
        Section {
            Picker("Local model", selection: $state.local) {
                ForEach(LocalModelChoice.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            if state.local == .apple {
                Picker("Apple model", selection: $state.apple) {
                    ForEach(AppleModelChoice.allCases, id: \.self) { Text($0.title).tag($0) }
                }
            } else {
                TextField("Server", text: $state.config.baseURL, prompt: Text("http://127.0.0.1:11434/v1"))
                    .font(.system(.body, design: .monospaced))
                HStack {
                    if state.models.isEmpty {
                        TextField("Model", text: $state.config.model, prompt: Text("e.g. foundation-sec-8b"))
                    } else {
                        Picker("Model", selection: $state.config.model) {
                            if !state.models.contains(state.config.model) {
                                Text(state.config.model.isEmpty ? "Choose…" : state.config.model).tag(state.config.model)
                            }
                            ForEach(state.models, id: \.self) { Text($0).tag($0) }
                        }
                    }
                    Button("Load Models") { state.loadModels() }
                }
                SecureField("API key", text: $state.config.apiKey, prompt: Text("only if the server needs one"))
                HStack {
                    Button(state.testing ? "Testing…" : "Test") { state.test() }.disabled(state.testing)
                    if !state.result.isEmpty {
                        Text(state.result).font(.callout).foregroundStyle(state.ok ? .green : .orange)
                            .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } header: {
            Text("Local model")
        } footer: {
            Footnote(state.local == .apple ? state.apple.help
                     : state.config.isLocal
                        ? "A server on this Mac (Ollama, LM Studio, llama.cpp): nothing leaves it. Secrets are masked anyway."
                        : "This server isn't on this Mac: pattern facts and Ask AI evidence (secrets masked) are sent to \(state.config.host).")
        }
        Section {
            Picker("Claude model", selection: $state.claude) {
                ForEach(ClaudeModelChoice.allCases, id: \.self) { Text($0.title).tag($0) }
            }
        } header: {
            Text("Claude")
        } footer: {
            Footnote("Used by Ask AI, classifying new patterns and Suggest Rules when the engine includes Claude.")
        }
    }
}

/// Settings state: every change is saved at once (the key sealed through the Vault).
@MainActor
final class AIModelSettingsState: ObservableObject {
    @Published var local = LocalModelChoice.current { didSet { UserDefaults.standard.set(local.rawValue, forKey: LocalModelChoice.key) } }
    @Published var apple = AppleModelChoice.current { didSet { UserDefaults.standard.set(apple.rawValue, forKey: AppleModelChoice.key) } }
    @Published var claude = ClaudeModelChoice.current { didSet { UserDefaults.standard.set(claude.rawValue, forKey: ClaudeModelChoice.key) } }
    @Published var config = CustomAIConfig.load() { didSet { if config != oldValue { config.save(); result = "" } } }
    @Published var models: [String] = []
    @Published var result = ""
    @Published var ok = false
    @Published var testing = false

    /// A harmless, obviously ordinary pattern: a working model calls it Safe.
    static let testPattern = "Program: Finder (/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder)\n"
        + "Activity: opened files: r ~/Documents/*\nSigner of the program it concerns: Apple, trusted\n"
        + "Local risk heuristic: routine\nSeen 120 times. Example target: ~/Documents/notes.txt"

    func loadModels() {
        let config = self.config
        Task {
            do {
                let list = try await CustomAIModel.models(config)
                models = list
                if config.model.isEmpty, let first = list.first { self.config.model = first }
                result = list.isEmpty ? "The server lists no models." : "\(list.count) models"
                ok = !list.isEmpty
            } catch {
                result = "Can't reach the server: \(error.localizedDescription)"
                ok = false
            }
        }
    }

    /// One real triage: proves the address, the model and the answer format together.
    func test() {
        let model = CustomAIModel(config: config)
        testing = true
        Task {
            let start = Date()
            do {
                let v = try await model.triage(Self.testPattern)
                ok = v.verdict != .unknown
                result = ok ? String(format: "Works: %@ in %.1f s", v.verdict.rawValue.capitalized, Date().timeIntervalSince(start))
                    : "It answered, but not in the expected form."
            } catch {
                ok = false
                result = error.localizedDescription
            }
            testing = false
        }
    }
}
