import AppKit
import Combine
import Foundation

// MARK: - Batch classification with Claude

@MainActor
final class PatternClassifier: ObservableObject {
    @Published private(set) var running = false {
        didSet { if oldValue && !running { DispatchQueue.main.async { [weak self] in self?.continueAll() } } }
    }

    /// "Classify with AI" for every New pattern: batches one after another, with progress.
    struct BulkRun: Equatable {
        var total: Int
        var done = 0
        var apply: Bool                 // apply the verdicts (never Safe for high risk or interpreters), or keep suggestions
        var attempted: Set<String> = []
        var batch: [String] = []
        /// Only these patterns (what the list shows, or what you selected); nil for every New pattern.
        var only: Set<String>? = nil
    }
    @Published private(set) var bulk: BulkRun?
    @Published private(set) var lastMessage = ""
    @Published private(set) var totalCost: Double = 0
    @Published var autoClassify: Bool {
        didSet { UserDefaults.standard.set(autoClassify, forKey: "autoClassifyPatterns") }
    }

    /// Which AI classifies new patterns (and answers Ask, see AIEngine.askEngine).
    @Published var engine: AIEngine {
        didSet { UserDefaults.standard.set(engine.rawValue, forKey: AIEngine.key); leftForYou.removeAll() }
    }

    /// Who started a pattern's example (the app's recorded launches): added to every triage prompt.
    var context: ((SignatureEntry) -> TriageContext?)?
    /// Pattern by pattern, as it happens (Classify with AI ▸ the live list).
    let live = ClassifyLive()
    private let store: SignatureStore
    /// Tests inject a model; otherwise the one chosen in Settings, read at each use.
    private let injectedModel: LocalTriageModel?
    private var localModel: LocalTriageModel { injectedModel ?? LocalModelChoice.model() }
    private var timer: Timer?
    private var process: Process?
    private var localTask: Task<Void, Never>?
    /// Patterns the on-device pass already left for you (Claude off): not re-run every cycle.
    private var leftForYou = Set<String>()
    let batchSize = 40

    var localStatus: LocalModelStatus { localModel.status() }

    init(store: SignatureStore, localModel: LocalTriageModel? = nil) {
        self.store = store
        self.injectedModel = localModel
        autoClassify = UserDefaults.standard.bool(forKey: "autoClassifyPatterns")
        engine = AIEngine.load()
        timer = Timer.scheduledTimer(withTimeInterval: 90, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.autoClassify, !self.running else { return }
                // Let new patterns settle for a minute so each batch is meaningful.
                let ready = self.store.unclassifiedForReview(limit: self.batchSize + self.leftForYou.count)
                    .filter { Date().timeIntervalSince($0.firstSeen) > 60 && !self.leftForYou.contains($0.id) }
                    .prefix(self.batchSize).map { $0 }
                if !ready.isEmpty { self.classify(ready) }
            }
        }
    }

    /// The local model's instructions, with the batch and the answer format: one prompt, so Claude and the local
    /// model judge on the same facts.
    static var systemPrompt: String {
        TriagePrompt.instructions + "\n"
            + "You get a numbered list of patterns observed on one Mac, each with its facts. Classify each one: "
            + "SAFE, SUSPICIOUS, DANGEROUS, or UNKNOWN when the facts aren't enough.\n"
            + "Output ONLY a JSON array, no prose, no code fences:\n"
            + #"[{"id": <number>, "verdict": "SAFE|SUSPICIOUS|DANGEROUS|UNKNOWN", "reason": "<= 20 words naming the deciding fact"}]"#
    }

    /// New patterns nobody decided and no AI has looked at yet.
    var classifiable: [SignatureEntry] {
        store.allEntries.filter { store.status(forKey: $0.id) == .unclassified && $0.suggestion == nil && $0.reopened == nil
            && !leftForYou.contains($0.id) }
    }

    /// New patterns among `keys` that Classify with AI would take (all New patterns when nil).
    func classifiable(in keys: Set<String>?) -> [SignatureEntry] {
        guard let keys else { return classifiable }
        return store.allEntries.filter { keys.contains($0.id) && store.status(forKey: $0.id) == .unclassified
            && $0.suggestion == nil && $0.reopened == nil }
    }

    /// Classifies New patterns, `batchSize` at a time (high-risk first, then most recent): every one, or only
    /// `only` (the patterns a list shows, or the ones you selected). Asking for them again retries what an earlier
    /// pass left for you.
    func classifyAll(apply: Bool, only: Set<String>? = nil) {
        guard bulk == nil, !running else { return }
        if let only { leftForYou.subtract(only) }
        let todo = classifiable(in: only)
        guard !todo.isEmpty else { lastMessage = only == nil ? "Nothing to classify." : "Nothing New to classify there."; return }
        bulk = BulkRun(total: todo.count, apply: apply, only: only)
        live.start(engine: engineText)
        continueAll()
    }

    func cancelAll() {
        bulk = nil
        cancel()
        live.finishOpen(.left("cancelled"))
    }

    /// The engine and its models in words, for the live list's header.
    var engineText: String {
        let local = (localModel as? any LocalAIModel)?.origin ?? "local model"
        let claude = ClaudeModelChoice.current == .cliDefault ? "Claude" : "Claude \(ClaudeModelChoice.current.rawValue.capitalized)"
        switch engine {
        case .onDevice: return "Local model: \(local)"
        case .claude: return claude
        case .hybrid: return "Local model first (\(local)), then \(claude)"
        }
    }

    private var localName: String { (localModel as? any LocalAIModel)?.origin ?? "local model" }

    private func continueAll() {
        guard var run = bulk, !running else { return }
        if run.apply, !run.batch.isEmpty { store.acceptSuggestions(keys: run.batch, yours: false) }
        // Claude unavailable or failing: stop rather than fail every remaining batch.
        if ["failed", "Cannot start", "not found", "Could not parse", "Cancelled"].contains(where: lastMessage.contains) {
            bulk = nil
            return
        }
        run.done = min(run.total, run.attempted.count)
        let next = classifiable(in: run.only).filter { !run.attempted.contains($0.id) }
            .sorted { $0.risk != $1.risk ? $0.risk > $1.risk : $0.lastSeen > $1.lastSeen }
            .prefix(batchSize)
        guard !next.isEmpty else {
            lastMessage = "Classified \(run.attempted.count) patterns" + (run.apply ? "; verdicts applied (not to high-risk)." : "; see Rules ▸ Needs You.")
            bulk = nil
            return
        }
        run.batch = next.map(\.id)
        run.attempted.formUnion(run.batch)
        bulk = run
        classify(Array(next))
        if !running { bulk = nil }       // nothing could run (no engine): stop instead of looping
    }

    func classifyNow() {
        leftForYou.removeAll()   // an explicit request retries everything
        let batch = store.unclassifiedForReview(limit: batchSize)
        guard !batch.isEmpty else { lastMessage = "Nothing to classify."; return }
        classify(batch)
    }

    func cancel() {
        localTask?.cancel()
        localTask = nil
        process?.terminate()
        process = nil
        running = false
        lastMessage = "Cancelled."
    }

    /// On-device first pass when available, then Claude for the rest (each step optional).
    /// Baseline: the on-device model only (never Claude) for these patterns; whatever it can't settle,
    /// and anything high-risk, stays New for you.
    func triageOnDevice(keys: [String]) {
        let model = localModel
        guard model.status().isReady else { return }
        let batch = keys.compactMap { store.entry($0) }
        let contexts = batch.map { context?($0) }
        let prompts = zip(batch, contexts).map { TriagePrompt.pattern($0, context: $1) }
        let warned = Dictionary(zip(batch, contexts).map { ($0.id, !TriagePrompt.warningSigns($0, context: $1).isEmpty) },
                                uniquingKeysWith: { a, _ in a })
        Task { [weak self] in
            for (entry, prompt) in zip(batch, prompts) {
                if Task.isCancelled { return }
                let verdict = try? await model.triage(prompt)
                guard let self else { return }
                if case .settle(let status, let note) = TriageRouter.route(risk: entry.risk, local: verdict, claudeEnabled: false, warned: warned[entry.id] ?? false) {
                    self.store.suggest(status, key: entry.id, source: "on-device", note: note)
                }
            }
        }
    }

    private func classify(_ batch: [SignatureEntry]) {
        guard !running else { return }
        let claudeOn = engine.usesClaude && ClaudeLocator.path != nil
        let local = localModel.status()
        guard engine.usesOnDevice && local.isReady else {
            if claudeOn { sendToClaude(batch) }
            else if engine == .onDevice { lastMessage = local.label + " (Settings ▸ AI)." }
            else { lastMessage = "Claude Code CLI not found." }
            return
        }
        running = true
        lastMessage = "On-device triage of \(batch.count) patterns…"
        let model = localModel
        let asker = localName
        live.add(batch, as: .waiting("local model"))
        let contexts = batch.map { context?($0) }
        let prompts = zip(batch, contexts).map { TriagePrompt.pattern($0, context: $1) }
        let warned = Dictionary(zip(batch, contexts).map { ($0.id, !TriagePrompt.warningSigns($0, context: $1).isEmpty) },
                                uniquingKeysWith: { a, _ in a })
        localTask = Task { [weak self] in
            var escalate: [SignatureEntry] = []
            var settled = 0, flagged = 0, left = 0
            for (entry, prompt) in zip(batch, prompts) {
                if Task.isCancelled { return }
                self?.live.set(entry.id, .asking(asker))
                let verdict = try? await model.triage(prompt)
                guard let self else { return }
                switch TriageRouter.route(risk: entry.risk, local: verdict, claudeEnabled: claudeOn, warned: warned[entry.id] ?? false) {
                case .settle(let status, let note):
                    self.store.suggest(status, key: entry.id, source: "on-device", note: note)
                    self.live.set(entry.id, .done(status, by: "Local", reason: note))
                    if status == .safe { settled += 1 } else { flagged += 1 }
                case .escalate:
                    escalate.append(entry)
                    self.live.set(entry.id, .waiting("Claude next" + (verdict.map { ": local said \($0.verdict.rawValue.lowercased()), \($0.confidence.rawValue) confidence" } ?? "")))
                case .leave:
                    self.leftForYou.insert(entry.id)
                    self.live.set(entry.id, .left(verdict.map { "local model: \($0.verdict.rawValue.lowercased()), \($0.reason)" } ?? "the local model didn't answer"))
                    left += 1
                }
            }
            guard let self, !Task.isCancelled else { return }
            self.running = false
            self.localTask = nil
            var parts = ["On-device: \(settled) safe"]
            if flagged > 0 { parts.append("\(flagged) flagged") }
            if left > 0 { parts.append("\(left) left for you") }
            if !escalate.isEmpty { parts.append("\(escalate.count) sent to Claude") }
            self.lastMessage = parts.joined(separator: ", ")
            if !escalate.isEmpty { self.sendToClaude(escalate, prefix: self.lastMessage) }
        }
    }

    private func sendToClaude(_ batch: [SignatureEntry], prefix: String = "") {
        guard !running else { return }
        guard let claude = ClaudeLocator.path else {
            lastMessage = "Claude Code CLI not found."
            return
        }
        running = true
        lastMessage = (prefix.isEmpty ? "" : prefix + " · ") + "Classifying \(batch.count) patterns with Claude…"
        live.add(batch, as: .waiting("Claude"))
        let who = ClaudeModelChoice.current == .cliDefault ? "Claude" : "Claude \(ClaudeModelChoice.current.rawValue.capitalized)"
        for e in batch { live.set(e.id, .asking(who)) }

        let prompt = Self.prompt(for: batch, contexts: batch.map { context?($0) })
        run(claude: claude, prompt: prompt, batch: batch)
    }

    private func run(claude: String, prompt: String, batch: [SignatureEntry]) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: claude)
        process.currentDirectoryURL = AppPaths.support
        process.arguments = ["-p", "--output-format", "json", "--no-session-persistence",
                             "--setting-sources", "", "--strict-mcp-config", "--tools", "",
                             "--system-prompt", Self.systemPrompt] + ClaudeModelChoice.arguments
        process.environment = ClaudeLocator.environment
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        process.terminationHandler = { proc in
            let out = stdout.fileHandleForReading.readDataToEndOfFile()
            let err = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let status = proc.terminationStatus
            DispatchQueue.main.async { self.finish(out: out, err: err, status: status, batch: batch) }
        }
        do { try process.run() } catch {
            running = false
            lastMessage = "Cannot start claude: \(error.localizedDescription)"
            live.finishOpen(.failed("Claude didn't start"))
            return
        }
        self.process = process
        DispatchQueue.global().async {
            stdin.fileHandleForWriting.write(Data(Secrets.mask(prompt).utf8))   // never send a secret
            try? stdin.fileHandleForWriting.close()
        }
    }

    private func finish(out: Data, err: String, status: Int32, batch: [SignatureEntry]) {
        guard running else { return }
        running = false
        process = nil
        let parsed = try? JSONSerialization.jsonObject(with: out) as? [String: Any]
        if let parsed { MainActor.assumeIsolated { ClaudeUsage.shared.add(result: parsed, .classify) } }
        guard status == 0,
              let obj = parsed,
              let text = obj["result"] as? String
        else {
            lastMessage = "Claude failed: " + String(err.trimmingCharacters(in: .whitespacesAndNewlines).suffix(200))
            live.finishOpen(.failed("Claude failed"))
            return
        }
        totalCost += obj["total_cost_usd"] as? Double ?? 0
        guard let start = text.firstIndex(of: "["), let end = text.lastIndex(of: "]"),
              let data = String(text[start...end]).data(using: .utf8),
              let items = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else {
            lastMessage = "Could not parse Claude's answer."
            live.finishOpen(.failed("Claude's answer couldn't be read"))
            return
        }
        var tally: [SignatureStatus: Int] = [:]
        for item in items {
            guard let id = (item["id"] as? NSNumber)?.intValue, id >= 1, id <= batch.count,
                  let word = (item["verdict"] as? String)?.uppercased(),
                  let verdict = Verdict(rawValue: word) else { continue }
            let status = SignatureStatus(verdict: verdict)
            store.suggest(status, key: batch[id - 1].id, source: "claude", note: item["reason"] as? String)
            live.set(batch[id - 1].id, .done(status, by: "Claude", reason: item["reason"] as? String ?? ""))
            tally[status, default: 0] += 1
        }
        let summary = SignatureStatus.allCases.compactMap { s in tally[s].map { "\($0) \(s.rawValue)" } }
        for e in batch { if case .asking? = live.steps.first(where: { $0.id == e.id })?.state { live.set(e.id, .left("Claude gave no answer for it")) } }
        lastMessage = "Claude classified \(items.count): " + summary.joined(separator: ", ")
            + String(format: " · total $%.3f", totalCost)
    }

    private static func prompt(for batch: [SignatureEntry], contexts: [TriageContext?]) -> String {
        var blocks = ["Classify these \(batch.count) patterns:"]
        for (i, (e, c)) in zip(batch, contexts).enumerated() {
            blocks.append("\(i + 1).\n" + TriagePrompt.pattern(e, context: c))
        }
        return blocks.joined(separator: "\n\n")
    }

}
