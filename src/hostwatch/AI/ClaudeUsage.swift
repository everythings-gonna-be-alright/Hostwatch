import Foundation

/// One `claude -p` run, from its result object (`usage` and `total_cost_usd`).
struct ClaudeRun: Sendable, Equatable {
    var input = 0          // input tokens, cache reads and writes included
    var output = 0
    var cached = 0         // of `input`: read from or written to the prompt cache
    var cost = 0.0

    init(input: Int = 0, output: Int = 0, cached: Int = 0, cost: Double = 0) {
        self.input = input; self.output = output; self.cached = cached; self.cost = cost
    }

    /// nil when the object carries no usage (a run that never reached Claude).
    init?(result obj: [String: Any]) {
        let usage = obj["usage"] as? [String: Any] ?? [:]
        func n(_ key: String) -> Int { (usage[key] as? NSNumber)?.intValue ?? 0 }
        let cache = n("cache_read_input_tokens") + n("cache_creation_input_tokens")
        self.init(input: n("input_tokens") + cache, output: n("output_tokens"), cached: cache,
                  cost: (obj["total_cost_usd"] as? NSNumber)?.doubleValue ?? 0)
        if input + output == 0, cost == 0 { return nil }
    }
}

/// Claude tokens and cost Hostwatch has used, over all runs since the counter started (or was reset).
/// Kept in the app's preferences, per feature.
@MainActor final class ClaudeUsage: ObservableObject {
    enum Feature: String, Codable, CaseIterable, Sendable {
        case ask, classify, rules
        var title: String {
            switch self {
            case .ask: "Ask AI"
            case .classify: "Classifying patterns"
            case .rules: "Suggest Rules"
            }
        }
    }

    struct Tally: Codable, Equatable {
        var runs = 0, input = 0, output = 0, cached = 0
        var cost = 0.0
        var tokens: Int { input + output }

        mutating func add(_ r: ClaudeRun) {
            runs += 1; input += r.input; output += r.output; cached += r.cached; cost += r.cost
        }
    }

    struct Totals: Codable, Equatable {
        var since = Date()
        var features: [String: Tally] = [:]
        var all: Tally { features.values.reduce(into: Tally()) { a, t in
            a.runs += t.runs; a.input += t.input; a.output += t.output; a.cached += t.cached; a.cost += t.cost } }
    }

    static let shared = ClaudeUsage()
    static let key = "claudeUsage"

    @Published private(set) var totals: Totals
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        totals = defaults.data(forKey: Self.key).flatMap { try? JSONDecoder().decode(Totals.self, from: $0) } ?? Totals()
    }

    func add(_ run: ClaudeRun?, _ feature: Feature) {
        guard let run else { return }
        totals.features[feature.rawValue, default: Tally()].add(run)
        save()
    }

    /// From a `claude -p --output-format json` result object.
    func add(result obj: [String: Any], _ feature: Feature) { add(ClaudeRun(result: obj), feature) }

    func reset() {
        totals = Totals()
        save()
    }

    func tally(_ feature: Feature) -> Tally { totals.features[feature.rawValue] ?? Tally() }

    private func save() {
        if let data = try? JSONEncoder().encode(totals) { defaults.set(data, forKey: Self.key) }
    }

    /// "1.2M", "48K", "950".
    nonisolated static func short(_ n: Int) -> String {
        switch n {
        case 1_000_000...: String(format: n >= 10_000_000 ? "%.0fM" : "%.1fM", Double(n) / 1_000_000)
        case 1_000...: String(format: n >= 10_000 ? "%.0fK" : "%.1fK", Double(n) / 1_000)
        default: "\(n)"
        }
    }

    nonisolated static func dollars(_ d: Double) -> String { String(format: d < 10 ? "$%.2f" : "$%.0f", d) }
}
