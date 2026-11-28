import Foundation

/// `Hostwatch --story-report [N]`: the last N stories (default 60) as plain text, to study which chains are noise.
/// Read only: it decodes stories.json through the vault and changes nothing.
func runStoryReport(_ limit: Int) -> Never {
    let url = AppPaths.support.appendingPathComponent("stories.json")
    guard let data = Vault.shared.read(url) else { print("no stories (or the data key didn't open)"); exit(1) }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    guard let stories = try? decoder.decode([Story].self, from: data) else { print("stories.json didn't decode"); exit(1) }
    let shown = stories.sorted { $0.lastSeen > $1.lastSeen }.prefix(limit)
    let fmt = ISO8601DateFormatter()
    var byStages: [String: Int] = [:]
    for s in stories { byStages[s.summary, default: 0] += 1 }
    print("\(stories.count) stories, \(stories.filter(\.dismissed).count) dismissed, "
          + "\(stories.filter { $0.severity == .dangerous }.count) dangerous")
    print("\nBy stages:")
    for (k, n) in byStages.sorted(by: { $0.value > $1.value }) { print("  \(n)\t\(k)") }
    for s in shown {
        print("\n=== \(fmt.string(from: s.firstSeen)) \(s.severity.rawValue)\(s.dismissed ? " dismissed" : "") score \(s.score) "
              + "origin \(s.origin.rawValue) \(s.originPath)")
        print("    \(s.title)")
        for st in s.steps {
            print("    - [\(st.stage.rawValue)] \(st.name) ← \(Agent.base(st.parent)): \(st.note) | \(st.detail.prefix(200))")
        }
    }
    exit(0)
}
