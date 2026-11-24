import SwiftUI

/// The Patterns footer's line when nothing else has news: where to start (the program with the most New patterns)
/// and the newest pattern. Worked out again only when the patterns change or the minute turns (8,000 patterns,
/// and the window's body runs often).
@MainActor
final class PatternHint: ObservableObject {
    private var last: (revision: Int, minute: Int, line: String)?
    private static let ago: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f
    }()

    func line(_ store: SignatureStore, now: Date = Date()) -> String {
        let minute = Int(now.timeIntervalSince1970 / 60)              // "3 minutes ago" moves on by itself
        if let last, last.revision == store.revision, last.minute == minute { return last.line }
        let made = Self.make(Array(store.entriesByKey.values), now: now)
        last = (store.revision, minute, made)
        return made
    }

    static func make(_ entries: [SignatureEntry], now: Date) -> String {
        guard !entries.isEmpty else { return "Nothing learned yet. Patterns appear as programs run." }
        var undecided: [String: Int] = [:]
        for e in entries where e.status == .unclassified { undecided[e.exampleName, default: 0] += 1 }
        let newest = entries.max { $0.firstSeen < $1.firstSeen }!
        let when = ago.localizedString(for: min(newest.firstSeen, now), relativeTo: now)
        let latest = "Newest: \(newest.exampleName), \(when)"
        guard let most = undecided.max(by: { ($0.value, $1.key) < ($1.value, $0.key) }) else { return latest }
        return "Most to decide: \(most.key), \(most.value.formatted()) pattern\(most.value == 1 ? "" : "s") · \(latest)"
    }
}
