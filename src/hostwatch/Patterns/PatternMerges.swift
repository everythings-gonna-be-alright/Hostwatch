import Foundation

// MARK: - Combined patterns

/// A shared pattern you made from similar ones: events whose own pattern it matches use it instead.
struct PatternMerge: Codable, Equatable {
    var kind: EventKind
    var process: String          // glob
    var pattern: String          // glob
    var created = Date()
    var automatic = false        // folded by tidying (routine Safe noise), not by you

    init(kind: EventKind, process: String, pattern: String, created: Date = Date(), automatic: Bool = false) {
        (self.kind, self.process, self.pattern, self.created, self.automatic) = (kind, process, pattern, created, automatic)
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(EventKind.self, forKey: .kind)
        process = try c.decode(String.self, forKey: .process)
        pattern = try c.decode(String.self, forKey: .pattern)
        created = try c.decodeIfPresent(Date.self, forKey: .created) ?? Date()
        automatic = try c.decodeIfPresent(Bool.self, forKey: .automatic) ?? false
    }

    var key: String { "\(kind.rawValue)|\(process)|\(pattern)" }
}

/// The combined patterns, readable from any thread (events get their pattern as they're decoded).
final class PatternMerges: @unchecked Sendable {
    static let shared = PatternMerges()
    private let lock = NSLock()
    /// By "kind|program" for an exact program (most, and every fold); the rest scanned.
    private var exact: [String: [PatternMerge]] = [:]
    private var wild: [PatternMerge] = []

    func set(_ merges: [PatternMerge]) {
        var exact: [String: [PatternMerge]] = [:], wild: [PatternMerge] = []
        for m in merges {
            if m.process.contains("*") || m.process.contains("?") { wild.append(m) }
            else { exact["\(m.kind.rawValue)|\(m.process.lowercased())", default: []].append(m) }
        }
        lock.lock(); (self.exact, self.wild) = (exact, wild); lock.unlock()
    }

    func apply(kind: EventKind, process: String, pattern: String) -> (String, String)? {
        lock.lock(); defer { lock.unlock() }
        if exact.isEmpty && wild.isEmpty { return nil }
        let candidates = (exact["\(kind.rawValue)|\(process.lowercased())"] ?? []) + wild
        return candidates.first { $0.kind == kind && Glob.match($0.process, process) && Glob.match($0.pattern, pattern) }
            .map { ($0.process, $0.pattern) }
    }
}
