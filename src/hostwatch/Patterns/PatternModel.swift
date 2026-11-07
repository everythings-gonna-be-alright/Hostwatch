import AppKit
import Combine
import Foundation

// MARK: - Signature model

enum SignatureStatus: String, Codable, CaseIterable {
    case unclassified, safe, suspicious, dangerous

    var title: String { rawValue.capitalized }

    var symbol: String {
        switch self {
        case .unclassified: return "questionmark.circle"
        case .safe: return "checkmark.shield"
        case .suspicious: return "exclamationmark.triangle"
        case .dangerous: return "xmark.octagon"
        }
    }

    var nsColor: NSColor {
        switch self {
        case .unclassified: return .systemGray
        case .safe: return .systemGreen
        case .suspicious: return .systemOrange
        case .dangerous: return .systemRed
        }
    }

    init(verdict: Verdict) {
        switch verdict {
        case .safe: self = .safe
        case .suspicious: self = .suspicious
        case .dangerous: self = .dangerous
        case .unknown: self = .unclassified
        }
    }
}

/// The one "Show" filter: the HUD, the Events tab and the Patterns tab all use it.
/// Show: three questions. All; New (not decided yet); Important (Suspicious and Dangerous, plus new
/// high-risk). The earlier "Not Safe" (New + Important) and "Suspicious" (inside Important) map onto them.
enum SignatureFilter: String, CaseIterable {
    case all, unclassified, important

    init?(stored: String) {
        switch stored {
        case "hideSafe": self = .unclassified
        case "flagged": self = .important
        default: self.init(rawValue: stored)
        }
    }

    var title: String {
        switch self {
        case .all: return "All Activity"
        case .unclassified: return "Only New (not reviewed)"
        case .important: return "Only Important (flagged + new high-risk)"
        }
    }

    /// Short name for the scope bar.
    var short: String {
        switch self {
        case .all: return "All"
        case .unclassified: return "New"
        case .important: return "Important"
        }
    }

    var symbol: String {
        switch self {
        case .all: return "square.stack"
        case .unclassified: return "questionmark.circle"
        case .important: return "exclamationmark.triangle"
        }
    }

    var explanation: String {
        switch self {
        case .all: return "Everything, decided or not"
        case .unclassified: return "What hasn't been decided yet"
        case .important: return "Suspicious and Dangerous, plus new high-risk patterns"
        }
    }

    /// `reviewed`: you decided it (the pattern or a whole-process rule). "New" = not reviewed by
    /// you: unclassified, plus Suspicious/Dangerous that only Claude or the baseline decided.
    func admits(_ status: SignatureStatus, risk: PatternRisk, reviewed: Bool) -> Bool {
        let flagged = status == .suspicious || status == .dangerous
        switch self {
        case .all: return true
        case .unclassified: return status == .unclassified || flagged && !reviewed
        case .important: return flagged || status == .unclassified && risk == .high
        }
    }
}

extension SignatureEntry {
    /// Seen often enough, over enough time, to call it regular behaviour: only such patterns may teach a Safe rule.
    /// Five sightings, the first and last at least an hour apart (a loop running something 50 times in a second
    /// isn't regular; an app used through a session is).
    static let regularCount = 5
    static let regularSpan: TimeInterval = 3600
    var isRegular: Bool { count >= Self.regularCount && lastSeen.timeIntervalSince(firstSeen) >= Self.regularSpan }
}

struct SignatureEntry: Codable, Identifiable {
    var id: String              // signature key
    var kind: EventKind
    var process: String         // normalized actor (exec: parent)
    var pattern: String         // normalized target
    var count: Int
    var risk: PatternRisk = .normal
    var firstSeen: Date
    var lastSeen: Date
    var status: SignatureStatus
    var source: String?         // "you", "claude", "baseline"
    var note: String?
    // Last concrete example, for evidence and Ask Claude.
    var exampleName: String
    var examplePid: Int
    var exampleProc: String
    var exampleTarget: String
    var exampleExtra: String
    var exampleParent: String
    var exampleHost: String?
    var exampleHostSource: String?
    /// What an AI (on-device or Claude) suggests for this New pattern; you accept it or decide yourself.
    var suggestion: AISuggestion? = nil
    /// A decided pattern sent back to you because something about it changed ("part of a story: …"). Until you
    /// decide again, no rule, baseline or AI decides it for you.
    var reopened: String? = nil

    var exampleEvent: ActivityEvent {
        ActivityEvent(kind: kind, time: "", pid: examplePid, ppid: 0, name: exampleName,
                      proc: exampleProc, target: exampleTarget, extra: exampleExtra, parent: exampleParent,
                      host: exampleHost ?? "", hostSource: exampleHostSource ?? "")
    }
}

/// An AI verdict waiting for you: AI suggests, you decide (unless you let it accept by itself).
struct AISuggestion: Codable, Equatable {
    var status: SignatureStatus
    var source: String          // "on-device" or "claude"
    var note: String?
    var date = Date()

    var engineName: String { source == "claude" ? "Claude" : "on-device AI" }
}

// MARK: - Risk

/// How much a pattern deserves a human look. Routine patterns are auto-marked Safe locally
/// (no Claude call); high-risk ones are reviewed first and can be shown alone.
enum PatternRisk: Int, Codable, Comparable, CaseIterable {
    case routine, normal, high

    static func < (a: PatternRisk, b: PatternRisk) -> Bool { a.rawValue < b.rawValue }
}

/// Everything derived from one event: its pattern identity plus a first, local risk opinion.
struct Signature {
    var key: String
    var process: String
    var pattern: String
    var risk: PatternRisk
    var reason: String
}

// MARK: - Normalization

// MARK: - Display helpers

/// "claude/#.#.#" rather than "#.#.#" for version-named executables.
func displayProcessName(_ path: String) -> String {
    let parts = path.split(separator: "/")
    guard let last = parts.last else { return path }
    if last.contains(where: \.isLetter) || parts.count < 3 { return String(last) }
    return "\(parts[parts.count - 3])/\(last)"
}
