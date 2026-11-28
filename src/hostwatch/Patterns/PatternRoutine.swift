import Foundation

/// Everyday on this Mac, as the pattern store knows it: what a program has done for days stops counting as a story's
/// evidence (ADR 0023). The aws CLI reading its cache every morning, a build tool's `python -c`, a helper starting a
/// shell: shown in a story, not what makes one.
extension SignatureStore {
    nonisolated static let routineAge: TimeInterval = 3 * 86_400
    nonisolated static let routineCount = 10

    func isRoutine(_ e: ActivityEvent, now: Date = Date()) -> Bool {
        guard !e.signatureKey.isEmpty, let entry = entry(e.signatureKey) else { return false }
        return Self.routine(entry, now: now)
    }

    /// Seen for three days or more and at least ten times, and nothing about it is in doubt: not marked Suspicious or
    /// Dangerous, not sent back to you (a swapped binary, a story it was part of).
    nonisolated static func routine(_ entry: SignatureEntry, now: Date) -> Bool {
        entry.status != .suspicious && entry.status != .dangerous && entry.reopened == nil
            && now.timeIntervalSince(entry.firstSeen) >= routineAge && entry.count >= routineCount
    }
}
