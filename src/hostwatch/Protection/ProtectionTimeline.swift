import Foundation

/// The Overview's charts as data: the last 24 hours by hour, or the last 7 days by day, every bucket present (an
/// empty hour is a zero bar, not a gap). Pure, so the cards' numbers and their charts can't disagree: both are sums
/// of the same buckets.
enum ProtectionTimeline {
    enum Range: String, CaseIterable, Sendable {
        case day, week

        var title: String { self == .day ? "24 Hours" : "7 Days" }
        /// "in the last 24 hours": what the cards' numbers cover, said once above them.
        var phrase: String { self == .day ? "the last 24 hours" : "the last 7 days" }
        var unit: Calendar.Component { self == .day ? .hour : .day }
    }

    struct Bucket: Identifiable, Equatable, Sendable {
        let start: Date
        var block = 0
        var ask = 0
        var id: Date { start }
        var total: Int { block + ask }
    }

    /// How long hourly counts are kept: the week view plus the day it starts in.
    static let keepHours = 8 * 24

    /// The empty buckets for a range, oldest first: 24 whole hours ending with the current one, or 7 calendar days
    /// ending today (your time zone, so "Tue" is your Tuesday).
    static func empty(_ range: Range, now: Date, calendar: Calendar = .current) -> [Bucket] {
        switch range {
        case .day:
            let current = Int(now.timeIntervalSince1970 / 3600)
            return (current - 23...current).map { Bucket(start: Date(timeIntervalSince1970: Double($0) * 3600)) }
        case .week:
            let today = calendar.startOfDay(for: now)
            return (0..<7).reversed().compactMap { calendar.date(byAdding: .day, value: -$0, to: today) }.map { Bucket(start: $0) }
        }
    }

    /// Counts that happened at `date` added to the bucket holding it. Anything outside the range is left out.
    static func fill(_ buckets: inout [Bucket], at date: Date, block: Int, ask: Int, range: Range,
                     calendar: Calendar = .current) {
        let start: Date
        switch range {
        case .day: start = Date(timeIntervalSince1970: (date.timeIntervalSince1970 / 3600).rounded(.down) * 3600)
        case .week: start = calendar.startOfDay(for: date)
        }
        guard let i = buckets.firstIndex(where: { $0.start == start }) else { return }
        buckets[i].block += block
        buckets[i].ask += ask
    }

    /// Launches or Files: from the monitor's hourly counts.
    static func buckets(_ hourly: [ProtectionMonitor.HourCount], area: ProtectionArea, range: Range, now: Date = Date(),
                        calendar: Calendar = .current) -> [Bucket] {
        var out = empty(range, now: now, calendar: calendar)
        for h in hourly where h.area == area {
            fill(&out, at: Date(timeIntervalSince1970: Double(h.hour) * 3600), block: h.block, ask: h.ask,
                 range: range, calendar: calendar)
        }
        return out
    }

    /// Network: new destinations by when they were first seen, blocked (or would be) or asked about.
    static func buckets(firstSeen: [(Date, blocked: Bool)], range: Range, now: Date = Date(),
                        calendar: Calendar = .current) -> [Bucket] {
        var out = empty(range, now: now, calendar: calendar)
        for (date, blocked) in firstSeen {
            fill(&out, at: date, block: blocked ? 1 : 0, ask: blocked ? 0 : 1, range: range, calendar: calendar)
        }
        return out
    }

    /// The top of a shared scale: cards side by side compare honestly only when their bars use the same one.
    /// Rounded up to a number worth reading on the axis (7 → 10, 23 → 25, 140 → 200), never below 1.
    static func sharedMax(_ series: [[Bucket]]) -> Int {
        tidy(series.flatMap { $0 }.map(\.total).max() ?? 0)
    }

    static func tidy(_ n: Int) -> Int {
        guard n > 5 else { return max(1, n) }
        var magnitude = 1
        while magnitude * 10 < n { magnitude *= 10 }
        return [1, 2, 2.5, 5, 10].map { Int(Double(magnitude) * $0) }.first { $0 >= n } ?? n
    }
}
