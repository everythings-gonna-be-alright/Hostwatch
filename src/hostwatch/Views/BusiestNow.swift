import SwiftUI

/// "Busiest now: Safari, 340 in 10 min" in the Events status strip: the one thing about the live list that the
/// list itself doesn't say. It observes the feed itself, so the window doesn't redraw for every batch.
struct BusiestNow: View {
    @ObservedObject var feed: LiveFeed
    /// Whether Events is on screen: hidden, it counts nothing.
    let shown: Bool
    @StateObject private var busiest = BusiestProgram()

    var body: some View {
        if shown, let top = busiest.top(feed.history) {
            Text("·")
            Text("Busiest now: \(top.name), \(top.count.formatted()) in 10 min")
                .monospacedDigit().lineLimit(1)
                .help("The program with the most events in the last 10 minutes")
        }
    }
}

/// The program with the most events in the last ten minutes, counted again at most every 3 s: a busy Mac sends
/// batches many times a second, and 5,000 events counted for each of them would be the strip's whole cost.
@MainActor
final class BusiestProgram: ObservableObject {
    private var last: (at: Date, value: (name: String, count: Int)?) = (.distantPast, nil)

    func top(_ events: [ActivityEvent], now: Date = Date()) -> (name: String, count: Int)? {
        guard now.timeIntervalSince(last.at) >= 3 else { return last.value }
        let from = now.timeIntervalSince1970 - 600
        var counts: [String: Int] = [:]
        for e in events where e.ts >= from { counts[e.name, default: 0] += 1 }
        let best = counts.max { ($0.value, $1.key) < ($1.value, $0.key) }.map { (name: $0.key, count: $0.value) }
        last = (now, best)
        return best
    }
}
