import SwiftUI

/// The map's time travel: Live, Play through the last 24 hours, an hour slider over the hours' activity, and Only
/// What Changed. source: docs/adr/0017-network-map.md
struct NetworkMapTimeline: View {
    @ObservedObject var store: NetworkMapStore
    @ObservedObject var state: NetworkMapViewState

    private static let hours = 24

    var body: some View {
        let _ = store.revision
        let now = Date()
        let last = MapTime.hour(now)
        let bars = store.activity(hours: Self.hours, now: now)
        let top = max(1, bars.max() ?? 1)
        let picked = state.hour.map { $0 - (last - Self.hours + 1) }
        HStack(spacing: 12) {
            Button { state.stop(); state.hour = nil } label: { Label("Live", systemImage: "dot.radiowaves.left.and.right") }
                .buttonStyle(.glass)
                .tint(state.hour == nil ? .green : nil)
                .help("Back to now")
            Button { state.playing ? state.stop() : state.play() } label: {
                Label(state.playing ? "Pause" : "Replay Day", systemImage: state.playing ? "pause.fill" : "play.fill")
            }
            .buttonStyle(.glass)
            .help("The last 24 hours, an hour a second")
            // Activity per hour, the replayed one in the text colour; click a bar to go there.
            GeometryReader { geo in
                let w = geo.size.width / CGFloat(Self.hours)
                HStack(alignment: .bottom, spacing: 0) {
                    ForEach(0..<Self.hours, id: \.self) { i in
                        let h = max(2, CGFloat(bars[i]) / CGFloat(top) * (geo.size.height - 2))
                        Button { state.stop(); state.hour = last - Self.hours + 1 + i } label: {
                            VStack(spacing: 0) {
                                Spacer(minLength: 0)
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(picked == i ? Color.primary : Color.secondary.opacity(state.hour == nil ? 0.45 : 0.3))
                                    .frame(width: max(2, w - 2), height: h)
                            }
                            .frame(width: w, height: geo.size.height)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("\(hourText(last - Self.hours + 1 + i)): \(bars[i]) connections and tries")
                        .accessibilityLabel("\(hourText(last - Self.hours + 1 + i)), \(bars[i]) connections and tries")
                        .accessibilityAddTraits(picked == i ? [.isButton, .isSelected] : .isButton)
                    }
                }
            }
            .frame(height: 26)
            Text(state.hour.map { "\(hourText($0))–\(hourText($0 + 1))" } ?? "Live")
                .font(.system(size: 12, weight: .medium)).monospacedDigit()
                .frame(width: 92, alignment: .leading)
            Toggle("Only What Changed", isOn: $state.changedOnly)
                .toggleStyle(.switch)
                .help("Only connections, devices and tries that weren't there in the 7 days before")
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.bottom, 7)
    }

    private func hourText(_ hour: Int) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f.string(from: MapTime.date(hour))
    }
}
