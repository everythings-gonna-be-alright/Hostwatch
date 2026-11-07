import Foundation
import SwiftUI

// MARK: - Timeline bar

/// The floating Liquid Glass timeline: activity histogram, markers, playhead and controls.
struct TimelineBar: View {
    @ObservedObject var travel: TimeTravel
    /// Pointer over the scrubber, for the time label. Local: publishing it from the model re-rendered the
    /// whole window on every mouse move.
    @StateObject private var pointer = ScrubberPointer()
    private var hover: CGFloat? { pointer.x }

    private static let dayTime: Date.FormatStyle = .dateTime.weekday(.abbreviated).day().month(.abbreviated)
        .hour().minute()
    private static let clock: Date.FormatStyle = .dateTime.hour().minute().second()

    var body: some View {
        VStack(spacing: 8) {
            if let range = travel.range {
                scrubber(range)
                if travel.cpuLane.contains(where: { $0 != nil }) { lanes }
                HStack {
                    Text(range.lowerBound, format: Self.dayTime)
                    Spacer()
                    Text(range.upperBound, format: Self.dayTime)
                }
                .font(.system(size: 10).monospacedDigit())
                .foregroundStyle(.secondary)
            } else {
                Text(travel.loading ? "Reading history…" : "No recorded history yet. Recording is in Settings ▸ History.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 56)
            }
            controls
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .padding(.horizontal, 14)
        .padding(.bottom, 12)
    }

    // MARK: Scrubber

    private func scrubber(_ range: ClosedRange<Date>) -> some View {
        GeometryReader { geo in
            let width = geo.size.width
            let total = max(1, range.upperBound.timeIntervalSince(range.lowerBound))
            let x = { (d: Date) -> CGFloat in CGFloat(d.timeIntervalSince(range.lowerBound) / total) * width }
            let date = { (x: CGFloat) -> Date in range.lowerBound.addingTimeInterval(Double(min(max(x, 0), width) / width) * total) }
            ZStack(alignment: .topLeading) {
                Canvas { ctx, size in
                    let bars = travel.activity
                    guard !bars.isEmpty else { return }
                    let w = size.width / CGFloat(bars.count)
                    let base = size.height - 4
                    for (i, v) in bars.enumerated() where v > 0 {
                        let h = max(2, CGFloat(v) * (base - 12))
                        let rect = CGRect(x: CGFloat(i) * w + 0.5, y: base - h, width: max(1, w - 1), height: h)
                        ctx.fill(Path(roundedRect: rect, cornerRadius: min(1.5, w / 2)),
                                 with: .color(.accentColor.opacity(0.35)))
                    }
                    // The shown slice.
                    let a = x(travel.windowStart), b = x(travel.playhead)
                    ctx.fill(Path(roundedRect: CGRect(x: a, y: 8, width: max(2, b - a), height: base - 8), cornerRadius: 3),
                             with: .color(.accentColor.opacity(0.18)))
                    // Search hits along the bottom, so you see when the matches happened.
                    if travel.showingSearch {
                        var ticks = Path()
                        var lastX = -1.0
                        for e in travel.searchHits where e.ts > 0 {
                            let hx = x(Date(timeIntervalSince1970: e.ts))
                            if abs(hx - lastX) < 1 { continue }       // one tick per point is enough
                            lastX = hx
                            ticks.addRect(CGRect(x: hx - 0.5, y: base - 10, width: 1, height: 10))
                        }
                        ctx.fill(ticks, with: .color(.primary.opacity(0.7)))
                    }
                    // Story and new-domain marks along the top.
                    for m in travel.markers {
                        let color: Color = m.kind == .dangerous ? .red : m.kind == .suspicious ? .orange : .purple
                        let r: CGFloat = m.kind == .newDomain ? 2.5 : 3.5
                        ctx.fill(Path(ellipseIn: CGRect(x: x(m.date) - r, y: 4 - r, width: r * 2, height: r * 2)),
                                 with: .color(color))
                    }
                    // Playhead.
                    ctx.fill(Path(roundedRect: CGRect(x: b - 1, y: 0, width: 2, height: size.height), cornerRadius: 1),
                             with: .color(.accentColor))
                }
                if let hover {
                    Text(date(hover), format: Self.clock)
                        .font(.system(size: 10, weight: .medium).monospacedDigit())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.regularMaterial, in: Capsule())
                        .offset(x: min(max(hover - 28, 0), width - 56), y: -18)
                        .allowsHitTesting(false)
                }
            }
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0).onChanged { g in
                travel.pause()
                travel.move(to: snapped(date(g.location.x), x: x, at: g.location.x))
            })
            .onContinuousHover { phase in
                if case .active(let p) = phase { pointer.x = p.x } else { pointer.x = nil }
            }
            .help(markerHelp(near: hover, x: x) ?? "Drag to travel through recorded activity")
        }
        .frame(height: 64)
        .accessibilityElement()
        .accessibilityLabel("Timeline")
        .accessibilityValue(Text(travel.playhead, format: Self.dayTime))
        .accessibilityAdjustableAction { direction in travel.step(direction == .increment ? 1 : -1) }
    }

    /// CPU and memory over the whole recording, on the same time axis as the bars.
    private var lanes: some View {
        HStack(spacing: 8) {
            ZStack {
                Sparkline(values: travel.memLane, color: .green, width: nil, height: 22)
                Sparkline(values: travel.cpuLane, color: .blue, width: nil, height: 22)
            }
            .frame(maxWidth: .infinity)
        }
        .overlay(alignment: .topLeading) {
            HStack(spacing: 8) {
                Label("CPU", systemImage: "circle.fill").foregroundStyle(.blue)
                Label("Memory", systemImage: "circle.fill").foregroundStyle(.green)
            }
            .font(.system(size: 9, weight: .medium))
            .labelStyle(.titleAndIcon)
            .imageScale(.small)
            .padding(.leading, 2)
            .offset(y: -2)
            .allowsHitTesting(false)
        }
        .accessibilityLabel("CPU and memory over time")
    }

    /// Clicking near a marker lands just after it, so its activity is in the slice.
    private func snapped(_ date: Date, x: (Date) -> CGFloat, at position: CGFloat) -> Date {
        guard let m = travel.markers.min(by: { abs(x($0.date) - position) < abs(x($1.date) - position) }),
              abs(x(m.date) - position) < 6 else { return date }
        return m.date.addingTimeInterval(min(travel.span / 2, 60))
    }

    private func markerHelp(near position: CGFloat?, x: (Date) -> CGFloat) -> String? {
        guard let position,
              let m = travel.markers.min(by: { abs(x($0.date) - position) < abs(x($1.date) - position) }),
              abs(x(m.date) - position) < 6 else { return nil }
        return "\(m.title) · \(m.date.formatted(date: .omitted, time: .shortened))"
    }

    // MARK: Controls

    /// Transport icons get room inside their circles; play is a little larger than the steps.
    private func transportIcon(_ name: String, size: CGFloat = 10, frame: CGFloat = 15) -> some View {
        Image(systemName: name)
            .font(.system(size: size, weight: .semibold))
            .frame(width: frame, height: frame)
    }

    private var controls: some View {
        HStack(spacing: 10) {
            HStack(spacing: 2) {
                Button { travel.step(-1) } label: { transportIcon("backward.fill") }
                    .help("Earlier (⌘[)")
                Button { travel.togglePlay() } label: {
                    transportIcon(travel.playing ? "pause.fill" : "play.fill", size: 13, frame: 21)
                }
                .help(travel.playing ? "Pause" : "Play history forward")
                .disabled(travel.range == nil)
                Button { travel.step(1) } label: { transportIcon("forward.fill") }
                    .help("Later (⌘])")
            }
            .buttonStyle(.glass)
            .buttonBorderShape(.circle)
            .controlSize(.regular)
            Menu {
                Picker("Speed", selection: $travel.speed) {
                    ForEach(TimeTravel.speeds, id: \.1) { Text($0.0).tag($0.1) }
                }
                .pickerStyle(.inline)
            } label: {
                Text(TimeTravel.speeds.first { $0.1 == travel.speed }?.0 ?? "")
                    .monospacedDigit()
            }
            .menuStyle(.button)
            .buttonStyle(.glass)
            .fixedSize()
            .help("Playback speed")
            DatePicker("", selection: Binding(get: { travel.playhead }, set: { travel.pause(); travel.move(to: $0) }),
                       in: (travel.range ?? Date.distantPast...Date.distantFuture),
                       displayedComponents: [.date, .hourAndMinute])
                .labelsHidden()
                .datePickerStyle(.compact)
                .fixedSize()
                .help("Jump to a date and time")
            Picker("Window", selection: $travel.span) {
                ForEach(TimeTravel.spans, id: \.1) { Text($0.0).tag($0.1) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("How much time the event list shows, ending at the playhead")
            if travel.loading { ProgressView().controlSize(.small) }
            Spacer(minLength: 8)
            Button { travel.exit() } label: { Label("Return to Live", systemImage: "dot.radiowaves.left.and.right") }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.cancelAction)
                .help("Back to the live stream (Esc)")
        }
        .controlSize(.small)
    }
}

/// The pointer's place over the scrubber, owned by the timeline bar alone.
final class ScrubberPointer: ObservableObject {
    @Published var x: CGFloat?
}

/// Above the event list while traveling: which slice is shown, and the way back.
struct TimeTravelBanner: View {
    @ObservedObject var travel: TimeTravel
    let shown: Int
    var noun = "events"

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "clock.arrow.circlepath").foregroundStyle(.tint)
            Text("History").fontWeight(.semibold)
            Text("\(travel.windowStart.formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated).hour().minute().second())) – \(travel.playhead.formatted(.dateTime.hour().minute().second()))")
                .monospacedDigit()
            Text("·").foregroundStyle(.secondary)
            Text(noun == "events" && (travel.clipped || travel.capped) ? "newest \(shown) events" : "\(shown) \(noun)")
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .help(noun != "events" ? "" : travel.capped ? "This window is very busy; only its newest part is shown. Choose a shorter window for the rest."
                      : travel.clipped ? "Older events of this window load as you scroll to the end of the list." : "")
            if noun == "events" && travel.loadingMore { ProgressView().controlSize(.mini) }
            if let s = travel.sampleAtPlayhead {
                Text("·").foregroundStyle(.secondary)
                Text("CPU \(Int(s.cpu.rounded()))% · Memory \(Int((s.mem * 100).rounded()))%"
                     + (s.top?.first.map { " · busiest: \($0.name) \(Int($0.cpu.rounded()))%" } ?? ""))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .help("Resource use at the playhead")
            }
            Spacer()
        }
        .font(.system(size: 12))
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .background(Color.accentColor.opacity(0.08))
    }
}

/// `Hostwatch --time-travel-probe [dir]`: times the overview and a few slices on real history.
func runTimeTravelProbe(_ path: String?) -> Never {
    let dir = path.map { URL(fileURLWithPath: $0) } ?? HistoryRecorder.defaultDirectory
    let archive = HistoryArchive(directory: dir)
    let clock = ContinuousClock()
    var segments: [HistoryArchive.Segment] = []
    print("segments:", clock.measure { segments = archive.segments() }, "\(segments.count) files")
    guard let range = HistoryArchive.range(of: segments) else { print("no history"); exit(1) }
    print("range:", range.lowerBound, "–", range.upperBound)
    var bars: [Double] = []
    print("activity (240 buckets):", clock.measure { bars = archive.activity(segments, over: range, buckets: 240) })
    print("busiest bucket: \(Int((bars.max() ?? 0) / 1000)) KB, empty buckets: \(bars.filter { $0 == 0 }.count)")
    let mid = range.lowerBound.addingTimeInterval(range.upperBound.timeIntervalSince(range.lowerBound) / 2)
    for span in [60.0, 300, 900, 3600] {
        var result: (events: [ActivityEvent], clipped: Bool) = ([], false)
        let t = clock.measure { result = archive.events(segments, from: mid.addingTimeInterval(-span), to: mid) }
        print("slice \(Int(span / 60)) min:", t, "\(result.events.count) events", result.clipped ? "(clipped)" : "")
    }
    // What Time Travel reads first: one page.
    var page: (events: [ActivityEvent], clipped: Bool) = ([], false)
    let pt = clock.measure { page = archive.events(segments, from: mid.addingTimeInterval(-3600), to: mid, maxBytes: TimeTravel.pageBytes) }
    print("first page of 1 hour:", pt, "\(page.events.count) events", page.clipped ? "(more on scroll)" : "")
    // What counts toward the history size limit (read only).
    let kept = HistoryFiles.kept(in: dir, current: nil, today: MetricsArchive.dayName(Date()))
    func sum(_ prefix: String) -> String {
        HistoryRecorder.format(kept.filter { $0.url.lastPathComponent.hasPrefix(prefix) }.reduce(0) { $0 + $1.bytes })
    }
    print("counted toward the limit: \(HistoryRecorder.format(kept.reduce(0) { $0 + $1.bytes }))",
          "(activity \(sum("activity-")), metrics \(sum("metrics-")), processes \(sum("processes-")))")
    // Running Now at moments 20 s apart over the newest recorded process lists.
    let processes = ProcessHistory(directory: dir)
    let cache = ProcessDayCache()
    if let day = processes.archive.days().last {
        let lines = cache.lines(day: day, archive: processes.archive)
        if lines.count >= 2 {
            let from = lines[lines.count - 2].t - 30
            for step in 0..<5 {
                let at = Date(timeIntervalSince1970: from + Double(step) * 20)
                var snap: ProcessHistory.Snapshot?
                let t = clock.measure { snap = processes.snapshot(at: at, cache: cache) }
                let busiest = snap?.processes.max { ($0.cpu ?? 0) < ($1.cpu ?? 0) }
                let total = snap?.processes.reduce(0) { $0 + $1.cpuTime } ?? 0
                print("processes at +\(step * 20) s:", t, "\(snap?.processes.count ?? 0) running,",
                      "CPU time \(Int(total)) s, busiest \(busiest?.name ?? "–") \(Int(busiest?.cpu ?? 0))%")
                let writer = snap?.processes.max { ($0.writeRate ?? 0) < ($1.writeRate ?? 0) }
                print("   writing most: \(writer?.name ?? "–") pid \(writer?.pid ?? 0) \(writer?.args.prefix(60) ?? "") \(Int((writer?.writeRate ?? 0) / 1000)) KB/s")
            }
        }
    }
    // Search all history: a common word (stops at the cap) and one that is rarely there (reads everything).
    for query in ["curl", "zz-not-recorded-zz"] {
        var hits = 0, back: Date?
        var capped = false
        let t = clock.measure {
            capped = archive.search(segments, query: query, limit: TimeTravel.maxSearchHits, stop: { false }) {
                hits += $0.hits.count; back = $0.reachedBack
            }
        }
        print("search \"\(query)\":", t, "\(hits) hits", capped ? "(capped)" : "", "back to", back.map { "\($0)" } ?? "–")
    }
    exit(0)
}
