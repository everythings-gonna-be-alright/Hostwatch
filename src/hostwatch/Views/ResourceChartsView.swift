import Charts
import SwiftUI

/// Running Now's charts: CPU, memory and network over the last minutes, as three glass cards above the list. Each
/// stacks the ten programs that used the most and Other, as soft gradient areas. Click a program in a legend to see
/// only it, in every card, and click it again for all. Hovering doesn't float a tooltip over the plot: the card's
/// own number, time and legend show that moment, as Stocks does. The time window glides between samples rather
/// than jumping at each one. In Time Travel they show the minutes up to the playhead, from history.
struct ResourceCharts: View {
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var travel: TimeTravel
    let traveling: Bool
    @AppStorage("resourceChartsMinutes") private var minutes = 10
    @AppStorage("resourceLegendOrder") private var order = ResourceLegendOrder.name.rawValue
    @StateObject private var focus = ResourceFocus()
    @StateObject private var fold = ResourceFold()
    private var shown: Bool { fold.shown }

    private static let cores = ProcessInfo.processInfo.activeProcessorCount
    private static let physical = Double(ProcessInfo.processInfo.physicalMemory)
    /// Programs named: the collector sends the ten busiest by CPU and the ten biggest by memory.
    private static let programs = 10

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            // Folding animates the height it was measured at, clipped from the bottom: the table under it grows in
            // one smooth motion. The cards stay built until the fold ends, then go, so hidden charts cost nothing.
            if shown || fold.rendered {
                let window = Double(minutes) * 60
                let source = traveling ? travel.windowSamples.filter { $0.date <= travel.playhead } : metrics.recent
                // A sample or two before the window too, so the line enters from the left edge rather than inside.
                let from = (source.last?.date ?? Date()).addingTimeInterval(-window - 15)
                let samples = source.filter { $0.date >= from }
                GlassEffectContainer(spacing: 12) {
                    HStack(alignment: .top, spacing: 12) {
                        ResourceCard(model: cpu(samples), window: window, focus: focus)
                        ResourceCard(model: memory(samples), window: window, focus: focus)
                        ResourceCard(model: network(samples), window: window, focus: focus)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { h in
                    if shown, abs(h - fold.height) >= 1 { fold.height = h }
                }
                .frame(height: shown ? (fold.height > 0 ? fold.height : nil) : 0, alignment: .top)
                .clipped()
                .opacity(shown ? 1 : 0)
            }
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, shown ? 12 : 6)
        .background { wash.opacity(shown ? 1 : 0) }
        .animation(.smooth(duration: 0.35), value: focus.program)
    }

    /// Soft pools of the cards' colours behind them, for the glass to pick up.
    private var wash: some View {
        ZStack {
            RadialGradient(colors: [ResourcePalette.cpu.opacity(0.13), .clear], center: UnitPoint(x: 0.12, y: 0.2),
                           startRadius: 0, endRadius: 420)
            RadialGradient(colors: [ResourcePalette.memory.opacity(0.11), .clear], center: UnitPoint(x: 0.5, y: 0.9),
                           startRadius: 0, endRadius: 420)
            RadialGradient(colors: [ResourcePalette.download.opacity(0.11), .clear], center: UnitPoint(x: 0.9, y: 0.25),
                           startRadius: 0, endRadius: 420)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Button { toggle() } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold))
                        .rotationEffect(.degrees(shown ? 90 : 0))
                        .frame(width: 12)
                    Text("Resources").font(.headline)
                    Text(traveling ? "\(minutes) minutes up to the playhead, by program" : "last \(minutes) minutes, by program")
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(shown ? "Hide the charts" : "Show the charts")
            Spacer()
            if shown {
                if let program = focus.program {
                    Button { focus.program = nil } label: {
                        Label("Only \(program)", systemImage: "xmark.circle.fill").lineLimit(1)
                    }
                    .buttonStyle(.glass)
                    .help("Show every program again")
                    .transition(.opacity.combined(with: .scale(scale: 0.9)))
                }
                Picker("Order", selection: $order) {
                    Text("A–Z").tag(ResourceLegendOrder.name.rawValue)
                    Text("By Load").tag(ResourceLegendOrder.load.rawValue)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
                .help("The order of the programs in the legends. The charts stay the same")
                Picker("Minutes", selection: $minutes) {
                    Text("5 min").tag(5); Text("10 min").tag(10); Text("30 min").tag(30)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
        }
    }

    private func toggle() {
        if fold.shown {
            withAnimation(.smooth(duration: 0.3)) { fold.shown = false } completion: { if !fold.shown { fold.rendered = false } }
        } else {
            fold.rendered = true
            withAnimation(.smooth(duration: 0.3)) { fold.shown = true }
        }
    }

    // MARK: Cards

    private func cpu(_ samples: [MetricSample]) -> ResourceCardModel {
        let lines = Self.programLines(ResourceSeries.split(ResourceSeries.cpuRows(samples, cores: Self.cores), limit: Self.programs))
        return ResourceCardModel(title: "CPU", symbol: "cpu", tint: ResourcePalette.cpu, lines: lines,
                                 scale: { peak, _ in min(100, ResourceCardModel.nice(peak, steps: [1, 2, 5, 10, 25, 50, 100])) },
                                 format: { "\(Int($0.rounded()))%" }, detail: "of \(Self.cores) cores",
                                 interval: glide(MetricsStore.interval), empty: empty)
    }

    private func memory(_ samples: [MetricSample]) -> ResourceCardModel {
        let pressure = samples.last.map { $0.pressure >= 2 ? ", pressure \($0.pressureText)" : "" } ?? ""
        let lines = Self.programLines(ResourceSeries.split(ResourceSeries.memoryRows(samples, physical: Self.physical), limit: Self.programs))
        return ResourceCardModel(title: "Memory", symbol: "memorychip", tint: ResourcePalette.memory, lines: lines,
                                 scale: { peak, stacked in stacked ? Self.physical : ResourceCardModel.nice(peak) }, format: Self.bytes,
                                 detail: "of \(Self.bytes(Self.physical))" + pressure, interval: glide(MetricsStore.interval),
                                 empty: empty, note: "Programs share memory, so they can add up to more than is used.")
    }

    /// Received above the line and sent below it, the same programs in the same colours on both sides: chosen by
    /// both directions together.
    private func network(_ samples: [MetricSample]) -> ResourceCardModel {
        let names = ResourceSeries.split(ResourceSeries.trafficRows(samples), limit: Self.programs).names
        let received = ResourceSeries.split(ResourceSeries.trafficRows(samples, direction: 0), names: names)
        let sent = ResourceSeries.split(ResourceSeries.trafficRows(samples, direction: 1), names: names)
        return ResourceCardModel(title: "Network", symbol: "network", tint: ResourcePalette.download,
                                 lines: Self.programLines(received, sent: sent),
                                 scale: { peak, _ in ResourceCardModel.nice(peak) }, format: Rate.text,
                                 detail: "received above the line, sent below", interval: glide(10), cadence: 10,
                                 empty: traveling ? "Nothing recorded here" : "Needs the collector", mirrored: true)
    }

    /// Live, the window glides over a sample's interval. In Time Travel it follows the playhead without delay.
    private func glide(_ seconds: TimeInterval) -> TimeInterval { traveling ? 0 : seconds }

    private var empty: String { traveling ? "Nothing recorded here" : "Measuring…" }

    private static func programLines(_ split: (names: [String], points: [ResourcePoint]),
                                     sent: (names: [String], points: [ResourcePoint])? = nil) -> [ResourceLine] {
        let byName = Dictionary(grouping: split.points, by: \.series)
        let sentByName = Dictionary(grouping: sent?.points ?? [], by: \.series)
        return (split.names + [ResourceSeries.other]).enumerated().map { i, name in
            ResourceLine(name: name, color: i < split.names.count ? ResourcePalette.programs[i] : ResourcePalette.other,
                         points: byName[name] ?? [], sent: sentByName[name] ?? [])
        }
    }

    static func bytes(_ n: Double) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .memory
        f.allowsNonnumericFormatting = false          // "0 KB", not "Zero KB"
        return f.string(fromByteCount: Int64(n))
    }
}

/// The fold's measured height, and whether the cards are still built while it closes.
/// Whether the charts show, kept between launches. Not @AppStorage: its changes reach the view outside the
/// animation they were made in, so the fold snapped instead of sliding.
final class ResourceFold: ObservableObject {
    private static let key = "resourceChartsShown"
    @Published var shown = UserDefaults.standard.object(forKey: key) as? Bool ?? true {
        didSet { UserDefaults.standard.set(shown, forKey: Self.key) }
    }
    @Published var height: CGFloat = 0
    /// The cards stay built while the fold closes, then go.
    @Published var rendered = UserDefaults.standard.object(forKey: key) as? Bool ?? true
}

/// How a legend lists the programs: by name (the default, it holds still while values change), or biggest first.
enum ResourceLegendOrder: String { case name, load }

/// The silences in a chart: between two samples further apart than a few intervals, and from the window's start to
/// a first sample that came late (a relaunch, a collector restart, a Mac asleep).
enum ResourceGaps {
    static func find(_ dates: [Date], from start: Date, cadence: TimeInterval) -> [ClosedRange<Date>] {
        let sorted = Array(Set(dates)).sorted()
        guard let first = sorted.first else { return [] }
        let limit = cadence * 2.5
        var gaps: [ClosedRange<Date>] = []
        if first.timeIntervalSince(start) > limit { gaps.append(start...first) }
        for (a, b) in zip(sorted, sorted.dropFirst()) where b.timeIntervalSince(a) > limit { gaps.append(a...b) }
        return gaps
    }
}

/// A stretch with no data: a grey band crossed by thin diagonal lines, "No data" in it when there is room.
private struct NoDataBand: View {
    var body: some View {
        ZStack {
            Rectangle().fill(Color.primary.opacity(0.05))
            Canvas { ctx, size in
                var path = Path()
                var x = -size.height
                while x < size.width {
                    path.move(to: CGPoint(x: x, y: size.height))
                    path.addLine(to: CGPoint(x: x + size.height, y: 0))
                    x += 7
                }
                ctx.stroke(path, with: .color(.primary.opacity(0.14)), lineWidth: 1)
            }
            .clipped()
            ViewThatFits {
                Text("No data").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.ultraThinMaterial, in: Capsule())
                Color.clear
            }
        }
        .accessibilityLabel("No data")
    }
}

/// How far a chart has slid towards its newest sample, 0 to 1 (no @State macro with the command line tools).
final class ChartSlide: ObservableObject {
    @Published var progress: CGFloat = 1
    /// The newest moment drawn.
    @Published var end: Date?
}

/// The program chosen in a legend, shown alone in every card (no @State macro with the command line tools).
final class ResourceFocus: ObservableObject {
    @Published var program: String?
}

/// The charts' colours: the cards' tints, and a fixed order for the programs. Neighbours in
/// the order differ in hue and lightness. Ten hues can't all stay apart for every kind of colour vision, so each
/// program is named in the legend with its value, and hovering reads them out: colour never carries identity
/// alone. Status colours (green, orange, red) stay out.
enum ResourcePalette {
    static let cpu = Color(nsColor: .systemBlue)
    static let memory = Color(nsColor: .systemPurple)
    static let download = Color(nsColor: .systemTeal)
    static let upload = Color(nsColor: .systemIndigo)
    static let programs: [Color] = [.systemBlue, .systemYellow, .systemPurple, .systemTeal, .systemPink, .systemBrown,
                                    .systemIndigo, .systemMint, .systemCyan, NSColor(srgbRed: 0.78, green: 0.66, blue: 1, alpha: 1)].map { Color(nsColor: $0) }
    static let other = Color(nsColor: .systemGray)
}

/// One series of a card.
struct ResourceLine {
    let name: String
    let color: Color
    let points: [ResourcePoint]
    /// The network's other direction (sent), drawn below the line.
    var sent: [ResourcePoint] = []

    /// Its value nearest a moment.
    func value(at date: Date) -> Double { Self.nearest(points, date) }
    func sentValue(at date: Date) -> Double { Self.nearest(sent, date) }
    /// Both directions together.
    func total(at date: Date) -> Double { value(at: date) + sentValue(at: date) }

    private static func nearest(_ points: [ResourcePoint], _ date: Date) -> Double {
        points.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }?.value ?? 0
    }
}

extension Array where Element == ResourceLine {
    /// The highest point, or the highest stack when the lines are stacked (they are summed at each moment).
    var peak: Double { Self.peak(map(\.points)) }
    /// The same below the line, for the network's sent half.
    var sentPeak: Double { Self.peak(map(\.sent)) }

    private static func peak(_ series: [[ResourcePoint]]) -> Double {
        var sums: [Date: Double] = [:]
        var single = 0.0
        for points in series {
            for p in points { sums[p.date, default: 0] += p.value; single = Swift.max(single, p.value) }
        }
        return Swift.max(single, sums.values.max() ?? 0)
    }
}

/// What a card shows, worked out by the panel.
struct ResourceCardModel {
    let title: String
    let symbol: String
    let tint: Color
    let lines: [ResourceLine]
    /// The scale's top for a peak: `stacked` is the whole stack, else one program alone.
    let scale: (_ peak: Double, _ stacked: Bool) -> Double
    let format: (Double) -> String
    let detail: String
    /// Seconds between samples: the window glides over exactly this long, so it never stops or jumps (0 in Time
    /// Travel, where it doesn't glide).
    let interval: TimeInterval
    /// How often samples come: a longer silence is a gap, drawn hatched rather than bridged by the curve.
    var cadence: TimeInterval = MetricsStore.interval
    let empty: String
    var note: String? = nil
    /// Received above the line and sent below it (each line's `sent`), on a scale as deep as it is high.
    var mirrored = false

    var last: Date? { lines.compactMap { $0.points.last?.date }.max() }

    /// A round top for the scale at or above `peak`: 1, 2 or 5 times a power of ten, or the first of `steps`.
    static func nice(_ peak: Double, steps: [Double]? = nil) -> Double {
        if let steps { return steps.first { $0 >= peak } ?? steps.last ?? max(peak, 1) }
        guard peak > 1 else { return 1 }
        let magnitude = pow(10, floor(log10(peak)))
        return [1, 2, 5, 10].map { $0 * magnitude }.first { $0 >= peak } ?? peak
    }
}

/// One resource: its name, the value now (or at the hovered moment), the chart, and a legend that reads the same
/// moment, biggest first. A program chosen in any legend is drawn alone, as a line over its own gradient.
private struct ResourceCard: View {
    let model: ResourceCardModel
    let window: TimeInterval
    @ObservedObject var focus: ResourceFocus
    @AppStorage("resourceLegendOrder") private var order = ResourceLegendOrder.name.rawValue
    @StateObject private var hover = ChartHover()
    @StateObject private var slide = ChartSlide()

    /// The chosen program's line here, or nil to show them all (also when this card doesn't list it).
    private var focused: ResourceLine? { focus.program.flatMap { name in model.lines.first { $0.name == name } } }
    private var lines: [ResourceLine] { focused.map { [$0] } ?? model.lines }
    private var stacked: Bool { focused == nil }
    private var top: Double { max(model.scale(max(lines.peak, lines.sentPeak), stacked), 0.001) }

    private var moment: Date? {
        guard let selected = hover.selected else { return nil }
        let dates = model.lines.flatMap { $0.points.map(\.date) }
        return dates.min { abs($0.timeIntervalSince(selected)) < abs($1.timeIntervalSince(selected)) }
    }

    private var isEmpty: Bool { Set(model.lines.flatMap { $0.points.map(\.date) }).count < 2 }

    var body: some View {
        let at = moment ?? model.last
        let value = lines.reduce(0) { $0 + (at.map($1.value(at:)) ?? 0) }
        let sentValue = lines.reduce(0) { $0 + (at.map($1.sentValue(at:)) ?? 0) }
        let headline = model.mirrored ? "\(model.format(value)) ↓  \(model.format(sentValue)) ↑" : model.format(value)
        let missing = focus.program != nil && focused == nil
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(model.title, systemImage: model.symbol).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Text(moment.map { $0.formatted(date: .omitted, time: .standard) } ?? "Now")
                    .font(.caption.weight(.medium)).monospacedDigit()
                    .foregroundStyle(moment == nil ? .tertiary : .secondary)
            }
            Text(headline)
                .font(.system(size: 24, weight: .semibold, design: .rounded)).monospacedDigit()
                .lineLimit(1).minimumScaleFactor(0.7)
                .contentTransition(.numericText())
            Text(focused.map { "\($0.name) only" } ?? model.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            plot.frame(height: 100).opacity(missing ? 0.4 : 1)
            legend(at)
            if missing, let program = focus.program {
                Text("\(program) isn't among the busiest ten here.").font(.caption2).foregroundStyle(.tertiary)
            } else if let note = model.note, focused == nil {
                Text(note).font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .glassEffect(.regular.tint((focused?.color ?? model.tint).opacity(0.08)),
                     in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(model.title), \(headline), \(model.detail)")
    }

    @ViewBuilder private var plot: some View {
        if isEmpty {
            Text(model.empty).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        } else {
            sliding
        }
    }

    /// Below the line the fade runs the other way: strongest at the edge, faint at the line.
    private func sentGradient(_ c: Color) -> LinearGradient {
        LinearGradient(colors: stacked ? [c.opacity(0.5), c.opacity(0.85)] : [c.opacity(0.03), c.opacity(0.45)],
                       startPoint: .top, endPoint: .bottom)
    }

    private func gradient(_ c: Color) -> LinearGradient {
        LinearGradient(colors: stacked ? [c.opacity(0.85), c.opacity(0.5)] : [c.opacity(0.45), c.opacity(0.03)],
                       startPoint: .top, endPoint: .bottom)
    }

    /// The chart slides as one picture. It is drawn one sample wider than the card, starting one interval earlier,
    /// and moved left over exactly that interval: when the next sample comes, the picture is redrawn one interval on
    /// and put back, which shows the very same view, so nothing jumps. Animating the chart's own scale instead
    /// redrew every mark on the way, and the old and new shapes blended into a ghost on every other update.
    private var sliding: some View {
        let end = model.last ?? Date()
        let lead = model.interval
        let top = top
        // The time drawn: the newest sample once the slide has caught up with it. A new sample changes it only
        // together with putting the slide back, in one step, so the picture never jumps ahead and back.
        let shown = slide.end ?? end
        return GeometryReader { geo in
            let extra = window > 0 ? geo.size.width * lead / window : 0
            chart(start: shown.addingTimeInterval(-window - lead), end: shown)
                // Swift Charts animates marks to their new places when the data changes: on top of the slide that
                // drew a ghost of the old shapes. The chart redraws plainly, only the slide moves.
                .transaction { $0.animation = nil }
                .frame(width: geo.size.width + extra, height: geo.size.height)
                .offset(x: -extra * slide.progress)
        }
        .clipped()
        .overlay(alignment: .topTrailing) {
            // The scale's top, small and in the corner: every card the same, no axis eating the plot's width.
            Text(model.format(top)).font(.caption2.weight(.medium)).monospacedDigit().foregroundStyle(.tertiary)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(4)
                .allowsHitTesting(false)
        }
        .onChange(of: end, initial: true) { old, new in
            var still = Transaction()
            still.disablesAnimations = true
            // Live, a newer sample: draw up to it, start one interval back, and slide over that interval. Anything
            // else (the first look, Time Travel, a jump back) shows the moment as it is.
            guard lead > 0, slide.end != nil, new > old, new.timeIntervalSince(old) <= lead * 3 else {
                withTransaction(still) { slide.end = new; slide.progress = 1 }
                return
            }
            withTransaction(still) { slide.end = new; slide.progress = 0 }
            DispatchQueue.main.async { withAnimation(.linear(duration: lead)) { slide.progress = 1 } }
        }
    }

    private func chart(start: Date, end: Date) -> some View {
        let step = window <= 300 ? 1 : window <= 600 ? 2 : 5
        let top = top
        let gaps = ResourceGaps.find(model.lines.flatMap { $0.points.map(\.date) }, from: start, cadence: model.cadence)
        // A gap ends one shape and starts the next: each run between gaps is its own series, so the curve never
        // bridges a time nothing was measured.
        let run = { (date: Date) in gaps.filter { $0.upperBound <= date }.count }
        return Chart {
            ForEach(lines, id: \.name) { line in
                ForEach(line.points) { p in
                    AreaMark(x: .value("Time", p.date), y: .value(model.title, p.value),
                             series: .value("Series", "\(line.name)#\(run(p.date))"), stacking: stacked ? .standard : .unstacked)
                        .interpolationMethod(.monotone)
                        .foregroundStyle(gradient(line.color))
                    if !stacked {
                        LineMark(x: .value("Time", p.date), y: .value(model.title, p.value), series: .value("Series", "\(line.name)#\(run(p.date))"))
                            .interpolationMethod(.monotone)
                            .foregroundStyle(line.color)
                            .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    }
                }
                // Sent, below the line: its own series, so it stacks downwards and never joins the received shape.
                ForEach(line.sent) { p in
                    AreaMark(x: .value("Time", p.date), y: .value(model.title, -p.value),
                             series: .value("Series", "\(line.name) sent#\(run(p.date))"), stacking: stacked ? .standard : .unstacked)
                        .interpolationMethod(.monotone)
                        .foregroundStyle(sentGradient(line.color))
                    if !stacked {
                        LineMark(x: .value("Time", p.date), y: .value(model.title, -p.value), series: .value("Series", "\(line.name) sent#\(run(p.date))"))
                            .interpolationMethod(.monotone)
                            .foregroundStyle(line.color)
                            .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    }
                }
            }
            if model.mirrored {
                RuleMark(y: .value(model.title, 0)).foregroundStyle(Color.primary.opacity(0.2)).lineStyle(StrokeStyle(lineWidth: 0.5))
            }
            if let moment {
                RuleMark(x: .value("Time", moment))
                    .foregroundStyle(Color.primary.opacity(0.35))
                    .lineStyle(StrokeStyle(lineWidth: 1))
                if let focused {
                    PointMark(x: .value("Time", moment), y: .value(model.title, focused.value(at: moment)))
                        .symbolSize(40)
                        .foregroundStyle(focused.color)
                    if model.mirrored {
                        PointMark(x: .value("Time", moment), y: .value(model.title, -focused.sentValue(at: moment)))
                            .symbolSize(40)
                            .foregroundStyle(focused.color)
                    }
                }
            }
        }
        .chartXScale(domain: start...end)
        .chartYScale(domain: (model.mirrored ? -top : 0)...top)
        .chartXAxis {
            AxisMarks(values: .stride(by: .minute, count: step)) { _ in
                AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [2, 3])).foregroundStyle(.quaternary)
                AxisValueLabel(format: .dateTime.hour().minute()).foregroundStyle(Color.secondary)
            }
        }
        .chartYAxis {
            AxisMarks(values: model.mirrored ? [-top, 0, top] : [0, top / 2, top]) { _ in
                AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [2, 3])).foregroundStyle(.quaternary)
            }
        }
        .chartPlotStyle { $0.clipped() }
        .chartOverlay { proxy in
            GeometryReader { geo in
                if let frame = proxy.plotFrame.map({ geo[$0] }) {
                    ForEach(gaps, id: \.lowerBound) { gap in
                        if let x1 = proxy.position(forX: gap.lowerBound), let x2 = proxy.position(forX: gap.upperBound) {
                            NoDataBand()
                                .frame(width: max(0, x2 - x1), height: frame.height)
                                .position(x: frame.minX + (x1 + x2) / 2, y: frame.midY)
                        }
                    }
                }
            }
            .allowsHitTesting(false)
        }
        .chartXSelection(value: $hover.selected)
    }

    /// The programs, two to a row, by name or biggest first (as chosen) and Other last: a colour, the name, the value.
    /// Three rows show, the rest scroll, so ten programs don't stretch the card. A click shows that program alone in
    /// every card, another click shows them all again.
    private func legend(_ at: Date?) -> some View {
        let valued = model.lines.map { line in (line: line, value: at.map(line.total(at:)) ?? 0) }
        let programs = valued.filter { $0.line.name != ResourceSeries.other }
        // By name by default: an order that holds still while the values change, so a program stays where you found it.
        let sorted = (order == ResourceLegendOrder.load.rawValue
            ? programs.sorted { ($0.value, $1.line.name) > ($1.value, $0.line.name) }
            : programs.sorted { $0.line.name.localizedStandardCompare($1.line.name) == .orderedAscending })
            + valued.filter { $0.line.name == ResourceSeries.other }
        return LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], alignment: .leading,
                         spacing: 2) {
            ForEach(sorted, id: \.line.name) { item in
                let chosen = focus.program == item.line.name
                let dimmed = focus.program != nil && !chosen
                Button {
                    focus.program = chosen ? nil : item.line.name
                } label: {
                    HStack(spacing: 6) {
                        RoundedRectangle(cornerRadius: 2.5, style: .continuous).fill(item.line.color.gradient)
                            .frame(width: 9, height: 9)
                        Text(item.line.name).lineLimit(1).truncationMode(.middle)
                            .fontWeight(chosen ? .semibold : .regular)
                        Spacer(minLength: 4)
                        Text(model.format(item.value)).foregroundStyle(.secondary).monospacedDigit().lineLimit(1)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background {
                        if chosen { Capsule().fill(item.line.color.opacity(0.2)) }
                    }
                    .contentShape(Capsule())
                    .opacity(dimmed ? 0.45 : 1)
                }
                .buttonStyle(.plain)
                .help(chosen ? "Show every program" : "Show only \(item.line.name)")
            }
        }
        .font(.caption)
        .padding(.trailing, 4)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .animation(.smooth(duration: 0.3), value: sorted.map(\.line.name))
        .modifier(LegendScroll(rows: (sorted.count + 1) / 2))
    }
}

/// Three rows of legend at most: more scroll inside a fixed height, so every card keeps the same size.
private struct LegendScroll: ViewModifier {
    let rows: Int
    static let row: CGFloat = 18
    static let shown = 3

    func body(content: Content) -> some View {
        if rows > Self.shown {
            ScrollView(.vertical) { content }
                .scrollIndicators(.automatic)
                .frame(height: Self.row * CGFloat(Self.shown))
                .mask(LinearGradient(stops: [.init(color: .black, location: 0), .init(color: .black, location: 0.75),
                                             .init(color: .black.opacity(0.25), location: 1)],
                                     startPoint: .top, endPoint: .bottom))
        } else {
            content.frame(minHeight: Self.row * CGFloat(Self.shown), alignment: .top)
        }
    }
}
