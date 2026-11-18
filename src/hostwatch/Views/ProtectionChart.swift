import Accessibility
import Charts
import SwiftUI

/// One Protection area over the chosen range: what was stopped (or would be) in red at the foot of each bar, what was
/// asked about (or would be) in a calm blue above it. Red and blue stay apart for every kind of colour vision, and a
/// question is pending rather than alarming. Each bucket stands on a faint track the full height of the scale, so a
/// quiet hour still reads as an hour. The card's two figures above name both colours, so the chart has no legend.
struct ProtectionChart: View {
    let buckets: [ProtectionTimeline.Bucket]
    let range: ProtectionTimeline.Range
    let stopLabel: String
    let askLabel: String
    /// The top of the scale.
    let yMax: Int
    /// The plot's height: the Overview gives a tall window's spare height to its charts.
    var height: CGFloat = 120
    @StateObject private var hover = ChartHover()

    static let stop = Color(nsColor: .systemRed)
    static let ask = Color(nsColor: .systemBlue)

    private static func fill(_ color: Color, dim: Bool) -> LinearGradient {
        LinearGradient(colors: [color.opacity(dim ? 0.35 : 0.95), color.opacity(dim ? 0.18 : 0.55)],
                       startPoint: .top, endPoint: .bottom)
    }

    private var empty: Bool { buckets.allSatisfy { $0.total == 0 } }

    /// Narrower bars for the many hours of a day, wider for the seven days of a week.
    private var barWidth: MarkDimension { .ratio(range == .week ? 0.42 : 0.62) }

    var body: some View {
        let selected = hover.selected.flatMap { bucket(at: $0) }?.start
        Chart {
            ForEach(buckets) { b in
                let dim = selected != nil && selected != b.start
                BarMark(x: .value("Time", b.start, unit: range.unit), yStart: .value("Count", 0),
                        yEnd: .value("Count", yMax), width: barWidth)
                    .foregroundStyle(Color.primary.opacity(0.05))
                    .clipShape(Capsule())
                    .accessibilityHidden(true)
                if b.ask > 0 {
                    BarMark(x: .value("Time", b.start, unit: range.unit), yStart: .value("Count", 0),
                            yEnd: .value("Count", b.block + b.ask), width: barWidth)
                        .foregroundStyle(Self.fill(Self.ask, dim: dim))
                        .clipShape(Capsule())
                        .accessibilityLabel(Self.label(b.start, range))
                        .accessibilityValue("\(b.ask) \(askLabel)")
                }
                if b.block > 0 {
                    BarMark(x: .value("Time", b.start, unit: range.unit), yStart: .value("Count", 0),
                            yEnd: .value("Count", b.block), width: barWidth)
                        .foregroundStyle(Self.fill(Self.stop, dim: dim))
                        .clipShape(Capsule())
                        .accessibilityLabel(Self.label(b.start, range))
                        .accessibilityValue("\(b.block) \(stopLabel)")
                }
            }
            if let selected, let b = bucket(at: selected) {
                RuleMark(x: .value("Time", b.start, unit: range.unit))
                    .foregroundStyle(.clear)
                    .annotation(position: .top, overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) { readout(b) }
            }
        }
        .chartLegend(.hidden)
        .chartYScale(domain: 0...yMax)
        .chartXAxis {
            switch range {
            case .day:
                AxisMarks(values: .stride(by: .hour, count: 6)) { _ in
                    AxisValueLabel(format: .dateTime.hour(), centered: true).foregroundStyle(Color.secondary)
                }
            case .week:
                AxisMarks(values: .stride(by: .day)) { _ in
                    AxisValueLabel(format: .dateTime.weekday(.abbreviated), centered: true).foregroundStyle(Color.secondary)
                }
            case .month:
                AxisMarks(values: .stride(by: .day, count: 7)) { _ in       // a label a week, the bars stay daily
                    AxisValueLabel(format: .dateTime.month(.abbreviated).day(), centered: true).foregroundStyle(Color.secondary)
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .trailing, values: [yMax]) { _ in          // the top only: the tracks show the floor
                AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [2, 3])).foregroundStyle(.quaternary)
                AxisValueLabel().foregroundStyle(Color.secondary)
            }
        }
        .chartXSelection(value: $hover.selected)
        .overlay {
            if empty {
                Text("Nothing in \(range.phrase)").font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(height: height)
        .accessibilityChartDescriptor(ProtectionChartDescriptor(buckets: buckets, range: range, stopLabel: stopLabel,
                                                                askLabel: askLabel, yMax: yMax))
    }

    private func bucket(at date: Date) -> ProtectionTimeline.Bucket? {
        buckets.min { abs($0.start.timeIntervalSince(date)) < abs($1.start.timeIntervalSince(date)) }
    }

    /// "05:00", "Tuesday 10" or "Nov 10": how a bucket is named in the readout and to VoiceOver.
    static func label(_ start: Date, _ range: ProtectionTimeline.Range) -> String {
        switch range {
        case .day: start.formatted(.dateTime.hour().minute())
        case .week: start.formatted(.dateTime.weekday(.wide).day())
        case .month: start.formatted(.dateTime.month(.abbreviated).day())
        }
    }

    /// The bucket's numbers in text ink: the colours beside them say which is which.
    private func readout(_ b: ProtectionTimeline.Bucket) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(Self.label(b.start, range)).font(.caption.weight(.semibold))
            HStack(spacing: 4) { Circle().fill(Self.stop).frame(width: 6, height: 6); Text("\(b.block) \(stopLabel)") }
            HStack(spacing: 4) { Circle().fill(Self.ask).frame(width: 6, height: 6); Text("\(b.ask) \(askLabel)") }
        }
        .font(.caption.monospacedDigit())
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(.regularMaterial))
    }
}

/// The hovered bucket (no @State macro with the command line tools).
final class ChartHover: ObservableObject {
    @Published var selected: Date?
}

/// The chart for VoiceOver's Audio Graphs: both series over the buckets, on the shared scale.
struct ProtectionChartDescriptor: AXChartDescriptorRepresentable {
    let buckets: [ProtectionTimeline.Bucket]
    let range: ProtectionTimeline.Range
    let stopLabel: String
    let askLabel: String
    let yMax: Int

    func makeChartDescriptor() -> AXChartDescriptor {
        let names = buckets.map { ProtectionChart.label($0.start, range) }
        let x = AXCategoricalDataAxisDescriptor(title: range == .day ? "Hour" : "Day", categoryOrder: names)
        let y = AXNumericDataAxisDescriptor(title: "Count", range: 0...Double(yMax), gridlinePositions: []) { "\(Int($0))" }
        func series(_ name: String, _ value: (ProtectionTimeline.Bucket) -> Int) -> AXDataSeriesDescriptor {
            AXDataSeriesDescriptor(name: name, isContinuous: false, dataPoints: zip(names, buckets).map {
                AXDataPoint(x: $0.0, y: Double(value($0.1)))
            })
        }
        let stopped = buckets.reduce(0) { $0 + $1.block }, asked = buckets.reduce(0) { $0 + $1.ask }
        return AXChartDescriptor(title: "Protection, \(range.phrase)",
                                 summary: "\(stopped) \(stopLabel), \(asked) \(askLabel)",
                                 xAxis: x, yAxis: y, additionalAxes: [],
                                 series: [series(stopLabel, \.block), series(askLabel, \.ask)])
    }
}
