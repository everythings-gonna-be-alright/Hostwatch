import Accessibility
import Charts
import SwiftUI

/// One Protection area over the chosen range: what was stopped (or would be) in red, what was asked about (or would
/// be) in a neutral grey, stacked. Red is the critical colour throughout Hostwatch, red beside orange failed the
/// colour-vision check, so a question, pending rather than alarming, is grey. The legend names both. The y scale is
/// passed in and shared by every card, so bars side by side compare honestly (HIG, Charts).
struct ProtectionChart: View {
    let buckets: [ProtectionTimeline.Bucket]
    let range: ProtectionTimeline.Range
    let stopLabel: String
    let askLabel: String
    /// The top of the shared scale.
    let yMax: Int
    /// The plot's height: the Overview gives a tall window's spare height to its charts.
    var height: CGFloat = 120
    @StateObject private var hover = ChartHover()

    static let stop = Color(nsColor: .systemRed)
    static let ask = Color(nsColor: .systemGray)

    private var empty: Bool { buckets.allSatisfy { $0.total == 0 } }

    var body: some View {
        Chart {
            ForEach(buckets) { b in
                BarMark(x: .value("Time", b.start, unit: range.unit), y: .value("Count", b.block))
                    .foregroundStyle(by: .value("What", stopLabel))
                    .cornerRadius(2)
                    .accessibilityLabel(Self.label(b.start, range))
                    .accessibilityValue("\(b.block) \(stopLabel)")
                BarMark(x: .value("Time", b.start, unit: range.unit), y: .value("Count", b.ask))
                    .foregroundStyle(by: .value("What", askLabel))
                    .cornerRadius(2)
                    .accessibilityLabel(Self.label(b.start, range))
                    .accessibilityValue("\(b.ask) \(askLabel)")
            }
            if let selected = hover.selected, let b = bucket(at: selected) {
                RuleMark(x: .value("Time", b.start, unit: range.unit))
                    .foregroundStyle(Color.secondary.opacity(0.25))
                    .annotation(position: .top, overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) { readout(b) }
            }
        }
        .chartForegroundStyleScale([stopLabel: Self.stop, askLabel: Self.ask])
        .chartLegend(position: .bottom, alignment: .leading, spacing: 6)
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
            AxisMarks(position: .trailing, values: [0, yMax]) { _ in       // the floor and the shared top, nothing between
                AxisGridLine().foregroundStyle(.quaternary)
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

    /// "3 PM", "Tuesday 10" or "Nov 10": how a bucket is named in the readout and to VoiceOver.
    static func label(_ start: Date, _ range: ProtectionTimeline.Range) -> String {
        switch range {
        case .day: start.formatted(.dateTime.hour())
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
        .padding(6)
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
