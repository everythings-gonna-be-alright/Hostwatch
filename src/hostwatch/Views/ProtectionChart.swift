import Charts
import SwiftUI

/// The last 24 hours of one Protection area, hour by hour: what was stopped (or would be) in red, what was asked
/// about (or would be) in a neutral grey. Red is the critical colour throughout Hostwatch. Red beside orange failed the
/// colour-vision check, so a question, which is pending rather than alarming, is grey. The legend names both.
struct ProtectionChart: View {
    struct Point: Identifiable {
        let hour: Date
        let block: Int
        let ask: Int
        var id: Date { hour }
    }

    let points: [Point]
    let stopLabel: String
    let askLabel: String
    @StateObject private var hover = ChartHover()

    static let stop = Color(nsColor: .systemRed)
    static let ask = Color(nsColor: .systemGray)

    private var empty: Bool { points.allSatisfy { $0.block == 0 && $0.ask == 0 } }

    var body: some View {
        Chart {
            ForEach(points) { p in
                BarMark(x: .value("Hour", p.hour, unit: .hour), y: .value("Count", p.block))
                    .foregroundStyle(by: .value("What", stopLabel))
                    .cornerRadius(2)
                BarMark(x: .value("Hour", p.hour, unit: .hour), y: .value("Count", p.ask))
                    .foregroundStyle(by: .value("What", askLabel))
                    .cornerRadius(2)
            }
            if let selected = hover.selected, let p = point(at: selected) {
                RuleMark(x: .value("Hour", p.hour, unit: .hour))
                    .foregroundStyle(Color.secondary.opacity(0.25))
                    .annotation(position: .top, overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) { readout(p) }
            }
        }
        .chartForegroundStyleScale([stopLabel: Self.stop, askLabel: Self.ask])
        .chartLegend(position: .bottom, alignment: .leading, spacing: 6)
        .chartXAxis {
            AxisMarks(values: .stride(by: .hour, count: 6)) { _ in
                AxisValueLabel(format: .dateTime.hour(), centered: true).foregroundStyle(Color.secondary)
            }
        }
        .chartYAxis {
            AxisMarks(position: .trailing, values: .automatic(desiredCount: 2)) { _ in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel().foregroundStyle(Color.secondary)
            }
        }
        .chartXSelection(value: $hover.selected)
        .overlay {
            if empty {
                Text("Quiet for the last 24 hours").font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(height: 96)
        .accessibilityLabel("The last 24 hours, by hour")
        .accessibilityValue("\(points.reduce(0) { $0 + $1.block }) \(stopLabel), \(points.reduce(0) { $0 + $1.ask }) \(askLabel)")
    }

    private func point(at date: Date) -> Point? {
        points.min { abs($0.hour.timeIntervalSince(date)) < abs($1.hour.timeIntervalSince(date)) }
    }

    /// The hour's numbers in text ink: the colours beside them say which is which.
    private func readout(_ p: Point) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(p.hour.formatted(.dateTime.hour().minute())).font(.caption.weight(.semibold))
            HStack(spacing: 4) { Circle().fill(Self.stop).frame(width: 6, height: 6); Text("\(p.block) \(stopLabel)") }
            HStack(spacing: 4) { Circle().fill(Self.ask).frame(width: 6, height: 6); Text("\(p.ask) \(askLabel)") }
        }
        .font(.caption.monospacedDigit())
        .padding(6)
        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(.regularMaterial))
    }
}

/// The hovered hour (no @State macro with the command line tools).
final class ChartHover: ObservableObject {
    @Published var selected: Date?
}

extension ProtectionChart {
    /// Hourly counts from the monitor, as chart points.
    static func points(_ hours: [ProtectionMonitor.HourCount]) -> [Point] {
        hours.map { Point(hour: Date(timeIntervalSince1970: Double($0.hour) * 3600), block: $0.block, ask: $0.ask) }
    }

    /// The firewall's findings by the hour each destination was first seen, the last 24 hours.
    static func points(_ connections: [(FirewallEntry, FirewallDecision)], now: Date = Date()) -> [Point] {
        let current = Int(now.timeIntervalSince1970 / 3600)
        var block: [Int: Int] = [:], ask: [Int: Int] = [:]
        for (e, d) in connections {
            let h = Int(e.firstSeen.timeIntervalSince1970 / 3600)
            guard h > current - 24 else { continue }
            if d.verdict == .block { block[h, default: 0] += 1 } else { ask[h, default: 0] += 1 }
        }
        return (current - 23...current).map { h in
            Point(hour: Date(timeIntervalSince1970: Double(h) * 3600), block: block[h] ?? 0, ask: ask[h] ?? 0)
        }
    }
}
