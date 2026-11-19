import Charts
import SwiftUI

/// The chart itself: the stacked areas (or one program's line), the zero line, the silences hatched. Equatable on
/// what it draws, so a hover, a legend's value or the card's headline never lay out its marks again: with ten
/// programs over 30 minutes that was thousands of marks for every move of the pointer.
struct ResourcePlot: View, @MainActor Equatable {      // compared where it is drawn: the main thread
    /// The time labels under the plot (the hover line stops above them).
    static let axisHeight: CGFloat = 18

    let model: ResourceCardModel
    let lines: [ResourceLine]
    let stacked: Bool
    let top: Double
    let start: Date
    let end: Date
    let window: TimeInterval
    let focused: String?
    /// Written by the chart's selection, never read here: reading it would redraw the plot on every move.
    let hover: ChartHover

    static func == (a: Self, b: Self) -> Bool {
        a.model.version == b.model.version && a.model.title == b.model.title && a.stacked == b.stacked && a.top == b.top
            && a.start == b.start && a.end == b.end && a.window == b.window && a.focused == b.focused
    }

    private func sentGradient(_ c: Color) -> LinearGradient {
        LinearGradient(colors: stacked ? [c.opacity(0.5), c.opacity(0.85)] : [c.opacity(0.03), c.opacity(0.45)],
                       startPoint: .top, endPoint: .bottom)
    }

    private func gradient(_ c: Color) -> LinearGradient {
        LinearGradient(colors: stacked ? [c.opacity(0.85), c.opacity(0.5)] : [c.opacity(0.45), c.opacity(0.03)],
                       startPoint: .top, endPoint: .bottom)
    }

    var body: some View {
        let step = window <= 300 ? 1 : window <= 600 ? 2 : 5
        let gaps = model.gaps
        Chart {
            ForEach(lines, id: \.name) { line in
                // Each run between silences is its own series, so the curve never bridges a time nothing was measured.
                ForEach(Array(line.runs.enumerated()), id: \.offset) { run, points in
                    ForEach(points) { p in
                        AreaMark(x: .value("Time", p.date), y: .value(model.title, p.value),
                                 series: .value("Series", "\(line.name)#\(run)"), stacking: stacked ? .standard : .unstacked)
                            .interpolationMethod(.monotone)
                            .foregroundStyle(gradient(line.color))
                        if !stacked {
                            LineMark(x: .value("Time", p.date), y: .value(model.title, p.value), series: .value("Series", "\(line.name)#\(run)"))
                                .interpolationMethod(.monotone)
                                .foregroundStyle(line.color)
                                .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                        }
                    }
                }
                // Sent, below the line: its own series, so it stacks downwards and never joins the received shape.
                ForEach(Array(line.sentRuns.enumerated()), id: \.offset) { run, points in
                    ForEach(points) { p in
                        AreaMark(x: .value("Time", p.date), y: .value(model.title, -p.value),
                                 series: .value("Series", "\(line.name) sent#\(run)"), stacking: stacked ? .standard : .unstacked)
                            .interpolationMethod(.monotone)
                            .foregroundStyle(sentGradient(line.color))
                        if !stacked {
                            LineMark(x: .value("Time", p.date), y: .value(model.title, -p.value), series: .value("Series", "\(line.name) sent#\(run)"))
                                .interpolationMethod(.monotone)
                                .foregroundStyle(line.color)
                                .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                        }
                    }
                }
            }
            if model.mirrored {
                RuleMark(y: .value(model.title, 0)).foregroundStyle(Color.primary.opacity(0.2)).lineStyle(StrokeStyle(lineWidth: 0.5))
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
        .chartXSelection(value: Binding(get: { hover.selected }, set: { hover.selected = $0 }))
    }
}

