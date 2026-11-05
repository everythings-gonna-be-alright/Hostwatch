import SwiftUI

enum DiskFormat {
    static func short(_ bytes: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    /// "+1.2 GB" / "−300 MB" for a change in free space.
    static func change(_ bytes: Double) -> String {
        (bytes < 0 ? "−" : "+") + short(abs(bytes))
    }
}

/// Free space over time and the programs that wrote the most, for the resource strip's disk popover.
@MainActor
final class DiskReport: ObservableObject {
    enum Period: Double, CaseIterable, Identifiable {
        case hour = 3600, day = 86_400
        var id: Double { rawValue }
        var title: String { self == .hour ? "Last Hour" : "Last 24 Hours" }
    }

    @Published var period: Period = .hour { didSet { load() } }
    @Published private(set) var freeSeries: [Double] = []
    @Published private(set) var freeChange: Double?
    @Published private(set) var writers: [ProcessHistory.Writer] = []
    @Published private(set) var loading = false

    private let metrics: MetricsStore
    private let end: Date?
    private var task: Task<Void, Never>?

    init(metrics: MetricsStore, at end: Date?) {
        self.metrics = metrics
        self.end = end
        load()
    }

    func load() {
        task?.cancel()
        let to = end ?? Date(), from = to.addingTimeInterval(-period.rawValue)
        let history = ProcessHistory(directory: metrics.archive.directory)
        loading = true
        task = Task { [weak self] in
            guard let self else { return }
            let samples = await self.metrics.samples(from: from, to: to).compactMap(\.free)
            let writers = await Task.detached(priority: .userInitiated) { history.writers(from: from, to: to) }.value
            guard !Task.isCancelled else { return }
            // At most ~120 points: enough for the shape.
            let stride = max(1, samples.count / 120)
            self.freeSeries = Swift.stride(from: 0, to: samples.count, by: stride).map { samples[$0] }
            self.freeChange = samples.count >= 2 ? samples.last! - samples.first! : nil
            self.writers = writers
            self.loading = false
        }
    }
}

struct DiskSpaceView: View {
    @StateObject private var report: DiskReport
    private let end: Date?

    init(metrics: MetricsStore, at end: Date?) {
        _report = StateObject(wrappedValue: DiskReport(metrics: metrics, at: end))
        self.end = end
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            Picker("Period", selection: $report.period) {
                ForEach(DiskReport.Period.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            trend
            Divider()
            writersList
        }
        .padding(14)
        .frame(width: 400)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Startup Disk").font(.headline)
            Spacer()
            if end == nil, let free = DiskSpace.shared.free(), let total = DiskSpace.shared.total() {
                Text("\(DiskFormat.short(Double(free))) free of \(DiskFormat.short(Double(total)))")
                    .monospacedDigit().foregroundStyle(.secondary)
            } else if let last = report.freeSeries.last {
                Text("\(DiskFormat.short(last)) free then").monospacedDigit().foregroundStyle(.secondary)
            }
        }
    }

    private var trend: some View {
        HStack(spacing: 10) {
            if report.freeSeries.count >= 2 {
                let lo = report.freeSeries.min()!, hi = report.freeSeries.max()!
                let span = max(hi - lo, 1)
                // Normalised to its own range, so small changes on a big disk still show.
                Sparkline(values: report.freeSeries.map { ($0 - lo) / span * 0.8 + 0.1 }, color: .teal, width: 180, height: 28)
                    .help("Free space, \(report.period.title.lowercased())")
            }
            if let change = report.freeChange {
                VStack(alignment: .leading, spacing: 1) {
                    Text(DiskFormat.change(change)).font(.title3.weight(.semibold).monospacedDigit())
                        .foregroundStyle(change < -1e9 ? .orange : .primary)
                    Text("free space, \(report.period.title.lowercased())").font(.caption).foregroundStyle(.secondary)
                }
            } else if !report.loading {
                Text("No free-space samples recorded in this period yet.").font(.callout).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder private var writersList: some View {
        HStack {
            Text("Wrote the Most").font(.subheadline.weight(.semibold))
            Spacer()
            if report.loading { ProgressView().controlSize(.small) }
        }
        if report.writers.isEmpty, !report.loading {
            Text("Nothing recorded yet. Hostwatch counts each program's disk writes in its once-a-minute process list "
                 + "(with history on), from this version on.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        } else {
            let top = report.writers.first?.bytes ?? 1
            VStack(alignment: .leading, spacing: 6) {
                ForEach(report.writers.prefix(12)) { w in
                    HStack(spacing: 8) {
                        Image(nsImage: ProcessIcons.icon(w.path)).resizable().frame(width: 16, height: 16)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(w.name).lineLimit(1)
                            GeometryReader { geo in
                                Capsule().fill(Color.teal.opacity(0.6))
                                    .frame(width: max(2, geo.size.width * CGFloat(Double(w.bytes) / Double(max(top, 1)))), height: 3)
                            }
                            .frame(height: 3)
                        }
                        Text(DiskFormat.short(Double(w.bytes))).monospacedDigit().frame(width: 72, alignment: .trailing)
                    }
                    .help("\(w.path.isEmpty ? w.name : w.path)\(w.processes > 1 ? " · \(w.processes) processes" : "")")
                }
            }
            Text("Bytes written, so temporary files that were deleted again count too.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
