import SwiftUI

// MARK: - UI

/// A tiny line chart of 0...1 values (gaps where a value is missing).
struct Sparkline: View {
    let values: [Double?]
    let color: Color
    var width: CGFloat? = 48               // nil: as wide as offered
    var height: CGFloat = 14
    var lineWidth: CGFloat = 1.2
    var fillOpacity: Double = 0.18

    var body: some View {
        Canvas { ctx, size in
            guard values.count > 1 else { return }
            let step = size.width / CGFloat(values.count - 1)
            var path = Path(), fill = Path()
            var drawing = false, runStart: CGFloat = 0, last: CGFloat = 0
            func close() {
                guard drawing else { return }
                fill.addLine(to: CGPoint(x: last, y: size.height))
                fill.addLine(to: CGPoint(x: runStart, y: size.height))
                fill.closeSubpath()
            }
            for (i, v) in values.enumerated() {
                let x = CGFloat(i) * step
                guard let v else { close(); drawing = false; continue }
                let y = size.height - CGFloat(min(max(v, 0), 1)) * (size.height - 1) - 0.5
                if drawing { path.addLine(to: CGPoint(x: x, y: y)); fill.addLine(to: CGPoint(x: x, y: y)) }
                else {
                    path.move(to: CGPoint(x: x, y: y))
                    fill.move(to: CGPoint(x: x, y: size.height)); fill.addLine(to: CGPoint(x: x, y: y))
                    runStart = x; drawing = true
                }
                last = x
            }
            close()
            ctx.fill(fill, with: .color(color.opacity(fillOpacity)))
            ctx.stroke(path, with: .color(color), lineWidth: lineWidth)
        }
        .frame(width: width, height: height)
        .frame(maxWidth: width == nil ? .infinity : nil)
    }
}

/// The startup disk's capacity and free space (read at most every 30 s: the query touches the file system).
final class DiskSpace: @unchecked Sendable {
    static let shared = DiskSpace()
    private let lock = NSLock()
    private var cached: (at: Date, free: Int64, total: Int64)?

    /// Bytes available, as Finder shows them (purgeable space counts as free).
    func free(now: Date = Date()) -> Int64? { read(now)?.free }
    func total(now: Date = Date()) -> Int64? { read(now)?.total }

    private func read(_ now: Date) -> (free: Int64, total: Int64)? {
        lock.lock(); defer { lock.unlock() }
        if let c = cached, now.timeIntervalSince(c.at) < 30 { return (c.free, c.total) }
        let keys: Set<URLResourceKey> = [.volumeAvailableCapacityForImportantUsageKey, .volumeTotalCapacityKey]
        guard let v = try? URL(fileURLWithPath: "/").resourceValues(forKeys: keys),
              let free = v.volumeAvailableCapacityForImportantUsage, let total = v.volumeTotalCapacity else { return nil }
        cached = (now, free, Int64(total))
        return (free, Int64(total))
    }
}

enum Rate {
    static func text(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond >= 1 else { return "0 B/s" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytesPerSecond), countStyle: .file) + "/s"
    }
}

extension MetricSample {
    var pressureColor: Color { pressure >= 4 ? .red : pressure >= 2 ? .orange : .green }
    var pressureText: String { pressure >= 4 ? "critical" : pressure >= 2 ? "warning" : "normal" }
}

/// Footer strip: CPU, memory, network and disk with sparklines; live, or around the playhead while
/// traveling. The list button shows the busiest processes at that moment.
struct MetricsStrip: View {
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var travel: TimeTravel
    let traveling: Bool

    private var samples: [MetricSample] { traveling ? travel.windowSamples : Array(metrics.recent.suffix(60)) }
    private var current: MetricSample? { traveling ? travel.sampleAtPlayhead : metrics.latest }

    var body: some View {
        HStack(spacing: 12) {
            if let s = current {
                // Grey like the text around it: colour only when it means something (busy CPU, memory pressure).
                metric("CPU", "\(Int(s.cpu.rounded()))%", samples.map { $0.cpu / 100 }, s.cpu >= 85 ? .orange : .secondary,
                       help: "CPU: share of all cores in use")
                metric("Memory", "\(Int((s.mem * 100).rounded()))%", samples.map(\.mem), s.pressure >= 2 ? s.pressureColor : .secondary,
                       help: "Memory used (app, wired and compressed): \(Self.memoryText(s.mem)). Memory pressure \(s.pressureText). "
                           + "A process's own footprint counts memory it shares with others, so processes don't add up to this.")
                Label("\(Rate.text(s.netIn)) ↓ \(Rate.text(s.netOut)) ↑", systemImage: "network")
                    .help("Network: download ↓ and upload ↑ on Wi-Fi, Ethernet and cellular")
                if let r = s.diskRead, let w = s.diskWrite {
                    Label("R \(Rate.text(r)) · W \(Rate.text(w))", systemImage: "internaldrive")
                        .help("Disk: read and written by all processes (from the collector)")
                }
                if let free = s.free {
                    Button { metrics.showDisk.toggle() } label: {
                        Label("\(DiskFormat.short(free)) free", systemImage: "externaldrive")
                    }
                    .buttonStyle(.borderless)
                    .help("Free space on the startup disk · click for its trend and which programs write the most")
                    .popover(isPresented: $metrics.showDisk, arrowEdge: .top) {
                        DiskSpaceView(metrics: metrics, at: traveling ? travel.playhead : nil)
                    }
                }
                Button { metrics.showTop.toggle() } label: { Image(systemName: "list.number") }
                    .buttonStyle(.borderless)
                    .help("Busiest processes at this moment")
                    .popover(isPresented: $metrics.showTop, arrowEdge: .top) { TopProcessesView(sample: s) }
            } else {
                Text(traveling ? "No resource data recorded here" : "Measuring…")
            }
        }
        .labelStyle(.titleAndIcon)
        .monospacedDigit()
        .lineLimit(1)
    }

    private func metric(_ name: String, _ value: String, _ series: [Double], _ color: Color, help: String) -> some View {
        HStack(spacing: 5) {
            Text(name).foregroundStyle(.secondary)
            Sparkline(values: series, color: color, width: 40, height: 11, lineWidth: 1, fillOpacity: 0.08)
            Text(value).foregroundStyle(color == .secondary ? .secondary : color).frame(minWidth: 28, alignment: .leading)
        }
        .help(help)
    }

    /// "14.0 GB of 18 GB used".
    static func memoryText(_ fraction: Double) -> String {
        let total = Int64(ProcessInfo.processInfo.physicalMemory)
        let used = Int64(Double(total) * fraction)
        let f = ByteCountFormatter()
        f.countStyle = .memory
        return "\(f.string(fromByteCount: used)) of \(f.string(fromByteCount: total))"
    }
}

/// The busiest processes in one sample.
struct TopProcessesView: View {
    let sample: MetricSample

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Busiest processes · \(sample.date.formatted(date: .omitted, time: .standard))")
                .font(.system(size: 12, weight: .semibold))
            if let top = sample.top, !top.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    GridRow {
                        Text("Process"); Text("CPU").gridColumnAlignment(.trailing)
                        Text("Memory").gridColumnAlignment(.trailing); Text("Disk").gridColumnAlignment(.trailing)
                    }
                    .foregroundStyle(.secondary)
                    ForEach(top, id: \.pid) { p in
                        GridRow {
                            Text("\(p.name) \(p.pid)").lineLimit(1).truncationMode(.middle).frame(maxWidth: 220, alignment: .leading)
                                .help(p.path)
                            Text("\(Int(p.cpu.rounded()))%")
                            Text(ByteCountFormatter.string(fromByteCount: p.mem, countStyle: .memory))
                            Text(p.read + p.write >= 1 ? Rate.text(p.read + p.write) : "–")
                        }
                    }
                }
                .font(.system(size: 11).monospacedDigit())
                Text("CPU is % of one core (200% = two cores).").font(.system(size: 10)).foregroundStyle(.secondary)
            } else {
                Text("Needs the collector (it can see every user's processes).")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(minWidth: 320)
    }
}

/// `Hostwatch --metrics-probe`: three readings, 2 s apart (to compare with Activity Monitor or `top`).
func runMetricsProbe() -> Never {
    let sampler = SystemSampler()
    _ = sampler.read()
    for _ in 0..<3 {
        Thread.sleep(forTimeInterval: 2)
        let r = sampler.read()
        print(String(format: "CPU %.1f%%  memory %.1f%% (pressure %d)  net in %@  out %@",
                     r.cpu, r.mem * 100, r.pressure, Rate.text(r.netIn), Rate.text(r.netOut)))
    }
    exit(0)
}
