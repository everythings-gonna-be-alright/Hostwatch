import SwiftUI

/// The HUD's top: what needs a look, only when something does. Flagged, threat-listed or stopped events of the last
/// ten minutes, and processes running heavy. The stream below is context: this is the point of glancing at the HUD.
struct HUDAttention: View {
    let flagged: [ActivityEvent]
    let heavy: [HeavyProcess]
    let s: CGFloat
    let reason: (ActivityEvent) -> String

    var body: some View {
        if !flagged.isEmpty || !heavy.isEmpty {
            VStack(alignment: .leading, spacing: 3 * s) {
                ForEach(flagged) { e in
                    HStack(spacing: 6 * s) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        Text(e.name).fontWeight(.bold).lineLimit(1).layoutPriority(1)
                        Text(reason(e)).foregroundStyle(HUDInk.secondary).lineLimit(1).truncationMode(.tail)
                        Spacer(minLength: 4)
                        Text(HUDTime.ago(e)).foregroundStyle(HUDInk.tertiary).monospacedDigit()
                    }
                }
                ForEach(heavy.prefix(2)) { h in
                    HStack(spacing: 6 * s) {
                        Text("🔥")
                        Text(h.name).fontWeight(.semibold).lineLimit(1).layoutPriority(1)
                        Text(h.cpuHeavy ? "\(Int(h.cpu))% CPU" : ProcessVitals.memory(h.mem))
                            .foregroundStyle(.orange).monospacedDigit()
                        Spacer(minLength: 4)
                    }
                }
            }
            .font(.system(size: 11 * s))
            .padding(.horizontal, 8 * s).padding(.vertical, 6 * s)
            .background(RoundedRectangle(cornerRadius: 8 * s, style: .continuous).fill(Color.orange.opacity(0.12)))
        }
    }
}

/// "now", "12s", "4m", "2h": how long ago, in the HUD's few characters.
enum HUDTime {
    static func ago(_ e: ActivityEvent, now: Date = Date()) -> String {
        let at: Double
        if e.ts > 0 { at = e.ts } else {
            // A live event without a stamp: its clock time today.
            let today = Calendar.current.startOfDay(for: now).timeIntervalSince1970
            at = today + HUDFold.seconds(e)
        }
        let d = max(0, now.timeIntervalSince1970 - at)
        switch d {
        case ..<3: return "now"
        case ..<60: return "\(Int(d))s"
        case ..<3600: return "\(Int(d / 60))m"
        default: return "\(Int(d / 3600))h"
        }
    }
}

/// One quiet line of resources with units, coloured only when something is abnormal: CPU busy, memory under pressure.
struct HUDResourceLine: View {
    let sample: MetricSample
    let s: CGFloat

    var body: some View {
        ViewThatFits(in: .horizontal) {
            line(upload: true)
            line(upload: false)
        }
        .font(.system(size: 10 * s).monospacedDigit())
        .foregroundStyle(HUDInk.tertiary)
        .lineLimit(1)
        .help("CPU · memory (coloured under pressure) · network download and upload")
    }

    private func line(upload: Bool) -> some View {
        HStack(spacing: 5 * s) {
            Text("CPU \(Int(sample.cpu.rounded()))%").foregroundStyle(sample.cpu >= 85 ? Color.orange : HUDInk.tertiary)
            Text("·")
            Text("Memory \(Int((sample.mem * 100).rounded()))%")
                .foregroundStyle(sample.pressure >= 2 ? sample.pressureColor : HUDInk.tertiary)
            Text("·")
            Text("Net \(Self.rate(sample.netIn)) ↓" + (upload ? "  \(Self.rate(sample.netOut)) ↑" : ""))
        }
        .fixedSize()
    }

    /// Bytes per second with a unit: "820 B/s", "613 KB/s", "1.2 MB/s".
    static func rate(_ bytesPerSecond: Double) -> String {
        let v = max(0, bytesPerSecond)
        switch v {
        case ..<1000: return "\(Int(v)) B/s"
        case ..<1_000_000: return "\(Int(v / 1000)) KB/s"
        case ..<1_000_000_000: return String(format: "%.1f MB/s", v / 1_000_000)
        default: return String(format: "%.1f GB/s", v / 1_000_000_000)
        }
    }
}
