import AppKit
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

/// The HUD header's buttons: one plain glyph each, the same size and weight for every action (no background: a
/// capsule behind each was heavier than the header it sits in). The hit area stays a comfortable size.
struct HUDIconButton: View {
    let symbol: String
    let s: CGFloat
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 8.5 * s, weight: .semibold))
                .foregroundStyle(HUDInk.secondary)
                .frame(width: 16 * s, height: 14 * s)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Moves the HUD's window by dragging anywhere in it: the window's origin follows the mouse from where the drag began.
struct HUDWindowDrag: ViewModifier {
    let enabled: Bool
    @StateObject private var drag = DragState()

    final class DragState: ObservableObject {
        weak var window: NSWindow?
        var startMouse: NSPoint?
        var startOrigin: NSPoint = .zero
    }

    func body(content: Content) -> some View {
        content
            .background(WindowFinder { drag.window = $0 })
            .simultaneousGesture(
                DragGesture(minimumDistance: 3, coordinateSpace: .global)
                    .onChanged { _ in
                        guard enabled, let window = drag.window else { return }
                        let mouse = NSEvent.mouseLocation           // screen coordinates: steady while the window moves
                        if drag.startMouse == nil { drag.startMouse = mouse; drag.startOrigin = window.frame.origin }
                        guard let start = drag.startMouse else { return }
                        window.setFrameOrigin(NSPoint(x: drag.startOrigin.x + mouse.x - start.x,
                                                      y: drag.startOrigin.y + mouse.y - start.y))
                    }
                    .onEnded { _ in drag.startMouse = nil }
            )
    }
}

/// Hands over the NSWindow a SwiftUI view is in.
private struct WindowFinder: NSViewRepresentable {
    let found: (NSWindow?) -> Void
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { [weak view] in found(view?.window) }
        return view
    }
    func updateNSView(_ view: NSView, context: Context) {
        DispatchQueue.main.async { [weak view] in found(view?.window) }
    }
}
