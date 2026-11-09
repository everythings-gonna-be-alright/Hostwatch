import AppKit
import SwiftUI

/// Actions the views can trigger; implemented by AppDelegate.
struct HUDActions {
    var openFullScreen: () -> Void
    var openExclusions: () -> Void
    var toggleCollector: () -> Void
    var quit: () -> Void
    var askAI: (ActivityEvent) -> Void
    var askStory: (Story) -> Void = { _ in }
    var openStories: () -> Void = {}
    var openSettings: () -> Void = {}
    var exclude: (String) -> Void = { _ in }
    var showInTimeline: (Date) -> Void = { _ in }
    var openBaseline: () -> Void = {}
    var openDomain: (String) -> Void = { _ in }
    var openFirewallSettings: () -> Void = {}
    /// Watch Closely: record what this event's process does for a while.
    var watch: (ActivityEvent) -> Void = { _ in }
    /// Running Now ▸ Show Spawn in Timeline: Time Travel at a process's launch.
    var showSpawn: (_ pid: Int, _ start: Date) -> Void = { _, _ in }
    var openStory: (Story) -> Void = { _ in }
}

// MARK: - Overlay

struct HUDView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var feed: LiveFeed             // the overlay follows every batch
    @ObservedObject var stories: StoryEngine
    @ObservedObject var collector: Collector
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var vitals: ProcessVitals
    @ObservedObject var intel: ThreatIntel
    let actions: HUDActions

    private var s: CGFloat { model.overlayScale }

    var body: some View {
        VStack(alignment: .leading, spacing: 6 * s) {
            header
            if model.overlayShowResources, let sample = metrics.latest {
                HUDResources(sample: sample, history: Array(metrics.recent.suffix(60)), s: s)
            }
            Rectangle().fill(HUDInk.hairline).frame(height: 0.5)
            let banners = Array(stories.recent().prefix(2))
            ForEach(banners) { story in
                StoryBanner(story: story, s: s)
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) { actions.openStories() }
                    .help("Double-click to open Stories")
            }

            if model.history.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(emptyTitle)
                        .font(.system(size: 12 * s, weight: .semibold))
                        .foregroundStyle(HUDInk.primary)
                    Text(emptySubtitle)
                        .font(.system(size: 10.5 * s, design: .monospaced))
                        .foregroundStyle(HUDInk.secondary)
                        .lineLimit(3)
                }
                .padding(.vertical, 8)
            } else {
                VStack(alignment: .leading, spacing: 1) {
                    // Each banner takes about two rows of room.
                    ForEach(Array(model.overlayEvents.prefix(max(0, model.overlayRows - 2 * min(2, stories.recent().count))))) { event in
                        EventRow(event: event, status: signatures.status(for: event), s: s, vital: vitals.badge(for: event),
                                 knownBad: intel.flag(for: event))
                            .contentShape(Rectangle())
                            // Only reachable when Click-Through Overlay is off.
                            .onTapGesture(count: 2) { actions.askAI(event) }
                            .contextMenu {
                                Button("Ask AI: Is This Dangerous?…") { actions.askAI(event) }
                                Button("Watch \(event.name) Closely…") { actions.watch(event) }
                                Menu("Exclude") {
                                    ForEach(event.exclusionSuggestions, id: \.1) { title, pattern in
                                        Button(title) { actions.exclude(pattern) }
                                    }
                                }
                            }
                    }
                }
            }
        }
        .padding(10 * s)
        .frame(width: model.overlayWidth, alignment: .leading)
        // Interactive: fill the panel so the box shows its real size while resizing.
        .frame(maxHeight: model.overlayClickThrough ? nil : .infinity, alignment: .top)
        .foregroundStyle(.white)
        // Legibility shadow: subtle on glass (like macOS does for text over vibrant backgrounds).
        .shadow(color: .black.opacity(model.overlayBackground == .solid ? 0 : 0.45), radius: 0.8)
        .modifier(HUDSurface(style: model.overlayBackground, tint: model.overlayOpacity,
                             interactive: !model.overlayClickThrough, shape: hudShape))
        .overlay(alignment: .leading) {
            // Left edge: width only (the HUD keeps its top-right corner).
            if !model.overlayClickThrough {
                ResizeGrip(size: 6, axis: .horizontal, onBegin: beginResize, onDrag: resize)
                    .frame(width: 6).frame(maxHeight: .infinity).padding(.vertical, 22 * s)
            }
        }
        .overlay(alignment: .bottom) {
            // Bottom edge: height only.
            if !model.overlayClickThrough {
                ResizeGrip(size: 6, axis: .vertical, onBegin: beginResize, onDrag: resize)
                    .frame(height: 6).frame(maxWidth: .infinity).padding(.horizontal, 22 * s)
            }
        }
        .overlay(alignment: .bottomLeading) {
            if !model.overlayClickThrough {
                ResizeGrip(size: 16 * s, axis: .both, onBegin: beginResize, onDrag: resize)
                    .frame(width: 16 * s, height: 16 * s)
                    .padding(3)
                    .help("Drag to resize")
            }
        }
        .environment(\.colorScheme, .dark)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
    }

    // MARK: Mouse resize (HUD is anchored top-right, so the bottom-left corner moves)

    private final class ResizeStart { var width: CGFloat = 0; var height: CGFloat = 0 }
    private let resizeStart = ResizeStart()

    /// Panel height for the current rows, matching AppDelegate.overlaySize().
    private var contentHeight: CGFloat {
        CGFloat(model.overlayRows) * (rowHeight(s) + 1) + model.overlayChrome(s)
    }

    private func beginResize() {
        resizeStart.width = model.overlayWidth
        resizeStart.height = contentHeight
    }

    /// dx/dy: screen points the mouse moved left/down since the drag began (positive = grow).
    private func resize(dx: CGFloat, dy: CGFloat) {
        let width = min(max(resizeStart.width + dx, HUDModel.widthRange.lowerBound), HUDModel.widthRange.upperBound)
        // Whole rows only after a full row of movement, so a sideways drag never changes the height.
        let startRows = (resizeStart.height - model.overlayChrome(s)) / (rowHeight(s) + 1)
        let rows = Int(startRows.rounded()) + Int((dy / (rowHeight(s) + 1)).rounded(.towardZero))
        let clampedRows = min(max(rows, HUDModel.rowRange.lowerBound), HUDModel.rowRange.upperBound)
        if abs(width - model.overlayWidth) >= 1 { model.overlayWidth = width.rounded() }
        if clampedRows != model.overlayRows { model.overlayRows = clampedRows }
    }

    private var hudShape: RoundedRectangle { RoundedRectangle(cornerRadius: 16 * s, style: .continuous) }

    private var emptyTitle: String {
        if model.socketWarning != nil { return "Refused an untrusted collector" }
        if model.connected { return "Waiting for activity…" }
        switch collector.state {
        case .starting: return "Starting collector…"
        case .failed: return "Collector failed"
        case .needsFullDiskAccess: return "Needs Full Disk Access"
        default: return "Collector not running"
        }
    }

    private var emptySubtitle: String {
        if let why = model.socketWarning { return why }
        if case .failed(let message) = collector.state { return message }
        if collector.state == .needsFullDiskAccess {
            return "Settings → Privacy & Security → Full Disk Access → enable Hostwatch, then relaunch"
        }
        return model.connected ? "" : "Menu bar 〰 → Start Collector"
    }

    /// "● LIVE" capsule: green live, yellow paused, orange off.
    private var liveBadge: some View {
        let color: Color = model.paused ? .yellow : model.connected ? .green : .orange
        return HStack(spacing: 4 * s) {
            Circle().fill(color).frame(width: 5 * s, height: 5 * s)
                .shadow(color: color.opacity(0.9), radius: 3 * s)
            Text(model.paused ? "PAUSED" : model.connected ? "LIVE" : "OFF")
                .font(.system(size: 9 * s, weight: .bold, design: .rounded))
                .tracking(0.6)
        }
        .foregroundStyle(color)
        .padding(.horizontal, 6 * s)
        .padding(.vertical, 2.5 * s)
        .background(Capsule().fill(color.opacity(0.22)))
    }

    private var header: some View {
        headerContent
            // The whole header bar moves the HUD (when interactive); buttons still get their clicks.
            .background(model.overlayClickThrough ? nil : WindowDragArea())
    }

    private var headerContent: some View {
        HStack(spacing: 8 * s) {
            Text("Activity")
                .font(.system(size: 12 * s, weight: .semibold, design: .rounded))
            Spacer(minLength: 4)
            ForEach(EventKind.allCases, id: \.self) { kind in
                HStack(spacing: 3) {
                    Image(systemName: kind.symbol).font(.system(size: 8.5 * s, weight: .bold))
                    Text("\(model.counts[kind, default: 0])")
                        .contentTransition(.numericText())
                }
                .font(.system(size: 10.5 * s, weight: .semibold, design: .rounded).monospacedDigit())
                .foregroundStyle(kind.color.opacity(model.visibleKinds.contains(kind) ? 1 : 0.4))
            }
            liveBadge

        }
    }
}

/// HUD background, drawn as its own layer under the content. Contrast sets how dark it is under the
/// HUD's white text. With Reduce Transparency on, glass becomes Solid.
struct HUDSurface: ViewModifier {
    let style: OverlayBackground
    let tint: Double
    let interactive: Bool
    let shape: RoundedRectangle
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    /// Contrast 0…1 → how dark the floor under the text is: 0 none (pure glass), the default 0.45
    /// keeps the earlier look (62%), 1 nearly opaque.
    static func floor(_ contrast: Double) -> Double {
        let v = min(max(contrast, 0), 1)
        return v <= 0.45 ? v / 0.45 * 0.62 : 0.62 + (v - 0.45) / 0.55 * 0.33
    }

    private var effective: OverlayBackground { reduceTransparency ? .solid : style }

    func body(content: Content) -> some View {
        content
            .background { layer }
            .clipShape(shape)
            .overlay {
                // Glass only: a faint edge while the HUD can be moved and resized. No border on Solid.
                if interactive, effective != .solid {
                    shape.strokeBorder(.white.opacity(0.28), lineWidth: 0.5)
                }
            }
    }

    @ViewBuilder private var layer: some View {
        switch effective {
        case .glass:
            shape.fill(Color.black.opacity(0.001))
                .glassEffect(.regular.tint(.black.opacity(Self.floor(tint))), in: shape)
        case .clear:
            // Clear glass darkens much faster with a tint: half as much keeps the scale even.
            shape.fill(Color.black.opacity(0.001))
                .glassEffect(.clear.tint(.black.opacity(Self.floor(tint) * 0.5)), in: shape)
        case .solid:
            ZStack {
                Rectangle().fill(.thickMaterial)
                Color.black.opacity(0.25 + Self.floor(tint) * 0.75)
            }
            .clipShape(shape)
        }
    }
}

/// A small preview of a HUD background over a wallpaper-like gradient (Settings ▸ HUD).
struct HUDBackgroundTile: View {
    let style: OverlayBackground
    let tint: Double
    let selected: Bool

    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                LinearGradient(colors: [Color(red: 0.98, green: 0.62, blue: 0.36), Color(red: 0.35, green: 0.45, blue: 0.95),
                                        Color(red: 0.95, green: 0.95, blue: 0.97)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
                VStack(alignment: .leading, spacing: 3) {
                    ForEach([0.9, 0.65, 0.8, 0.5], id: \.self) { w in
                        Capsule().fill(.white.opacity(0.9)).frame(width: 44 * w, height: 3)
                    }
                }
                .padding(8)
                .shadow(color: .black.opacity(0.3), radius: 0.8)
                .modifier(HUDSurface(style: style, tint: tint, interactive: false,
                                     shape: RoundedRectangle(cornerRadius: 8, style: .continuous)))
            }
            .frame(width: 92, height: 60)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(selected ? Color.accentColor : Color.secondary.opacity(0.25), lineWidth: selected ? 3 : 0.5)
            }
            Text(style.title).font(.caption).foregroundStyle(selected ? .primary : .secondary)
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(style.title)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// Drag handle that moves its window. Native `performDrag` works for borderless,
/// non-activating panels where SwiftUI content would otherwise swallow the mouse-down.
struct WindowDragArea: NSViewRepresentable {
    func makeNSView(context: Context) -> DragView { DragView() }
    func updateNSView(_ view: DragView, context: Context) {}

    final class DragView: NSView {
        override var mouseDownCanMoveWindow: Bool { false }   // we drag explicitly
        override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

        override func updateTrackingAreas() {
            super.updateTrackingAreas()
            trackingAreas.forEach(removeTrackingArea)
            addTrackingArea(NSTrackingArea(rect: bounds, options: [.cursorUpdate, .activeAlways, .inVisibleRect],
                                           owner: self))
        }

        override func cursorUpdate(with event: NSEvent) { NSCursor.openHand.set() }

        override func mouseDown(with event: NSEvent) {
            NSCursor.closedHand.set()
            window?.performDrag(with: event)   // runs until mouse-up; frame autosave keeps the spot
            NSCursor.openHand.set()
        }
    }
}

/// Resize handle. An NSView rather than a SwiftUI gesture: it refuses to move the window
/// (the panel is movable by background) and reads the mouse in screen coordinates, which stay
/// stable while the window resizes under it.
struct ResizeGrip: NSViewRepresentable {
    enum Axis { case horizontal, vertical, both }
    let size: CGFloat
    var axis: Axis = .both
    let onBegin: () -> Void
    let onDrag: (_ dx: CGFloat, _ dy: CGFloat) -> Void

    func makeNSView(context: Context) -> GripView { GripView() }

    func updateNSView(_ view: GripView, context: Context) {
        view.axis = axis
        view.onBegin = onBegin
        view.onDrag = onDrag
        view.needsDisplay = true
    }

    final class GripView: NSView {
        var axis: Axis = .both
        var onBegin: () -> Void = {}
        var onDrag: (CGFloat, CGFloat) -> Void = { _, _ in }
        private var start: NSPoint?

        override var mouseDownCanMoveWindow: Bool { false }
        override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

        private var cursor: NSCursor {
            if #available(macOS 15.0, *) {
                switch axis {
                case .horizontal: return .frameResize(position: .left, directions: .all)
                case .vertical: return .frameResize(position: .bottom, directions: .all)
                case .both: return .frameResize(position: .bottomLeft, directions: .all)
                }
            }
            return axis == .horizontal ? .resizeLeftRight : axis == .vertical ? .resizeUpDown : .crosshair
        }

        override func updateTrackingAreas() {
            super.updateTrackingAreas()
            trackingAreas.forEach(removeTrackingArea)
            addTrackingArea(NSTrackingArea(rect: bounds, options: [.cursorUpdate, .activeAlways, .inVisibleRect],
                                           owner: self))
        }

        override func cursorUpdate(with event: NSEvent) { cursor.set() }

        override func mouseDown(with event: NSEvent) {
            start = NSEvent.mouseLocation
            onBegin()
        }

        override func mouseDragged(with event: NSEvent) {
            guard let start else { return }
            let now = NSEvent.mouseLocation
            cursor.set()
            // Left/down = grow; an edge moves only its own dimension.
            onDrag(axis == .vertical ? 0 : start.x - now.x, axis == .horizontal ? 0 : start.y - now.y)
        }

        override func mouseUp(with event: NSEvent) { start = nil }

        /// Three diagonal strokes in the bottom-left corner (edges are invisible).
        override func draw(_ dirtyRect: NSRect) {
            guard axis == .both else { return }
            let path = NSBezierPath()
            let w = bounds.width
            for f in [0.35, 0.6, 0.85] as [CGFloat] {
                path.move(to: NSPoint(x: 3, y: w * f))
                path.line(to: NSPoint(x: w * f, y: 3))
            }
            path.lineWidth = 1.2
            path.lineCapStyle = .round
            NSColor.white.withAlphaComponent(0.55).setStroke()
            path.stroke()
        }
    }
}

/// Height of one HUD row at a given text scale (shared with the panel sizing).
func rowHeight(_ s: CGFloat) -> CGFloat { (16 * s).rounded(.up) }

/// HUD text hierarchy on the dark-tinted panel: primary / secondary / tertiary (timestamps).
/// Sized against the glass tint floor so body text stays near Apple's 4.5:1 over bright wallpapers.
/// One compact line of resource use for the HUD: CPU and memory with tiny sparklines, network and
/// disk throughput. Sparklines, then disk, give way first when the HUD is narrow.
struct HUDResources: View {
    let sample: MetricSample
    let history: [MetricSample]
    let s: CGFloat

    var body: some View {
        ViewThatFits(in: .horizontal) {
            line(sparklines: true, disk: true)
            line(sparklines: false, disk: true)
            line(sparklines: false, disk: false)
        }
        .font(.system(size: 10 * s, weight: .semibold, design: .rounded).monospacedDigit())
        .foregroundStyle(HUDInk.secondary)
        .lineLimit(1)
        .help("CPU · memory (orange or red under memory pressure) · network download/upload · disk read/write")
    }

    private func line(sparklines: Bool, disk: Bool) -> some View {
        HStack(spacing: 7 * s) {
            gauge("CPU", "\(Int(sample.cpu.rounded()))%", history.map { $0.cpu / 100 }, .blue, sparklines)
            gauge("MEM", "\(Int((sample.mem * 100).rounded()))%", history.map(\.mem), sample.pressureColor, sparklines,
                  valueColor: sample.pressure >= 2 ? sample.pressureColor : nil)
            Text("↓\(Self.short(sample.netIn)) ↑\(Self.short(sample.netOut))")
                .foregroundStyle(EventKind.net.color.opacity(0.95))
            if disk, let r = sample.diskRead, let w = sample.diskWrite {
                Text("R\(Self.short(r)) W\(Self.short(w))")
                    .foregroundStyle(EventKind.file.color.opacity(0.95))
            }
        }
        .fixedSize()
    }

    private func gauge(_ label: String, _ value: String, _ series: [Double], _ color: Color, _ spark: Bool,
                       valueColor: Color? = nil) -> some View {
        HStack(spacing: 3 * s) {
            Text(label).foregroundStyle(HUDInk.tertiary)
            Text(value).foregroundStyle(valueColor ?? HUDInk.primary)
            if spark, series.count > 1 { Sparkline(values: series, color: color, width: 18 * s, height: 9 * s) }
        }
    }

    /// Bytes per second, as short as possible: 0, 820, 12K, 1.2M, 3G.
    static func short(_ bytesPerSecond: Double) -> String {
        let v = max(0, bytesPerSecond)
        switch v {
        case ..<1000: return "\(Int(v))"
        case ..<10_000: return String(format: "%.1fK", v / 1000)
        case ..<1_000_000: return "\(Int(v / 1000))K"
        case ..<10_000_000: return String(format: "%.1fM", v / 1_000_000)
        case ..<1_000_000_000: return "\(Int(v / 1_000_000))M"
        default: return String(format: "%.1fG", v / 1_000_000_000)
        }
    }
}

enum HUDInk {
    static let primary = Color.white.opacity(0.95)
    static let secondary = Color.white.opacity(0.78)
    static let tertiary = Color.white.opacity(0.62)
    static let hairline = Color.white.opacity(0.18)
}

struct EventRow: View {
    let event: ActivityEvent
    var status: SignatureStatus = .unclassified
    var s: CGFloat = 1
    /// Still running heavy (or recently ended after being heavy).
    var vital: ProcessVitals.Badge? = nil
    /// On a threat list.
    var knownBad: String? = nil

    var body: some View {
        HStack(spacing: 6) {
            KindTile(kind: event.kind, size: 12 * s)
                .overlay(alignment: .leading) {
                    // Status stripe: red/orange for flagged patterns, green for safe.
                    if knownBad != nil || status != .unclassified {
                        Rectangle().fill(knownBad != nil ? Color.red : Color(nsColor: status.nsColor))
                            .frame(width: 2 * s, height: rowHeight(s) - 2)
                            .offset(x: -5 * s)
                    }
                }
            Text(event.name)
                .font(.system(size: 11 * s, weight: .semibold, design: .monospaced))
                .foregroundStyle(HUDInk.primary)
                .lineLimit(1)
                .frame(maxWidth: 104 * s, alignment: .leading)
            Text(event.detail)
                .font(.system(size: 10.5 * s, design: .monospaced))
                .foregroundStyle(HUDInk.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 2)
            if let knownBad {
                Text("KNOWN BAD")
                    .font(.system(size: 8.5 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.35, blue: 0.35))
                    .help(knownBad)
            } else if case .heavy(let cpu, let mem, _, let cpuHeavy, _) = vital {
                Text(cpuHeavy ? "🔥 \(Int(cpu))%" : "🔥 \(ProcessVitals.memory(mem))")
                    .font(.system(size: 8.5 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.62, blue: 0.25))
                    .help("Still running heavy")
            } else if !event.beacon.isEmpty {
                Text("BEACON \(event.beacon.replacingOccurrences(of: "every ", with: ""))")
                    .font(.system(size: 8 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.45, blue: 0.4))
                    .help("Connects \(event.beacon) — a steady interval, like malware calling home")
            } else if event.rawIP {
                Text("RAW IP")
                    .font(.system(size: 8 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.7, blue: 0.3))
                    .help("Public IP on an unusual port with no DNS lookup")
            } else if !event.newDomain.isEmpty {
                Text("NEW DOMAIN")
                    .font(.system(size: 8 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(Color(red: 0.85, green: 0.6, blue: 1.0))
                    .help("First contact with \(event.newDomain)")
            } else if event.isFirst {
                Text("FIRST")
                    .font(.system(size: 8 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(.yellow)
                    .help("First time this pattern was ever seen")
            }
            Text(event.clockTime)
                .font(.system(size: 9.5 * s, design: .monospaced).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
        }
        .frame(height: rowHeight(s))
    }
}
