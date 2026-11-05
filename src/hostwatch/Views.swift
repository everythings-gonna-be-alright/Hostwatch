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
            Image(systemName: event.kind.symbol)
                .font(.system(size: 8 * s, weight: .bold))
                .foregroundStyle(event.kind.color)
                .frame(width: 11 * s)
                .overlay(alignment: .leading) {
                    // Status stripe: red/orange for flagged patterns, green for safe.
                    if status != .unclassified {
                        Rectangle().fill(Color(nsColor: status.nsColor))
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
            Text(event.time)
                .font(.system(size: 9.5 * s, design: .monospaced).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
        }
        .frame(height: rowHeight(s))
    }
}

// MARK: - Full-screen activity window

/// The one "Show" filter, identical on the Events and Patterns tabs: a scope bar (like Finder's search or
/// Mail's filters) with every choice visible and its count, one selected. Narrow windows drop the icons;
/// the narrowest falls back to a pop-up menu. View ▸ Show has the same choices.
struct ShowFilterPicker: View {
    @Binding var filter: SignatureFilter
    /// How many rows each choice would show in this tab (events on Events, patterns on Patterns).
    let counts: [SignatureFilter: Int]

    var body: some View {
        ViewThatFits(in: .horizontal) {
            bar(counts, icons: true)
            bar(counts, icons: false)
            Picker("Show", selection: $filter) {
                ForEach(SignatureFilter.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .fixedSize()
        }
        .help("Show: filter by how patterns are decided (Events, Patterns and the HUD)")
    }

    private func bar(_ counts: [SignatureFilter: Int], icons: Bool) -> some View {
        HStack(spacing: 4) {
            ForEach(SignatureFilter.allCases, id: \.self) { option in
                let selected = filter == option
                Button { filter = option } label: {
                    HStack(spacing: 5) {
                        if icons {
                            Image(systemName: option.symbol)
                                .symbolVariant(selected ? .fill : .none)
                                .font(.system(size: 11, weight: .medium))
                        }
                        Text(option.short).font(.system(size: 12, weight: selected ? .semibold : .regular))
                        if let n = counts[option] {
                            Text(n.formatted())
                                .font(.system(size: 11).monospacedDigit())
                                .foregroundStyle(selected ? Color.accentColor.opacity(0.85) : Color.secondary)
                        }
                    }
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .foregroundStyle(selected ? Color.accentColor : Color.primary.opacity(0.8))
                    .background(Capsule().fill(selected ? Color.accentColor.opacity(0.16) : Color.primary.opacity(0.05)))
                    .overlay(Capsule().strokeBorder(selected ? Color.accentColor.opacity(0.35) : Color.clear, lineWidth: 0.5))
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .help(option.explanation)
                .accessibilityLabel("\(option.short)\(counts[option].map { ", \($0)" } ?? "")")
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .fixedSize()
    }
}

struct ActivityWindowView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var stories: StoryEngine
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var networkState: NetworkViewState
    @ObservedObject var firewall: FirewallMonitor
    let rulesTab: RulesTabState
    @ObservedObject var vitals: ProcessVitals
    @ObservedObject var heavyStrip: HeavyStripState
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var sheets: WindowSheetState
    @ObservedObject var rules: RuleBook
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var collector: Collector
    @ObservedObject var history: HistoryRecorder
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var travel: TimeTravel
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var running: RunningProcesses
    let actions: HUDActions

    private var traveling: Bool { travel.active && model.windowTab == 0 }
    /// Time Travel rows, derived only when the events or a filter change (not on every playhead or hover update).
    @StateObject private var travelRows = TravelRowsCache()
    /// Events ▸ Running Now instead of the event list.
    /// In Time Travel it shows what was running at the playhead.
    private var runningNow: Bool { running.showing && model.windowTab == 0 }

    var body: some View {
        VStack(spacing: 0) {
            if !collector.isRunning && !model.connected { collectorBanner; Divider() }
            VulnerabilityBanner(intel: intel, sheets: sheets)
            if model.windowTab == 0 { filterBar; Divider() }
            if model.windowTab == 0 && !runningNow { heavySection }
            if traveling {
                if !runningNow, model.searchText.trimmingCharacters(in: .whitespaces).count >= TimeTravel.minSearchLength {
                    HistorySearchScopeBar(travel: travel, query: model.searchText); Divider()
                }
                TimeTravelBanner(travel: travel, shown: runningNow ? running.rows.count : travel.listed.count,
                                 noun: runningNow ? "processes" : "events"); Divider()
            }
            switch model.windowTab {
            case 0:
                if runningNow {
                    RunningProcessesView(running: running, signatures: signatures, search: model.searchText,
                                         history: model.history, showSpawn: { row in
                                             if let start = row.started { actions.showSpawn(row.pid, start) }
                                         }, actions: actions)
                } else {
                    eventsList
                }
            case 1: PatternsView(signatures: signatures, classifier: classifier, actions: actions,
                                 filter: $model.signatureFilter)
            case 2: StoriesView(stories: model.stories, search: model.searchText, actions: actions)
            case 3: NetworkView(domains: domains, firewall: firewall, signatures: signatures, state: networkState,
                                search: model.searchText, openDetails: actions.openDomain,
                                openFirewallSettings: actions.openFirewallSettings, knownBad: { intel.reason(forDomain: $0) })
            default: RulesView(book: rules, signatures: signatures, classifier: classifier, baseline: baseline, tab: rulesTab,
                               showPatterns: { app in
                                   signatures.scope = nil
                                   signatures.search = app
                                   model.windowTab = 1
                               },
                               showKeys: { title, keys in
                                   signatures.search = ""
                                   signatures.scope = .init(title: title, keys: Set(keys))
                                   model.windowTab = 1
                               })
            }
        }
        .frame(minWidth: 900, minHeight: 480)
        .sheet(isPresented: $sheets.showVulns) { VulnerabilityList(intel: intel, close: { sheets.showVulns = false }) }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if traveling { TimelineBar(travel: travel).transition(.move(edge: .bottom).combined(with: .opacity)) }
        }
        .animation(.smooth(duration: 0.25), value: traveling)
        // Time Travel searches all recorded history (scope All History), in the background.
        .onChange(of: model.searchText) { _, text in if traveling && !runningNow { travel.search(text) } }
        .onChange(of: traveling) { _, on in
            if on && !runningNow { travel.search(model.searchText) }
            syncRunningMoment()
        }
        .onChange(of: runningNow) { _, on in
            if traveling && !on { travel.search(model.searchText) }
            syncRunningMoment()
        }
        // Native window toolbar (bridged by NSHostingController): Liquid Glass controls + search.
        .toolbar { toolbarContent }
        .searchable(text: searchText, placement: .toolbar,
                    prompt: ["Name, path, host, PID", "Process or pattern", "Chain, process, path",
                             "Domain, host, program", "Not used on Rules", "Not used on Overview"][min(model.windowTab, 5)])
        .navigationTitle("Hostwatch")
        .navigationSubtitle(subtitle)
    }

    /// Running Now follows the playhead while traveling, the present otherwise.
    private func syncRunningMoment() {
        travel.processesWanted = traveling && runningNow
        if !travel.processesWanted { running.showLive() }
    }

    /// One search field, routed to whichever tab is showing.
    private var searchText: Binding<String> {
        model.windowTab == 1 ? $signatures.search : $model.searchText
    }

    private var subtitle: String {
        let state = model.paused ? "Paused" : model.connected ? "Live" : "Collector off"
        if traveling {
            return "History · " + travel.playhead.formatted(.dateTime.weekday(.abbreviated).hour().minute())
        }
        switch model.windowTab {
        case 0: return "\(state) · \(model.history.count) events"
        case 1: return "\(state) · \(signatures.total) patterns"
        case 2: return "\(state) · \(stories.activeCount) open stories"
        case 3:
            return "\(state) · \(domains.newCount) new domains" + (firewall.prompts.isEmpty ? "" : " · \(firewall.prompts.count) waiting")
        default: return "\(state) · \(rules.activeCount) active rules"
        }
    }

    /// The order here is the ⌘1–⌘5 order (the View menu matches).
    private var windowTabs: [WindowTabBar.Tab] {
        let waiting = rules.proposals.count + (baseline.report?.review.count ?? 0)
        let dangerous = stories.stories.contains { !$0.dismissed && $0.severity == .dangerous }
        return [
            .init(id: 0, title: "Events", symbol: "list.bullet.rectangle"),
            .init(id: 1, title: "Patterns", symbol: "square.stack.3d.up"),
            .init(id: 4, title: "Rules", symbol: "checklist",
                  badge: rules.running ? "…" : waiting > 0 ? "\(waiting)" : nil, badgeTint: .accentColor),
            .init(id: 2, title: "Stories", symbol: "point.3.connected.trianglepath.dotted",
                  badge: stories.activeCount > 0 ? "\(stories.activeCount)" : nil, badgeTint: dangerous ? .red : .orange),
            .init(id: 3, title: "Network", symbol: "network.badge.shield.half.filled",
                  badge: !firewall.prompts.isEmpty ? "\(firewall.prompts.count)" : domains.newCount > 0 ? "\(domains.newCount)" : nil,
                  badgeTint: !firewall.prompts.isEmpty ? .orange : .purple),
        ]
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            WindowTabBar(tabs: windowTabs, selection: $model.windowTab)
        }
        ToolbarItemGroup(placement: .principal) {
          if model.windowTab == 0 && !runningNow {
            ForEach(EventKind.allCases, id: \.self) { kind in
                let on = model.visibleKinds.contains(kind)
                Button { model.toggle(kind) } label: {
                    Label { Text("\(model.counts[kind, default: 0])").monospacedDigit() } icon: {
                        Image(systemName: kind.symbol)
                    }
                    .labelStyle(.titleAndIcon)
                    .foregroundStyle(on ? kind.color : .secondary)
                    .opacity(on ? 1 : 0.45)
                }
                .help(on ? "Hide \(kind.title.lowercased())" : "Show \(kind.title.lowercased())")
            }
          }
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Toggle(isOn: Binding(get: { travel.active }, set: { on in
                if on { model.windowTab = 0; running.showing = false; travel.enter() } else { travel.exit() }
            })) {
                Label("Time Travel", systemImage: "clock.arrow.circlepath")
            }
            .help("Travel through recorded activity (⌥⌘T)")
            Button { model.paused.toggle() } label: {
                Label(model.paused ? "Resume" : "Pause", systemImage: model.paused ? "play.fill" : "pause.fill")
            }
            .help(model.paused ? "Resume the live stream" : "Pause the live stream")
            .disabled(traveling || runningNow)
            Button { model.clear() } label: { Label("Clear", systemImage: "trash") }
                .help("Clear the event list")
                .disabled(traveling || runningNow)
            Toggle(isOn: $model.overlayEnabled) {
                Label("HUD", systemImage: "rectangle.inset.topright.filled")
            }
            .help("Show or hide the HUD overlay (⌃⌥⌘H)")
            Button(action: actions.openSettings) { Label("Settings", systemImage: "gearshape") }
                .help("Settings (⌘,)")
        }
    }

    /// Nothing is watched while the collector is off: say so where you look, with the fix.
    private var collectorBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text("The collector is off, so nothing is being watched.").fontWeight(.medium)
            Spacer()
            Button(collector.state == .starting ? "Starting…" : "Start Collector", action: actions.toggleCollector)
                .buttonStyle(.glassProminent)
                .disabled(collector.state == .starting)
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.10))
    }

    /// Slim bar under the toolbar: which events to show, and the pattern tally.
    private var filterBar: some View {
        HStack(spacing: 12) {
            Picker("View", selection: $running.showing) {
                Label("Events", systemImage: "list.bullet").tag(false)
                Label("Running Now", systemImage: "cpu").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help(traveling ? "Events: what happened in the window · Running Now: what was running at the playhead (⌥⌘R)"
                  : "Events: what happened · Running Now: every process running at this moment (⌥⌘R)")
            if runningNow {
                if running.isRecorded {
                    Text(running.recordedAt.map { "Recorded \($0.formatted(date: .omitted, time: .standard)) · once a minute" }
                         ?? "Nothing recorded at this moment")
                        .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                } else if let updated = running.updated {
                    Text("Updated \(updated.formatted(date: .omitted, time: .standard)) · every \(Int(RunningProcesses.interval)) s")
                        .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer(minLength: 0)
            } else {
                Divider().frame(height: 16)
                ShowFilterPicker(filter: $model.signatureFilter,
                                 counts: traveling ? travelDerived.counts : model.showCounts(model.history))
                Spacer(minLength: 0)
                ClassifyAllButton(classifier: classifier, signatures: signatures)
            }
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    @ViewBuilder
    /// Heavy processes, live or at the Time Travel playhead (recorded every 5 s): one design for both.
    private var heavy: HeavyContext {
        let _ = vitals.revision
        if traveling {
            return HeavyContext(entries: travel.sampleAtPlayhead?.heavy ?? [], at: travel.playhead, live: false,
                                events: { pid in travel.events.first { $0.kind == .exec && $0.pid == pid } })
        }
        return vitals.liveContext
    }

    @ViewBuilder private var heavySection: some View {
        let context = heavy
        if !context.entries.isEmpty {
            HeavyStrip(context: context, state: heavyStrip, onlyThese: model.onlyPids != nil, toggleOnlyThese: {
                model.onlyPids = model.onlyPids == nil ? context.pids : nil
            }, actions: actions)
        } else if model.onlyPids != nil {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle").foregroundStyle(.secondary)
                Text(traveling ? "Nothing ran heavy at this moment." : "Those processes are no longer heavy.")
                    .foregroundStyle(.secondary)
                Button("Show All Events") { model.onlyPids = nil }.buttonStyle(.link)
            }
            .font(.callout)
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
    }

    /// Show Spawn in Timeline: the launch selected, with whatever filter would hide it relaxed.
    private func revealLaunch(_ event: ActivityEvent) {
        let q = model.searchText.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty && !event.matches(q) { model.searchText = "" }
        model.onlyPids = nil
        if !model.visibleKinds.contains(.exec) { model.toggle(.exec) }
        if !model.passes(event, model.signatureFilter) { model.signatureFilter = .all }
        model.eventSelection = [event.id]
    }

    /// Rows (and Show counts) for the Time Travel list, from the cache when nothing they depend on changed.
    private var travelDerived: TravelRowsCache.Result {
        let key = TravelRowsCache.Key(revision: travel.revision, showingSearch: travel.showingSearch,
                                      kinds: model.visibleKinds, filter: model.signatureFilter,
                                      search: model.searchText, only: model.onlyPids, exclusions: model.exclusionText,
                                      signatures: signatures.revision, order: model.eventOrder)
        return travelRows.result(for: key) {
            TravelRowsCache.Result(rows: makeRows(model.filtered(travel.listed, applyExclusions: true)),
                                   counts: model.showCounts(travel.listed, applyExclusions: true))
        }
    }

    private func makeRows(_ events: [ActivityEvent]) -> [EventItem] {
        let items = events.map { e -> EventItem in
            let status = signatures.status(for: e)
            return EventItem(event: e, status: status, statusRank: signatures.rank(status))
        }
        // The list is already newest first: only sort for another column or direction.
        let newestFirst = model.eventOrder.count == 1 && model.eventOrder[0].keyPath == \EventItem.seq
            && model.eventOrder[0].order == .reverse
        return newestFirst ? items : items.sorted(using: model.eventOrder)
    }

    private var eventsList: some View {
        let rows = traveling ? travelDerived.rows : makeRows(model.searchResults)
        // Search hits span days: their Time column shows the day too.
        let withDay = traveling && travel.showingSearch
        return VStack(spacing: 0) {
          ScrollViewReader { proxy in
            Table(rows, selection: $model.eventSelection, sortOrder: $model.eventOrder) {
                TableColumn("Time", value: \.seq) { item in
                    Text(withDay ? item.event.dayTime : item.event.time).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 56, ideal: withDay ? 104 : 60, max: withDay ? 130 : 72)
                TableColumn("Kind", value: \.kind) { item in
                    Image(systemName: item.event.kind.symbol)
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(item.event.kind.color)
                        .help(item.event.kind.title)
                }
                .width(min: 20, ideal: 24, max: 32)
                TableColumn("Status", value: \.statusRank) { item in
                    HStack(spacing: 4) {
                        StatusPill(status: item.status)
                        if let bad = intel.flag(for: item.event) {
                            Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                                .help("KNOWN BAD · \(bad)")
                        } else if case .heavy = heavy.badge(for: item.event) {
                            Image(systemName: "flame.fill").foregroundStyle(.orange)
                                .help("Still running and using a lot of CPU or memory")
                        } else if !item.event.beacon.isEmpty {
                            Image(systemName: "dot.radiowaves.right").foregroundStyle(.red)
                                .help("BEACON: connects \(item.event.beacon)")
                        } else if item.event.rawIP {
                            Image(systemName: "number").foregroundStyle(.orange)
                                .help("RAW IP: public IP on an unusual port with no DNS lookup")
                        } else if !item.event.newDomain.isEmpty {
                            Image(systemName: "globe.badge.chevron.backward").foregroundStyle(.purple)
                                .help("NEW DOMAIN: first contact with \(item.event.newDomain)")
                        } else if item.event.isFirst {
                            Image(systemName: "sparkle").foregroundStyle(.yellow)
                                .help("First time this pattern was ever seen")
                                .accessibilityLabel("First seen")
                        }
                    }
                }
                .width(min: 70, ideal: 84, max: 100)
                TableColumn("Process", value: \.name) { item in
                    Text(item.event.name).fontWeight(.semibold).lineLimit(1).help(item.event.proc)
                }
                .width(min: 60, ideal: 110, max: 150)
                TableColumn("PID", value: \.pid) { item in
                    Text(String(item.event.pid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("PPID", value: \.ppid) { item in
                    Text(String(item.event.ppid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("Detail", value: \.detail) { item in
                    HStack(spacing: 6) {
                        if let bad = intel.flag(for: item.event) { KnownBadTag(detail: bad) }
                        if let badge = heavy.badge(for: item.event) { VitalBadgeView(badge: badge) }
                        if item.event.kind == .file {
                            FileModeIcon(mode: item.event.extra)
                            Text(item.event.target).truncationMode(.middle).help(item.event.target)
                        } else if item.event.kind == .net, !item.event.extra.isEmpty {
                            ProtocolTag(proto: item.event.extra)
                            Text(item.event.fullDetail.dropFirst(item.event.extra.count).trimmingCharacters(in: .whitespaces))
                                .truncationMode(.middle).help(item.event.target)
                        } else {
                            Text(item.event.fullDetail).truncationMode(.middle).help(item.event.target)
                        }
                    }
                }
                .width(min: 200, ideal: 900)
            }
            .font(.system(size: 12, design: .monospaced))
            .contextMenu(forSelectionType: UUID.self) { ids in
                if let id = ids.first, let item = rows.first(where: { $0.id == id }) { rowMenu(item.event) }
            } primaryAction: { ids in
                guard let id = ids.first, let item = rows.first(where: { $0.id == id }) else { return }
                // A search hit opens its moment; elsewhere a double-click asks the AI.
                if withDay { travel.reveal(item.event) } else { actions.askAI(item.event) }
            }
            .onChange(of: travel.focusID) { _, id in
                guard let id, let event = travel.events.first(where: { $0.id == id }) else { return }
                revealLaunch(event)
                DispatchQueue.main.async { proxy.scrollTo(id, anchor: .center) }
            }
          }
            Divider()
            HStack {
                MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)
                Spacer(minLength: 12)
                Button(history.statusText) { history.revealInFinder() }
                    .buttonStyle(.link)
                    .help("Show history files in Finder")
                Text("·")
                let total = traveling ? travel.listed.count : model.history.count
                if !traveling, model.restoredCount > 0 {
                    Text("\(model.restoredCount) from before the restart ·")
                        .help("Loaded from recorded history at launch, so the list isn't empty. Time Travel shows all of it.")
                }
                Text(rows.count == total ? "\(total) events" : "\(rows.count) of \(total) events")
                    .monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    @ViewBuilder
    private func rowMenu(_ event: ActivityEvent) -> some View {
        if traveling && travel.showingSearch && event.ts > 0 {
            Button("Show in Timeline") { travel.reveal(event) }
            Divider()
        }
        Button("Ask AI: Is This Dangerous?…") { actions.askAI(event) }
        Button("Watch \(event.name) Closely…") { actions.watch(event) }
        Divider()
        Text("Pattern: \(event.signatureProcess) → \(event.signaturePattern)")
        ForEach(SignatureStatus.allCases, id: \.self) { status in
            Button("Mark Pattern \(status.title)") { signatures.set(status, keys: [event.signatureKey]) }
        }
        Menu("Mark All \(event.kind.title) From This Process") {
            ForEach(SignatureStatus.allCases, id: \.self) { status in
                Button(status == .unclassified ? "Clear Rule" : status.title) {
                    signatures.setProcessRule(status, kind: event.kind, process: event.signatureProcess)
                }
                .disabled(status == .safe && !SignatureStore.canTrustWholeProcess(event.signatureProcess))
            }
        }
        Menu("Exclude") {
            ForEach(event.exclusionSuggestions, id: \.1) { title, pattern in
                Button(title) { model.addExclusion(pattern) }
            }
            Divider()
            Button("Edit Exclusions…", action: actions.openExclusions)
        }
        Divider()
        Button("Copy Detail") { copy(event.target) }
        Button("Copy Process Path") { copy(event.proc) }
            .disabled(event.proc.isEmpty)
        if event.kind == .file || event.kind == .exec {
            Button("Reveal in Finder") {
                NSWorkspace.shared.selectFile(event.target, inFileViewerRootedAtPath: "")
            }
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - Exclusions editor

/// Holds the unsaved editor text (avoids @State, which needs SwiftUI macro plugins).
final class EditorDraft: ObservableObject {
    @Published var text = ""
}

struct ExclusionsEditor: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var draft: EditorDraft
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(exclusionHelp)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $draft.text)
                .font(.system(size: 12, design: .monospaced))
                .autocorrectionDisabled()
                .border(Color.secondary.opacity(0.3))
            HStack {
                Button("Restore Defaults") { draft.text = defaultExclusions }
                Spacer()
                Button("Cancel") { onClose() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { model.exclusionText = draft.text; onClose() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(14)
        .frame(minWidth: 480, minHeight: 380)
    }
}

/// Read or write as an icon instead of "r" / "w": an eye for reading, a pencil for writing, both for both.
struct FileModeIcon: View {
    let mode: String

    private var writes: Bool { mode.contains("w") }
    private var reads: Bool { mode.contains("r") || !writes }

    var body: some View {
        Image(systemName: reads && writes ? "square.and.pencil" : writes ? "pencil" : "eye")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(writes ? Color.orange : Color.secondary)
            .frame(width: 14)
            .help(reads && writes ? "Read and write" : writes ? "Write" : "Read")
            .accessibilityLabel(reads && writes ? "Read and write" : writes ? "Write" : "Read")
    }
}

/// TCP or UDP as a small tag instead of a word in the text.
struct ProtocolTag: View {
    let proto: String

    var body: some View {
        let udp = proto.uppercased().hasPrefix("UDP")
        Text(proto.uppercased())
            .font(.system(size: 9, weight: .bold, design: .rounded))
            .foregroundStyle(udp ? Color.teal : Color.blue)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(Capsule().fill((udp ? Color.teal : Color.blue).opacity(0.14)))
            .overlay(Capsule().strokeBorder((udp ? Color.teal : Color.blue).opacity(0.35), lineWidth: 0.5))
            .help(udp ? "UDP: connectionless (DNS, QUIC, streaming…)" : "TCP connection")
            .accessibilityLabel(proto)
    }
}

/// "⛔ KNOWN BAD" on a row whose connection or program is on a threat list.
struct KnownBadTag: View {
    let detail: String

    var body: some View {
        Label("KNOWN BAD", systemImage: "xmark.octagon.fill")
            .labelStyle(.titleAndIcon)
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Capsule().fill(Color.red))
            .help(detail)
            .accessibilityLabel("Known bad: \(detail)")
    }
}

/// "Classify with AI": every New pattern, in batches, with progress. A popover says how many, which AI and
/// roughly what it costs, and whether to apply the verdicts or keep them as suggestions.
struct ClassifyAllButton: View {
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var signatures: SignatureStore
    @StateObject private var ui = ClassifyAllState()

    var body: some View {
        if let run = classifier.bulk {
            HStack(spacing: 8) {
                ProgressView(value: Double(run.done), total: Double(max(run.total, 1))).frame(width: 110)
                Text("Classifying \(run.done.formatted()) of \(run.total.formatted())").font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
                Button("Cancel") { classifier.cancelAll() }.buttonStyle(.glass)
            }
        } else {
            Button { ui.show = true } label: { Label("Classify with AI", systemImage: "sparkles") }
                .buttonStyle(.glass)
                .disabled(classifier.running)
                .help("Ask AI about every New pattern")
                .popover(isPresented: $ui.show, arrowEdge: .bottom) { confirm }
        }
    }

    private var confirm: some View {
        let _ = signatures.revision
        let count = classifier.classifiable.count
        let batches = (count + classifier.batchSize - 1) / classifier.batchSize
        let engine = classifier.engine
        return VStack(alignment: .leading, spacing: 12) {
            Text("Classify \(count.formatted()) new pattern\(count == 1 ? "" : "s") with AI").font(.headline)
            Label(engine.title, systemImage: engine == .onDevice ? "lock.laptopcomputer" : "sparkles")
                .font(.callout)
            Text(engine == .onDevice ? "Free and private: nothing leaves this Mac. What it can't settle stays New."
                 : engine == .claude ? "About $\(String(format: "%.2f", Double(batches) * 0.03)) with Claude (\(batches) batches of \(classifier.batchSize)). Pattern summaries are sent, secrets masked."
                 : "On-device first (free, private); only what it can't settle goes to Claude, at most about $\(String(format: "%.2f", Double(batches) * 0.03)).")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Picker("", selection: $ui.apply) {
                Text("Apply the verdicts").tag(true)
                Text("Keep them as suggestions").tag(false)
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            Text(ui.apply ? "Never Safe for high-risk patterns, python, bash and the like: those stay for you."
                 : "You accept them in Rules ▸ Needs You.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Text("Engine: Settings ▸ AI").font(.caption).foregroundStyle(.tertiary)
                Spacer()
                Button("Cancel") { ui.show = false }.keyboardShortcut(.cancelAction)
                Button("Classify") {
                    ui.show = false
                    classifier.classifyAll(apply: ui.apply)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(count == 0)
            }
        }
        .padding(16)
        .frame(width: 380)
    }
}

final class ClassifyAllState: ObservableObject {
    @Published var show = false
    @Published var apply = true
}


/// The Time Travel list's derived rows, kept between renders. Not observed: SwiftUI re-renders the window for
/// the playhead, hover and progress many times a second, and re-filtering ~20,000 events each time was the lag.
final class TravelRowsCache: ObservableObject {
    struct Key: Equatable {
        var revision: Int
        var showingSearch: Bool
        var kinds: Set<EventKind>
        var filter: SignatureFilter
        var search: String
        var only: Set<Int>?
        var exclusions: String
        var signatures: Int
        var order: [KeyPathComparator<EventItem>]
    }

    struct Result {
        var rows: [EventItem] = []
        var counts: [SignatureFilter: Int] = [:]
    }

    private var key: Key?
    private var cached = Result()

    func result(for key: Key, _ make: () -> Result) -> Result {
        if key != self.key {
            cached = make()
            self.key = key
        }
        return cached
    }
}

/// Finder-style scope while traveling with a search: everything recorded, or only the shown window.
struct HistorySearchScopeBar: View {
    @ObservedObject var travel: TimeTravel
    let query: String

    var body: some View {
        HStack(spacing: 10) {
            Text("Search:").foregroundStyle(.secondary)
            Picker("Search", selection: $travel.searchAll) {
                Text("All History").tag(true)
                Text("This Window").tag(false)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("All History searches everything recorded (newest first, up to \(TimeTravel.maxSearchHits.formatted()) matches) · This Window filters the shown slice")
            if travel.searchAll {
                if travel.searching { ProgressView().controlSize(.small) }
                Text(status).foregroundStyle(.secondary).monospacedDigit().lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .font(.system(size: 12))
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
    }

    private var status: String {
        let n = travel.searchHits.count
        let matches = n == 1 ? "1 match" : "\(n.formatted()) matches"
        let back = travel.searchReachedBack.map {
            $0.formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated).hour().minute())
        }
        if travel.searching { return back.map { "\(matches) · searching, back to \($0)…" } ?? "Searching…" }
        if travel.searchCapped {
            return "Newest \(matches), back to \(back ?? "–"). Refine the search to reach older ones."
        }
        return n == 0 ? "No matches in recorded history" : "\(matches) in all recorded history · double-click one to open its moment"
    }
}
