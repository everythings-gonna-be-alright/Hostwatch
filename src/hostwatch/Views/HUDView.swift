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
    /// Events ▸ Show Launch Chain: who started this process, all the way up.
    var showLaunchChain: (ActivityEvent) -> Void = { _ in }
    /// The launch chain as data, for the Events details panel.
    var launchChain: (ActivityEvent) -> LaunchChainReport? = { _ in nil }
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
            Rectangle().fill(HUDInk.hairline).frame(height: 0.5)
            // What needs a look first, only when something does.
            HUDAttention(flagged: attention, heavy: vitals.liveContext.entries, s: s) { e in
                if !e.protectionReason.isEmpty { return e.protectionReason }
                if let bad = intel.flag(for: e) { return bad }
                let parent = (e.parent as NSString).lastPathComponent
                return signatures.status(for: e).title + (parent.isEmpty ? "" : " · from \(parent)")
            }
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
                    // Each banner takes about two rows of room. Repeats fold into one row (HUDFold).
                    let rows = max(0, model.overlayRows - 2 * min(2, stories.recent().count))
                    ForEach(model.overlayItems(rows: rows, flag: { vitals.badge(for: $0) != nil || intel.flag(for: $0) != nil })) { item in
                        let event = item.event
                        EventRow(event: event, status: signatures.status(for: event), s: s, vital: vitals.badge(for: event),
                                 knownBad: intel.flag(for: event), count: item.count,
                                 summary: item.folded ? HUDFold.summary(item.events) : nil)
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
            // One quiet line at the bottom, coloured only when something is abnormal.
            if model.overlayShowResources, let sample = metrics.latest {
                Spacer(minLength: 0)
                Rectangle().fill(HUDInk.hairline).frame(height: 0.5)
                HUDResourceLine(sample: sample, s: s)
                    .padding(.leading, model.overlayClickThrough ? 0 : 14 * s)    // clear of the resize grip
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
    private var header: some View {
        headerContent
            // The whole header bar moves the HUD (when interactive); buttons still get their clicks.
            .background(model.overlayClickThrough ? nil : WindowDragArea())
    }

    /// Flagged, threat-listed or stopped events of the last ten minutes: the HUD's attention section.
    private var attention: [ActivityEvent] {
        var out: [ActivityEvent] = []
        for e in model.history.prefix(2_000) {
            if HUDTime.ago(e) .hasSuffix("h") { break }
            let status = signatures.status(for: e)
            if e.protection != .none || intel.flag(for: e) != nil || status == .suspicious || status == .dangerous {
                if !out.contains(where: { $0.signatureKey == e.signatureKey }) { out.append(e) }
            }
            if out.count == 2 { break }
        }
        return out.filter { e in
            let ago = HUDTime.ago(e)
            return ago == "now" || ago.hasSuffix("s") || (ago.hasSuffix("m") && (Int(ago.dropLast()) ?? 99) < 10)
        }
    }

    private var stateWord: String { model.paused ? "Paused" : model.connected ? "Live" : "Collector off" }

    private var headerContent: some View {
        HStack(spacing: 6 * s) {
            // The name and the state: the running totals said nothing at a glance (they're in the tooltip).
            HStack(spacing: 5 * s) {
                Circle().fill(model.paused ? Color.yellow : model.connected ? Color.green : Color.orange)
                    .frame(width: 6 * s, height: 6 * s)
                Text("Hostwatch").font(.system(size: 12 * s, weight: .semibold))
                Text("· \(stateWord)").font(.system(size: 12 * s)).foregroundStyle(HUDInk.secondary)
            }
            .help(EventKind.allCases.map { "\($0.title): \(model.counts[$0, default: 0].formatted())" }.joined(separator: "\n"))
            Spacer(minLength: 4)
            if !model.overlayClickThrough {
                Button { model.paused.toggle() } label: { Image(systemName: model.paused ? "play.fill" : "pause.fill") }
                    .help(model.paused ? "Resume the live stream" : "Pause the live stream")
            }
        }
        .buttonStyle(.plain)
        .font(.system(size: 11 * s, weight: .semibold))
        .foregroundStyle(HUDInk.primary)
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
    /// A folded row: how many events, and what they did in words ("read 12 files in Shortcuts.app").
    var count = 1
    var summary: String? = nil

    /// Something to look at: flagged, on a threat list, or stopped (or would be) by protection.
    private var flagged: Bool {
        knownBad != nil || status == .suspicious || status == .dangerous || event.protection != .none
    }

    /// Ordinary, decided Safe, nothing to point out: it steps back, so an exception stands out (most rows are these).
    private var quiet: Bool {
        status == .safe && !flagged && vital == nil && !event.isFirst && event.newDomain.isEmpty && event.beacon.isEmpty && !event.rawIP
    }

    /// Colour only for exceptions: red for dangerous, threat-listed or stopped, orange for New and Suspicious.
    private var stripe: Color? {
        if knownBad != nil || status == .dangerous || event.protection != .none { return .red }
        if status == .suspicious || status == .unclassified { return .orange }
        return nil
    }

    var body: some View {
        HStack(spacing: 6) {
            KindTile(kind: event.kind, size: 12 * s)
                .saturation(stripe == nil ? 0 : 1)              // a tinted icon only where there's a bar
                .opacity(stripe == nil ? 0.5 : 1)
                .overlay(alignment: .leading) {
                    // A stripe only for what needs a look: a green one on every Safe row said nothing.
                    if let stripe {
                        Rectangle().fill(stripe)
                            .frame(width: 2 * s, height: rowHeight(s) - 2)
                            .offset(x: -5 * s)
                    }
                }
            // The name has the most room: it's what you recognise.
            Text(event.name)
                .font(.system(size: 11.5 * s, weight: flagged ? .bold : quiet ? .regular : .semibold))
                .foregroundStyle(flagged ? (stripe ?? HUDInk.primary) : quiet ? HUDInk.secondary : HUDInk.primary)
                .lineLimit(1)
                .layoutPriority(1)
            Text(summary ?? HUDFold.detail(event))
                .font(event.kind == .net && summary == nil ? .system(size: 10.5 * s, design: .monospaced) : .system(size: 11 * s))
                .foregroundStyle(quiet ? HUDInk.tertiary : HUDInk.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(event.target)
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
            if count > 1 {
                Text("\(count)×")
                    .font(.system(size: 9.5 * s, weight: .semibold).monospacedDigit())
                    .foregroundStyle(HUDInk.secondary)
                    .padding(.horizontal, 5 * s)
                    .background(Capsule().fill(Color.white.opacity(0.1)))
                    .help("\(count) events folded into this row")
            }
            Text(HUDTime.ago(event))
                .font(.system(size: 9.5 * s).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
                .frame(minWidth: 22 * s, alignment: .trailing)
                .help(event.time)
        }
        .frame(height: rowHeight(s))
    }
}
