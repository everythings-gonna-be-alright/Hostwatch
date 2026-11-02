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
}

// MARK: - Overlay

struct HUDView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var stories: StoryEngine
    @ObservedObject var collector: Collector
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var metrics: MetricsStore
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
                        EventRow(event: event, status: signatures.status(for: event), s: s)
                            .contentShape(Rectangle())
                            // Only reachable when Click-Through Overlay is off.
                            .onTapGesture(count: 2) { actions.askAI(event) }
                            .contextMenu {
                                Button("Ask AI: Is This Dangerous?…") { actions.askAI(event) }
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
        // On a transparent background a tight dark shadow keeps text readable on any wallpaper.
        // Legibility shadow: strong on a transparent background, subtle on materials (like macOS
        // does for text over vibrant backgrounds).
        .shadow(color: .black.opacity(transparent ? 0.95 : model.overlayBackground == .dark ? 0 : 0.45),
                radius: transparent ? 1.2 : 0.8)
        .modifier(HUDSurface(style: model.overlayBackground, tint: model.overlayOpacity,
                             interactive: !model.overlayClickThrough, shape: hudShape))
        .overlay(alignment: .bottomLeading) {
            if !model.overlayClickThrough {
                ResizeGrip(size: 16 * s, onBegin: beginResize, onDrag: resize)
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
        let rows = Int(((resizeStart.height + dy - model.overlayChrome(s)) / (rowHeight(s) + 1)).rounded())
        let clampedRows = min(max(rows, HUDModel.rowRange.lowerBound), HUDModel.rowRange.upperBound)
        if abs(width - model.overlayWidth) >= 1 { model.overlayWidth = width.rounded() }
        if clampedRows != model.overlayRows { model.overlayRows = clampedRows }
    }

    private var transparent: Bool { model.overlayBackground == .transparent }
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

/// HUD background. Liquid Glass is tinted dark by the Opacity setting so white text stays
/// readable over any wallpaper; the other styles are the classic ones.
struct HUDSurface: ViewModifier {
    let style: OverlayBackground
    let tint: Double
    let interactive: Bool
    let shape: RoundedRectangle

    func body(content: Content) -> some View {
        switch style {
        case .glass:
            content
                // A dark floor under white text: 0.35 + setting, so the default (45%) gives 62%.
                // Over a white wallpaper that keeps primary text near 5.6:1 and secondary near 4.4:1.
                .glassEffect(.regular.tint(.black.opacity(0.35 + tint * 0.6)), in: shape)
        case .blur:
            content
                .background { ZStack { Rectangle().fill(.ultraThinMaterial); Color.black.opacity(tint) } }
                .clipShape(shape)
                .overlay { shape.strokeBorder(.white.opacity(interactive ? 0.35 : 0.15), lineWidth: 1) }
        case .dark:
            content
                .background(Color.black.opacity(tint))
                .clipShape(shape)
                .overlay { shape.strokeBorder(.white.opacity(interactive ? 0.35 : 0.15), lineWidth: 1) }
        case .transparent:
            // Fully clear pixels don't receive clicks, so keep a near-invisible fill while interactive.
            content
                .background(Color.black.opacity(interactive ? 0.02 : 0))
                .clipShape(shape)
                .overlay { shape.strokeBorder(.white.opacity(interactive ? 0.3 : 0), lineWidth: 1) }
        }
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
    let size: CGFloat
    let onBegin: () -> Void
    let onDrag: (_ dx: CGFloat, _ dy: CGFloat) -> Void

    func makeNSView(context: Context) -> GripView { GripView() }

    func updateNSView(_ view: GripView, context: Context) {
        view.onBegin = onBegin
        view.onDrag = onDrag
        view.needsDisplay = true
    }

    final class GripView: NSView {
        var onBegin: () -> Void = {}
        var onDrag: (CGFloat, CGFloat) -> Void = { _, _ in }
        private var start: NSPoint?

        override var mouseDownCanMoveWindow: Bool { false }
        override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

        private var cursor: NSCursor {
            if #available(macOS 15.0, *) { return .frameResize(position: .bottomLeft, directions: .all) }
            return .crosshair
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
            onDrag(start.x - now.x, start.y - now.y)   // left/down = grow
        }

        override func mouseUp(with event: NSEvent) { start = nil }

        /// Three diagonal strokes in the bottom-left corner.
        override func draw(_ dirtyRect: NSRect) {
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
            if !event.beacon.isEmpty {
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
                Text("NEW")
                    .font(.system(size: 8 * s, weight: .heavy, design: .rounded))
                    .foregroundStyle(.yellow)
            }
            Text(event.time)
                .font(.system(size: 9.5 * s, design: .monospaced).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
        }
        .frame(height: rowHeight(s))
    }
}

// MARK: - Full-screen activity window

/// The one "Show" filter control, identical on the Events and Patterns tabs (and the menu).
struct ShowFilterPicker: View {
    @Binding var filter: SignatureFilter

    var body: some View {
        Picker("Show", selection: $filter) {
            ForEach(SignatureFilter.allCases, id: \.self) { Text($0.title).tag($0) }
        }
        .fixedSize()
        .help("Filter by how patterns are classified. Applies to the HUD, Events and Patterns.")
    }
}

struct ActivityWindowView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var stories: StoryEngine
    @ObservedObject var domains: DomainRegistry
    let domainsState: DomainsViewState
    let rulesTab: RulesTabState
    @ObservedObject var rules: RuleBook
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var collector: Collector
    @ObservedObject var history: HistoryRecorder
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var travel: TimeTravel
    @ObservedObject var metrics: MetricsStore
    let actions: HUDActions

    private var traveling: Bool { travel.active && model.windowTab == 0 }

    var body: some View {
        VStack(spacing: 0) {
            if !collector.isRunning && !model.connected { collectorBanner; Divider() }
            if model.windowTab == 0 { filterBar; Divider() }
            if traveling { TimeTravelBanner(travel: travel, shown: travel.events.count); Divider() }
            switch model.windowTab {
            case 0: eventsList
            case 1: PatternsView(signatures: signatures, classifier: classifier, actions: actions,
                                 filter: $model.signatureFilter)
            case 2: StoriesView(stories: model.stories, search: model.searchText, actions: actions)
            case 3: DomainsView(domains: domains, state: domainsState, search: model.searchText, openDetails: actions.openDomain)
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
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if traveling { TimelineBar(travel: travel).transition(.move(edge: .bottom).combined(with: .opacity)) }
        }
        .animation(.smooth(duration: 0.25), value: traveling)
        // Native window toolbar (bridged by NSHostingController): Liquid Glass controls + search.
        .toolbar { toolbarContent }
        .searchable(text: searchText, placement: .toolbar,
                    prompt: ["Name, path, host, PID", "Process or pattern", "Chain, process, path",
                             "Domain, host, program", "Not used on Rules"][min(model.windowTab, 4)])
        .navigationTitle("Hostwatch")
        .navigationSubtitle(subtitle)
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
        case 3: return "\(state) · \(domains.newCount) new domains"
        default: return "\(state) · \(rules.activeCount) active rules"
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Picker("View", selection: $model.windowTab) {
                Label("Events", systemImage: "list.bullet.rectangle").tag(0)
                Label("Patterns", systemImage: "square.stack.3d.up").tag(1)
                let waiting = rules.proposals.count + (baseline.report?.review.count ?? 0)
                Label(waiting == 0 ? "Rules" : "Rules (\(waiting))",
                      systemImage: "checklist").tag(4)
                Label(stories.activeCount > 0 ? "Stories (\(stories.activeCount))" : "Stories",
                      systemImage: "point.3.connected.trianglepath.dotted").tag(2)
                Label(domains.newCount > 0 ? "Domains (\(domains.newCount))" : "Domains",
                      systemImage: "globe").tag(3)
            }
            .pickerStyle(.segmented)
            .labelStyle(.titleAndIcon)
            .help("Events: the live stream · Patterns: learned fingerprints · Rules: what decides them · Stories: correlated chains · Domains (⌘1–⌘5)")
        }
        ToolbarItemGroup(placement: .principal) {
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
        ToolbarItemGroup(placement: .primaryAction) {
            Toggle(isOn: Binding(get: { travel.active }, set: { on in
                if on { model.windowTab = 0; travel.enter() } else { travel.exit() }
            })) {
                Label("Time Travel", systemImage: "clock.arrow.circlepath")
            }
            .help("Travel through recorded activity (⌥⌘T)")
            Button { model.paused.toggle() } label: {
                Label(model.paused ? "Resume" : "Pause", systemImage: model.paused ? "play.fill" : "pause.fill")
            }
            .help(model.paused ? "Resume the live stream" : "Pause the live stream")
            .disabled(traveling)
            Button { model.clear() } label: { Label("Clear", systemImage: "trash") }
                .help("Clear the event list")
                .disabled(traveling)
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
            ShowFilterPicker(filter: $model.signatureFilter)
            Spacer()
            PatternTally(signatures: signatures)
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    @ViewBuilder
    private var eventsList: some View {
        let events = traveling ? model.filtered(travel.events, applyExclusions: true) : model.searchResults
        let items = events.map { e -> EventItem in
            let status = signatures.status(for: e)
            return EventItem(event: e, status: status, statusRank: signatures.rank(status))
        }
        // The list is already newest first: only sort for another column or direction.
        let newestFirst = model.eventOrder.count == 1 && model.eventOrder[0].keyPath == \EventItem.seq
            && model.eventOrder[0].order == .reverse
        let rows = newestFirst ? items : items.sorted(using: model.eventOrder)
        return VStack(spacing: 0) {
            Table(rows, selection: $model.eventSelection, sortOrder: $model.eventOrder) {
                TableColumn("Time", value: \.seq) { item in
                    Text(item.event.time).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 56, ideal: 60, max: 72)
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
                        if !item.event.beacon.isEmpty {
                            Image(systemName: "dot.radiowaves.right").foregroundStyle(.red)
                                .help("BEACON: connects \(item.event.beacon)")
                        } else if item.event.rawIP {
                            Image(systemName: "number").foregroundStyle(.orange)
                                .help("RAW IP: public IP on an unusual port with no DNS lookup")
                        } else if !item.event.newDomain.isEmpty {
                            Image(systemName: "globe.badge.chevron.backward").foregroundStyle(.purple)
                                .help("NEW DOMAIN: first contact with \(item.event.newDomain)")
                        } else if item.event.isFirst {
                            Text("NEW").font(.system(size: 9, weight: .heavy)).foregroundStyle(.yellow)
                        }
                    }
                }
                .width(min: 88, ideal: 100, max: 136)
                TableColumn("Process", value: \.name) { item in
                    Text(item.event.name).fontWeight(.semibold).help(item.event.proc)
                }
                .width(min: 90, ideal: 170)
                TableColumn("PID", value: \.pid) { item in
                    Text(String(item.event.pid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("PPID", value: \.ppid) { item in
                    Text(String(item.event.ppid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("Detail", value: \.detail) { item in
                    Text(item.event.fullDetail).truncationMode(.middle).help(item.event.target)
                }
                .width(min: 200, ideal: 520)
            }
            .font(.system(size: 12, design: .monospaced))
            .contextMenu(forSelectionType: UUID.self) { ids in
                if let id = ids.first, let event = model.history.first(where: { $0.id == id }) { rowMenu(event) }
            } primaryAction: { ids in
                if let id = ids.first, let event = model.history.first(where: { $0.id == id }) { actions.askAI(event) }
            }
            Divider()
            HStack {
                MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)
                Spacer(minLength: 12)
                Button(history.statusText) { history.revealInFinder() }
                    .buttonStyle(.link)
                    .help("Show history files in Finder")
                Text("·")
                let total = traveling ? travel.events.count : model.history.count
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
        Button("Ask AI: Is This Dangerous?…") { actions.askAI(event) }
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
