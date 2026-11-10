import AppKit
import SwiftUI

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

    /// "Read and write", "Write" or "Read", for tooltips.
    static func title(_ mode: String) -> String {
        let writes = mode.contains("w"), reads = mode.contains("r") || !writes
        return reads && writes ? "Read and write" : writes ? "Write" : "Read"
    }

    var body: some View {
        Image(systemName: reads && writes ? "square.and.pencil" : writes ? "pencil" : "eye")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(writes ? Color.orange : Color.secondary)
            .frame(width: 14)
            .help(Self.title(mode))
            .accessibilityLabel(Self.title(mode))
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
/// The Status column for an event on a threat list: same shape as `StatusPill`, red.
struct KnownBadPill: View {
    var body: some View {
        Label {
            Text("Known bad").foregroundStyle(.primary)
        } icon: {
            Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        }
        .font(.system(size: 11, weight: .semibold))
        .labelStyle(.titleAndIcon)
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .background(Capsule().fill(Color.red.opacity(0.16)))
        .overlay(Capsule().strokeBorder(Color.red.opacity(0.45), lineWidth: 0.5))
        .lineLimit(1)
        .fixedSize()
        .accessibilityLabel("Known bad")
    }
}

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
    /// The patterns the list shows (its filter and search): Classify with AI takes only those.
    var shown: (() -> Set<String>)? = nil
    /// The selected rows' patterns: when you selected some, Classify with AI takes those instead of the whole list.
    var selected: (() -> Set<String>)? = nil
    /// The tab is in front: only then does the live list open by itself (hidden tabs stay alive).
    var active = true
    @StateObject private var ui = ClassifyAllState()

    var body: some View {
        Group {
            if let run = classifier.bulk {
                HStack(spacing: 8) {
                    ProgressView(value: Double(run.done), total: Double(max(run.total, 1))).frame(width: 110)
                    Text("Classifying \(run.done.formatted()) of \(run.total.formatted())").font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Button { ui.live.toggle() } label: { Label("Show", systemImage: "list.bullet.rectangle") }
                        .buttonStyle(.glass)
                        .help("Which patterns are being classified, live")
                    Button("Cancel") { classifier.cancelAll() }.buttonStyle(.glass)
                }
            } else {
                HStack(spacing: 6) {
                    LastRunButton(live: classifier.live) { ui.live = true }
                    Button { ui.show = true } label: { Label("Classify with AI", systemImage: "sparkles") }
                        .buttonStyle(.glass)
                        .disabled(classifier.running)
                        .help("Ask AI about every New pattern")
                        .popover(isPresented: $ui.show, arrowEdge: .bottom) { confirm }
                }
            }
        }
        // On the whole control: it stays open when the button turns into the progress bar and back.
        .popover(isPresented: $ui.live, arrowEdge: .bottom) {
            ClassifyLiveView(live: classifier.live, classifier: classifier)
        }
        // A run started (here or from a right-click menu): you see it work.
        .onChange(of: classifier.bulk != nil) { _, started in
            if started, active, !ui.show { DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { ui.live = classifier.bulk != nil } }
        }
    }

    private var confirm: some View {
        let _ = signatures.revision
        let picked = selected?() ?? []
        let scope = picked.isEmpty ? shown?() : picked
        let count = scope.map { classifier.undecided(in: $0) } ?? classifier.classifiable.count
        let place = picked.isEmpty ? "in this list" : "you selected"
        let batches = (count + classifier.batchSize - 1) / classifier.batchSize
        let engine = classifier.engine
        return VStack(alignment: .leading, spacing: 12) {
            Text("Classify \(count.formatted()) new pattern\(count == 1 ? "" : "s")\(scope == nil ? "" : " " + place) with AI")
                .font(.headline)
            if scope != nil {
                Text(picked.isEmpty ? "Only New patterns the list shows now, with its filter and search. Select rows to classify just those."
                     : "Only the New patterns of the rows you selected. Clear the selection to take the whole list.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
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
                    classifier.classifyAll(apply: ui.apply, only: scope)
                    // You asked to see it: the live list opens once the confirmation has closed.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { ui.live = classifier.bulk != nil }
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
    @Published var live = false
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
        var grouping = EventGrouping.none
        var sessions = 0            // a stamp of the sessions the grouping used
    }

    struct Result {
        var rows: [EventItem] = []
        var counts: [SignatureFilter: Int] = [:]
        /// Counts up each time the rows are rebuilt: the AppKit list reloads only then.
        var version = 0
    }

    private var key: Key?
    private var cached = Result()
    private var builds = 0

    func result(for key: Key, _ make: () -> Result) -> Result {
        result(for: key) { _, _ in make() }
    }

    /// `make` also gets the previous rows and their key, to reuse what a new batch didn't change.
    func result(for key: Key, _ make: (Result?, Key?) -> Result) -> Result {
        if key != self.key {
            builds += 1
            let previous = self.key == nil ? nil : cached
            cached = make(previous, self.key)
            cached.version = builds
            self.key = key
        }
        return cached
    }
}

/// Which group rows are folded. Groups open when shown (a grouping you chose is there to be read, not unfolded
/// one by one); a group you fold stays folded while the window lives.
final class GroupExpansion: ObservableObject {
    @Published private var closed: Set<AnyHashable> = []

    func isOpen(_ id: some Hashable) -> Binding<Bool> {
        let key = AnyHashable(id)
        return Binding(get: { !self.closed.contains(key) },
                       set: { open in if open { self.closed.remove(key) } else { self.closed.insert(key) } })
    }
}

/// A group row's heading. It is drawn in the outline column and left to run over the empty cells beside it, on a
/// tinted band the width of the table: a SwiftUI Table has no row background of its own, and a group should read
/// as a section heading, not as one more row.
struct GroupHeader: View {
    let title: String
    var facts = ""
    var agent: CodingAgent?
    /// A program group's icon (By Process), when there is no agent.
    var icon: NSImage?
    var dimmed = false

    var body: some View {
        HStack(spacing: 8) {
            if let agent {
                AgentBadge(agent: agent, size: 16)
            } else if let icon {
                Image(nsImage: icon).resizable().frame(width: 16, height: 16)
            } else {
                RoundedRectangle(cornerRadius: 4, style: .continuous).fill(.quaternary).frame(width: 16, height: 16)
            }
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(dimmed ? .secondary : .primary)
            if !facts.isEmpty { Text(facts).font(.system(size: 12)).foregroundStyle(.secondary) }
        }
        .fixedSize()
        .padding(.leading, 2)
    }
}

/// Draws the rows of a SwiftUI Table the way the Events list draws its own: a rounded zebra stripe on every other
/// row, nothing below the last row, and a group row's band (SwiftUI content laid across the whole row, past the
/// disclosure triangle, no colour of its own). SwiftUI's Table can't be told any of this, but AppKit's row view is there
/// behind it. Every row carries one (groups with content, the rest without) because AppKit reuses row views.
struct RowBand: NSViewRepresentable {
    var content: AnyView?

    static let groundID = NSUserInterfaceItemIdentifier("rowbandground")

    /// The Events list's ground (AppKit's table background), behind a SwiftUI table that draws none of its own.
    final class GroundView: NSView {
        override func draw(_ dirtyRect: NSRect) { NSColor.controlBackgroundColor.setFill(); dirtyRect.fill() }
    }

    /// The band's outline: inset and rounded the way the inset table style draws its alternating rows.
    static func shape(in bounds: NSRect) -> NSBezierPath {
        NSBezierPath(roundedRect: bounds.insetBy(dx: 10, dy: 0), xRadius: 5, yRadius: 5)
    }

    func makeNSView(context: Context) -> BandView { BandView() }
    func updateNSView(_ view: BandView, context: Context) { view.content = content; view.apply() }

    final class BandView: NSView {
        var content: AnyView?
        private var trailing: NSLayoutConstraint?
        private static let bandID = NSUserInterfaceItemIdentifier("rowband")
        private static let tintID = NSUserInterfaceItemIdentifier("rowbandtint")

        /// A stripe or a band, drawn (not layered) so it follows the appearance. Which one is decided as it draws:
        /// when the cell is attached the row has no index yet.
        final class TintView: NSView {
            weak var row: NSTableRowView?
            weak var table: NSTableView?
            var isBand = false { didSet { needsDisplay = true } }

            override func draw(_ dirtyRect: NSRect) {
                // SwiftUI re-clears the table's background on every update, which leaves the window's lighter
                // material under the rows: the Events list's ground is put back as the rows draw.
                if let scroll = table?.enclosingScrollView, !scroll.subviews.contains(where: { $0.identifier == RowBand.groundID }) {
                    let ground = GroundView(frame: scroll.bounds)
                    ground.identifier = RowBand.groundID
                    ground.autoresizingMask = [.width, .height]
                    scroll.addSubview(ground, positioned: .below, relativeTo: scroll.contentView)
                }
                // Group rows take part in the zebra like any other row: their heading sets them apart.
                guard let row, let table, table.row(for: row) % 2 == 1 else { return }
                NSColor.alternatingContentBackgroundColors[1].setFill()
                RowBand.shape(in: bounds).fill()
            }
        }

        override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); apply() }
        override func viewDidMoveToSuperview() { super.viewDidMoveToSuperview(); apply() }

        func apply() {
            var v = superview
            while let s = v, !(s is NSTableRowView) { v = s.superview }
            guard let row = v as? NSTableRowView else { return }
            var t: NSView? = row
            while let s = t, !(s is NSTableView) { t = s.superview }
            let table = t as? NSTableView
            // The zebra is ours from here on: AppKit's would also stripe the space below the last row.
            if table?.usesAlternatingRowBackgroundColors == true { table?.usesAlternatingRowBackgroundColors = false }

            let tint = (row.subviews.first { $0.identifier == Self.tintID } as? TintView) ?? {
                let view = TintView()
                view.row = row
                view.table = table
                view.identifier = Self.tintID
                view.translatesAutoresizingMaskIntoConstraints = false
                row.addSubview(view, positioned: .below, relativeTo: nil)
                NSLayoutConstraint.activate([
                    view.leadingAnchor.constraint(equalTo: row.leadingAnchor), view.trailingAnchor.constraint(equalTo: row.trailingAnchor),
                    view.topAnchor.constraint(equalTo: row.topAnchor), view.bottomAnchor.constraint(equalTo: row.bottomAnchor),
                ])
                return view
            }()
            let existing = row.subviews.first { $0.identifier == Self.bandID } as? NSHostingView<AnyView>
            tint.table = table
            tint.needsDisplay = true
            // SwiftUI's row view draws a separator line under each row: the Events list has none.
            for sub in row.subviews where String(describing: type(of: sub)).contains("SeparatorDrawing") { sub.isHidden = true }
            guard let content else {
                existing?.removeFromSuperview()
                tint.isBand = false
                return
            }
            tint.isBand = true
            let host: NSHostingView<AnyView>
            if let existing {
                existing.rootView = content
                host = existing
            } else {
                host = NSHostingView(rootView: content)
                host.identifier = Self.bandID
                host.translatesAutoresizingMaskIntoConstraints = false
                row.addSubview(host)
                NSLayoutConstraint.activate([
                    host.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 22),   // past the triangle
                    host.centerYAnchor.constraint(equalTo: row.centerYAnchor),
                ])
            }
            // The right end sits 22 pt inside the visible width (a table wider than its window would carry it
            // off-screen). A width, not a position: tying the band to the clip view's edge made Auto Layout solve
            // it again on every scroll step, and the list shook. The scroll view is there only once the row is
            // placed, so the relation is checked on every pass.
            let edge: NSView = row.enclosingScrollView?.contentView ?? row
            if trailing?.secondItem !== edge {
                trailing?.isActive = false
                trailing = host.widthAnchor.constraint(equalTo: edge.widthAnchor, constant: -44)
                trailing?.priority = .defaultHigh
                trailing?.isActive = true
            }
            Self.centreDisclosure(in: row)
        }

        /// SwiftUI puts the disclosure triangle at the top of a row taller than its text: the band is centred.
        static func centreDisclosure(in row: NSTableRowView) {
            func visit(_ view: NSView) {
                for sub in view.subviews {
                    // SwiftUI's own disclosure control is a small button at the row's left edge.
                    if let button = sub as? NSButton, button.frame.width <= 24 && button.frame.minX < 40
                        || String(describing: type(of: sub)).lowercased().contains("disclosure") {
                        // Only when it is off: setting a frame while scrolling asks for another layout pass.
                        var frame = button.frame
                        let rowFrame = button.superview!.convert(row.bounds, from: row)
                        let y = (rowFrame.midY - frame.height / 2).rounded()
                        if abs(frame.origin.y - y) > 0.5 { frame.origin.y = y; button.frame = frame }
                    } else {
                        visit(sub)
                    }
                }
            }
            visit(row)
        }
    }
}

/// A link in a group's band ("Only this session", "Mark all Safe…").
struct BandLink {
    let title: String
    let action: () -> Void
}

/// The one band every grouped list draws for a group row (Events, Patterns, Running Now): the heading on the
/// left, then links, notes, the worst status and the count on the right.
struct GroupBand: View {
    var title: String
    var facts = ""
    var agent: CodingAgent?
    var icon: NSImage?
    var dimmed = false
    var links: [BandLink] = []
    var notes: [String] = []
    var newCount = 0
    var status: SignatureStatus?
    var count: Int
    var noun: String

    var body: some View {
        HStack(spacing: 12) {
            GroupHeader(title: title, facts: facts, agent: agent, icon: icon, dimmed: dimmed)
            Spacer(minLength: 12)
            HStack(spacing: 14) {
                ForEach(links.indices, id: \.self) { i in
                    Button(links[i].title, action: links[i].action).buttonStyle(.link).font(.system(size: 11.5))
                }
                ForEach(notes, id: \.self) { Text($0).font(.system(size: 11)).monospacedDigit().foregroundStyle(.secondary) }
                if newCount > 0 { Text("\(newCount) New").font(.system(size: 11)).foregroundStyle(.orange) }
                if let status { StatusPill(status: status).help("The most serious status in this group") }
                CountCapsule(count: count, noun: noun)
            }
        }
        .frame(height: 32)
    }
}

/// "2,341 events" (or "1 event"): a group row's count, as a quiet capsule.
/// An event kind as a small tinted tile (the glyph in its colour on a soft square of it), as macOS draws icons
/// in Settings and sidebars. Used in the lists; the toolbar counters keep the bare glyph.
struct KindTile: View {
    let kind: EventKind
    var size: CGFloat = 16

    var body: some View {
        Image(systemName: kind.symbol)
            .font(.system(size: size * 0.56, weight: .semibold))
            .foregroundStyle(kind.color)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).fill(kind.color.opacity(0.18)))
            .help(kind.title)
            .accessibilityLabel(kind.title)
    }
}

struct CountCapsule: View {
    let count: Int
    let noun: String

    var body: some View {
        Text("\(count.formatted()) \(noun)\(count == 1 ? "" : "s")")
            .font(.system(size: 11)).monospacedDigit()
            .padding(.horizontal, 7).padding(.vertical, 1)
            .background(Capsule().fill(.quaternary.opacity(0.6)))
            .foregroundStyle(.secondary)
    }
}

/// Under the toolbar while the search field filters the list: what it's filtered by, in the accent color, and Clear.
/// `accessory` adds controls (Time Travel's search scope).
struct SearchActiveBar<Accessory: View>: View {
    @Binding var text: String
    @ViewBuilder var accessory: Accessory

    init(text: Binding<String>, @ViewBuilder accessory: () -> Accessory = { EmptyView() }) {
        _text = text
        self.accessory = accessory()
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "line.3.horizontal.decrease.circle.fill").foregroundStyle(.tint)
            Text("Showing only matches for").foregroundStyle(.secondary)
            Text(text.trimmingCharacters(in: .whitespaces))
                .fontWeight(.semibold)
                .foregroundStyle(.tint)
                .lineLimit(1)
                .truncationMode(.middle)
                .padding(.horizontal, 8).padding(.vertical, 2)
                .background(Capsule().fill(Color.accentColor.opacity(0.16)))
                .overlay(Capsule().strokeBorder(Color.accentColor.opacity(0.45), lineWidth: 0.5))
            accessory
            Spacer(minLength: 8)
            Button("Clear Search") { text = "" }
                .help("Show everything again")
        }
        .font(.system(size: 12))
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .background(Color.accentColor.opacity(0.10))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Filtered by search: \(text)")
    }
}

/// Finder-style scope while traveling with a search: everything recorded, or only the shown window.
struct HistorySearchScopeBar: View {
    @ObservedObject var travel: TimeTravel
    @Binding var text: String

    var body: some View {
        SearchActiveBar(text: $text) {
            Text("in").foregroundStyle(.secondary)
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
        }
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
