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

/// Which group rows are open. Groups start folded, so a grouping reads as its list of headings; a click on a
/// disclosure is kept while the window lives.
final class GroupExpansion: ObservableObject {
    @Published private var open: Set<AnyHashable> = []

    func isOpen(_ id: some Hashable) -> Binding<Bool> {
        let key = AnyHashable(id)
        return Binding(get: { self.open.contains(key) },
                       set: { isOpen in if isOpen { self.open.insert(key) } else { self.open.remove(key) } })
    }
}

/// A group row's heading. It is drawn in the outline column and left to run over the empty cells beside it, on a
/// tinted band the width of the table: a SwiftUI Table has no row background of its own, and a group should read
/// as a section heading, not as one more row.
struct GroupHeader: View {
    let title: String
    var facts = ""
    var agent: CodingAgent?
    var dimmed = false

    var body: some View {
        HStack(spacing: 8) {
            if let agent {
                AgentBadge(agent: agent, size: 16)
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

/// Tints the whole table row the cell sits in. SwiftUI's Table has no row background of its own, but AppKit's
/// row view does, so a group row can be a band the width of the table. Every row carries one (group rows with a
/// colour, the rest with none), because AppKit reuses row views and a tint would otherwise stay behind.
struct RowTint: NSViewRepresentable {
    var color: NSColor?

    /// The band behind a group row, over either appearance.
    static let group = NSColor.controlAccentColor.withAlphaComponent(0.13)

    func makeNSView(context: Context) -> TintView { TintView() }
    func updateNSView(_ view: TintView, context: Context) { view.color = color; view.apply() }

    final class TintView: NSView {
        var color: NSColor?
        override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); apply() }
        override func viewDidMoveToSuperview() { super.viewDidMoveToSuperview(); apply() }
        func apply() {
            var v = superview
            while let s = v, !(s is NSTableRowView) { v = s.superview }
            guard let row = v as? NSTableRowView else { return }
            // A table with alternating row colours ignores `backgroundColor`: the group-row style is drawn
            // regardless, and is AppKit's own section-heading look.
            row.isGroupRowStyle = color != nil
            row.backgroundColor = color ?? .clear
            row.needsDisplay = true
        }
    }
}

/// "2,341 events" (or "1 event"): a group row's count, as a quiet capsule.
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
