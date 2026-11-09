import AppKit
import SwiftUI

extension Color {
    /// Claude's warm clay accent, for anything Claude decided or suggested.
    static let claude = Color(red: 0.85, green: 0.47, blue: 0.34)
}

/// "Decided By": regular text with a small mark for who decided (Claude, on-device AI, you, a rule…).
struct DeciderLabel: View {
    let text: String

    private var mark: (symbol: String, color: Color)? {
        if text.contains("Claude") { return ("asterisk", .claude) }
        if text.hasPrefix("AI suggests") { return ("sparkle", .secondary) }
        if text.hasPrefix("AI") { return ("apple.intelligence", .secondary) }
        if text.hasPrefix("You") { return ("person.fill", .secondary) }
        if text.hasPrefix("Rule") { return ("checklist", .secondary) }
        if text.hasPrefix("Baseline") { return ("checkmark.shield", .secondary) }
        if text.hasPrefix("Automatic") { return ("gearshape", .secondary) }
        return nil
    }

    var body: some View {
        HStack(spacing: 4) {
            if let mark {
                Image(systemName: mark.symbol)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(mark.color)
                    .frame(width: 12)
            }
            Text(text).foregroundStyle(text == "New" ? .secondary : .primary).lineLimit(1)
        }
        .help(text)
    }
}

struct StatusPill: View {
    let status: SignatureStatus

    var body: some View {
        // Color carries meaning in the icon, tint and hairline; the label stays in the primary
        // text color so it reads in light and dark mode (colored text on its own tint did not).
        let tint = Color(nsColor: status.nsColor)
        Label {
            Text(status == .unclassified ? "New" : status.title).foregroundStyle(.primary)
        } icon: {
            Image(systemName: status.symbol).foregroundStyle(tint)
        }
        .font(.system(size: 11, weight: .semibold))
        .labelStyle(.titleAndIcon)
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .background(Capsule().fill(tint.opacity(0.16)))
        .overlay(Capsule().strokeBorder(tint.opacity(0.45), lineWidth: 0.5))
        .lineLimit(1)
        .fixedSize()
    }
}

/// "12 dangerous · 3 suspicious · 80 new · 900 safe"
struct PatternTally: View {
    let counts: [SignatureStatus: Int]

    var body: some View {
        HStack(spacing: 10) {
            ForEach([SignatureStatus.dangerous, .suspicious, .unclassified, .safe], id: \.self) { status in
                let n = counts[status] ?? 0
                Label("\(n)", systemImage: status.symbol)
                    .foregroundStyle(n > 0 ? Color(nsColor: status.nsColor) : .secondary)
                    .help("\(n) \(status == .unclassified ? "unclassified" : status.rawValue) patterns")
            }
        }
        .font(.system(size: 11, weight: .medium))
    }
}

struct PatternsView: View {
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    let actions: HUDActions
    @Binding var filter: SignatureFilter
    /// Owned by the window, so the rows survive a tab switch (rebuilding 8,000 rows on every switch froze it ~1 s).
    @ObservedObject var list: PatternListModel
    @StateObject private var combine = CombineState()
    @StateObject private var inspector = InspectorState()
    @StateObject private var groups = GroupExpansion()

    var body: some View {
        let rows = list.rows
        VStack(spacing: 0) {
            toolbar(count: list.shown)
                .sheet(isPresented: $combine.show) { CombineSheet(state: combine, signatures: signatures) }
            Divider()
            HStack(spacing: 0) {
            table(rows)
            if inspector.shown {
                Divider()
                PatternInspector(signatures: signatures, actions: actions)
                    .frame(width: 320)
                    .background(.background.secondary)
                    .transition(.move(edge: .trailing))
            }
            }
            Divider()
            footer(rows)
        }
        .onAppear { list.request(signatures) { filter } }
        .onReceive(signatures.listChanges) { list.request(signatures) { filter } }
        .onChange(of: filter) { list.request(signatures) { filter } }
    }

    /// Whether the Pattern column wraps. Off: one line per row like the Events list (the tooltip and the
    /// inspector have the whole pattern). A probe can turn it on to measure.
    nonisolated(unsafe) static var wrapsPatterns = false

    /// The same band as the Events list's.
    private func band(_ item: PatternItem) -> some View {
        GroupBand(title: displayProcessName(item.entry.process), facts: item.groupFacts, agent: item.agent,
                  icon: item.agent == nil && item.entry.process != "No AI session"
                      ? ProcessIcons.icon(SignatureStore.subjectPath(item.entry)) : nil,
                  dimmed: item.entry.process == "No AI session",
                  links: item.agent == nil ? [] : [BandLink(title: "Mark all Safe…") { markAllSafe(item) }],
                  newCount: item.newCount, status: item.status, count: item.children?.count ?? 0, noun: "pattern")
            .help(item.entry.process)
    }

    /// A session's whole footprint marked Safe at once, after asking.
    private func markAllSafe(_ group: PatternItem) {
        let keys = (group.children ?? []).map(\.id)
        let alert = NSAlert()
        alert.messageText = "Mark \(keys.count) patterns Safe?"
        alert.informativeText = "Everything \(group.entry.process) did so far becomes routine for this Mac. You can mark single patterns back later."
        alert.addButton(withTitle: "Mark Safe")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { signatures.set(.safe, keys: keys) }
    }

    private func table(_ rows: [PatternItem]) -> some View {
            Table(selection: $signatures.selection, sortOrder: $signatures.patternOrder) {
                TableColumn("Status", value: \.priority) { item in
                    Group {
                    Group {
                    if item.isGroup {
                        Color.clear.frame(width: 1, height: 30)        // the band carries the whole row, as tall as on Events
                    } else {
                        HStack(spacing: 4) {
                            StatusPill(status: item.status)
                            if item.entry.risk == .high {
                                Image(systemName: "flame.fill").foregroundStyle(.red).help("High-risk pattern")
                            }
                        }
                    }
                    }
                    .background(RowBand(content: item.isGroup ? AnyView(band(item)) : nil))
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 100, ideal: 112, max: 160)
                TableColumn("Kind", value: \.kind) { item in
                    Group {
                    if item.isGroup {
                        EmptyView()                          // the header runs over this cell
                    } else {
                        Image(systemName: item.entry.kind.symbol)
                            .foregroundStyle(item.entry.kind.color)
                            .help(item.entry.kind.title)
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 24, ideal: 56, max: 64)
                TableColumn("Process", value: \.processName) { item in
                    Group {
                    if item.isGroup {
                        EmptyView()
                    } else {
                        // Under a group row the names step back, so the groups read first.
                        let grouped = signatures.groupBySession || signatures.groupByProcess
                        Text(displayProcessName(item.entry.process)).fontWeight(grouped ? .regular : .semibold)
                            .lineLimit(1).truncationMode(.tail).help(item.entry.process)
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 60, ideal: signatures.groupBySession ? 260 : 110)
                TableColumn("Pattern", value: \.pattern) { item in
                    Group {
                    if item.isGroup {
                        EmptyView()
                    } else {
                        // Whole, wrapped: a pattern is what you decide on, so it must be readable without
                        // dragging the column wider. The inspector has it selectable, with the rest.
                        Text(item.pattern)
                            .lineLimit(Self.wrapsPatterns ? 3 : 1)
                            .fixedSize(horizontal: false, vertical: Self.wrapsPatterns)
                            .truncationMode(.middle)
                            .help(RuleText.does(kind: item.entry.kind, pattern: item.pattern))
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 160, ideal: 360)
                TableColumn("Decided By", value: \.decidedBy) { item in
                    Group {
                    if !item.isGroup { DeciderLabel(text: item.decidedBy) }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 56, ideal: 96, max: 220)
                TableColumn("Signer", value: \.signer) { item in
                    Group {
                    let id = SigningCache.shared.cached(SignatureStore.subjectPath(item.entry))
                    if !item.isGroup {
                    HStack(spacing: 4) {
                        if let id, id.untrustedCode || id.valid == false {
                            Image(systemName: "exclamationmark.shield").foregroundStyle(.orange)
                        } else if let id, SigningCache.shared.isTrusted(id) {
                            Image(systemName: "checkmark.seal").foregroundStyle(.green)
                        }
                        Text(item.signer)
                    }
                    .help(id.map { "\($0.label) · Team \($0.teamID ?? "none")"
                        + (SigningCache.shared.isTrusted($0) ? " · trusted" : "") } ?? "not inspected yet")
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 70, ideal: 130, max: 220)
                TableColumn("Reason", value: \.reason) { item in
                    Group {
                    if !item.isGroup { Text(item.reason).foregroundStyle(.secondary).help(item.reason) }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 60, ideal: 140)
                TableColumn("Count", value: \.count) { item in
                    Group {
                    if !item.isGroup { Text("\(item.count)×").monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing) }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 50, ideal: 70, max: 100)
                TableColumn("First Seen", value: \.firstSeen) { item in
                    Group {
                    if !item.isGroup {
                        Text(Self.relative.localizedString(for: item.firstSeen, relativeTo: Date()))
                            .foregroundStyle(.secondary).help(item.firstSeen.formatted())
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 70, ideal: 90, max: 130)
                TableColumn("Last Seen", value: \.lastSeen) { item in
                    Group {
                    if !item.isGroup {
                        Text(Self.relative.localizedString(for: item.lastSeen, relativeTo: Date()))
                            .foregroundStyle(.secondary).help(item.lastSeen.formatted())
                    }
                    }
                    .font(.system(size: 12, design: .monospaced))
                }
                .width(min: 70, ideal: 90, max: 130)
            } rows: {
                // Group rows start folded; a click on one is remembered while the window lives.
                ForEach(rows) { item in
                    if let kids = item.children {
                        DisclosureTableRow(item, isExpanded: groups.isOpen(item.id)) {
                            ForEach(kids) { TableRow($0) }
                        }
                    } else {
                        TableRow(item)
                    }
                }
            }
            .font(.system(size: 11, weight: .bold))                       // the column legend, as AppKit draws it on Events
            .tableStyle(.inset(alternatesRowBackgrounds: false))           // the zebra is drawn by RowBand, like Events
            .overlay {
                if rows.isEmpty && list.built {
                    ContentUnavailableView {
                        Label(signatures.search.isEmpty ? "No patterns here" : "No matches", systemImage: "magnifyingglass")
                    } description: {
                        Text(signatures.search.isEmpty
                             ? "Nothing matches the current Show filter. New patterns appear as programs do things."
                             : "No pattern matches “\(signatures.search)”. Seen-once patterns are searched too.")
                    }
                }
            }
            // A click on the only selected row deselects it (the Table itself can't); Escape clears the selection.
            .onExitCommand { signatures.selection.removeAll() }
            .background(ClickTracker(current: { signatures.selection }, clear: { signatures.selection = [] }))
            // Double-click (primaryAction) asks AI; right-click acts on the selection.
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first, id.hasPrefix(PatternItem.groupPrefix) || id.hasPrefix(PatternItem.sessionPrefix) {
                    groupMenu(ids)
                } else if let id = ids.first, let entry = signatures.entry(id) { menu(for: entry) }
            } primaryAction: { ids in
                if let id = ids.first, let entry = signatures.entry(id) { actions.askAI(entry.exampleEvent) }
            }
    }

    private func footer(_ rows: [PatternItem]) -> some View {
            HStack {
                Text(!classifier.lastMessage.isEmpty ? classifier.lastMessage
                     : !signatures.tidySummary.isEmpty ? signatures.tidySummary
                     : "Patterns are fingerprints: the same process doing the same kind of thing is one pattern.")
                    .lineLimit(1)
                Spacer()
                PatternTally(counts: list.counts.byStatus)
                Text("·")
                Text("\(signatures.keys(forSelection: signatures.selection).count) selected · \(list.shown) shown"
                     + (signatures.groupBySession ? " · \(rows.count) groups" : signatures.groupByProcess ? " · \(rows.count) programs" : ""))
                    .monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
    }

    private func toolbar(count: Int) -> some View {
        HStack(spacing: 10) {
            if let scope = signatures.scope {
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill").foregroundStyle(.tint)
                    Text("\(scope.title) · \(scope.keys.count) pattern\(scope.keys.count == 1 ? "" : "s")").lineLimit(1)
                    Button { signatures.scope = nil } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .help("Show all patterns")
                }
                .font(.system(size: 12, weight: .medium))
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(Capsule().fill(Color.accentColor.opacity(0.14)))
                .fixedSize()
            } else {
                Text("Show").font(.system(size: 11)).foregroundStyle(.secondary)
                ShowFilterPicker(filter: $filter, counts: [.unclassified: list.counts.new, .important: list.counts.important],
                                 allowsMenu: false)
                let once = list.counts.oneOffs
                Toggle(isOn: $signatures.showSeenOnce) {
                    Label("Seen Once\(once > 0 ? " \(once)" : "")", systemImage: "1.circle")
                }
                .toggleStyle(.button)
                .fixedSize()
                .help("Patterns seen only once, that you didn't decide and aren't risky: hidden unless this is on (search "
                      + "finds them anyway). They're forgotten a week later unless they happen again.")
            }
            Divider().frame(height: 16)
            Text("Group").font(.system(size: 11)).foregroundStyle(.secondary)
            // The same control as on Events: flat, one row per program, or one row per AI session.
            Picker("Group", selection: Binding(
                get: { signatures.groupBySession ? EventGrouping.session : signatures.groupByProcess ? .process : .none },
                set: { choice in
                    signatures.groupBySession = choice == .session
                    signatures.groupByProcess = choice == .process
                })) {
                ForEach(EventGrouping.allCases, id: \.self) { Label($0.title, systemImage: $0.symbol).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("Group the patterns: flat, one row per program, or one row per AI coding session (Claude Code, Cursor agent, Codex, Gemini CLI) with the patterns it produced under it, seen-once ones included; the rest under No AI session")
            Menu("Mark Selected") {
                ForEach(SignatureStatus.allCases, id: \.self) { status in
                    Button(status == .unclassified ? "Unclassified" : status.title) {
                        signatures.set(status, keys: signatures.keys(forSelection: signatures.selection))
                    }
                }
                Divider()
                Button("Combine Into One Pattern…") { combine.start(signatures.keys(forSelection: signatures.selection), signatures) }
                    .disabled(signatures.keys(forSelection: signatures.selection).count < 2)
                Button("Delete Selected Patterns") { signatures.delete(keys: signatures.keys(forSelection: signatures.selection)) }
            }
            .disabled(signatures.selection.isEmpty)
            .fixedSize()
            Spacer()
            ClassifyAllButton(classifier: classifier, signatures: signatures)
            Button { actions.openBaseline() } label: { Label("Needs You…", systemImage: "checklist") }
                .buttonStyle(.glass)
                .help("Rules ▸ Needs You: decide New patterns, with AI suggestions")
            Toggle(isOn: $inspector.shown.animation(.snappy(duration: 0.2))) { Image(systemName: "sidebar.trailing") }
                .toggleStyle(.button)
                .help(inspector.shown ? "Hide the inspector" : "Show the inspector: the selected pattern in full")
        }
        .controlSize(.small)
        .buttonBorderShape(.capsule)                    // every toolbar button the shape of the Show and Group controls
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    /// Trust (or stop trusting) the developer who signed this pattern's binary; re-scores patterns.
    @ViewBuilder
    private func trustMenu(for entry: SignatureEntry) -> some View {
        let cache = SigningCache.shared
        if let id = cache.cached(SignatureStore.subjectPath(entry)), id.signed, !id.adhoc, !id.apple,
           let team = id.teamID {
            let name = id.organization ?? team
            if cache.trustedTeams.contains(team) {
                Button("Stop Trusting Developer “\(name)” (\(team))") {
                    cache.setTrusted(team, false); signatures.reassess()
                }
            } else {
                Button("Trust Developer “\(name)” (\(team))") {
                    cache.setTrusted(team, true); signatures.reassess()
                }
            }
            Divider()
        }
    }

    @ViewBuilder
    private func menu(for entry: SignatureEntry) -> some View {
        // Act on the whole selection when right-clicking inside it.
        let keys = signatures.selection.contains(entry.id) ? signatures.keys(forSelection: signatures.selection) : [entry.id]
        Button("Ask AI About This Pattern…") { actions.askAI(entry.exampleEvent) }
        Divider()
        if keys.count > 1 {
            Button("Combine \(keys.count) Patterns into One…") { combine.start(keys, signatures) }
        }
        if signatures.isCombined(entry.id) {
            Button("Separate Combined Pattern") { signatures.separate(entry.id) }
        }
        trustMenu(for: entry)
        ForEach(SignatureStatus.allCases, id: \.self) { status in
            Button("Mark \(keys.count > 1 ? "\(keys.count) Patterns" : "Pattern") \(status.title)") {
                signatures.set(status, keys: keys)
            }
        }
        Menu("Mark All \(entry.kind.title) From \((entry.process as NSString).lastPathComponent)") {
            ForEach(SignatureStatus.allCases, id: \.self) { status in
                Button(status == .unclassified ? "Clear Rule" : status.title) {
                    signatures.setProcessRule(status, kind: entry.kind, process: entry.process)
                }
                .disabled(status == .safe && !SignatureStore.canTrustWholeProcess(entry.process))
            }
        }
        Divider()
        Button("Copy Pattern") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("\(entry.process) → \(entry.pattern)", forType: .string)
        }
        Button("Delete Pattern") { signatures.delete(keys: keys) }
    }
}

extension PatternsView {
    /// Right-click on a program's row (grouped): acts on all its listed patterns.
    @ViewBuilder
    func groupMenu(_ ids: Set<String>) -> some View {
        let all = ids.union(signatures.selection.filter { $0.hasPrefix(PatternItem.groupPrefix) && ids.contains($0) })
        let keys = signatures.keys(forSelection: signatures.selection.isSuperset(of: ids) ? signatures.selection : all)
        let names = all.filter { $0.hasPrefix(PatternItem.groupPrefix) }.map { String($0.dropFirst(PatternItem.groupPrefix.count)) }.sorted()
        ForEach(SignatureStatus.allCases, id: \.self) { status in
            Button("Mark All \(keys.count) Patterns \(status.title)") { signatures.set(status, keys: keys) }
        }
        Divider()
        if names.count == 1, let name = names.first {
            Button("Show Only \(name)") { signatures.search = name }
        }
        Button("Copy Program Name\(names.count > 1 ? "s" : "")") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(names.joined(separator: "\n"), forType: .string)
        }
        Divider()
        Button("Delete All \(keys.count) Patterns") { signatures.delete(keys: keys) }
    }
}

/// Watches clicks over the table: a single click on the row that was already the only selection, with no modifier
/// keys, clears the selection on mouse-up (the Table keeps it selected otherwise, with no way to deselect but ⌘-click).
private struct ClickTracker: NSViewRepresentable {
    let current: () -> Set<String>
    let clear: () -> Void

    func makeNSView(context: Context) -> NSView {
        let view = TrackerView()
        view.current = current; view.clear = clear
        return view
    }
    func updateNSView(_ nsView: NSView, context: Context) {
        (nsView as? TrackerView)?.current = current; (nsView as? TrackerView)?.clear = clear
    }

    final class TrackerView: NSView {
        var current: (() -> Set<String>)?
        var clear: (() -> Void)?
        private var monitor: Any?
        private var before: Set<String> = []
        private var pending = false

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if monitor != nil { NSEvent.removeMonitor(monitor!); monitor = nil }
            guard window != nil else { return }
            // Only reads on mouse-down (writing the selection there re-rendered the table and cancelled a
            // column-edge drag in the header); writes once, on mouse-up, and only to clear.
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .leftMouseUp]) { [weak self] event in
                guard let self, let window = self.window, event.window == window else { return event }
                let inTable = self.superview.map { $0.bounds.contains($0.convert(event.locationInWindow, from: nil)) } ?? false
                guard inTable, event.modifierFlags.intersection([.command, .shift, .option]).isEmpty else { return event }
                if event.type == .leftMouseDown {
                    self.pending = event.clickCount == 1
                    self.before = self.current?() ?? []
                } else if self.pending {
                    self.pending = false
                    let before = self.before
                    DispatchQueue.main.async { [weak self] in
                        guard let self, let now = self.current?(), now.count == 1, now == before else { return }
                        self.clear?()
                    }
                }
                return event
            }
        }
    }
}

/// Whether the inspector is shown; remembered.
final class InspectorState: ObservableObject {
    @Published var shown = UserDefaults.standard.object(forKey: "patternsInspector") as? Bool ?? true {
        didSet { UserDefaults.standard.set(shown, forKey: "patternsInspector") }
    }
}

// MARK: - Combine patterns

final class CombineState: ObservableObject {
    @Published var show = false
    @Published var keys: [String] = []
    @Published var process = ""
    @Published var pattern = ""

    /// Proposes the shared pattern: the chosen ones' common shape.
    @MainActor func start(_ keys: [String], _ signatures: SignatureStore) {
        let chosen = keys.compactMap { signatures.entry($0) }
        guard chosen.count > 1 else { return }
        self.keys = chosen.map(\.id)
        process = SignatureBuilder.commonGlob(chosen.map(\.process))
        pattern = SignatureBuilder.commonGlob(chosen.map(\.pattern))
        show = true
    }
}

/// "Combine into One Pattern": the proposed shared pattern (editable), what it covers, why not if it can't.
private struct CombineSheet: View {
    @ObservedObject var state: CombineState
    @ObservedObject var signatures: SignatureStore

    var body: some View {
        let chosen = state.keys.compactMap { signatures.entry($0) }
        let problems = signatures.combineProblems(keys: state.keys, process: state.process, pattern: state.pattern)
        let kind = chosen.first?.kind ?? .file
        let covered = signatures.covered(kind: kind, process: state.process, pattern: state.pattern)
        let others = covered.filter { !state.keys.contains($0.id) }
        VStack(alignment: .leading, spacing: 14) {
            Text("Combine \(chosen.count) Patterns into One").font(.headline)
            Text("One shared pattern replaces them; later activity that matches it joins it instead of making new patterns.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 3) {
                ForEach(chosen.prefix(6)) { e in
                    Text("\((e.process as NSString).lastPathComponent)  \(e.pattern)")
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                if chosen.count > 6 { Text("and \(chosen.count - 6) more").font(.caption).foregroundStyle(.tertiary) }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.secondary.opacity(0.08)))
            Form {
                TextField("Program", text: $state.process).font(.system(.body, design: .monospaced))
                TextField("Pattern", text: $state.pattern).font(.system(.body, design: .monospaced))
            }
            .formStyle(.columns)
            Text("* stands for anything there. Edit to make it narrower or wider.").font(.caption).foregroundStyle(.secondary)
            if problems.isEmpty {
                Label(others.isEmpty ? "Covers the \(chosen.count) chosen patterns."
                      : "Covers the \(chosen.count) chosen patterns and \(others.count) more that look the same.",
                      systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.callout)
            } else {
                ForEach(problems, id: \.self) { Label($0, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.callout) }
            }
            HStack {
                Spacer()
                Button("Cancel") { state.show = false }.keyboardShortcut(.cancelAction)
                Button("Combine") {
                    signatures.combine(keys: state.keys, process: state.process, pattern: state.pattern)
                    state.show = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!problems.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 560)
    }
}
