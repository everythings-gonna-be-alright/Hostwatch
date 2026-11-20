import AppKit
import SwiftUI

/// Protection ▸ Found: everything protection would stop or ask about, launches, files and connections together,
/// grouped by program so a long list is a short one. Filter by area and kind, search, sort, and decide a whole program
/// at once. A row leaves the moment you act on it.
struct FoundPage: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    let connections: () -> [(FirewallEntry, FirewallDecision)]
    var markConnection: ((FirewallEntry, SignatureStatus) -> Void)? = nil
    let mark: ([String], SignatureStatus) -> Void
    @StateObject private var state = FoundState()

    var body: some View {
        let _ = protection.revision
        let all = items()
        let shown = state.filter(all)
        let groups = state.arrange(FoundGroup.make(shown, sort: state.sort))
        VStack(alignment: .leading, spacing: 18) {
            hero(all)
            if all.isEmpty {
                allClear
            } else {
                FoundFilterBar(state: state, all: all)
                if groups.isEmpty {
                    Text("Nothing matches. Clear the search or choose another filter.")
                        .foregroundStyle(.secondary).padding(.horizontal, 4)
                }
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(groups.prefix(state.groupLimit)) { g in
                        FoundGroupCard(group: g, state: state, act: act, actAll: actAll)
                    }
                    if groups.count > state.groupLimit {
                        Button("Show \(min(30, groups.count - state.groupLimit)) More Programs") { state.groupLimit += 30 }
                            .buttonStyle(.glass).controlSize(.small)
                    }
                }
            }
        }
    }

    // MARK: Items

    private func items() -> [FoundItem] {
        let files = protection.findings.values.map(FoundItem.init(finding:))
        let net = connections().map { FoundItem(entry: $0.0, decision: $0.1) }
        return (files + net).filter { !state.gone.contains($0.id) }
    }

    // MARK: Header

    private func hero(_ all: [FoundItem]) -> some View {
        let stops = all.filter(\.blocks).count
        let questions = all.count - stops
        let top = Dictionary(grouping: all, by: \.program).max { $0.value.count < $1.value.count }
        let oldest = all.min { $0.lastSeen < $1.lastSeen }
        let overall = protection.state(network: firewall?.mode ?? .off)
        let areaState: AreaState = overall == .paused ? .paused : overall == .off ? .off : overall == .protecting ? .protecting : .watching
        let sentence = all.isEmpty ? "Nothing to decide. What would be stopped or asked about appears here first."
            : "Allow marks a pattern Safe, Block marks it Dangerous, and either way it leaves this list. What doesn't "
              + "happen again leaves by itself: a question after a week, a stop after a month."
        return AreaHero(symbol: "exclamationmark.shield.fill", title: "Found", accent: AreaAccent.found, state: areaState,
                        sentence: sentence, facts: [
            StatusFact(symbol: "tray.full", title: "To review", value: all.count.formatted(),
                       detail: "\(Set(all.map(\.program)).count) programs"),
            StatusFact(symbol: "nosign", title: "Would stop", value: stops.formatted(),
                       detail: stops == 0 ? "Nothing would be stopped" : "Stopped in Ask and Strict"),
            StatusFact(symbol: "questionmark.bubble", title: "Questions", value: questions.formatted(),
                       detail: "Asked about in Ask"),
            StatusFact(symbol: "flame", title: "Found most", value: top.map { $0.value[0].programName } ?? "Nobody",
                       detail: top.map { "\($0.value.count) entries" } ?? "Nothing yet"),
            StatusFact(symbol: "clock.arrow.circlepath", title: "Oldest", value: oldest.map {
                $0.lastSeen.formatted(.relative(presentation: .named)) } ?? "None",
                       detail: "Unseen entries leave by themselves"),
        ]) {
            forgetMenu(all)
        } notice: {
            EmptyView()
        }
    }

    private func forgetMenu(_ all: [FoundItem]) -> some View {
        let dayAgo = Date().addingTimeInterval(-86_400)
        let shown = state.filter(all)
        return Menu {
            Button("Forget Shown (\(shown.count))") { forget(shown) }.disabled(shown.count == all.count || shown.isEmpty)
            Button("Forget Questions (\(all.filter { !$0.blocks }.count))") { forget(all.filter { !$0.blocks }) }
            Button("Forget Older Than a Day (\(all.filter { $0.lastSeen < dayAgo }.count))") { forget(all.filter { $0.lastSeen < dayAgo }) }
            Divider()
            Button("Forget All (\(all.count))") { forget(all) }
        } label: {
            Label("Forget", systemImage: "eraser")
        }
        .menuStyle(.button).buttonStyle(.glass).fixedSize()
        .help("Clear entries from this list. Decisions, rules and patterns stay, and what happens again comes back.")
    }

    private var allClear: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.seal.fill").font(.system(size: 44)).foregroundStyle(.green)
                .symbolRenderingMode(.hierarchical)
            Text("All clear").font(.title3.weight(.semibold))
            Text("Nothing would be stopped or asked about. When something is, it waits here for your decision.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    // MARK: Actions

    /// One decision: hidden at once (the stores catch up a moment later), then made.
    private func act(_ item: FoundItem, _ action: FoundAction) {
        state.hide([item.id])
        perform(item, action)
    }

    /// The same decision for a whole program's entries.
    private func actAll(_ items: [FoundItem], _ action: FoundAction) {
        // A threat list's match is never allowed in bulk: each needs its own confirmed Allow Anyway.
        let chosen = action == .allow ? items.filter { !$0.onThreatList } : items
        state.hide(chosen.map(\.id))
        if action == .forget { forget(chosen); return }
        for item in chosen { perform(item, action) }
    }

    private func perform(_ item: FoundItem, _ action: FoundAction) {
        switch (item.source, action) {
        case (.finding(let f), .allow): mark([f.patternKey], .safe)
        case (.finding(let f), .block): mark([f.patternKey], .dangerous)
        case (.finding(let f), .forget): protection.forget([f.id])
        case (.connection(let e, _), .allow):
            if item.onThreatList {
                if ThreatException.confirm(e) { firewall?.setThreatException(true, e.facts) } else { state.unhide([item.id]) }
                return
            }
            // A domain you blocked for this app outranks the pattern: Safe alone changed nothing.
            if let domain = firewall?.blockedDomain(e.facts) { firewall?.setBlocked(false, domain: domain, program: e.facts.program) }
            markConnection?(e, .safe) ?? mark([e.facts.patternKey], .safe)
        case (.connection(let e, _), .block):
            // Only this destination for this program: its pattern is often the whole web.
            if firewall?.blockDestination(e.facts) != true { markConnection?(e, .dangerous) ?? mark([e.facts.patternKey], .dangerous) }
        case (.connection(let e, _), .forget): firewall?.dismiss([e.id])
        }
    }

    private func forget(_ items: [FoundItem]) {
        state.hide(items.map(\.id))
        var findings: [String] = [], entries: [String] = []
        for i in items {
            switch i.source {
            case .finding(let f): findings.append(f.id)
            case .connection(let e, _): entries.append(e.id)
            }
        }
        if !findings.isEmpty { protection.forget(findings) }
        if !entries.isEmpty { firewall?.dismiss(entries) }
    }
}

enum FoundAction { case allow, block, forget }

/// Launches, files or connections: Found's first filter.
enum FoundArea: String, CaseIterable {
    case all, launches, files, connections

    var title: String {
        switch self {
        case .all: "All"
        case .launches: "Launches"
        case .files: "Files"
        case .connections: "Connections"
        }
    }
}

enum FoundKind: String, CaseIterable { case everything, stops, questions }

enum FoundSort: String, CaseIterable {
    case often, recent, name

    var title: String {
        switch self {
        case .often: "Most Often"
        case .recent: "Most Recent"
        case .name: "Program Name"
        }
    }
}

/// One entry of Found, from a launch or file finding or from a connection the firewall found.
struct FoundItem: Identifiable {
    enum Source {
        case finding(ProtectionFinding)
        case connection(FirewallEntry, FirewallDecision)
    }

    let id: String
    let source: Source
    let area: FoundArea
    let program: String
    let programName: String
    let what: String
    let reason: String
    let blocks: Bool
    let enforced: Bool
    let onThreatList: Bool
    let count: Int
    let lastSeen: Date

    init(finding f: ProtectionFinding) {
        id = "p|" + f.id
        source = .finding(f)
        area = f.area == .launches ? .launches : .files
        program = f.program
        programName = f.name.isEmpty ? (f.program as NSString).lastPathComponent : f.name
        what = f.pattern
        reason = f.reason
        blocks = f.verdict == .block
        enforced = f.enforced
        onThreatList = false
        count = f.count
        lastSeen = f.lastSeen
    }

    init(entry e: FirewallEntry, decision d: FirewallDecision) {
        id = "n|" + e.id
        source = .connection(e, d)
        area = .connections
        program = e.facts.program
        programName = e.name
        what = "\(e.facts.proto) \(e.destination):\(e.facts.port)"
        reason = d.reason
        blocks = d.verdict == .block
        enforced = false
        onThreatList = !e.facts.knownBad.isEmpty
        count = e.count
        lastSeen = e.lastSeen
    }

    var kind: EventKind {
        switch area {
        case .launches: .exec
        case .files: .file
        default: .net
        }
    }

    func matches(_ text: String) -> Bool {
        text.isEmpty || [programName, program, what, reason].contains { $0.localizedCaseInsensitiveContains(text) }
    }
}

/// One program's entries, the unit Found is read and decided in.
struct FoundGroup: Identifiable {
    let program: String
    let name: String
    let items: [FoundItem]
    var id: String { program }
    var stops: Int { items.filter(\.blocks).count }
    var total: Int { items.reduce(0) { $0 + $1.count } }
    var lastSeen: Date { items.map(\.lastSeen).max() ?? .distantPast }

    static func make(_ items: [FoundItem], sort: FoundSort) -> [FoundGroup] {
        let groups = Dictionary(grouping: items, by: \.program).map { program, list in
            FoundGroup(program: program, name: list[0].programName,
                       items: list.sorted { ($0.blocks ? 0 : 1, -$0.count) < ($1.blocks ? 0 : 1, -$1.count) })
        }
        switch sort {
        case .often: return groups.sorted { ($0.stops > 0 ? 0 : 1, -$0.total) < ($1.stops > 0 ? 0 : 1, -$1.total) }
        case .recent: return groups.sorted { $0.lastSeen > $1.lastSeen }
        case .name: return groups.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        }
    }
}

/// Found's filters, search and what you just decided (hidden at once, before the stores publish it).
@MainActor final class FoundState: ObservableObject {
    @Published var area: FoundArea = .all
    @Published var kind: FoundKind = .everything
    @Published var search = ""
    @Published var sort: FoundSort = .often
    @Published var groupLimit = 30
    @Published var open: Set<String> = []
    @Published private(set) var gone: Set<String> = []

    func filter(_ items: [FoundItem]) -> [FoundItem] {
        items.filter { i in
            (area == .all || i.area == area)
                && (kind == .everything || (kind == .stops) == i.blocks)
                && i.matches(search.trimmingCharacters(in: .whitespaces))
        }
    }

    /// Hidden now, and let go a few seconds later: by then the stores have it, and an entry that happens again may
    /// come back.
    func hide(_ ids: [String]) {
        withAnimation(.easeOut(duration: 0.2)) { gone.formUnion(ids) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            MainActor.assumeIsolated { self?.gone.subtract(ids) }
        }
    }

    func unhide(_ ids: [String]) { gone.subtract(ids) }

    /// The order on screen, kept while you work: deciding an entry changes its program's counts, and re-sorting
    /// moved the program away from under the pointer. Programs and entries keep the place they were first shown in,
    /// new ones come after. A new sort, filter or search orders everything afresh. Not published: it only remembers.
    private var groupRank: [String: Int] = [:]
    private var itemRank: [String: Int] = [:]
    private var arrangedFor = ""

    func arrange(_ groups: [FoundGroup]) -> [FoundGroup] {
        let key = [sort.rawValue, area.rawValue, kind.rawValue, search.trimmingCharacters(in: .whitespaces).lowercased()]
            .joined(separator: "|")
        if key != arrangedFor { arrangedFor = key; groupRank = [:]; itemRank = [:] }
        var nextGroup = (groupRank.values.max() ?? -1) + 1
        var nextItem = (itemRank.values.max() ?? -1) + 1
        for g in groups {
            if groupRank[g.id] == nil { groupRank[g.id] = nextGroup; nextGroup += 1 }
            for i in g.items where itemRank[i.id] == nil { itemRank[i.id] = nextItem; nextItem += 1 }
        }
        return groups.sorted { groupRank[$0.id, default: 0] < groupRank[$1.id, default: 0] }.map { g in
            FoundGroup(program: g.program, name: g.name,
                       items: g.items.sorted { itemRank[$0.id, default: 0] < itemRank[$1.id, default: 0] })
        }
    }
}

/// Area and kind as segmented controls with counts, the search field and the sort.
private struct FoundFilterBar: View {
    @ObservedObject var state: FoundState
    let all: [FoundItem]

    var body: some View {
        HStack(spacing: 12) {
            Picker("Area", selection: $state.area) {
                ForEach(FoundArea.allCases, id: \.self) { a in
                    let n = a == .all ? all.count : all.filter { $0.area == a }.count
                    Text("\(a.title) \(n)").tag(a)
                }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            Picker("Kind", selection: $state.kind) {
                Text("Everything").tag(FoundKind.everything)
                Text("Would Stop").tag(FoundKind.stops)
                Text("Questions").tag(FoundKind.questions)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            Spacer(minLength: 8)
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Program, pattern or destination", text: $state.search).textFieldStyle(.plain)
                if !state.search.isEmpty {
                    Button { state.search = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.borderless).foregroundStyle(.secondary).help("Clear the search")
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .frame(minWidth: 180, maxWidth: 280)
            .background(Capsule().fill(Color.primary.opacity(0.06)))
            Menu {
                Picker("Sort", selection: $state.sort) {
                    ForEach(FoundSort.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.inline)
            } label: {
                Label("Sort", systemImage: "arrow.up.arrow.down")
            }
            .menuStyle(.button).buttonStyle(.glass).fixedSize()
            .help("Order the programs")
        }
        .controlSize(.small)
    }
}

/// One program: its icon and name, how much it found, Decide All, and its entries (the first five, then the rest on
/// request).
private struct FoundGroupCard: View {
    let group: FoundGroup
    @ObservedObject var state: FoundState
    let act: (FoundItem, FoundAction) -> Void
    let actAll: ([FoundItem], FoundAction) -> Void

    private static let preview = 5

    var body: some View {
        let open = state.open.contains(group.id)
        let rows = open ? group.items : Array(group.items.prefix(Self.preview))
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: ProcessIcons.icon(group.program)).resizable().frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.name).font(.headline).lineLimit(1)
                    HStack(spacing: 6) {
                        if group.stops > 0 {
                            Label("\(group.stops) would stop", systemImage: "nosign").foregroundStyle(.red)
                        }
                        if group.items.count > group.stops {
                            Label("\(group.items.count - group.stops) to ask", systemImage: "questionmark.circle")
                                .foregroundStyle(.orange)
                        }
                        Text("\(group.total.formatted())× in all").foregroundStyle(.secondary).monospacedDigit()
                    }
                    .font(.caption).labelStyle(.titleAndIcon)
                }
                Spacer(minLength: 8)
                Menu {
                    Button("Allow All \(group.items.count)") { actAll(group.items, .allow) }
                    Button("Block All \(group.items.count)") { actAll(group.items, .block) }
                    Divider()
                    Button("Forget All \(group.items.count)") { actAll(group.items, .forget) }
                } label: {
                    Text("Decide All")
                }
                .menuStyle(.button).buttonStyle(.glass).controlSize(.small).fixedSize()
                .help("Allow, block or forget every entry of \(group.name) at once. A threat list's match is never allowed in bulk")
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            Divider().padding(.leading, 14)
            ForEach(rows) { item in
                FoundRow(item: item, act: act)
                    .transition(.asymmetric(insertion: .opacity, removal: .move(edge: .trailing).combined(with: .opacity)))
            }
            if group.items.count > Self.preview {
                Button(open ? "Show Fewer" : "Show \(group.items.count - Self.preview) More") {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        if open { state.open.remove(group.id) } else { state.open.insert(group.id) }
                    }
                }
                .buttonStyle(.borderless).controlSize(.small).padding(.horizontal, 14).padding(.vertical, 8)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

/// One entry: its kind, what it touched, why, how often, and Allow, Block and Forget at the trailing edge. The row
/// lights up under the pointer, and the same actions are in its context menu.
private struct FoundRow: View {
    let item: FoundItem
    let act: (FoundItem, FoundAction) -> Void
    @StateObject private var hover = ExpandState()

    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; f.dateTimeStyle = .named; return f
    }()

    private var verdict: String {
        if item.onThreatList { return "On a threat list" }
        if item.blocks { return item.enforced ? "Stopped" : "Would stop" }
        return "Would ask"
    }

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            KindTile(kind: item.kind, size: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(verdict).font(.caption.weight(.semibold)).foregroundStyle(item.blocks ? Color.red : Color.orange)
                    Text("\(item.count.formatted())× · \(Self.relative.localizedString(for: item.lastSeen, relativeTo: Date()))")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Text(item.what).font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    .help(item.what)
                Text(item.reason).font(.caption).foregroundStyle(.secondary).lineLimit(1).help(item.reason)
            }
            Spacer(minLength: 8)
            Button(item.onThreatList ? "Allow Anyway…" : "Allow") { act(item, .allow) }
                .help(item.onThreatList ? "On a threat list: allow it anyway, after a confirmation" : "Mark the pattern Safe")
            Button("Block") { act(item, .block) }
                .help(item.area == .connections ? "Block this destination for this program" : "Mark the pattern Dangerous")
            Button { act(item, .forget) } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless).foregroundStyle(.secondary)
                .help("Remove from this list without deciding")
                .accessibilityLabel("Forget")
        }
        .controlSize(.small)
        .padding(.horizontal, 14).padding(.vertical, 7)
        .background(Color.primary.opacity(hover.open ? 0.05 : 0))
        .contentShape(Rectangle())
        .onHover { hover.open = $0 }
        .contextMenu {
            Button(item.onThreatList ? "Allow Anyway…" : "Allow") { act(item, .allow) }
            Button("Block") { act(item, .block) }
            Divider()
            Button("Forget") { act(item, .forget) }
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(item.programName) \(item.what)", forType: .string)
            }
        }
    }
}
