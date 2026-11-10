import AppKit
import SwiftUI

// The Network tab: one timeline of where this Mac connects. Each row is a destination (a domain, or an address
// without a name) with what the domain inventory knows (new, known, on a threat list) and what the firewall does
// with it; open a row for the programs that connected there, with Block and Allow. Connections the firewall holds
// for your answer are on top. The firewall's mode and settings are in Rules ▸ Protection ▸ Network Firewall.

/// What the firewall does with a destination or connection; the order is the sort order (most urgent last).
enum NetworkFirewall: Int, Comparable {
    case off, passes, undecided, waiting, blocks, blockedByYou
    static func < (a: NetworkFirewall, b: NetworkFirewall) -> Bool { a.rawValue < b.rawValue }

    func title(_ mode: FirewallMode) -> String {
        switch self {
        case .off: return "—"
        case .passes: return "Passes"
        case .undecided: return mode == .strict ? "Blocks: undecided" : mode == .ask ? "Asks" : "Would ask"
        case .waiting: return "Waiting for you"
        case .blocks: return mode == .watch ? "Would block" : "Blocks"
        case .blockedByYou: return "Blocked by you"
        }
    }

    var color: Color {
        switch self {
        case .off: return .secondary
        case .passes: return .green
        case .undecided, .waiting: return .orange
        case .blocks, .blockedByYou: return .red
        }
    }

    /// Something to decide or already stopped.
    var needsAttention: Bool { self >= .undecided }
}

struct NetworkRow: Identifiable {
    let id: String
    /// Domain or address (a destination); the program's name (a connection).
    var destination: String
    /// A connection: "TCP api.example.com:443".
    var detail = ""
    var record: DomainRecord?
    var isNew = false
    var entry: FirewallEntry?
    var reason = ""
    var firewall: NetworkFirewall
    var firstSeen: Date
    var lastSeen: Date
    var count: Int
    var programs: String
    var children: [NetworkRow]?

    var isConnection: Bool { entry != nil && children == nil && id.hasPrefix("c:") }
    var firewallRank: Int { firewall.rawValue }
    /// New first, then seen, then known/baseline, then addresses without a domain.
    var statusRank: Int {
        guard let r = record else { return 4 }
        return isNew ? 0 : r.known ? 2 : r.baseline ? 3 : 1
    }
    var status: String {
        guard let r = record else { return "" }
        return isNew ? "New" : r.known ? "Known" : r.baseline ? "Baseline" : "Seen"
    }

    static let sortColumns: [String: (SortOrder) -> KeyPathComparator<NetworkRow>] = [
        "last": { KeyPathComparator(\.lastSeen, order: $0) },
        "destination": { KeyPathComparator(\.destination, order: $0) },
        "firewall": { KeyPathComparator(\.firewallRank, order: $0) },
        "status": { KeyPathComparator(\.statusRank, order: $0) },
        "programs": { KeyPathComparator(\.programs, order: $0) },
        "count": { KeyPathComparator(\.count, order: $0) },
        "first": { KeyPathComparator(\.firstSeen, order: $0) },
    ]

    /// Where an entry belongs: its domain, else its host, else its address.
    static func group(_ f: FirewallFacts) -> String {
        DomainRegistry.registrable(f.host) ?? (f.host.isEmpty ? f.ip : f.host.lowercased())
    }

    /// Domains and the firewall's connections, merged into one row per destination.
    static func build(records: [DomainRecord], isNew: (DomainRecord) -> Bool,
                      entries: [(FirewallEntry, FirewallDecision)], allEntries: [FirewallEntry] = [],
                      byYou: (FirewallEntry) -> Bool, waiting: Set<String>, firewallOn: Bool) -> [NetworkRow] {
        func connection(_ e: FirewallEntry, _ d: FirewallDecision?) -> NetworkRow {
            var state = NetworkFirewall.passes
            if let d {
                state = d.verdict == .block ? (byYou(e) ? .blockedByYou : .blocks) : d.verdict == .ask ? .undecided : .passes
            }
            if waiting.contains(e.facts.patternKey), state != .blockedByYou { state = .waiting }
            let base = e.name.isEmpty || e.name == "?" ? (e.facts.program as NSString).lastPathComponent : e.name
            let name = SignatureBuilder.vmGateway(e.facts.program) ?? (base.isEmpty ? "Unknown program" : base)
            return NetworkRow(id: "c:" + e.id, destination: name,
                              detail: "\(e.facts.proto) \(e.destination):\(e.facts.port)", entry: e,
                              reason: d.map { $0.reason.prefix(1).uppercased() + $0.reason.dropFirst() } ?? "",
                              firewall: firewallOn ? state : .off, firstSeen: e.firstSeen, lastSeen: e.lastSeen,
                              count: e.count, programs: e.facts.program)
        }
        let grouped = Dictionary(grouping: entries, by: { group($0.0.facts) })
        var rows: [NetworkRow] = []
        var used = Set<String>()
        for r in records {
            let children = (grouped[r.domain] ?? []).map { connection($0.0, $0.1) }.sorted { $0.lastSeen > $1.lastSeen }
            used.insert(r.domain)
            rows.append(NetworkRow(id: "d:" + r.domain, destination: r.domain, record: r, isNew: isNew(r),
                                   firewall: firewallOn ? (children.map(\.firewall).max() ?? .passes) : .off,
                                   firstSeen: r.firstSeen, lastSeen: max(r.lastSeen, children.map(\.lastSeen).max() ?? .distantPast),
                                   count: r.count, programs: r.programs.joined(separator: ", "),
                                   children: children.isEmpty ? nil : children))
        }
        for (key, list) in grouped where !used.contains(key) {
            let children = list.map { connection($0.0, $0.1) }.sorted { $0.lastSeen > $1.lastSeen }
            let names = children.map(\.destination).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
            rows.append(NetworkRow(id: "d:" + key, destination: key,
                                   firewall: firewallOn ? (children.map(\.firewall).max() ?? .passes) : .off,
                                   firstSeen: children.map(\.firstSeen).min() ?? Date(), lastSeen: children.map(\.lastSeen).max() ?? Date(),
                                   count: children.reduce(0) { $0 + $1.count }, programs: names.joined(separator: ", "),
                                   children: children))
        }
        return rows
    }
}

/// The Network tab's state: the filter, selection and sort (avoids @State, which needs SwiftUI macro plugins).
@MainActor
final class NetworkViewState: ObservableObject {
    enum Filter: String, CaseIterable {
        case all, new, attention
        var title: String {
            switch self {
            case .all: return "All"
            case .new: return "New Domains"
            case .attention: return "Blocked & Undecided"
            }
        }
    }

    @Published var filter = Filter(rawValue: UserDefaults.standard.string(forKey: "networkFilter") ?? "") ?? .all {
        didSet { UserDefaults.standard.set(filter.rawValue, forKey: "networkFilter") }
    }
    @Published var selection = Set<String>()
    @Published var order: [KeyPathComparator<NetworkRow>] =
        SortMemory.load(key: "networkTableSort", columns: NetworkRow.sortColumns,
                        fallback: KeyPathComparator(\.lastSeen, order: .reverse)) {
        didSet { SortMemory.save(order, key: "networkTableSort", columns: NetworkRow.sortColumns) }
    }
}

struct NetworkView: View {
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var state: NetworkViewState
    let search: String
    /// The coding-agent session that reached a destination, by name (nil: none).
    var sessionTag: (String) -> String? = { _ in nil }
    /// Opens the domain's details window (risk score, programs, Ask AI).
    var openDetails: (String) -> Void = { _ in }
    /// Rules ▸ Protection ▸ Network Firewall.
    var openFirewallSettings: () -> Void = {}
    /// On a threat list: the reason, else nil.
    var knownBad: (String) -> String? = { _ in nil }

    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    var body: some View {
        let _ = domains.revision
        let all = allRows
        let rows = shown(all)
        VStack(spacing: 0) {
            bar
            Divider()
            if !firewall.prompts.isEmpty {
                waiting
                Divider()
            }
            Group {
                if rows.isEmpty {
                    ContentUnavailableView {
                        Label(emptyTitle, systemImage: state.filter == .attention ? "checkmark.shield" : "globe")
                    } description: {
                        Text(emptyText)
                    }
                } else {
                    table(rows)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack(spacing: 12) {
                Text(counts(all))
                Spacer()
                Text("Open a row for its programs · right-click for more")
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .monospacedDigit()
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    // MARK: Rows

    private var allRows: [NetworkRow] {
        let now = Date()
        return NetworkRow.build(records: Array(domains.records.values), isNew: { domains.isNew($0, now: now) },
                                entries: firewall.list(status: { signatures.status(forKey: $0) }),
                                byYou: { firewall.blockedDomain($0.facts) != nil || signatures.entry($0.facts.patternKey)?.source == "you" },
                                waiting: Set(firewall.prompts.map(\.patternKey)), firewallOn: firewall.mode != .off)
    }

    private func shown(_ all: [NetworkRow]) -> [NetworkRow] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return all.filter { row in
            switch state.filter {
            case .all: break
            case .new: guard row.isNew else { return false }
            case .attention: guard row.firewall.needsAttention else { return false }
            }
            guard !q.isEmpty else { return true }
            return row.destination.lowercased().contains(q) || row.programs.lowercased().contains(q)
                || (row.record?.hosts.contains { $0.contains(q) } ?? false)
                || (row.children ?? []).contains { $0.detail.lowercased().contains(q) || $0.programs.lowercased().contains(q) }
        }
        .sorted(using: state.order)
    }

    private var emptyTitle: String {
        if !search.isEmpty { return "No Matches" }
        switch state.filter {
        case .all: return "No Connections Yet"
        case .new: return "No New Domains"
        case .attention: return firewall.mode == .off ? "Firewall Is Off" : "Nothing Blocked or Undecided"
        }
    }

    private var emptyText: String {
        if !search.isEmpty { return "Nothing matches “\(search)”." }
        switch state.filter {
        case .all, .new:
            return domains.isLearning
                ? "Hostwatch is still learning which domains this Mac normally talks to. Domains seen now become the baseline."
                : "A domain is new when no program on this Mac has contacted it before. Connections to it are badged NEW DOMAIN and count in Stories."
        case .attention:
            return firewall.mode == .off ? "Turn it on in Rules ▸ Protection ▸ Network Firewall: Watch shows what it would block, without blocking anything."
                : "Every connection seen in the last 7 days passes: the local network, macOS, Safe patterns and trusted developers."
        }
    }

    private func counts(_ all: [NetworkRow]) -> String {
        let connections = all.flatMap { $0.children ?? [] }
        let blocked = connections.filter { $0.firewall >= .blocks }.count
        let undecided = connections.filter { $0.firewall == .undecided || $0.firewall == .waiting }.count
        var parts = ["\(domains.newCount) new", "\(domains.records.count) domains"]
        if firewall.mode != .off {
            parts.append("\(blocked) \(firewall.mode == .watch ? "would block" : "blocked") · \(undecided) undecided · "
                         + "\(firewall.allowedCount) passed (7 days)")
        }
        return parts.joined(separator: " · ")
    }

    // MARK: Top

    private var bar: some View {
        HStack(spacing: 12) {
            Picker("Show", selection: $state.filter) {
                ForEach(NetworkViewState.Filter.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            if domains.isLearning {
                Label("Learning your usual domains until \(domains.learningUntil.formatted(date: .omitted, time: .shortened))",
                      systemImage: "graduationcap")
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Button("End Learning Now") { domains.endLearning() }.buttonStyle(.glass)
            }
            Spacer()
            Button(action: openFirewallSettings) {
                Label { Text("Firewall: \(firewallState)") } icon: {
                    Image(systemName: firewall.mode == .off ? "shield.slash" : "shield.lefthalf.filled").foregroundStyle(firewallColor)
                }
            }
            .buttonStyle(.glass)
            .help("Firewall settings: Off, Watch, Ask or Strict")
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    private var firewallState: String {
        guard firewall.mode == .ask || firewall.mode == .strict else { return firewall.mode.short }
        switch firewall.relayState {
        case "on": return firewall.mode.short
        case "failed": return "\(firewall.mode.short), failed"
        default: return "\(firewall.mode.short), starting"
        }
    }

    private var firewallColor: Color {
        switch firewall.mode {
        case .off: return .secondary
        case .watch: return .accentColor
        case .ask, .strict: return firewall.relayState == "failed" ? .red : firewall.relayState == "on" ? .green : .orange
        }
    }

    /// Connections held for your answer (Ask): answered here or in their question windows.
    private var waiting: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(firewall.prompts) { FirewallWaitingRow(prompt: $0, firewall: firewall) }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 4)
        .background(Color.orange.opacity(0.08))
    }

    // MARK: Table

    private func table(_ rows: [NetworkRow]) -> some View {
        Table(rows, children: \.children, selection: $state.selection, sortOrder: $state.order) {
            TableColumn("Last Seen", value: \.lastSeen) { row in
                Text(time(row.lastSeen)).foregroundStyle(.secondary).monospacedDigit().help(row.lastSeen.formatted())
            }
            .width(min: 70, ideal: 90, max: 130)
            TableColumn("Destination", value: \.destination) { row in destination(row) }
                .width(min: 160, ideal: 280)
            TableColumn("Firewall", value: \.firewallRank) { row in
                if row.firewall != .off {
                    Tag(text: row.firewall.title(firewall.mode), color: row.firewall.color, faint: row.firewall == .passes)
                        .help(row.reason.isEmpty ? row.firewall.title(firewall.mode) : row.reason)
                }
            }
            .width(min: 80, ideal: 120, max: 160)
            TableColumn("Domain", value: \.statusRank) { row in
                if !row.isConnection {
                    if let bad = knownBad(row.destination) {
                        KnownBadTag(detail: bad)
                    } else if row.record != nil {
                        Tag(text: row.status, color: row.isNew ? .purple : .secondary, faint: !row.isNew)
                    }
                }
            }
            .width(min: 64, ideal: 76, max: 110)
            TableColumn("Programs", value: \.programs) { row in
                Text(row.isConnection ? row.reason : row.programs)
                    .foregroundStyle(row.isConnection ? .secondary : .primary)
                    .truncationMode(.tail).help(row.isConnection ? row.programs : row.programs)
            }
            .width(min: 100, ideal: 220)
            TableColumn("Connections", value: \.count) { row in
                Text("\(row.count)").monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 60, ideal: 80, max: 100)
            TableColumn("First Seen", value: \.firstSeen) { row in
                Text(Self.relative.localizedString(for: min(row.firstSeen, Date()), relativeTo: Date()))
                    .foregroundStyle(.secondary).help(row.firstSeen.formatted())
            }
            .width(min: 70, ideal: 90, max: 130)
            TableColumn("") { row in actions(row) }
                .width(min: 110, ideal: 130, max: 160)
        }
        .font(.system(size: 12))                        // words and program names in SF Pro, hosts monospaced below
        .contextMenu(forSelectionType: String.self) { ids in
            menu(ids, rows: rows)
        } primaryAction: { ids in
            if let id = ids.first, id.hasPrefix("d:"), let row = rows.first(where: { $0.id == id }), row.record != nil {
                openDetails(row.destination)                                       // double-click
            }
        }
    }

    @ViewBuilder private func destination(_ row: NetworkRow) -> some View {
        if let e = row.entry, row.isConnection {
            HStack(spacing: 6) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: e.facts.program)).resizable().frame(width: 14, height: 14)
                Text(row.destination).fontWeight(.medium).font(.system(size: 12, design: .monospaced))
                Text(row.detail).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .help("\(e.facts.program)\n\(row.detail)")
        } else {
            HStack(spacing: 6) {
                Text(row.destination).fontWeight(.semibold).font(.system(size: 12, design: .monospaced))
                    .help(row.record?.hosts.joined(separator: "\n") ?? row.destination)
                if let name = sessionTag(row.destination) {
                    Tag(text: "via \(name)", color: .accentColor, faint: true)
                        .help("A coding-agent session connected here: \(name)")
                }
            }
        }
    }

    @ViewBuilder private func actions(_ row: NetworkRow) -> some View {
        if row.isConnection, let e = row.entry, let domain = firewall.blockedDomain(e.facts) {
            Button("Unblock") { firewall.setBlocked(false, domain: domain, program: e.facts.program) }
                .help("Let \(row.destination) reach \(domain) again")
                .controlSize(.small)
                .font(.system(size: 11))
        } else if row.isConnection, let e = row.entry, row.firewall.needsAttention, !e.facts.patternKey.isEmpty, e.facts.knownBad.isEmpty {
            let pattern = e.facts.patternKey.split(separator: "|").last.map(String.init) ?? ""
            HStack(spacing: 6) {
                if row.firewall == .blockedByYou {
                    Button("Allow Instead") { decide([e.facts.patternKey], allow: true) }
                        .help("Mark Safe: \(e.name) → \(pattern)")
                } else {
                    Button("Block") { decide([e.facts.patternKey], allow: false) }
                        .help("Mark Suspicious: \(e.name) → \(pattern)")
                    Button("Allow") { decide([e.facts.patternKey], allow: true) }
                        .help("Mark Safe: \(e.name) → \(pattern)")
                }
            }
            .controlSize(.small)
            .font(.system(size: 11))
        }
    }

    /// Your decision for patterns; a connection waiting for it is answered too.
    private func decide(_ keys: [String], allow: Bool) {
        for p in firewall.prompts where keys.contains(p.patternKey) {
            firewall.resolve(p.id, allow: allow)
            return
        }
        signatures.set(allow ? .safe : .suspicious, keys: keys, note: allow ? "allowed in Network" : "blocked in Network")
    }

    @ViewBuilder private func menu(_ ids: Set<String>, rows: [NetworkRow]) -> some View {
        let flat = rows + rows.flatMap { $0.children ?? [] }
        let picked = flat.filter { ids.contains($0.id) }
        let named = picked.filter { $0.record != nil }.map(\.destination)
        let keys = Array(Set(picked.compactMap { $0.isConnection ? $0.entry?.facts.patternKey : nil }.filter { !$0.isEmpty }))
        if named.count == 1, let domain = named.first {
            Button("Details & Ask AI…") { openDetails(domain) }
            Divider()
        }
        if !keys.isEmpty {
            Button(keys.count > 1 ? "Allow \(keys.count) Patterns" : "Allow") { decide(keys, allow: true) }
            Button(keys.count > 1 ? "Block \(keys.count) Patterns" : "Block") { decide(keys, allow: false) }
            Divider()
        }
        domainBlockItems(picked)
        if !named.isEmpty {
            Button("Mark \(named.count > 1 ? "\(named.count) Domains" : "Domain") Known") { domains.setKnown(named, true) }
            Button("Mark as Not Known") { domains.setKnown(named, false) }
        }
        if !picked.isEmpty {
            Button(named.isEmpty ? "Forget" : "Forget (treat as new next time)") { forget(picked) }
                .help("Also removes its firewall connections and the Allow or Block you gave them; they're asked about again")
            Divider()
        }
        if let e = picked.first(where: \.isConnection)?.entry, picked.count == 1 {
            Button("Show Program in Finder") { NSWorkspace.shared.selectFile(e.facts.program, inFileViewerRootedAtPath: "") }
        }
        Button("Copy") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(picked.map { $0.isConnection ? "\($0.destination) \($0.detail)" : $0.destination }
                .joined(separator: "\n"), forType: .string)
        }
    }

    /// Block one domain for one app: from a domain (an item per app that reached it) or from a connection (its app).
    /// An ordinary app has one pattern for the whole web, so this is a rule of the firewall's own, not a pattern.
    @ViewBuilder private func domainBlockItems(_ picked: [NetworkRow]) -> some View {
        if picked.count == 1, let row = picked.first {
            if let e = row.entry, row.isConnection, let domain = FirewallMonitor.domain(of: e.facts) {
                let blocked = firewall.isBlocked(domain: domain, program: e.facts.program)
                Button(blocked ? "Unblock \(domain) for \(row.destination)" : "Block \(domain) for \(row.destination)") {
                    firewall.setBlocked(!blocked, domain: domain, program: e.facts.program)
                }
                firewallOffNote
                Divider()
            } else if let record = row.record, !record.programs.isEmpty {
                Menu("Block for an App") {
                    ForEach(record.programs, id: \.self) { program in
                        let blocked = firewall.isBlocked(domain: record.domain, program: program)
                        Button(blocked ? "Unblock \(program)" : "Block \(program)") {
                            firewall.setBlocked(!blocked, domain: record.domain, program: program)
                        }
                    }
                    firewallOffNote
                }
                Divider()
            }
        }
    }

    /// A block is kept either way, but only an active firewall stops anything.
    @ViewBuilder private var firewallOffNote: some View {
        if firewall.mode == .off || firewall.mode == .watch {
            Text(firewall.mode == .off ? "The firewall is off: turn it on to stop the connections"
                 : "The firewall only watches: choose Ask or Strict to stop the connections")
        }
    }

    /// Forget: the domains (new again next time), their firewall connections, and your firewall decisions for them.
    private func forget(_ picked: [NetworkRow]) {
        let named = picked.filter { $0.record != nil && !$0.isConnection }.map(\.destination)
        let ids = picked.flatMap { row in row.isConnection ? [row.entry?.id].compactMap { $0 } : (row.children ?? []).compactMap(\.entry?.id) }
        if !named.isEmpty { domains.forget(named) }
        firewall.forget(ids, signatures: signatures)
        state.selection = []
    }

    private func time(_ d: Date) -> String {
        Calendar.current.isDateInToday(d) ? d.formatted(date: .omitted, time: .shortened)
            : Calendar.current.isDateInYesterday(d) ? "Yesterday" : d.formatted(.dateTime.day().month(.abbreviated))
    }
}

/// A small status capsule (Firewall and Domain columns).
private struct Tag: View {
    let text: String
    let color: Color
    var faint = false

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(faint ? .secondary : .primary)
            .lineLimit(1)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(faint ? 0.10 : 0.16)))
            .overlay(Capsule().strokeBorder(color.opacity(faint ? 0.30 : 0.45), lineWidth: 0.5))
    }
}
