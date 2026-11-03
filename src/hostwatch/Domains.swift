import AppKit
import Foundation
import SwiftUI

// First-seen domains: an inventory of every registrable domain programs connect to. After a
// baseline (recorded history + a learning period), a domain never seen before is "new" and gets
// extra attention: a badge on its connections, the Important/New filters, a Stories stage and
// the Domains tab.

struct DomainRecord: Codable, Identifiable {
    var domain: String
    var firstSeen: Date
    var lastSeen: Date
    var count: Int
    var programs: [String]         // up to 6 program names that used it
    var hosts: [String]            // up to 6 full hostnames seen under it
    var baseline: Bool             // learned during the baseline: never "new"
    var known = false              // you marked it known

    var id: String { domain }
}

@MainActor
final class DomainRegistry: ObservableObject {
    /// Not @Published: a known domain's count changes on every connection. Views follow `revision`,
    /// bumped at once for new domains and changes you make, and at most once a second for counts.
    private(set) var records: [String: DomainRecord] = [:]
    @Published private(set) var revision = 0
    private var pendingRevision = false
    private var revisionTimer: Timer?

    /// A domain counts as new for this long after its first sighting (Domains tab, menu badge).
    let attentionWindow: TimeInterval = 24 * 3600
    /// Its connections carry the NEW DOMAIN badge for this long (the first burst).
    let badgeWindow: TimeInterval = 3600

    private(set) var learningUntil: Date
    private let fileURL: URL
    private var dirty = false
    private var timer: Timer?
    private let persistent: Bool

    /// Replays: in memory only, learning until the given time.
    init(replayLearningUntil: Date) {
        persistent = false
        learningUntil = replayLearningUntil
        fileURL = URL(fileURLWithPath: "/dev/null")
    }

    init() {
        persistent = true
        let dir = AppPaths.support
        fileURL = dir.appendingPathComponent("domains.json")
        let defaults = UserDefaults.standard
        if let saved = defaults.object(forKey: "domainLearningUntil") as? Date {
            learningUntil = saved
        } else {
            learningUntil = Date().addingTimeInterval(60 * 60)     // first run: learn for an hour (3 waves)
            defaults.set(learningUntil, forKey: "domainLearningUntil")
        }
        load()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.save() }
        }
    }

    var isLearning: Bool { Date() < learningUntil }

    func endLearning() {
        learningUntil = Date()
        UserDefaults.standard.set(learningUntil, forKey: "domainLearningUntil")
        revision += 1
    }

    /// New = first seen within the attention window, after the baseline, not marked known.
    func isNew(_ r: DomainRecord, now: Date = Date()) -> Bool {
        !r.baseline && !r.known && now.timeIntervalSince(r.firstSeen) < attentionWindow
    }

    var newCount: Int { records.values.filter { isNew($0) }.count }

    // MARK: Observing

    /// "www.google.com" -> "google.com", "a.b.co.uk" -> "b.co.uk"; nil for IPs and local names.
    nonisolated static func registrable(_ host: String) -> String? {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard h.contains("."), !h.hasSuffix(".local"), !h.hasSuffix(".arpa"), !h.hasSuffix(".internal"),
              h.rangeOfCharacter(from: .letters) != nil, !h.contains(":") else { return nil }
        let labels = h.split(separator: ".")
        guard labels.count > 2 else { return h }
        let secondLevel: Set<Substring> = ["co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc"]
        let sld = labels[labels.count - 2]
        let take = labels.last!.count == 2 && sld.count <= 3 && secondLevel.contains(sld) ? 3 : 2
        return labels.suffix(take).joined(separator: ".")
    }

    /// Hostname worth tracking for this event: one the program looked up (DNS) or named on its
    /// command line. Reverse-DNS names are provider names and macOS daemons talk to Apple.
    nonisolated static func trackedDomain(_ e: ActivityEvent) -> (domain: String, host: String)? {
        guard e.kind == .net, !e.host.isEmpty, e.hostSource == "dns" || e.hostSource == "args",
              !SignatureBuilder.isSealedSystem(e.proc) || SignatureBuilder.isLolbin(e.proc),
              let domain = registrable(e.host) else { return nil }
        return (domain, e.host.lowercased())
    }

    /// Records a connection; returns the domain when its connections should carry the
    /// NEW DOMAIN badge (first hour after a post-baseline first sighting).
    /// Coalesces count/last-seen changes into one revision bump per second.
    private func scheduleRevision() {
        guard !pendingRevision else { return }
        pendingRevision = true
        guard Thread.isMainThread, revisionTimer == nil else { return }
        revisionTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.revisionTimer = nil
                if self.pendingRevision { self.pendingRevision = false; self.revision += 1 }
            }
        }
    }

    /// Unsigned, ad-hoc or quarantined code, or a program run from Downloads, Shared or a mounted volume.
    /// (Temporary folders are left out: updaters and developer builds live there all day.)
    static func untrustedProgram(_ path: String) -> Bool {
        guard !path.isEmpty else { return false }
        if ["/Downloads/", "/Users/Shared/", "/Volumes/"].contains(where: path.contains) { return true }
        guard let id = SigningCache.shared.cached(path) else { return false }
        return id.untrustedCode || id.quarantined
    }

    func observe(_ e: ActivityEvent, at now: Date = Date()) -> String? {
        guard let (domain, host) = Self.trackedDomain(e) else { return nil }
        let program = displayProcessName(e.proc.isEmpty ? e.name : e.proc)
        if var r = records[domain] {
            r.lastSeen = now
            r.count += 1
            if !r.programs.contains(program), r.programs.count < 6 { r.programs.append(program) }
            if !r.hosts.contains(host), r.hosts.count < 6 { r.hosts.append(host) }
            records[domain] = r
            dirty = true
            scheduleRevision()
            return !r.baseline && !r.known && now.timeIntervalSince(r.firstSeen) < badgeWindow ? domain : nil
        }
        // While learning, a domain becomes "usual" only if a trustworthy program reached it: one first
        // contacted by unsigned code or a program from Downloads/temp stays new.
        let learning = now < learningUntil && !Self.untrustedProgram(e.proc)
        records[domain] = DomainRecord(domain: domain, firstSeen: now, lastSeen: now, count: 1,
                                       programs: [program], hosts: [host], baseline: learning)
        dirty = true
        revision += 1
        return learning ? nil : domain
    }

    func setKnown(_ domains: [String], _ known: Bool) {
        for d in domains { records[d]?.known = known }
        dirty = true
        revision += 1
    }

    func forget(_ domains: [String]) {
        for d in domains { records[d] = nil }
        dirty = true
        revision += 1
    }

    /// First run: every domain already in recorded history is part of the baseline.
    func seedBaseline(fromHistory directory: URL) {
        guard !UserDefaults.standard.bool(forKey: "domainsSeeded") else { return }
        UserDefaults.standard.set(true, forKey: "domainsSeeded")
        DispatchQueue.global(qos: .utility).async {
            var found: [String: String] = [:]   // domain -> a host
            let decoder = JSONDecoder()
            let hostKey = Data(#""host":""#.utf8)
            HistoryFiles.forEachLine(path: directory.path) { line in
                guard line.range(of: hostKey) != nil,
                      let e = try? decoder.decode(ActivityEvent.self, from: line),
                      let (domain, host) = Self.trackedDomain(e) else { return }
                found[domain] = host
            }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    let now = Date()
                    for (domain, host) in found where self.records[domain] == nil {
                        self.records[domain] = DomainRecord(domain: domain, firstSeen: now, lastSeen: now, count: 0,
                                                            programs: [], hosts: [host], baseline: true)
                    }
                    self.dirty = true
                    self.revision += 1
                }
            }
        }
    }

    // MARK: Persistence

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let list = try? decoder.decode([DomainRecord].self, from: data) {
            records = Dictionary(list.map { ($0.domain, $0) }, uniquingKeysWith: { a, _ in a })
        }
    }

    func save() {
        guard dirty, persistent else { return }
        dirty = false
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(Array(records.values)) { try? data.write(to: fileURL, options: .atomic) }
    }
}

// MARK: - Table row

struct DomainItem: Identifiable {
    let record: DomainRecord
    let isNew: Bool
    var id: String { record.domain }
    var domain: String { record.domain }
    /// New first, then seen, then known/baseline.
    var statusRank: Int { isNew ? 0 : record.known ? 2 : record.baseline ? 3 : 1 }
    var status: String { isNew ? "New" : record.known ? "Known" : record.baseline ? "Baseline" : "Seen" }
    var firstSeen: Date { record.firstSeen }
    var lastSeen: Date { record.lastSeen }
    var count: Int { record.count }
    var programs: String { record.programs.joined(separator: ", ") }

    static let sortColumns: [String: (SortOrder) -> KeyPathComparator<DomainItem>] = [
        "status": { KeyPathComparator(\.statusRank, order: $0) },
        "domain": { KeyPathComparator(\.domain, order: $0) },
        "first": { KeyPathComparator(\.firstSeen, order: $0) },
        "last": { KeyPathComparator(\.lastSeen, order: $0) },
        "count": { KeyPathComparator(\.count, order: $0) },
        "programs": { KeyPathComparator(\.programs, order: $0) },
    ]
}

// MARK: - Domains tab

/// Holds the Domains tab's table state (avoids @State, which needs SwiftUI macro plugins).
@MainActor
final class DomainsViewState: ObservableObject {
    @Published var selection = Set<String>()
    @Published var onlyNew = UserDefaults.standard.object(forKey: "domainsOnlyNew") as? Bool ?? true {
        didSet { UserDefaults.standard.set(onlyNew, forKey: "domainsOnlyNew") }
    }
    @Published var order: [KeyPathComparator<DomainItem>] =
        SortMemory.load(key: "domainTableSort", columns: DomainItem.sortColumns,
                        fallback: KeyPathComparator(\.firstSeen, order: .reverse)) {
        didSet { SortMemory.save(order, key: "domainTableSort", columns: DomainItem.sortColumns) }
    }
}

struct DomainsView: View {
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var state: DomainsViewState
    let search: String
    /// Opens the domain's details window (risk score, programs, Ask AI).
    var openDetails: (String) -> Void = { _ in }
    /// On a threat list: the reason, else nil.
    var knownBad: (String) -> String? = { _ in nil }

    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    var body: some View {
        let _ = domains.revision
        let rows = items
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Toggle("Only new (first seen in the last 24 h)", isOn: $state.onlyNew)
                    .toggleStyle(.switch)
                Spacer()
                if domains.isLearning {
                    Label("Learning your usual domains until \(domains.learningUntil.formatted(date: .omitted, time: .shortened))",
                          systemImage: "graduationcap")
                        .foregroundStyle(.secondary)
                    Button("End Learning Now") { domains.endLearning() }.buttonStyle(.glass)
                }
            }
            .controlSize(.small)
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            Divider()
            Group {
                if rows.isEmpty {
                    ContentUnavailableView {
                        Label(state.onlyNew ? "No New Domains" : "No Domains Yet", systemImage: "globe")
                    } description: {
                        Text(domains.isLearning
                             ? "Hostwatch is still learning which domains this Mac normally talks to. Domains seen now become the baseline."
                             : "A domain is new when no program on this Mac has contacted it before. Connections to it are badged NEW DOMAIN and count in Stories.")
                    }
                } else {
                    table(rows)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack {
                Text("\(domains.newCount) new · \(domains.records.count) domains known")
                Spacer()
                Text("Right-click to mark known")
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    private var items: [DomainItem] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let now = Date()
        return domains.records.values
            .map { DomainItem(record: $0, isNew: domains.isNew($0, now: now)) }
            .filter { !state.onlyNew || $0.isNew }
            .filter { q.isEmpty || $0.domain.contains(q) || $0.programs.lowercased().contains(q)
                || $0.record.hosts.contains { $0.contains(q) } }
            .sorted(using: state.order)
    }

    private func table(_ rows: [DomainItem]) -> some View {
        Table(rows, selection: $state.selection, sortOrder: $state.order) {
            TableColumn("Status", value: \.statusRank) { item in
              if let bad = knownBad(item.domain) {
                KnownBadTag(detail: bad)
              } else {
                Text(item.status)
                    .font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Capsule().fill((item.isNew ? Color.purple : Color.secondary).opacity(0.16)))
                    .overlay(Capsule().strokeBorder((item.isNew ? Color.purple : Color.secondary).opacity(0.45), lineWidth: 0.5))
              }
            }
            .width(min: 64, ideal: 76, max: 110)
            TableColumn("Domain", value: \.domain) { item in
                Text(item.domain).fontWeight(.semibold)
                    .help(item.record.hosts.joined(separator: "\n"))
            }
            .width(min: 140, ideal: 240)
            TableColumn("Hosts") { item in
                Text(item.record.hosts.joined(separator: ", ")).foregroundStyle(.secondary).truncationMode(.middle)
            }
            .width(min: 100, ideal: 260)
            TableColumn("Programs", value: \.programs) { item in
                Text(item.programs).truncationMode(.tail).help(item.programs)
            }
            .width(min: 100, ideal: 220)
            TableColumn("Connections", value: \.count) { item in
                Text("\(item.count)").monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 60, ideal: 80, max: 100)
            TableColumn("First Seen", value: \.firstSeen) { item in
                Text(Self.relative.localizedString(for: item.firstSeen, relativeTo: Date()))
                    .foregroundStyle(.secondary).help(item.firstSeen.formatted())
            }
            .width(min: 70, ideal: 90, max: 130)
            TableColumn("Last Seen", value: \.lastSeen) { item in
                Text(Self.relative.localizedString(for: item.lastSeen, relativeTo: Date()))
                    .foregroundStyle(.secondary).help(item.lastSeen.formatted())
            }
            .width(min: 70, ideal: 90, max: 130)
        }
        .font(.system(size: 12, design: .monospaced))
        .contextMenu(forSelectionType: String.self) { ids in
            let list = Array(ids)
            if list.count == 1, let domain = list.first {
                Button("Details & Ask AI…") { openDetails(domain) }
                Divider()
            }
            Button("Mark \(list.count > 1 ? "\(list.count) Domains" : "Domain") Known") { domains.setKnown(list, true) }
            Button("Mark as Not Known") { domains.setKnown(list, false) }
            Divider()
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(list.joined(separator: "\n"), forType: .string)
            }
            Button("Forget (treat as new next time)") { domains.forget(list) }
        } primaryAction: { ids in
            if let domain = ids.first { openDetails(domain) }   // double-click
        }
    }
}
