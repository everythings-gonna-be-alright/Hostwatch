import AppKit
import Combine
import Foundation

// First-seen domains: an inventory of every registrable domain programs connect to. After a
// baseline (recorded history + a learning period), a domain never seen before is "new" and gets
// extra attention: a badge on its connections, the Important/New filters, a Stories stage and
// Network ▸ Domains.

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

    /// A domain counts as new for this long after its first sighting (Network ▸ Domains, menu badge).
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
        guard let data = Vault.shared.read(fileURL) else { return }
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
        if let data = try? encoder.encode(Array(records.values)) { try? Vault.shared.write(data, to: fileURL) }
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
