import Foundation

// Firewall, stage 1: the rules and Watch mode. Every connection Hostwatch sees is judged as the firewall
// would judge it (allow, ask, block) and what wouldn't simply pass is listed. Nothing is blocked yet:
// blocking needs the relay in the collector (pf redirect), which comes next.

enum FirewallMode: String, CaseIterable, Codable {
    case off, watch

    var title: String {
        switch self {
        case .off: "Off"
        case .watch: "Watch (block nothing, show what would be blocked)"
        }
    }
}

enum FirewallVerdict: Int, Codable, Comparable {
    case allow, ask, block
    static func < (a: FirewallVerdict, b: FirewallVerdict) -> Bool { a.rawValue < b.rawValue }
}

struct FirewallDecision: Equatable {
    var verdict: FirewallVerdict
    var reason: String
}

/// What a connection looked like when seen: enough to judge it again when its pattern's status changes.
struct FirewallFacts: Codable, Equatable {
    var program: String          // the binary that connected
    var proto: String            // "TCP" / "UDP"
    var ip: String
    var port: String
    var host: String             // DNS name, "" if unknown
    var risk: PatternRisk
    var riskReason: String
    var knownBad: String
    var patternKey: String
}

enum FirewallPolicy {
    /// The firewall's rule for one connection, given its pattern's current status.
    static func decide(_ f: FirewallFacts, status: SignatureStatus, hostwatch: String = Bundle.main.executablePath ?? "") -> FirewallDecision {
        let bucket = SignatureBuilder.hostBucket(f.ip)
        if SignatureBuilder.localBuckets.contains(bucket) {
            return FirewallDecision(verdict: .allow, reason: "local network")
        }
        if !hostwatch.isEmpty, f.program == hostwatch {
            return FirewallDecision(verdict: .allow, reason: "Hostwatch itself")
        }
        if !f.knownBad.isEmpty {
            return FirewallDecision(verdict: .block, reason: "known malware address (\(f.knownBad))")
        }
        switch status {
        case .dangerous, .suspicious:
            return FirewallDecision(verdict: .block, reason: "its pattern is marked \(status.title)")
        case .safe:
            return FirewallDecision(verdict: .allow, reason: "its pattern is Safe")
        case .unclassified:
            break
        }
        switch f.risk {
        case .high:
            return FirewallDecision(verdict: .block, reason: "high-risk: \(f.riskReason)")
        case .routine:
            return FirewallDecision(verdict: .allow, reason: f.riskReason.isEmpty ? "routine" : f.riskReason)
        case .normal:
            if SignatureBuilder.isSealedSystem(f.program), !SignatureBuilder.isLolbin(f.program) {
                return FirewallDecision(verdict: .allow, reason: "macOS system process")
            }
            return FirewallDecision(verdict: .ask, reason: "new connection, not decided yet")
        }
    }
}

/// A destination a program would be stopped at (or asked about), with how often it was seen.
struct FirewallEntry: Codable, Identifiable, Equatable {
    var id: String               // program|proto|destination|port
    var facts: FirewallFacts
    var name: String
    var count: Int
    var firstSeen: Date
    var lastSeen: Date

    var destination: String { facts.host.isEmpty ? facts.ip : facts.host }
}

@MainActor
final class FirewallMonitor: ObservableObject {
    @Published var mode: FirewallMode { didSet { defaults.set(mode.rawValue, forKey: "firewallMode") } }
    /// Connections that wouldn't simply pass (would ask or block), newest first.
    @Published private(set) var entries: [String: FirewallEntry] = [:]
    @Published private(set) var allowedCount = 0
    /// Bumped when a pattern's status changes, so lists judge again.
    @Published var revision = 0

    static let keep: TimeInterval = 7 * 86400
    static let maxEntries = 500

    private let defaults: UserDefaults
    private let fileURL: URL
    private var dirty = false
    private var saveTimer: Timer?

    init(defaults: UserDefaults = .standard, fileURL: URL = AppPaths.support.appendingPathComponent("firewall-watch.json")) {
        self.defaults = defaults
        self.fileURL = fileURL
        mode = FirewallMode(rawValue: defaults.string(forKey: "firewallMode") ?? "") ?? .off
        if let data = try? Data(contentsOf: fileURL), let saved = try? Self.decoder.decode(Saved.self, from: data) {
            entries = saved.entries
            allowedCount = saved.allowed
        }
    }

    private struct Saved: Codable { var entries: [String: FirewallEntry]; var allowed: Int }

    static func facts(_ e: ActivityEvent) -> FirewallFacts? {
        guard e.kind == .net, let ip = e.remoteHost?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")) else { return nil }
        return FirewallFacts(program: e.proc, proto: e.extra.uppercased(), ip: ip, port: e.remotePort, host: e.host,
                             risk: e.signatureRisk, riskReason: e.signatureReason, knownBad: e.knownBad, patternKey: e.signatureKey)
    }

    /// A connection Hostwatch saw: judged, and listed unless it would simply pass.
    @discardableResult
    func observe(_ e: ActivityEvent, status: SignatureStatus, now: Date = Date()) -> FirewallDecision? {
        guard mode != .off, let f = Self.facts(e) else { return nil }
        let decision = FirewallPolicy.decide(f, status: status)
        guard decision.verdict != .allow else { allowedCount += 1; return decision }
        let id = [f.program, f.proto, f.host.isEmpty ? f.ip : f.host, f.port].joined(separator: "|")
        if var old = entries[id] {
            old.count += 1; old.lastSeen = now; old.facts = f
            entries[id] = old
        } else {
            entries[id] = FirewallEntry(id: id, facts: f, name: e.name, count: 1, firstSeen: now, lastSeen: now)
            prune(now: now)
        }
        scheduleSave()
        return decision
    }

    /// Entries with today's verdict (a pattern you've allowed since drops out), most serious and newest first.
    func list(status: (String) -> SignatureStatus) -> [(FirewallEntry, FirewallDecision)] {
        entries.values.map { ($0, FirewallPolicy.decide($0.facts, status: status($0.facts.patternKey))) }
            .filter { $0.1.verdict != .allow }
            .sorted { $0.1.verdict != $1.1.verdict ? $0.1.verdict > $1.1.verdict : $0.0.lastSeen > $1.0.lastSeen }
    }

    func clear() { entries = [:]; allowedCount = 0; scheduleSave() }

    private func prune(now: Date) {
        entries = entries.filter { now.timeIntervalSince($0.value.lastSeen) < Self.keep }
        if entries.count > Self.maxEntries {
            let keep = entries.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(Self.maxEntries)
            entries = Dictionary(uniqueKeysWithValues: keep.map { ($0.id, $0) })
        }
    }

    private func scheduleSave() {
        dirty = true
        guard saveTimer == nil else { return }
        saveTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated { self?.saveTimer = nil; self?.save() }
        }
    }

    func save() {
        guard dirty, let data = try? Self.encoder.encode(Saved(entries: entries, allowed: allowedCount)) else { return }
        dirty = false
        try? data.write(to: fileURL, options: .atomic)
        chmod(fileURL.path, 0o600)
    }

    private static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }()
    private static let decoder: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}
