import CryptoKit
import Foundation
import Security

// Known-bad check: public threat lists, downloaded once a day and matched on this Mac only (nothing about
// the Mac is sent anywhere). Domains and IPs of every connection, and the SHA-256 of new untrusted
// programs (with an abuse.ch key), are compared; a match is a "Known malware" story stage. Plus CISA's
// list of actively exploited Apple vulnerabilities, compared with this Mac's macOS and pending updates.

/// One match: what, where it's listed, and who touched it.
struct ThreatHit: Codable, Equatable, Identifiable {
    enum Kind: String, Codable { case domain, ip, file }
    var id = UUID()
    var date: Date
    var kind: Kind
    var indicator: String        // "evil-cdn.xyz", "45.1.2.3", a SHA-256
    var source: String           // "ThreatFox", "HaGeZi Threat Intelligence", …
    var detail: String           // "AsyncRAT command server, reported 2 days ago"
    var process: String          // program name ("" for a retro-check of a domain)
    var path: String
    var pid: Int
    var retro = false            // found when the lists were updated, in what was seen before

    var summary: String { "\(source): \(detail)" }
}

/// An actively exploited Apple vulnerability (CISA KEV).
struct ExploitedVuln: Codable, Equatable, Identifiable {
    var cve: String
    var product: String
    var name: String
    var description: String
    var dateAdded: Date
    var ransomware: Bool
    var advisory: String?        // first Apple support link in CISA's notes

    var id: String { cve }

    /// "WebKit", "Kernel", "CoreGraphics" from the description, else the product.
    var component: String {
        for word in ["WebKit", "Kernel", "CoreGraphics", "ImageIO", "Image I/O", "CoreAudio", "CoreMedia", "Safari",
                     "AppleAVD", "IOMobileFrameBuffer", "FontParser", "Messages", "Wi-Fi", "Bluetooth", "dyld", "Gatekeeper"]
            where description.localizedCaseInsensitiveContains(word) { return word }
        return product
    }
}

/// How sure Hostwatch is that a vulnerability is fixed on this Mac (CISA doesn't name fixed versions).
enum VulnStatus: Equatable {
    case likelyFixed(Date)        // macOS was updated after it was published
    case fixedByPendingUpdate(String)
    case notFixed                 // no newer macOS installed and no update waiting
}

@MainActor
final class ThreatIntel: ObservableObject {
    enum Feed: String, CaseIterable, Identifiable {
        case hagezi, feodo, threatfox, bazaar, kev
        var id: String { rawValue }

        var title: String {
            switch self {
            case .hagezi: return "HaGeZi Threat Intelligence"
            case .feodo: return "Feodo Tracker"
            case .threatfox: return "ThreatFox"
            case .bazaar: return "MalwareBazaar"
            case .kev: return "CISA Known Exploited"
            }
        }

        var detail: String {
            switch self {
            case .hagezi: return "malware, phishing and C2 domains and IPs"
            case .feodo: return "botnet command servers"
            case .threatfox: return "C2 servers and files, with the malware family"
            case .bazaar: return "malware file hashes"
            case .kev: return "actively exploited Apple vulnerabilities"
            }
        }

        var needsKey: Bool { self == .threatfox || self == .bazaar }
    }

    struct FeedState: Codable, Equatable {
        var count = 0
        var updated: Date?
        var error: String?
    }

    static let refreshInterval: TimeInterval = 24 * 3600
    static let keepIndicators: TimeInterval = 180 * 24 * 3600
    static let hagezi = URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt")!
    static let hageziIPs = URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt")!
    static let feodo = URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")!
    static let threatfox = URL(string: "https://threatfox-api.abuse.ch/api/v1/")!
    static let kev = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
    static func bazaar(key: String) -> URL? {
        URL(string: "https://mb-api.abuse.ch/v2/files/exports/\(key.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "")/recent.csv")
    }

    @Published var enabled: Bool { didSet { defaults.set(enabled, forKey: "threatIntelEnabled"); if enabled { refreshIfStale() } } }
    @Published var vulnerabilitiesEnabled: Bool { didSet { defaults.set(vulnerabilitiesEnabled, forKey: "threatVulnsEnabled") } }
    @Published private(set) var states: [String: FeedState] = [:]
    @Published private(set) var updating = false
    @Published private(set) var hits: [ThreatHit] = []
    @Published private(set) var vulns: [ExploitedVuln] = []
    @Published private(set) var pendingUpdate: String?
    @Published private(set) var osVersion = ProcessInfo.processInfo.operatingSystemVersionString
    @Published private(set) var osUpdated: Date?
    @Published private(set) var revision = 0

    // Lookups (built off the main thread, swapped in at once).
    private var domains: Set<String> = []
    private var ips: Set<String> = []
    private var c2: [String: String] = [:]          // ThreatFox: domain / ip / ip:port → "AsyncRAT command server, reported …"
    private var hashes: [String: String] = [:]      // SHA-256 → "AMOS stealer (MalwareBazaar), first seen …"
    private var fileHashes: [String: (stamp: String, sha: String)] = [:]   // path → hash, by size + date
    private var hashing = Set<String>()
    private var reported = Set<String>()            // indicator|process, one hit per day
    private var timer: Timer?

    let directory: URL
    private let defaults: UserDefaults
    var session: URLSession = .shared
    var now: () -> Date = { Date() }
    /// A match on a connection or a program: the app adds the story stage.
    var onHit: ((ThreatHit, ActivityEvent?) -> Void)?
    /// Domains seen before (registrable, with their programs), for the retro-check after an update.
    var seenDomains: () -> [(domain: String, programs: [String])] = { [] }

    init(directory: URL = AppPaths.support.appendingPathComponent("intel", isDirectory: true), defaults: UserDefaults = .standard) {
        self.directory = directory
        self.defaults = defaults
        enabled = defaults.object(forKey: "threatIntelEnabled") as? Bool ?? true
        vulnerabilitiesEnabled = defaults.object(forKey: "threatVulnsEnabled") as? Bool ?? true
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let data = try? Data(contentsOf: directory.appendingPathComponent("state.json")),
           let saved = try? JSONDecoder().decode([String: FeedState].self, from: data) { states = saved }
        if let data = try? Data(contentsOf: directory.appendingPathComponent("hits.json")),
           let saved = try? JSONDecoder().decode([ThreatHit].self, from: data) { hits = saved }
        osUpdated = Self.lastOSUpdate()
    }

    // MARK: Key (Keychain)

    private static let keychainService = "Hostwatch abuse.ch"

    var apiKey: String? {
        get {
            var item: CFTypeRef?
            let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.keychainService,
                                    kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
            guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
            let key = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return key.isEmpty ? nil : key
        }
        set {
            let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.keychainService]
            SecItemDelete(base as CFDictionary)
            if let newValue, !newValue.trimmingCharacters(in: .whitespaces).isEmpty {
                var add = base
                add[kSecValueData as String] = Data(newValue.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
                SecItemAdd(add as CFDictionary, nil)
            }
            revision &+= 1
        }
    }

    // MARK: Start and refresh

    /// Loads what was downloaded before, then refreshes when a day has passed (checked hourly).
    func start() {
        Task {
            await load()
            refreshIfStale()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshIfStale() }
        }
    }

    func refreshIfStale() {
        guard enabled || vulnerabilitiesEnabled, !updating else { return }
        let oldest = Feed.allCases.compactMap { states[$0.rawValue]?.updated }.min()
        if oldest == nil || now().timeIntervalSince(oldest!) > Self.refreshInterval {
            Task { await update() }
        }
    }

    /// Downloads every list (each on its own: one failing doesn't stop the others), rebuilds the lookups,
    /// and re-checks the domains seen in the last 30 days.
    func update() async {
        guard !updating else { return }
        updating = true
        defer { updating = false }
        let key = apiKey
        if enabled {
            await fetch(.hagezi) { [session] in
                let (d, _) = try await session.data(from: Self.hagezi)
                let (i, _) = try await session.data(from: Self.hageziIPs)
                return d + Data("\n#ips\n".utf8) + i
            }
            await fetch(.feodo) { [session] in try await session.data(from: Self.feodo).0 }
            if let key {
                await fetch(.threatfox) { [session] in
                    var request = URLRequest(url: Self.threatfox)
                    request.httpMethod = "POST"
                    request.setValue(key, forHTTPHeaderField: "Auth-Key")
                    request.httpBody = Data(#"{"query":"get_iocs","days":7}"#.utf8)
                    return try await session.data(for: request).0
                }
                if let url = Self.bazaar(key: key) {
                    await fetch(.bazaar) { [session] in try await session.data(from: url).0 }
                }
            }
        }
        if vulnerabilitiesEnabled {
            await fetch(.kev) { [session] in try await session.data(from: Self.kev).0 }
            pendingUpdate = await Self.pendingMacOSUpdate()
            osUpdated = Self.lastOSUpdate()
        }
        await load()
        save()
        retroCheck()
    }

    /// Downloads one feed into the cache. ThreatFox and MalwareBazaar give recent additions only, so they
    /// accumulate into a local file (kept 180 days).
    private func fetch(_ feed: Feed, _ download: @escaping () async throws -> Data) async {
        var state = states[feed.rawValue] ?? FeedState()
        do {
            let data = try await download()
            guard !data.isEmpty, data.count < 200_000_000 else { throw URLError(.cannotDecodeContentData) }
            let file = directory.appendingPathComponent(feed.rawValue)
            switch feed {
            case .threatfox, .bazaar:
                let fresh = feed == .threatfox ? Self.parseThreatFox(data) : Self.parseBazaar(data)
                if let problem = Self.rejection(feed, data, parsed: fresh.count) { throw ThreatError.rejected(problem) }
                var all = (try? JSONDecoder().decode([String: Indicator].self, from: Data(contentsOf: file))) ?? [:]
                for (k, v) in fresh { all[k] = v }
                let cutoff = now().addingTimeInterval(-Self.keepIndicators)
                all = all.filter { $0.value.seen >= cutoff }
                try JSONEncoder().encode(all).write(to: file, options: .atomic)
                state.count = all.count
            default:
                try data.write(to: file, options: .atomic)
            }
            state.updated = now()
            state.error = nil
        } catch {
            state.error = (error as? ThreatError)?.description ?? error.localizedDescription
        }
        states[feed.rawValue] = state
    }

    enum ThreatError: Error, CustomStringConvertible {
        case rejected(String)
        var description: String {
            switch self { case .rejected(let text): return "Rejected: " + text.trimmingCharacters(in: .whitespacesAndNewlines) }
        }
    }

    /// Why a keyed feed's answer isn't data (a wrong key, rate limit…), or nil.
    nonisolated static func rejection(_ feed: Feed, _ data: Data, parsed: Int) -> String? {
        if feed == .threatfox {
            let status = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["query_status"] as? String
            return status == "ok" || status == "no_result" ? nil : (status ?? "unexpected answer")
        }
        let text = String(decoding: data.prefix(300), as: UTF8.self)
        return parsed > 0 || text.contains("sha256") ? nil : text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(120).description
    }

    struct Indicator: Codable {
        var detail: String
        var seen: Date
        var type: String          // "domain", "ip", "ip:port", "sha256"
    }

    /// Reads the cached lists into lookups (off the main thread).
    func load() async {
        let dir = directory
        let built = await Task.detached(priority: .utility) { () -> (Set<String>, Set<String>, [String: String], [String: String], [ExploitedVuln], [String: Int]) in
            var domains = Set<String>(), ips = Set<String>(), c2: [String: String] = [:], hashes: [String: String] = [:]
            var counts: [String: Int] = [:]
            if let text = try? String(contentsOf: dir.appendingPathComponent(Feed.hagezi.rawValue), encoding: .utf8) {
                var inIPs = false
                for line in text.split(whereSeparator: \.isNewline) {
                    if line == "#ips" { inIPs = true; continue }
                    guard let first = line.first, first != "#", first != "!" else { continue }
                    var entry = line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    if entry.hasPrefix("*.") { entry.removeFirst(2) }
                    if inIPs { ips.insert(entry) } else { domains.insert(entry) }
                }
                counts[Feed.hagezi.rawValue] = domains.count + ips.count
            }
            if let text = try? String(contentsOf: dir.appendingPathComponent(Feed.feodo.rawValue), encoding: .utf8) {
                var n = 0
                for line in text.split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
                    let ip = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !ip.isEmpty else { continue }
                    c2[ip] = c2[ip] ?? "Feodo Tracker: botnet command server"
                    n += 1
                }
                counts[Feed.feodo.rawValue] = n
            }
            for feed in [Feed.threatfox, .bazaar] {
                guard let data = try? Data(contentsOf: dir.appendingPathComponent(feed.rawValue)),
                      let all = try? JSONDecoder().decode([String: Indicator].self, from: data) else { continue }
                for (k, v) in all {
                    if v.type == "sha256" { hashes[k] = "\(feed.title): \(v.detail)" } else { c2[k] = "\(feed.title): \(v.detail)" }
                }
                counts[feed.rawValue] = all.count
            }
            var vulns: [ExploitedVuln] = []
            if let data = try? Data(contentsOf: dir.appendingPathComponent(Feed.kev.rawValue)) {
                vulns = ThreatIntel.parseKEV(data)
                counts[Feed.kev.rawValue] = vulns.count
            }
            return (domains, ips, c2, hashes, vulns, counts)
        }.value
        (domains, ips, c2, hashes, vulns) = (built.0, built.1, built.2, built.3, built.4)
        for (feed, n) in built.5 { states[feed, default: FeedState()].count = n }
        revision &+= 1
    }

    private func save() {
        if let data = try? JSONEncoder().encode(states) { try? data.write(to: directory.appendingPathComponent("state.json"), options: .atomic) }
        if let data = try? JSONEncoder().encode(Array(hits.suffix(500))) {
            try? data.write(to: directory.appendingPathComponent("hits.json"), options: .atomic)
        }
    }

    // MARK: Parsing

    /// ThreatFox `get_iocs`: domains, IPs (and ip:port), URLs (their host) and SHA-256 hashes.
    nonisolated static func parseThreatFox(_ data: Data) -> [String: Indicator] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let items = obj["data"] as? [[String: Any]] else { return [:] }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss 'UTC'"
        var out: [String: Indicator] = [:]
        for item in items {
            guard var ioc = (item["ioc"] as? String)?.lowercased(), let type = item["ioc_type"] as? String else { continue }
            let family = item["malware_printable"] as? String ?? "malware"
            let what = (item["threat_type"] as? String) == "botnet_cc" ? "command server" : (item["threat_type_desc"] as? String ?? "indicator").lowercased()
            let seen = (item["first_seen"] as? String).flatMap(f.date(from:)) ?? Date()
            let detail = "\(family) \(what), reported \(seen.formatted(date: .abbreviated, time: .omitted))"
            switch type {
            case "domain": out[ioc] = Indicator(detail: detail, seen: seen, type: "domain")
            case "ip:port":
                out[ioc] = Indicator(detail: detail, seen: seen, type: "ip:port")
                if let ip = ioc.split(separator: ":").first { out[String(ip)] = Indicator(detail: detail, seen: seen, type: "ip") }
            case "url":
                if let host = URL(string: ioc)?.host?.lowercased() { ioc = host; out[ioc] = Indicator(detail: detail, seen: seen, type: "domain") }
            case "sha256_hash": out[ioc] = Indicator(detail: detail, seen: seen, type: "sha256")
            default: continue
            }
        }
        return out
    }

    /// MalwareBazaar recent.csv: `"first_seen_utc","sha256_hash","md5","sha1","reporter","file_name",
    /// "file_type","mime","signature",…`; comment lines start with #.
    nonisolated static func parseBazaar(_ data: Data) -> [String: Indicator] {
        var out: [String: Indicator] = [:]
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
            let fields = line.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\" \r\n")) }
            guard fields.count > 1, fields[1].count == 64, fields[1].allSatisfy(\.isHexDigit) else { continue }
            let seen = f.date(from: fields[0]) ?? Date()
            let family = fields.count > 8 && !fields[8].isEmpty && fields[8] != "n/a" ? fields[8] : "malware"
            let type = fields.count > 6 ? fields[6] : ""
            out[fields[1].lowercased()] = Indicator(detail: "\(family)\(type.isEmpty ? "" : " (\(type))"), first seen \(seen.formatted(date: .abbreviated, time: .omitted))",
                                                    seen: seen, type: "sha256")
        }
        return out
    }

    /// Apple entries that concern macOS (or several Apple systems), newest first.
    nonisolated static func parseKEV(_ data: Data) -> [ExploitedVuln] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let items = obj["vulnerabilities"] as? [[String: Any]] else { return [] }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return items.compactMap { v -> ExploitedVuln? in
            guard (v["vendorProject"] as? String)?.lowercased() == "apple",
                  let cve = v["cveID"] as? String, let product = v["product"] as? String else { return nil }
            let text = v["shortDescription"] as? String ?? ""
            let mac = product.contains("macOS") || product.contains("OS X")
                || (product == "Multiple Products" && (text.contains("macOS") || text.contains("Safari") || text.contains("WebKit")))
            guard mac, let added = (v["dateAdded"] as? String).flatMap(f.date(from:)) else { return nil }
            let notes = v["notes"] as? String ?? ""
            let advisory = notes.split(whereSeparator: { $0 == " " || $0 == ";" })
                .map(String.init).first { $0.hasPrefix("https://support.apple.com") }
            return ExploitedVuln(cve: cve, product: product, name: v["vulnerabilityName"] as? String ?? cve,
                                 description: text, dateAdded: added,
                                 ransomware: (v["knownRansomwareCampaignUse"] as? String)?.lowercased() == "known",
                                 advisory: advisory)
        }
        .sorted { $0.dateAdded > $1.dateAdded }
    }

    // MARK: Matching

    /// The listed domain this host falls under: "a.b.evil.com" → "evil.com" when that's listed.
    func listedDomain(_ host: String) -> (domain: String, detail: String)? {
        var h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".~≈"))
        while h.contains(".") {
            if let d = c2[h] { return (h, d) }
            if domains.contains(h) { return (h, "HaGeZi Threat Intelligence: malware or phishing domain") }
            h = String(h.drop { $0 != "." }.dropFirst())
        }
        return nil
    }

    func listedIP(_ ip: String, port: String) -> String? {
        if let d = c2["\(ip):\(port)"] ?? c2[ip] { return d }
        return ips.contains(ip) ? "HaGeZi Threat Intelligence: malicious IP" : nil
    }

    /// A connection: its host or IP on a list? (Cheap: a few set lookups.)
    func check(_ e: ActivityEvent) -> ThreatHit? {
        guard enabled, e.kind == .net else { return nil }
        if !e.host.isEmpty, let (domain, detail) = listedDomain(e.host) {
            return hit(.domain, domain, detail, e)
        }
        if let ip = e.remoteHost?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), let detail = listedIP(ip, port: e.remotePort) {
            return hit(.ip, ip, detail, e)
        }
        return nil
    }

    private func hit(_ kind: ThreatHit.Kind, _ indicator: String, _ detail: String, _ e: ActivityEvent) -> ThreatHit {
        let parts = detail.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let h = ThreatHit(date: now(), kind: kind, indicator: indicator, source: parts.first ?? "",
                          detail: parts.count > 1 ? parts[1] : detail, process: e.name, path: e.proc, pid: e.pid)
        record(h, e)
        return h
    }

    private func record(_ h: ThreatHit, _ e: ActivityEvent?) {
        let key = "\(h.indicator)|\(h.process)|\(Calendar.current.startOfDay(for: h.date).timeIntervalSince1970)"
        guard reported.insert(key).inserted else { return }
        hits.append(h)
        if hits.count > 500 { hits.removeFirst(hits.count - 500) }
        save()
        onHit?(h, e)
    }

    /// A launch of an untrusted program (unsigned, ad-hoc, quarantined, from a download/temp folder): its
    /// SHA-256 against the file lists, in the background (once per file version).
    func checkLaunch(_ e: ActivityEvent) {
        guard enabled, e.kind == .exec, !hashes.isEmpty, !hashing.contains(e.target) else { return }
        let path = e.target
        let untrusted = SignatureBuilder.isDropZone(SignatureBuilder.normalize(path))
            || SigningCache.shared.cached(path).map { $0.untrustedCode || $0.quarantined } ?? false
        guard untrusted, let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? Int, size < 500_000_000 else { return }
        let stamp = "\(size)-\((attrs[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)"
        if let known = fileHashes[path], known.stamp == stamp { match(known.sha, e); return }
        hashing.insert(path)
        Task {
            let sha = await Task.detached(priority: .utility) { Self.sha256(of: path) }.value
            hashing.remove(path)
            guard let sha else { return }
            fileHashes[path] = (stamp, sha)
            match(sha, e)
        }
    }

    private func match(_ sha: String, _ e: ActivityEvent) {
        guard let detail = hashes[sha] else { return }
        let parts = detail.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        record(ThreatHit(date: now(), kind: .file, indicator: sha, source: parts.first ?? "", detail: parts.count > 1 ? parts[1] : detail,
                         process: e.name, path: e.target, pid: e.pid), e)
    }

    nonisolated static func sha256(of path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 4 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// After an update: domains seen in the last 30 days that are on a list now.
    private func retroCheck() {
        guard enabled else { return }
        for (domain, programs) in seenDomains() {
            guard let (listed, detail) = listedDomain(domain) else { continue }
            let parts = detail.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            record(ThreatHit(date: now(), kind: .domain, indicator: listed, source: parts.first ?? "",
                             detail: parts.count > 1 ? parts[1] : detail, process: programs.first ?? "", path: "", pid: 0,
                             retro: true), nil)
        }
        for (path, known) in fileHashes {
            guard let detail = hashes[known.sha] else { continue }
            let parts = detail.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            record(ThreatHit(date: now(), kind: .file, indicator: known.sha, source: parts.first ?? "",
                             detail: parts.count > 1 ? parts[1] : detail, process: (path as NSString).lastPathComponent,
                             path: path, pid: 0, retro: true), nil)
        }
    }

    /// Is this domain listed (Domains tab, domain details)?
    func reason(forDomain domain: String) -> String? { enabled ? listedDomain(domain)?.detail : nil }

    /// A known-bad tag for an event row (its connection, or its program's file).
    func flag(for e: ActivityEvent) -> String? {
        guard enabled else { return nil }
        if !e.knownBad.isEmpty { return e.knownBad }
        if e.kind == .exec, let known = fileHashes[e.target], let detail = hashes[known.sha] { return detail }
        return nil
    }

    // MARK: Vulnerabilities

    /// For one vulnerability: fixed by an update already installed, by the one waiting, or not yet.
    func status(_ v: ExploitedVuln) -> VulnStatus {
        if let updated = osUpdated, updated >= v.dateAdded { return .likelyFixed(updated) }
        if let pending = pendingUpdate { return .fixedByPendingUpdate(pending) }
        return .notFixed
    }

    /// Exploited flaws added in the last `days`, and how many the waiting update would fix.
    func recentVulns(days: Int = 90) -> [ExploitedVuln] {
        let cutoff = now().addingTimeInterval(-Double(days) * 86400)
        return vulns.filter { $0.dateAdded >= cutoff }
    }

    var unfixedCount: Int { recentVulns().filter { if case .likelyFixed = status($0) { return false }; return true }.count }

    /// When macOS was last installed or updated (the system version file changes with each update).
    nonisolated static func lastOSUpdate() -> Date? {
        let attrs = try? FileManager.default.attributesOfItem(atPath: "/System/Library/CoreServices/SystemVersion.plist")
        return attrs?[.modificationDate] as? Date
    }

    /// "macOS Tahoe 27.2.1" when Software Update has one waiting (from its last check, no admin needed).
    nonisolated static func pendingMacOSUpdate() async -> String? {
        await Task.detached(priority: .utility) {
            let out = LocalCommand.run("/usr/sbin/softwareupdate", ["--list", "--no-scan"], timeout: 30)
            return parsePendingUpdate(out)
        }.value
    }

    nonisolated static func parsePendingUpdate(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            guard let range = line.range(of: "Title: ") else { continue }
            let title = line[range.upperBound...].split(separator: ",").first.map(String.init) ?? ""
            if title.hasPrefix("macOS") { return title }
        }
        return nil
    }
}
