import AppKit
import Darwin
import Network
import SwiftUI

// MARK: - Event model

enum EventKind: String, CaseIterable, Codable {
    case exec, net, file

    var title: String {
        switch self {
        case .exec: return "Processes"
        case .net: return "Connections"
        case .file: return "Files"
        }
    }

    var symbol: String {
        switch self {
        case .exec: return "play.fill"
        case .net: return "network"
        case .file: return "doc.fill"
        }
    }

    var color: Color {
        switch self {
        case .exec: return .cyan
        case .net: return .green
        case .file: return .orange
        }
    }
}

struct ActivityEvent: Identifiable, Decodable {
    let id = UUID()
    let kind: EventKind
    let time: String
    let pid: Int
    let ppid: Int
    let name: String
    let proc: String
    let target: String
    let extra: String
    let parent: String           // exec only: program that spawned it
    let host: String             // net only: DNS name for the remote IP ("" if unknown)
    let hostSource: String       // "dns" (name the program looked up) or "ptr" (reverse DNS)
    let args: String             // exec only: command line, secrets masked by the collector
    let inferred: Bool           // net only: seen via traffic stats after it closed; target inferred
    let note: String             // collector's remark (e.g. why a connection is inferred)
    var pstart: Double = 0       // exec only: when the process started (s since 1970), 0 if unknown
    var ts: Double = 0           // when it was recorded (s since 1970), 0 if unknown
    private(set) var signatureKey = ""
    private(set) var signatureProcess = ""
    private(set) var signaturePattern = ""
    private(set) var signatureRisk = PatternRisk.normal
    private(set) var signatureReason = ""
    var isFirst = false          // first time this pattern was ever seen
    var seq = 0                  // arrival order, for sorting by time
    var newDomain = ""           // net: registrable domain first seen within the last hour
    var beacon = ""              // net: "every ~60s" when part of a worrying beacon
    var rawIP = false            // net: public IP, unusual port, no DNS, untrusted program
    var knownBad = ""            // on a threat list: "ThreatFox: AsyncRAT command server, reported …"

    /// Any per-connection network signal that deserves attention.
    var networkSignal: Bool { !newDomain.isEmpty || !beacon.isEmpty || rawIP }

    enum CodingKeys: String, CodingKey {
        case kind, time, pid, ppid, name, proc, target, extra, parent, host, args, inferred, note, pstart
        case hostSource = "host_src"
    }

    init(kind: EventKind, time: String, pid: Int, ppid: Int, name: String,
         proc: String, target: String, extra: String, parent: String, host: String = "", hostSource: String = "", args: String = "") {
        self.kind = kind; self.time = time; self.pid = pid; self.ppid = ppid; self.name = name
        self.proc = proc; self.target = target; self.extra = extra; self.parent = parent
        self.host = host; self.hostSource = hostSource; self.args = args
        self.inferred = false; self.note = ""
        applySignature()
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(EventKind.self, forKey: .kind)
        time = ((try? c.decodeIfPresent(String.self, forKey: .time)) ?? nil) ?? ""
        pid = ((try? c.decodeIfPresent(Int.self, forKey: .pid)) ?? nil) ?? 0
        ppid = ((try? c.decodeIfPresent(Int.self, forKey: .ppid)) ?? nil) ?? 0
        name = ((try? c.decodeIfPresent(String.self, forKey: .name)) ?? nil) ?? "?"
        proc = ((try? c.decodeIfPresent(String.self, forKey: .proc)) ?? nil) ?? ""
        target = ((try? c.decodeIfPresent(String.self, forKey: .target)) ?? nil) ?? ""
        extra = ((try? c.decodeIfPresent(String.self, forKey: .extra)) ?? nil) ?? ""
        parent = ((try? c.decodeIfPresent(String.self, forKey: .parent)) ?? nil) ?? ""
        host = ((try? c.decodeIfPresent(String.self, forKey: .host)) ?? nil) ?? ""
        hostSource = ((try? c.decodeIfPresent(String.self, forKey: .hostSource)) ?? nil) ?? ""
        args = ((try? c.decodeIfPresent(String.self, forKey: .args)) ?? nil) ?? ""
        inferred = ((try? c.decodeIfPresent(Bool.self, forKey: .inferred)) ?? nil) ?? false
        note = ((try? c.decodeIfPresent(String.self, forKey: .note)) ?? nil) ?? ""
        pstart = ((try? c.decodeIfPresent(Double.self, forKey: .pstart)) ?? nil) ?? 0
        applySignature()
    }

    /// "Tue 3 Nov 14:02:11" for a recorded event; the clock time when the day is unknown.
    var dayTime: String {
        guard ts > 0 else { return time }
        return Date(timeIntervalSince1970: ts).formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated)
            .hour(.twoDigits(amPM: .omitted)).minute().second())
    }

    /// The event list's search: `query` (already lowercased) in the name, path, detail or host, or the exact PID.
    func matches(_ query: String) -> Bool {
        name.lowercased().contains(query) || proc.lowercased().contains(query)
            || target.lowercased().contains(query) || host.contains(query) || String(pid) == query
    }

    /// One recorded or streamed line. Same result as `JSONDecoder` but several times faster
    /// (`JSONSerialization` plus plain casts): Time Travel and history search parse tens of thousands of lines.
    static func parse(_ line: Data) -> ActivityEvent? {
        guard let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return nil }
        return ActivityEvent(record: obj)
    }

    init?(record r: [String: Any]) {
        guard let raw = r["kind"] as? String, let kind = EventKind(rawValue: raw) else { return nil }
        func str(_ k: String) -> String { r[k] as? String ?? "" }
        func int(_ k: String) -> Int { (r[k] as? NSNumber)?.intValue ?? 0 }
        self.kind = kind
        time = str("time"); pid = int("pid"); ppid = int("ppid")
        name = r["name"] as? String ?? "?"
        proc = str("proc"); target = str("target"); extra = str("extra"); parent = str("parent")
        host = str("host"); hostSource = str("host_src"); args = str("args")
        inferred = (r["inferred"] as? NSNumber)?.boolValue ?? false
        note = str("note")
        pstart = (r["pstart"] as? NSNumber)?.doubleValue ?? 0
        if let stamp = r["ts"] as? String, let date = HistoryArchive.parseISO(Data(stamp.utf8)) {
            ts = date.timeIntervalSince1970
        }
        applySignature()
    }

    private mutating func applySignature() {
        let sig = SignatureBuilder.signature(for: self)
        (signatureKey, signatureProcess, signaturePattern) = (sig.key, sig.process, sig.pattern)
        (signatureRisk, signatureReason) = (sig.risk, sig.reason)
    }

    var detail: String {
        switch kind {
        case .exec: return "\(pid) ← \(ppid)"
        case .net:
            if target.hasPrefix("?") { return "\(extra) (closed too fast to read)" }
            return "\(extra) \(hostLabel.map { "\($0):\(remotePort)" } ?? target)"
        case .file: return "\(extra) \(abbreviate(target))"
        }
    }

    /// Hostname to show: plain when it is the name the program looked up, "~name" when it is
    /// only reverse DNS (often a CDN/provider name).
    var hostLabel: String? {
        guard kind == .net, !host.isEmpty else { return nil }
        switch hostSource {
        case "ptr": return "~" + host        // reverse DNS: often a provider name
        case "args": return "≈" + host       // taken from the command line, not confirmed by DNS
        default: return host
        }
    }

    var remotePort: String { target.split(separator: ":").last.map(String.init) ?? "" }

    /// "www.google.com" -> "google.com", "a.b.co.uk" -> "b.co.uk".
    var registrableDomain: String? {
        guard !host.isEmpty, hostSource == "dns" else { return nil }
        return DomainRegistry.registrable(host)
    }

    /// Remote host part of a net target ("1.2.3.4:443" -> "1.2.3.4", "[::1]:53" -> "[::1]").
    var remoteHost: String? {
        guard kind == .net, let colon = target.lastIndex(of: ":") else { return nil }
        return String(target[..<colon])
    }
}

private let homeDir = AppPaths.userHome

private func abbreviate(_ path: String) -> String {
    path.hasPrefix(homeDir) ? "~" + path.dropFirst(homeDir.count) : path
}

// MARK: - Exclusion rules (same semantics as the agent)

struct ExclusionRules {
    private struct Rule {
        let scope: String?   // nil = whole process, "proc", "net", "file"
        let pattern: String
        let isGlob: Bool
    }

    private let rules: [Rule]
    let lines: [String]

    init(text: String) {
        var rules: [Rule] = []
        var lines: [String] = []
        for raw in text.split(whereSeparator: \.isNewline) {
            var s = raw.trimmingCharacters(in: .whitespaces)
            if s.isEmpty || s.hasPrefix("#") { continue }
            lines.append(s)
            var scope: String?
            for prefix in ["proc:", "net:", "file:"] where s.lowercased().hasPrefix(prefix) {
                scope = String(prefix.dropLast())
                s = String(s.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
                break
            }
            guard !s.isEmpty else { continue }
            rules.append(Rule(scope: scope, pattern: s.lowercased(),
                              isGlob: s.contains("*") || s.contains("?")))
        }
        self.rules = rules
        self.lines = lines
    }

    func excludes(_ e: ActivityEvent) -> Bool {
        let kindScope: String = e.kind == .exec ? "proc" : e.kind.rawValue
        for rule in rules {
            let fields: [String]
            switch rule.scope {
            case nil: fields = [e.name, e.proc]
            case kindScope?: fields = rule.scope == "proc" ? [e.name, e.target] : [e.target]
            default: continue
            }
            if fields.contains(where: { match(rule, $0) }) { return true }
        }
        return false
    }

    private func match(_ rule: Rule, _ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let v = value.lowercased()
        return rule.isGlob ? fnmatch(rule.pattern, v, 0) == 0 : v.contains(rule.pattern)
    }
}

let exclusionHelp = """
One pattern per line, case-insensitive. Lines starting with # are ignored.
With * or ? it is a glob (whole value must match), otherwise a substring.
  name-or-path      hide everything from matching processes
  proc:<pattern>    hide spawns of matching executables
  net:<pattern>     hide connections to matching remote host:port
  file:<pattern>    hide opens of matching file paths
"""

let defaultExclusions = [
    "file:/dev/*",
    "file:/System/*",
    "file:/usr/lib/*",
    "file:/usr/share/*",
    "file:/Library/Preferences/*",
    "file:/private/var/db/*",
    "file:/private/var/folders/*",
    "file:*/Library/Caches/*",
    "file:*.dylib",
    "net:127.0.0.1:*",
    "net:[::1]:",
    "mdworker",
    "mds_stores",
].joined(separator: "\n") + "\n"


extension ActivityEvent {
    /// Ready-made exclusion patterns for this row: (menu title, pattern).
    var exclusionSuggestions: [(String, String)] {
        var out: [(String, String)] = [("Hide process “\(name)”", name)]
        switch kind {
        case .exec:
            out.append(("Hide spawns of \(target)", "proc:\(target)"))
        case .net:
            if !host.isEmpty, hostSource == "dns" {
                out.append(("Hide host \(host)", "net:\(host):*"))
                if let domain = registrableDomain, domain != host {
                    out.append(("Hide domain *.\(domain)", "net:*.\(domain):*"))
                }
            }
            if let host = remoteHost {
                // IPv6 hosts contain [ ], which glob treats as a class, so use substring form.
                out.append(("Hide host \(host)", host.hasPrefix("[") ? "net:\(host):" : "net:\(host):*"))
            }
            out.append(("Hide endpoint \(target)", "net:\(target)"))
        case .file:
            let folder = (target as NSString).deletingLastPathComponent
            out.append(("Hide folder \(folder)/", "file:\(folder)/*"))
            out.append(("Hide file \(target)", "file:\(target)"))
        }
        return out
    }

    var fullDetail: String {
        switch kind {
        case .exec: return args.isEmpty ? target : "\(target)  ·  \(args)"
        case .net:
            let tail = inferred ? "  · inferred (\(note))" : ""
            if target.hasPrefix("?") { return "\(extra) destination unknown\(tail)" }
            guard let label = hostLabel else { return "\(extra) \(target)\(tail)" }
            return "\(extra) \(label):\(remotePort)  [\(target)]\(tail)"
        case .file: return "\(extra.padding(toLength: 3, withPad: " ", startingAt: 0)) \(target)"
        }
    }
}

/// HUD background: three clearly different looks (like System Settings ▸ Appearance).
enum OverlayBackground: String, CaseIterable {
    case glass, clear, solid

    /// Earlier versions' "blur" (frosted) becomes Glass, "dark" becomes Solid.
    init?(stored: String) {
        switch stored {
        case "blur": self = .glass
        case "dark": self = .solid
        case "transparent": self = .clear              // None was removed: the most see-through left
        default: self.init(rawValue: stored)
        }
    }

    var title: String {
        switch self {
        case .glass: return "Glass"
        case .clear: return "Clear Glass"
        case .solid: return "Solid"
        }
    }

    var detail: String {
        switch self {
        case .glass: return "Liquid Glass that adapts to what's behind it."
        case .clear: return "More see-through Liquid Glass, for calm wallpapers."
        case .solid: return "A dense dark surface: the easiest to read on busy screens."
        }
    }
}

/// The collector's Unix socket, and the checks that make sure it really is the root collector:
/// it must sit in a root-owned folder nobody else can write (so only root could have created it),
/// belong to you and be closed to everyone else. The collector in turn only accepts this app.
enum CollectorSocket {
    static let defaultPath = "/var/run/hostwatch/collector.sock"
    /// HOSTWATCH_SOCKET points elsewhere for development; then the folder need not be root's.
    static var path: String { ProcessInfo.processInfo.environment["HOSTWATCH_SOCKET"] ?? defaultPath }
    static var endpoint: NWEndpoint { .unix(path: path) }

    enum Check: Equatable {
        case ok
        case missing                    // collector not running
        case unsafe(String)             // exists but cannot be trusted: never connect
    }

    static func check(path: String = path, uid: uid_t = getuid()) -> Check {
        var sock = stat(), folder = stat()
        let hasSocket = lstat(path, &sock) == 0
        let hasFolder = lstat((path as NSString).deletingLastPathComponent, &folder) == 0
        return evaluate(folder: hasFolder ? folder : nil, socket: hasSocket ? sock : nil, uid: uid,
                        requireRootFolder: path == defaultPath)
    }

    static func evaluate(folder: stat?, socket: stat?, uid: uid_t, requireRootFolder: Bool) -> Check {
        guard let socket else { return .missing }
        guard socket.st_mode & S_IFMT == S_IFSOCK else { return .unsafe("the collector path is not a socket") }
        guard socket.st_uid == uid else { return .unsafe("the socket belongs to user \(socket.st_uid), not you") }
        guard socket.st_mode & 0o077 == 0 else { return .unsafe("the socket is open to other users") }
        guard let folder, folder.st_mode & S_IFMT == S_IFDIR else { return .unsafe("the socket folder is missing or a link") }
        if requireRootFolder, folder.st_uid != 0 {
            return .unsafe("the socket folder is not owned by root, so it may not be the real collector")
        }
        guard folder.st_mode & 0o022 == 0 else { return .unsafe("the socket folder is writable by others") }
        return .ok
    }
}

// MARK: - Model

@MainActor
final class HUDModel: ObservableObject {
    @Published private(set) var history: [ActivityEvent] = []
    @Published private(set) var connected = false
    /// Why the collector socket was refused (it exists but can't be trusted); nil when fine.
    @Published private(set) var socketWarning: String?
    @Published private(set) var counts: [EventKind: Int] = [:]
    @Published var paused = false
    @Published var searchText = ""
    /// "Show Only These" in the heavy-process strip: only events of these processes.
    @Published var onlyPids: Set<Int>?
    @Published var windowTab = 0          // 0 events, 1 patterns, 2 stories, 3 domains, 4 rules
    @Published var eventSelection = Set<UUID>()
    /// Events table sort (click a column header); newest first by default.
    @Published var eventOrder: [KeyPathComparator<EventItem>] {
        didSet { SortMemory.save(eventOrder, key: "eventTableSort", columns: EventItem.sortColumns) }
    }
    private var nextSeq = 0

    /// Which patterns the overlay and event list show.
    @Published var signatureFilter: SignatureFilter {
        didSet { UserDefaults.standard.set(signatureFilter.rawValue, forKey: "signatureFilter") }
    }
    let signatures: SignatureStore
    let stories: StoryEngine
    let domains: DomainRegistry
    let beacons = BeaconDetector()
    /// Optional "hold suspicious processes" (set by the app; off unless you turn it on).
    var hold: ProcessHold?
    /// Threat lists: a connection to a listed domain or IP carries `knownBad` into stories and the rows.
    var intel: ThreatIntel?
    /// The collector's 5-second "top processes" samples (procs, disk read B/s, disk write B/s).
    var onTop: (([TopProcess], Double, Double) -> Void)?
    /// Every process above the collector's floor (CPU or memory), every 5 s.
    var onVitals: (([ProcessVitalSample]) -> Void)?
    /// Every event that arrives (launches feed `ProcessVitals`).
    var onEvent: ((ActivityEvent) -> Void)?
    /// The firewall asks about a new connection (key, the connection as a net event); answer with sendFirewallAnswer.
    var onFirewallAsk: ((String, ActivityEvent) -> Void)?
    /// The firewall's state in the collector ("on", "off", "failed") and why.
    var onFirewallStatus: ((String, String) -> Void)?
    /// Watch Closely: the collector's recording of one process (progress and result).
    var onWatch: ((WatchMessage) -> Void)?
    var onProcessList: (([RunningProcessInfo]) -> Void)?
    /// What the collector's firewall should do: "off", "ask" or "strict" (sent on every connect).
    var firewallMode = "off" { didSet { if firewallMode != oldValue { sendFirewall() } } }

    @Published var exclusionText: String {
        didSet {
            UserDefaults.standard.set(exclusionText, forKey: Keys.exclusions)
            rules = ExclusionRules(text: exclusionText)
            applyFilters()
        }
    }

    /// Which kinds the HUD and event list *show*. Display only: the collector, patterns,
    /// stories and recorded history always get every kind.
    @Published var visibleKinds: Set<EventKind> {
        didSet { UserDefaults.standard.set(visibleKinds.map(\.rawValue), forKey: Keys.kinds) }
    }

    @Published var overlayClickThrough: Bool {
        didSet { UserDefaults.standard.set(overlayClickThrough, forKey: Keys.clickThrough) }
    }

    /// HUD on/off; remembered across launches.
    @Published var overlayEnabled: Bool {
        didSet { UserDefaults.standard.set(overlayEnabled, forKey: Keys.overlayEnabled) }
    }

    @Published var overlayBackground: OverlayBackground {
        didSet { UserDefaults.standard.set(overlayBackground.rawValue, forKey: Keys.overlayBackground) }
    }

    /// Tint strength for the Blur and Dark backgrounds (0.1…1).
    @Published var overlayOpacity: Double {
        didSet { UserDefaults.standard.set(overlayOpacity, forKey: Keys.overlayOpacity) }
    }

    /// HUD size, all remembered across launches.
    @Published var overlayRows: Int {
        didSet { UserDefaults.standard.set(overlayRows, forKey: Keys.overlayRows) }
    }
    @Published var overlayWidth: CGFloat {
        didSet { UserDefaults.standard.set(Double(overlayWidth), forKey: Keys.overlayWidth) }
    }
    @Published var overlayScale: CGFloat {
        didSet { UserDefaults.standard.set(Double(overlayScale), forKey: Keys.overlayScale) }
    }
    /// Height of the HUD's fixed parts (title, resource line, padding), at text scale `s`.
    func overlayChrome(_ s: CGFloat) -> CGFloat { (62 + (overlayShowResources ? 17 : 0)) * s }

    /// A compact CPU / memory / network / disk line under the HUD's title.
    @Published var overlayShowResources: Bool =
        UserDefaults.standard.object(forKey: "overlayShowResources") as? Bool ?? true {
        didSet { UserDefaults.standard.set(overlayShowResources, forKey: "overlayShowResources") }
    }

    static let rowRange = 3...200
    static let widthRange: ClosedRange<CGFloat> = 240...2400
    static let scaleOptions: [(String, CGFloat)] = [("Small", 0.85), ("Medium", 1.0), ("Large", 1.25), ("Extra Large", 1.5)]
    let historyLimit = 5000
    private var rules: ExclusionRules
    private var connection: NWConnection?
    private var reconnectScheduled = false
    private let queue = DispatchQueue(label: "hostwatch.network")
    private var pending = Data()

    // UI batching: detection (patterns, stories, hold, domains) sees every event at once; the list,
    // counters and HUD get them in batches at most every `uiInterval`, and not at all while nothing
    // is on screen (they catch up when shown).
    static let uiInterval: TimeInterval = 0.2
    private var uiBuffer: [ActivityEvent] = []
    private var countBuffer: [EventKind: Int] = [:]
    private var flushScheduled = false
    /// Set by the app: the activity window or the HUD is visible on screen.
    var uiVisible = true {
        didSet { if uiVisible && !oldValue { flushUI() } }
    }
    private let decoder = JSONDecoder()

    private enum Keys {
        static let exclusions = "exclusions"
        static let kinds = "visibleKinds"
        static let clickThrough = "overlayClickThrough"
        static let overlayEnabled = "overlayEnabled"
        static let overlayBackground = "overlayBackground"
        static let overlayOpacity = "overlayOpacity"
        static let overlayRows = "overlayRows"
        static let overlayWidth = "overlayWidth"
        static let overlayScale = "overlayScale"
    }

    init(signatures: SignatureStore, stories: StoryEngine, domains: DomainRegistry) {
        self.signatures = signatures
        self.stories = stories
        self.domains = domains
        eventOrder = SortMemory.load(key: "eventTableSort", columns: EventItem.sortColumns,
                                     fallback: KeyPathComparator(\.seq, order: .reverse))
        signatureFilter = UserDefaults.standard.string(forKey: "signatureFilter")
            .flatMap(SignatureFilter.init(stored:)) ?? .all
        let defaults = UserDefaults.standard
        let text = defaults.string(forKey: Keys.exclusions) ?? defaultExclusions
        exclusionText = text
        rules = ExclusionRules(text: text)
        if let stored = defaults.stringArray(forKey: Keys.kinds) {
            visibleKinds = Set(stored.compactMap(EventKind.init(rawValue:)))
        } else {
            visibleKinds = Set(EventKind.allCases)
        }
        // Click-through is off by default: the HUD can be moved, resized and double-clicked.
        // Installs that only had the old default (on) are switched off once.
        if !defaults.bool(forKey: "clickThroughDefaultOff") {
            defaults.set(true, forKey: "clickThroughDefaultOff")
            defaults.removeObject(forKey: Keys.clickThrough)
        }
        overlayClickThrough = defaults.object(forKey: Keys.clickThrough) as? Bool ?? false
        overlayEnabled = defaults.object(forKey: Keys.overlayEnabled) as? Bool ?? true
        overlayBackground = defaults.string(forKey: Keys.overlayBackground)
            .flatMap(OverlayBackground.init(stored:)) ?? .glass
        // One-time switch to the Liquid Glass look for existing installs.
        if !defaults.bool(forKey: "designGlassAdopted") {
            defaults.set(true, forKey: "designGlassAdopted")
            overlayBackground = .glass
        }
        overlayOpacity = defaults.object(forKey: Keys.overlayOpacity) as? Double ?? 0.45
        overlayRows = defaults.object(forKey: Keys.overlayRows) as? Int ?? 24
        overlayWidth = CGFloat(defaults.object(forKey: Keys.overlayWidth) as? Double ?? 360)
        overlayScale = CGFloat(defaults.object(forKey: Keys.overlayScale) as? Double ?? 1.0)
    }

    private func passesSignatureFilter(_ e: ActivityEvent) -> Bool { passes(e, signatureFilter) }

    func passes(_ e: ActivityEvent, _ filter: SignatureFilter) -> Bool {
        if filter == .all { return true }
        // New domains, beacons, raw-IP connections and known-bad matches count as new and important on their own.
        if e.networkSignal || !e.knownBad.isEmpty { return true }
        return filter.admits(signatures.status(for: e), risk: e.signatureRisk, reviewed: signatures.reviewedByYou(e.signatureKey))
    }

    /// How many of these events each Show choice would list (with the other filters as they are).
    func showCounts(_ events: [ActivityEvent], applyExclusions: Bool = false) -> [SignatureFilter: Int] {
        var out: [SignatureFilter: Int] = [:]
        for f in SignatureFilter.allCases where f != .all {
            out[f] = filtered(events, applyExclusions: applyExclusions, show: f).count
        }
        return out
    }

    var overlayEvents: [ActivityEvent] {
        var out: [ActivityEvent] = []
        for e in history where visibleKinds.contains(e.kind) && passesSignatureFilter(e) {
            out.append(e)
            if out.count == overlayRows { break }
        }
        return out
    }

    var searchResults: [ActivityEvent] { filtered(history) }

    /// The Show filter, kind toggles, exclusions and search, applied to any list (live or history).
    func filtered(_ events: [ActivityEvent], applyExclusions: Bool = false, show: SignatureFilter? = nil) -> [ActivityEvent] {
        let q = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        let only = onlyPids
        let filter = show ?? signatureFilter
        let visible = events.filter { e in
            visibleKinds.contains(e.kind) && passes(e, filter) && !(applyExclusions && rules.excludes(e))
                && (only?.contains(e.pid) ?? true)
        }
        guard !q.isEmpty else { return visible }
        return visible.filter { $0.matches(q) }
    }

    // MARK: Exclusions

    func addExclusion(_ pattern: String) {
        guard !rules.lines.contains(pattern) else { return }
        var text = exclusionText
        if !text.isEmpty && !text.hasSuffix("\n") { text += "\n" }
        exclusionText = text + pattern + "\n"
    }

    func toggle(_ kind: EventKind) {
        if visibleKinds.contains(kind) { visibleKinds.remove(kind) } else { visibleKinds.insert(kind) }
    }

    func clear() {
        uiBuffer.removeAll()
        countBuffer.removeAll()
        history.removeAll()
        counts = [:]
    }

    private func applyFilters() {
        history.removeAll { rules.excludes($0) }
        sendConfig()
    }

    // MARK: Networking

    #if DEMO
    /// Demo mode: shown as live, with no collector behind it.
    func demoConnect() { connected = true }
    #endif

    func connect() {
        reconnectScheduled = false
        pending.removeAll()
        // Only connect to a socket that can only have been made by the root collector.
        switch CollectorSocket.check() {
        case .ok:
            socketWarning = nil
        case .missing:
            socketWarning = nil
            dropConnection()
            return
        case .unsafe(let why):
            if socketWarning != why { print("refusing collector socket: \(why)") }
            socketWarning = why
            dropConnection()
            return
        }
        let conn = NWConnection(to: CollectorSocket.endpoint, using: .tcp)
        connection = conn

        conn.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self, conn === self.connection else { return }
                switch state {
                case .ready:
                    self.connected = true
                    self.sendConfig()
                    self.receiveNext(conn)
                case .waiting, .failed, .cancelled:
                    self.dropConnection()
                default:
                    break
                }
            }
        }
        conn.start(queue: queue)
    }

    private func dropConnection() {
        connected = false
        connection?.cancel()
        connection = nil
        guard !reconnectScheduled else { return }
        reconnectScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.connect()
        }
    }

    private func send(_ object: [String: Any], completion: (() -> Void)? = nil) {
        guard let connection, connected,
              var data = try? JSONSerialization.data(withJSONObject: object)
        else { completion?(); return }
        data.append(0x0A)
        connection.send(content: data, completion: .contentProcessed { _ in
            DispatchQueue.main.async { completion?() }
        })
    }

    /// The agent filters per client too, so exclusions also cut collector traffic.
    private func sendConfig() {
        send(["exclude": rules.lines, "kinds": EventKind.allCases.map(\.rawValue), "top": true])
        sendFirewall()
    }

    func sendFirewall(flush: Bool = false) {
        send(["firewall": ["mode": firewallMode, "flush": flush]])
    }

    /// The answer to a firewall question, remembered by the collector for `ttl` seconds.
    /// Starts or stops a watch; false when the collector isn't connected.
    func sendWatch(_ watch: [String: Any]) -> Bool {
        guard connected else { return false }
        send(["watch": watch])
        return true
    }

    /// Asks for every running process (Events ▸ Running Now); false when the collector isn't connected.
    func requestProcesses() -> Bool {
        guard connected else { return false }
        send(["processes": true])
        return true
    }

    func sendFirewallAnswer(key: String, pass: Bool, ttl: TimeInterval) {
        send(["fw_answer": ["key": key, "pass": pass, "ttl": ttl]])
    }

    /// Asks the collector to exit; it only obeys a client that knows its token.
    /// Returns false when there is no connection to send it on.
    @discardableResult
    func sendShutdown(token: String, completion: (() -> Void)? = nil) -> Bool {
        guard connected else { completion?(); return false }
        send(["cmd": "shutdown", "token": token], completion: completion)
        return true
    }

    private func receiveNext(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            Task { @MainActor in
                guard let self, conn === self.connection else { return }
                if let data, !data.isEmpty {
                    self.receive(data)
                }
                if error != nil || isComplete {
                    self.dropConnection()
                } else {
                    self.receiveNext(conn)
                }
            }
        }
    }

    private static let topMarker = Data(#""kind":"top""#.utf8)
    private static let askMarker = Data(#""kind":"fw_ask""#.utf8)
    private static let statusMarker = Data(#""kind":"fw_status""#.utf8)
    private static let watchMarker = Data(#""kind":"watch""#.utf8)
    private static let processListMarker = Data(#""kind":"proc_list""#.utf8)
    private struct TopMessage: Decodable {
        var procs: [TopProcess]
        var disk_read: Double?
        var disk_write: Double?
        var vitals: [ProcessVitalSample]?
    }

    /// Collector output (JSON lines, possibly partial) into the model.
    func receive(_ data: Data) {
        pending.append(data)
        consumeLines()
    }

    private func consumeLines() {
        var fresh: [ActivityEvent] = []
        while let newline = pending.firstIndex(of: 0x0A) {
            let line = pending[pending.startIndex..<newline]
            pending.removeSubrange(...newline)
            if line.range(of: Self.topMarker) != nil {
                if let top = try? decoder.decode(TopMessage.self, from: Data(line)) {
                    onTop?(top.procs, top.disk_read ?? 0, top.disk_write ?? 0)
                    if let vitals = top.vitals { onVitals?(vitals) }
                }
                continue
            }
            // Firewall questions are answered even while paused: a connection is waiting.
            if line.range(of: Self.askMarker) != nil {
                if let obj = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any], let key = obj["key"] as? String,
                   let netLine = String(decoding: line, as: UTF8.self).replacingOccurrences(of: #""kind":"fw_ask""#, with: #""kind":"net""#)
                       .data(using: .utf8),
                   let event = try? decoder.decode(ActivityEvent.self, from: netLine) {
                    onFirewallAsk?(key, event)
                }
                continue
            }
            // A watch is reported even while paused: you asked for it.
            if line.range(of: Self.watchMarker) != nil {
                if let m = try? WatchMessage.decoder.decode(WatchMessage.self, from: Data(line)) { onWatch?(m) }
                continue
            }
            // Asked for, so answered even while paused. The marker is the list's first key: an event's
            // command line can't put it there.
            if line.prefix(40).range(of: Self.processListMarker) != nil {
                if let m = try? decoder.decode(ProcessListMessage.self, from: Data(line)) { onProcessList?(m.list) }
                continue
            }
            if line.range(of: Self.statusMarker) != nil {
                if let obj = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any] {
                    onFirewallStatus?(obj["state"] as? String ?? "", obj["detail"] as? String ?? "")
                }
                continue
            }
            guard !paused,
                  var event = ActivityEvent.parse(Data(line)),
                  !rules.excludes(event)
            else { continue }
            event.isFirst = signatures.observe(event)
            nextSeq += 1
            event.seq = nextSeq
            if event.kind == .net {
                if let domain = domains.observe(event) { event.newDomain = domain }
                if let beacon = beacons.observe(event) { event.beacon = beacon }
                event.rawIP = NetSignals.isRawIP(event)
                if let hit = intel?.check(event) { event.knownBad = hit.summary }
            } else if event.kind == .exec {
                intel?.checkLaunch(event)       // untrusted programs: SHA-256 against the file lists
            }
            let stages = stories.ingest(event, decidedSafe: signatures.markedSafeByYou(event))
            hold?.consider(event, stages: stages, status: signatures.status(for: event))
            onEvent?(event)
            fresh.append(event)
            countBuffer[event.kind, default: 0] += 1
        }
        guard !fresh.isEmpty else { return }
        uiBuffer.append(contentsOf: fresh)
        // While hidden, keep only what the list could show anyway.
        if uiBuffer.count > historyLimit { uiBuffer.removeFirst(uiBuffer.count - historyLimit) }
        guard uiVisible, !flushScheduled else { return }
        flushScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.uiInterval) { [weak self] in
            MainActor.assumeIsolated { self?.flushUI() }
        }
    }

    /// After a restart: the newest recorded events (up to the list's limit) fill the list, so it isn't
    /// empty. Display only: detection handled them in the previous session. They sort below live events.
    func restoreRecent(from directory: URL, completion: (() -> Void)? = nil) {
        let limit = historyLimit, rules = self.rules
        Task {
            let restored = await Task.detached(priority: .utility) { () -> [ActivityEvent] in
                let archive = HistoryArchive(directory: directory)
                let segments = archive.segments()
                guard let last = segments.map(\.end).max() else { return [] }
                // Newest first; ~600 bytes per event keeps the read small even for busy history.
                let events = archive.events(segments, from: .distantPast, to: last.addingTimeInterval(1),
                                            maxBytes: Int64(limit) * 600).events
                return Array(events.filter { !rules.excludes($0) }.prefix(limit))
            }.value
            guard !restored.isEmpty else { completion?(); return }
            var older = restored
            for i in older.indices { older[i].seq = -(i + 1) }        // below every live event
            var updated = history
            updated.append(contentsOf: older.prefix(max(0, limit - updated.count)))
            history = updated
            restoredCount = min(restored.count, limit)
            completion?()
        }
    }

    /// How many events were restored from history at launch (0 = none).
    @Published private(set) var restoredCount = 0

    /// Hands buffered events to the list, counters and HUD in one update.
    func flushUI() {
        flushScheduled = false
        guard !uiBuffer.isEmpty || !countBuffer.isEmpty else { return }
        if !uiBuffer.isEmpty {
            var updated = history
            updated.insert(contentsOf: uiBuffer.reversed(), at: 0)
            if updated.count > historyLimit { updated.removeLast(updated.count - historyLimit) }
            history = updated
            uiBuffer.removeAll(keepingCapacity: true)
        }
        if !countBuffer.isEmpty {
            var c = counts
            for (kind, n) in countBuffer { c[kind, default: 0] += n }
            counts = c
            countBuffer.removeAll()
        }
    }
}
