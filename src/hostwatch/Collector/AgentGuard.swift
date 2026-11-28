import Foundation

// Protection with Endpoint Security (ADR 0011, 0018): launches and opens in protected places are held inside macOS
// before they happen, and allowed or denied. What the collector can settle alone (its own processes, other users',
// unprotected files, a place's expected programs and your blocks, a reused answer) never waits for the app; the rest
// becomes a guard_ask the app answers from its rules or by asking you.

/// A held launch or file open, as the kernel reported it.
struct HoldRequest: Sendable {
    enum What: String, Sendable { case exec, open }
    var what: What
    var path: String            // the program: what is launched, or what opens the file
    var pid: Int
    var ppid: Int
    var parent = ""             // launches: the program that launched it
    var args = ""
    var file = ""               // opens
    var mode = "r"
    var uid: uid_t
    var seconds: TimeInterval   // until macOS's deadline
    var installs: [InstallTarget] = []   // launches: the packages it installs or runs (read only while packages are guarded)
    var argv: [String] = []              // launches: the words, while packages are guarded (containment reads them)

    /// The same launch or open again: what an answer may be reused for (exact, so `curl a` never answers `curl b`).
    var key: String {
        what == .exec ? "x\0\(parent)\0\(path)\0\(args)" : "o\0\(path)\0\(file)\0\(mode)"
    }

    var fields: [(String, JValue)] {
        var f: [(String, JValue)] = [("what", .str(what.rawValue)), ("path", .str(path)), ("pid", .int(pid)),
                                     ("ppid", .int(ppid)), ("parent", .str(parent))]
        if what == .exec { f.append(("args", .str(args))) } else { f += [("file", .str(file)), ("mode", .str(mode))] }
        return f
    }
}

/// A protected place as the app describes it (`ProtectionMonitor.collectorConfig`).
struct HoldPlace: Equatable, Sendable {
    var id: String
    var prefixes: [String]
    var owners: [String]        // program names (ssh) or paths (an app, a program you always allow)
    var blocked: [String]
    var writesOnly = false
    var names: [String] = []    // only these file names count (browser credential stores)
    /// Held only for the programs listed: a place one app's card names that General doesn't protect.
    var othersPass = false

    init(id: String, prefixes: [String], owners: [String] = [], blocked: [String] = [], writesOnly: Bool = false,
         names: [String] = [], othersPass: Bool = false) {
        self.id = id; self.prefixes = prefixes; self.owners = owners; self.blocked = blocked
        self.writesOnly = writesOnly; self.names = names; self.othersPass = othersPass
    }

    init?(_ d: [String: Any]) {
        guard let id = d["id"] as? String, let prefixes = d["prefixes"] as? [String], !prefixes.isEmpty else { return nil }
        self.init(id: id, prefixes: prefixes, owners: d["owners"] as? [String] ?? [], blocked: d["blocked"] as? [String] ?? [],
                  writesOnly: d["writesOnly"] as? Bool ?? false, names: d["names"] as? [String] ?? [],
                  othersPass: d["othersPass"] as? Bool ?? false)
    }

    /// How deep the place covers `path` (the length of the matching prefix), nil when it doesn't.
    func depth(_ path: String) -> Int? {
        prefixes.filter { path == $0 || path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }.map(\.count).max()
    }

    /// A program named in `list`: a path (an app covers what's inside it, as `AccessRules.runs`), or the start of an
    /// executable's name (`SignatureBuilder.owners`: ssh covers ssh-agent).
    static func names(_ list: [String], _ program: String) -> Bool {
        let base = (program as NSString).lastPathComponent
        return list.contains { entry in
            entry.contains("/") ? program == entry || program.hasPrefix(entry.hasSuffix("/") ? entry : entry + "/")
                : !entry.isEmpty && base.hasPrefix(entry)
        }
    }
}

/// What the app asked the collector to enforce.
struct HoldConfig: Equatable, Sendable {
    var launches = false
    var files = false
    var places: [HoldPlace] = []
    var hostwatch = ""

    init(launches: Bool = false, files: Bool = false, places: [HoldPlace] = [], hostwatch: String = "") {
        self.launches = launches; self.files = files; self.places = places; self.hostwatch = hostwatch
    }

    init(_ d: [String: Any]) {
        let enforces: (Any?) -> Bool = { ["ask", "strict"].contains($0 as? String ?? "") }
        self.init(launches: enforces(d["launches"]), files: enforces(d["files"]),
                  places: (d["groups"] as? [[String: Any]] ?? []).compactMap(HoldPlace.init),
                  hostwatch: d["hostwatch"] as? String ?? "")
    }

    var prefixes: [String] { files ? Array(Set(places.flatMap(\.prefixes))).sorted() : [] }

    /// Settled without the app: allow, deny (with why), or nil to ask the app. Pure.
    func local(_ r: HoldRequest, userUID: uid_t?, ours: (Int) -> Bool) -> (allow: Bool, reason: String)? {
        if ours(r.pid) || ours(r.ppid) { return (true, "") }                          // Hostwatch's own
        if let user = userUID, r.uid != user { return (true, "") }                 // only your own processes
        switch r.what {
        case .exec:
            if !launches || r.path == hostwatch || Self.systemProgram(r.path) { return (true, "") }
            return nil
        case .open:
            if !files || r.path == hostwatch { return (true, "") }
            guard let place = places.compactMap({ p in p.depth(r.file).map { (p, $0) } }).max(by: { $0.1 < $1.1 })?.0
            else { return (true, "") }
            if !place.names.isEmpty, !place.names.contains((r.file as NSString).lastPathComponent) { return (true, "") }
            if place.writesOnly, !r.mode.contains("w") { return (true, "") }
            if HoldPlace.names(place.blocked, r.path) { return (false, "you always block it there") }
            if HoldPlace.names(place.owners, r.path) || Self.systemProgram(r.path) || place.othersPass { return (true, "") }
            return nil
        }
    }

    /// macOS's own programs, except the ones that run whatever they're told (shells, curl, python): the app allows
    /// them anyway unless you marked the pattern, and asking it would put every system tool a build or Mail runs
    /// through a round trip. A pattern you mark on one of them is enforced the old way, right after it starts.
    static func systemProgram(_ path: String) -> Bool {
        SignatureBuilder.isSealedSystem(path) && !SignatureBuilder.isLolbin(path)
    }
}

/// The holds: who decides, what waits, the answers to reuse, and the clock. Each request is answered exactly once:
/// by a local rule, a reused answer, the app, the app's silence (it goes on, and the app pauses it the old way), or
/// macOS's deadline once you're being asked (blocked, your choice).
final class AgentGuard: @unchecked Sendable {
    /// The app answers what it can settle in a few milliseconds; silence this long means it's busy or gone, and the
    /// launch goes on rather than every program on the Mac waiting for Hostwatch.
    static let quickAnswer: TimeInterval = 0.15
    /// Answered this long before macOS's own deadline, which would end the client.
    static let margin: TimeInterval = 1.0

    struct Pending {
        let key: String
        let request: HoldRequest
        let respond: @Sendable (Bool) -> Void
        var waiting = false        // the app is asking you: no quick answer expected
        var answered = false       // let go after the app's silence: a later answer is only remembered
    }

    private let lock = NSLock()
    // The kernel clients, under their own lock (starting one takes a moment).
    let clientsLock = NSLock()
    var esState = "unknown", esDetail = ""
    var execClient: ESAuthClient?
    var openClient: ESAuthClient?
    var openPrefixes: [String] = []
    var reported = ("", "", "")
    private(set) var config = HoldConfig()
    let packages = PackageHold()
    private weak var decider: AgentClient?
    private var deciderUID: uid_t?
    private var pending: [Int: Pending] = [:]
    private var answers: [String: (allow: Bool, until: TimeInterval)] = [:]
    private var nextID = 0
    private let queue = DispatchQueue(label: "hostwatch.guard")
    /// Sends one line to the deciding app (replaced in tests).
    var send: (AgentClient?, AgentEvent) -> Void = { client, ev in
        guard let client else { return }
        client.lock.lock(); _ = client.send(ev.jsonLine()); client.lock.unlock()
    }
    var ours: (Int) -> Bool = { _ in false }
    /// The quick-answer wait (tests lengthen it to drive the timers by hand).
    var quick = AgentGuard.quickAnswer
    var now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    /// Called when the config changes what must be held (the collector starts or stops its auth clients).
    var onConfig: ((HoldConfig, HoldConfig) -> Void)?

    /// {"guard": {...}} from the app's main connection. Answers reused so far may no longer hold: forgotten.
    func configure(_ d: [String: Any], from client: AgentClient?) {
        let new = HoldConfig(d)
        lock.lock()
        let old = config
        config = new
        decider = client
        deciderUID = client?.uid
        answers = [:]
        lock.unlock()
        onConfig?(old, new)
        applyClients()
    }

    /// A held launch or open: `respond` is called exactly once, on some thread, before macOS's deadline.
    func request(_ r: HoldRequest, respond: @escaping @Sendable (Bool) -> Void) {
        if packages.isActive, !ours(r.pid), !ours(r.ppid), let allow = packageDecision(r) {
            respond(allow)
            return
        }
        lock.lock()
        if let (allow, reason) = config.local(r, userUID: deciderUID, ours: ours) {
            let client = decider
            lock.unlock()
            respond(allow)
            if !allow { send(client, Self.line("guard_block", r, ["reason": .str(reason)])) }
            return
        }
        let t = now()
        if let a = answers[r.key], a.until > t {
            let client = decider
            lock.unlock()
            respond(a.allow)
            if !a.allow { send(client, Self.line("guard_block", r, ["reason": .str("your answer a moment ago")])) }
            return
        }
        guard let client = decider else { lock.unlock(); respond(true); return }      // nobody to ask: it goes on
        nextID += 1
        let id = nextID
        pending[id] = Pending(key: r.key, request: r, respond: respond)
        lock.unlock()
        let hard = max(0, r.seconds - Self.margin)
        send(client, Self.line("guard_ask", r, ["id": .int(id), "deadline": .double(hard)]))
        queue.asyncAfter(deadline: .now() + min(quick, hard / 2)) { [weak self] in self?.quiet(id) }
        queue.asyncAfter(deadline: .now() + hard) { [weak self] in self?.expire(id) }
    }

    /// {"guard_answer": {"id": 3, "allow": true, "ttl": 300}}. ttl 0: this time only, nothing reused.
    func answer(_ a: [String: Any]) {
        guard let id = (a["id"] as? NSNumber)?.intValue else { return }
        let allow = a["allow"] as? Bool ?? true
        let ttl = (a["ttl"] as? NSNumber)?.doubleValue ?? 0
        lock.lock()
        guard let p = pending.removeValue(forKey: id) else { lock.unlock(); return }
        if ttl > 0 { answers[p.key] = (allow, now() + ttl) }
        if answers.count > 4000 { let t = now(); answers = answers.filter { $0.value.until > t } }
        lock.unlock()
        if !p.answered { p.respond(allow) }
    }

    /// {"guard_wait": {"id": 3}}: the app is asking you; the hold lasts until your answer or macOS's deadline.
    func wait(_ a: [String: Any]) {
        guard let id = (a["id"] as? NSNumber)?.intValue else { return }
        lock.lock(); pending[id]?.waiting = true; lock.unlock()
    }

    /// The app's connection closed: everything it held goes on, and nothing is held until it's back.
    func clientGone(_ client: AgentClient) {
        lock.lock()
        guard decider === client else { lock.unlock(); return }
        decider = nil
        deciderUID = nil
        let all = pending.values.filter { !$0.answered }
        pending = [:]
        lock.unlock()
        for p in all { p.respond(true) }
        applyClients()
    }

    /// The deciding app's connection (read under `lock`).
    var currentDecider: AgentClient? { lock.lock(); defer { lock.unlock() }; return decider }

    var isDeciding: Bool { lock.lock(); defer { lock.unlock() }; return decider != nil }

    /// No quick answer and not being asked: it goes on, and the app pauses it the old way if it must.
    func quiet(_ id: Int) {
        lock.lock()
        guard var p = pending[id], !p.waiting, !p.answered else { lock.unlock(); return }
        p.answered = true
        pending[id] = p
        let client = decider
        lock.unlock()
        p.respond(true)
        send(client, AgentEvent([("kind", .str("guard_late")), ("id", .int(id)), ("pid", .int(p.request.pid))]))
    }

    /// macOS's deadline: a question you didn't answer is blocked.
    func expire(_ id: Int) {
        lock.lock()
        guard let p = pending.removeValue(forKey: id) else { lock.unlock(); return }
        let client = decider
        lock.unlock()
        guard !p.answered else { return }
        p.respond(false)
        send(client, Self.line("guard_block", p.request, ["id": .int(id), "reason": .str("no answer in time")]))
    }

    var pendingCount: Int { lock.lock(); defer { lock.unlock() }; return pending.count }

    static func line(_ kind: String, _ r: HoldRequest, _ extra: [String: JValue]) -> AgentEvent {
        AgentEvent([("kind", .str(kind))] + r.fields + extra.sorted { $0.key < $1.key }.map { ($0.key, $0.value) })
    }
}

// MARK: The kernel clients

extension AgentGuard {
    /// Whether Endpoint Security works here (the collector's own client started): "available", or why not.
    func setEndpointSecurity(_ state: String, detail: String = "") {
        clientsLock.lock(); esState = state; esDetail = detail; clientsLock.unlock()
        applyClients()
    }

    /// Starts and stops the holding clients for the config: nothing is held without the app or outside Ask and
    /// Strict. All or nothing: with one missing, the app pauses programs the old way for both.
    func applyClients() {
        lock.lock()
        let cfg = config
        let deciding = decider != nil
        let client = decider
        lock.unlock()
        clientsLock.lock()
        var state = esState, detail = esDetail
        if state == "available" {
            let wantExec = deciding && (cfg.launches || packages.isActive)
            let prefixes = deciding ? Array(Set(cfg.prefixes + packages.prefixes)).sorted() : []
            if !wantExec { execClient?.stop(); execClient = nil }
            if prefixes.isEmpty || prefixes != openPrefixes { openClient?.stop(); openClient = nil; openPrefixes = [] }
            if wantExec, execClient == nil {
                switch ESAuthClient.start(.exec, guard: self) {
                case .success(let c): execClient = c
                case .failure(let why): state = "failed"; detail = "launches: \(why.text)"
                }
            }
            if state == "available", !prefixes.isEmpty, openClient == nil {
                switch ESAuthClient.start(.open, prefixes: prefixes, guard: self) {
                case .success(let c): openClient = c; openPrefixes = prefixes
                case .failure(let why): state = "failed"; detail = "protected files: \(why.text)"
                }
            }
            if state != "available" {
                execClient?.stop(); execClient = nil
                openClient?.stop(); openClient = nil; openPrefixes = []
            }
        } else {
            execClient?.stop(); execClient = nil
            openClient?.stop(); openClient = nil; openPrefixes = []
        }
        let holding = ((execClient != nil ? ["launches"] : []) + (openClient != nil ? ["protected files"] : [])).joined(separator: " and ")
        let changed = (state, detail) != (reported.0, reported.1)
        let logIt = changed || holding != reported.2
        reported = (state, detail, holding)
        clientsLock.unlock()
        if changed || deciding {
            send(client, AgentEvent([("kind", .str("guard_status")), ("state", .str(state)), ("detail", .str(detail))]))
        }
        if logIt { Agent.log("protection: Endpoint Security \(state)\(detail.isEmpty ? "" : " (\(detail))"), holding \(holding.isEmpty ? "nothing" : holding)") }
    }
}
