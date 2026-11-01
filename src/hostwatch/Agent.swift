import Darwin
import Foundation

// `Hostwatch --collector`: the root collector, run by the collector launcher (launchd job).
// Sources: eslogger exec/exit/open, tcpdump pktap (DNS answers, SYNs), an lsof diff, a nettop
// backstop and libproc (busiest processes). Events go out as JSON lines on a Unix socket that only
// the verified app may use. Details: docs/reference.md, "How the collector works".

let collectorFlag = "--collector"

// MARK: - JSON values (output identical to Python's json.dumps(separators=(",", ":")))

indirect enum JValue {
    case str(String), int(Int), double(Double), bool(Bool), array([JValue]), object([(String, JValue)])

    func write(into out: inout String) {
        switch self {
        case .str(let s): JValue.escape(s, into: &out)
        case .int(let i): out += String(i)
        case .double(let d): out += d.isFinite ? "\(d)" : "0"
        case .bool(let b): out += b ? "true" : "false"
        case .array(let items):
            out += "["
            for (i, v) in items.enumerated() { if i > 0 { out += "," }; v.write(into: &out) }
            out += "]"
        case .object(let pairs):
            out += "{"
            for (i, (k, v)) in pairs.enumerated() {
                if i > 0 { out += "," }
                JValue.escape(k, into: &out); out += ":"; v.write(into: &out)
            }
            out += "}"
        }
    }

    /// Like Python's json (ensure_ascii): non-ASCII and control characters as \uXXXX.
    static func escape(_ s: String, into out: inout String) {
        out += "\""
        for u in s.utf16 {
            switch u {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x08: out += "\\b"
            case 0x0C: out += "\\f"
            case 0..<0x20, 0x80...:
                let hex = String(u, radix: 16)
                out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default: out.unicodeScalars.append(Unicode.Scalar(u)!)
            }
        }
        out += "\""
    }
}

/// One event, with its fields in a fixed order (like the Python collector's dicts).
struct AgentEvent {
    var pairs: [(String, JValue)]

    init(_ pairs: [(String, JValue)]) { self.pairs = pairs }

    var kind: String { string("kind") }

    func string(_ key: String) -> String {
        if case .str(let s)? = pairs.first(where: { $0.0 == key })?.1 { return s }
        return ""
    }

    func int(_ key: String) -> Int {
        if case .int(let i)? = pairs.first(where: { $0.0 == key })?.1 { return i }
        return 0
    }

    mutating func set(_ key: String, _ value: JValue) {
        if let i = pairs.firstIndex(where: { $0.0 == key }) { pairs[i].1 = value } else { pairs.append((key, value)) }
    }

    /// One JSON line; "ts" (local time with offset, milliseconds) is added last if missing.
    func jsonLine() -> Data {
        var event = self
        if !pairs.contains(where: { $0.0 == "ts" }) { event.pairs.append(("ts", .str(Agent.nowISO()))) }
        var out = ""
        JValue.object(event.pairs).write(into: &out)
        out += "\n"
        return Data(out.utf8)
    }
}

// MARK: - Small bounded caches

/// A dictionary that forgets its oldest keys past `limit` (an LRU by last write).
struct BoundedMap<Key: Hashable, Value> {
    private var values: [Key: (Value, Int)] = [:]
    private var order: [(Key, Int)] = []
    private var head = 0
    private var stamp = 0
    let limit: Int

    init(limit: Int) { self.limit = limit }

    subscript(key: Key) -> Value? {
        get { values[key]?.0 }
        set {
            guard let newValue else { values[key] = nil; return }
            stamp += 1
            values[key] = (newValue, stamp)
            order.append((key, stamp))
            while values.count > limit, head < order.count {
                let (k, s) = order[head]
                head += 1
                if values[k]?.1 == s { values[k] = nil }
            }
            if head > 4096, head * 2 > order.count { order.removeFirst(head); head = 0 }
        }
    }

    var count: Int { values.count }
}

/// Remembers keys for `ttl` seconds, so repeated opens or connections are reported once.
final class RecentSet<Key: Hashable>: @unchecked Sendable {
    private var map: BoundedMap<Key, TimeInterval>
    private let ttl: TimeInterval
    private let lock = NSLock()

    init(ttl: TimeInterval = 120, limit: Int = 50_000) {
        self.ttl = ttl
        map = BoundedMap(limit: limit)
    }

    /// True if `key` was seen within the ttl; otherwise remembers it now.
    func seen(_ key: Key, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let t = map[key], now - t < ttl { return true }
        map[key] = now
        return false
    }
}

/// Hashable pair for cache keys.
struct PidKey: Hashable { let pid: Int; let text: String }

struct ExclusionRule: Equatable {
    let scope: String?        // nil, "proc", "net" or "file"
    let pattern: String       // lowercased
    let glob: Bool
}

// MARK: - Clients

final class AgentClient: @unchecked Sendable {
    static let fileRate = 40              // max file events per second per client (display)
    let fd: Int32
    let lock = NSLock()
    var rules: [ExclusionRule] = []
    var kinds: Set<String> = Set(Agent.allKinds)
    var rateLimit = true
    var top = false
    private var window = 0
    private var fileCount = 0

    init(fd: Int32) { self.fd = fd }

    func configure(_ cfg: [String: Any]) {
        if let exclude = cfg["exclude"] { rules = Agent.compileRules(exclude as? [Any] ?? []) }
        if let kinds = cfg["kinds"] {
            self.kinds = Set((kinds as? [Any] ?? []).compactMap { $0 as? String }.filter(Agent.allKinds.contains))
        }
        if let top = cfg["top"] { self.top = Agent.truthy(top) }
        if let rate = cfg["rate_limit"] { rateLimit = Agent.truthy(rate) }   // history wants every event
    }

    func wants(_ ev: AgentEvent, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        if ev.kind == "top" { return top }
        guard kinds.contains(ev.kind), !Agent.isExcluded(rules, ev) else { return false }
        if ev.kind == "file" && rateLimit {
            let second = Int(now)
            if second != window { window = second; fileCount = 0 }
            fileCount += 1
            if fileCount > Self.fileRate { return false }
        }
        return true
    }

    /// Writes all of `data`; false if the client is gone.
    func send(_ data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard var p = raw.baseAddress else { return true }
            var left = raw.count
            while left > 0 {
                let n = Darwin.write(fd, p, left)
                if n < 0 { if errno == EINTR { continue }; return false }
                p += n
                left -= n
            }
            return true
        }
    }
}

// MARK: - The collector

final class Agent: @unchecked Sendable {
    static let allKinds = ["exec", "net", "file"]
    static let scopeForKind = ["exec": "proc", "net": "net", "file": "file"]

    let selfPid = Int(getpid())
    private var stopped = false
    private let stopLock = NSLock()
    private var shutdownHooks: [() -> Void] = []
    var shutdownToken: String?

    // Hostwatch's own activity is not reported: the verified owner app, other runs of its exact
    // executable (e.g. the MCP server), our helpers, and children. Exited pids leave the set.
    private let ownLock = NSLock()
    private var ignoredPids: Set<Int> = []
    private var ourTree: Set<Int> = []
    var ownExe = ""

    private let pidLock = NSLock()
    private var pidPaths = BoundedMap<Int, String>(limit: 8192)
    private var pidParents = BoundedMap<Int, Int>(limit: 8192)

    let netLock = NSLock()
    var pidArgs = BoundedMap<Int, String>(limit: 8192)       // command lines, for inferred destinations
    var netPids = BoundedMap<Int, TimeInterval>(limit: 8192)  // pids a connection was reported for

    let dnsLock = NSLock()
    var dnsNames = BoundedMap<String, String>(limit: 50_000)                       // ip -> asked name
    var dnsByName = BoundedMap<String, ([String], TimeInterval)>(limit: 5000)      // name -> ips
    var ptrNames = BoundedMap<String, String>(limit: 50_000)                       // ip -> PTR ("" none)

    let recentOpens = RecentSet<PidKey>()
    let seenConns = RecentSet<PidKey>(ttl: 600)

    private let clientsLock = NSLock()
    private var clients: [ObjectIdentifier: AgentClient] = [:]

    init() { ignoredPids = [selfPid] }

    // MARK: Lifecycle

    var isStopped: Bool { stopLock.lock(); defer { stopLock.unlock() }; return stopped }

    func onShutdown(_ hook: @escaping () -> Void) {
        stopLock.lock(); shutdownHooks.append(hook); stopLock.unlock()
    }

    func requestShutdown() {
        stopLock.lock()
        let first = !stopped
        stopped = true
        let hooks = shutdownHooks
        stopLock.unlock()
        guard first else { return }
        for hook in hooks { hook() }
    }

    /// Waits up to `seconds` or until shutdown; true if shutting down.
    func wait(_ seconds: TimeInterval) -> Bool {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if isStopped { return true }
            Thread.sleep(forTimeInterval: min(0.2, max(0, end.timeIntervalSinceNow)))
        }
        return isStopped
    }

    static func log(_ text: String) { FileHandle.standardOutput.write(Data((text + "\n").utf8)) }
    static func logError(_ text: String) { FileHandle.standardError.write(Data((text + "\n").utf8)) }

    // MARK: Own processes

    func ignore(_ pid: Int) { ownLock.lock(); ignoredPids.insert(pid); ownLock.unlock() }
    func unignore(_ pid: Int) { ownLock.lock(); ignoredPids.remove(pid); ownLock.unlock() }

    func isOurs(_ pid: Int) -> Bool {
        ownLock.lock(); defer { ownLock.unlock() }
        return ignoredPids.contains(pid) || ourTree.contains(pid)
    }

    private func isIgnored(_ pid: Int) -> Bool {
        ownLock.lock(); defer { ownLock.unlock() }
        return ignoredPids.contains(pid)
    }

    /// For every exec: true if it belongs to Hostwatch (and remembers it).
    func noteExec(pid: Int, ppid: Int, path: String) -> Bool {
        ownLock.lock(); defer { ownLock.unlock() }
        let ours = ourTree.contains(ppid) || ignoredPids.contains(ppid) || (!ownExe.isEmpty && path == ownExe)
        if ours { ourTree.insert(pid) } else { ourTree.remove(pid) }     // a reused pid runs something else
        return ours
    }

    func noteExit(_ pid: Int) { ownLock.lock(); ourTree.remove(pid); ownLock.unlock() }
    func addToOurTree(_ pid: Int) { ownLock.lock(); ourTree.insert(pid); ownLock.unlock() }

    /// At start: the owner app, our launcher, and Hostwatch processes already running.
    func adoptOwnProcesses(ownerPid: Int) {
        ownExe = ownerPid > 0 ? pidPath(ownerPid) : ""
        if ownerPid > 0 { addToOurTree(ownerPid) }
        addToOurTree(Int(getppid()))                         // Hostwatch --collector-launcher
        guard !ownExe.isEmpty else { return }
        for pid in ProcessList.allPids() where ProcessList.path(pid) == ownExe { addToOurTree(pid) }
    }

    // MARK: Pid facts

    func rememberPid(_ pid: Int, path: String, ppid: Int = 0) {
        guard pid != 0, !path.isEmpty else { return }
        pidLock.lock(); defer { pidLock.unlock() }
        pidPaths[pid] = path
        if ppid != 0 { pidParents[pid] = ppid }
    }

    func pidPath(_ pid: Int) -> String {
        pidLock.lock()
        let cached = pidPaths[pid]
        pidLock.unlock()
        if let cached { return cached }
        let path = ProcessList.path(pid)                     // not seen via Endpoint Security yet
        if !path.isEmpty { rememberPid(pid, path: path) }
        return path
    }

    func pidParent(_ pid: Int) -> Int {
        pidLock.lock()
        let cached = pidParents[pid]
        pidLock.unlock()
        return cached ?? ProcessList.parent(pid)
    }

    func rememberArgs(_ pid: Int, _ args: String) {
        guard pid != 0 else { return }
        netLock.lock(); pidArgs[pid] = args; netLock.unlock()
    }

    func markNetPid(_ pid: Int) {
        netLock.lock(); netPids[pid] = ProcessInfo.processInfo.systemUptime; netLock.unlock()
    }

    // MARK: Publishing

    func addClient(_ client: AgentClient) {
        clientsLock.lock(); clients[ObjectIdentifier(client)] = client; clientsLock.unlock()
    }

    func dropClient(_ client: AgentClient) {
        clientsLock.lock()
        let had = clients.removeValue(forKey: ObjectIdentifier(client)) != nil
        clientsLock.unlock()
        if had { close(client.fd) }
    }

    var clientCount: Int { clientsLock.lock(); defer { clientsLock.unlock() }; return clients.count }

    var anyClientWantsTop: Bool {
        clientsLock.lock()
        let all = Array(clients.values)
        clientsLock.unlock()
        return all.contains { c in c.lock.lock(); defer { c.lock.unlock() }; return c.top }
    }

    func publish(_ ev: AgentEvent) {
        let payload = ev.jsonLine()
        clientsLock.lock()
        let targets = Array(clients.values)
        clientsLock.unlock()
        for client in targets {
            client.lock.lock()
            let ok = client.wants(ev) ? client.send(payload) : true
            client.lock.unlock()
            if !ok { dropClient(client) }
        }
    }

    func closeAllClients() {
        clientsLock.lock()
        let all = Array(clients.values)
        clients.removeAll()
        clientsLock.unlock()
        for c in all { close(c.fd) }
    }

    // MARK: Helpers

    static func nowHMS() -> String {
        var t = time(nil)
        var tmv = tm()
        localtime_r(&t, &tmv)
        return String(format: "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec)
    }

    /// "2026-11-01T05:41:56.360+02:00", like Python's datetime.now().astimezone().isoformat("milliseconds").
    static func nowISO(_ date: Date = Date()) -> String {
        var seconds = time_t(date.timeIntervalSince1970.rounded(.down))
        let millis = min(999, Int((date.timeIntervalSince1970 - Double(seconds)) * 1000))
        var tmv = tm()
        localtime_r(&seconds, &tmv)
        let offset = Int(tmv.tm_gmtoff)
        let sign = offset < 0 ? "-" : "+"
        return String(format: "%04d-%02d-%02dT%02d:%02d:%02d.%03d%@%02d:%02d",
                      tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                      millis, sign, abs(offset) / 3600, abs(offset) % 3600 / 60)
    }

    static func truthy(_ value: Any) -> Bool {
        if let b = value as? Bool { return b }
        if let n = value as? NSNumber { return n.intValue != 0 }
        if let s = value as? String { return !s.isEmpty }
        return false
    }

    static func intValue(_ value: Any?) -> Int {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) ?? 0 }
        return 0
    }

    static func base(_ path: String) -> String { (path as NSString).lastPathComponent }

    // MARK: Exclusion rules

    static func compileRules(_ lines: [Any]) -> [ExclusionRule] {
        var rules: [ExclusionRule] = []
        for line in lines {
            var s = "\(line)".trimmingCharacters(in: .whitespaces)
            guard !s.isEmpty, !s.hasPrefix("#") else { continue }
            var scope: String?
            for prefix in ["proc:", "net:", "file:"] where s.lowercased().hasPrefix(prefix) {
                scope = String(prefix.dropLast())
                s = String(s.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
                break
            }
            if !s.isEmpty {
                rules.append(ExclusionRule(scope: scope, pattern: s.lowercased(), glob: s.contains("*") || s.contains("?")))
            }
        }
        return rules
    }

    static func matches(_ rule: ExclusionRule, _ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let v = value.lowercased()
        return rule.glob ? fnmatch(rule.pattern, v, 0) == 0 : v.contains(rule.pattern)
    }

    static func isExcluded(_ rules: [ExclusionRule], _ ev: AgentEvent) -> Bool {
        let kindScope = scopeForKind[ev.kind]
        for rule in rules {
            let fields: [String]
            if rule.scope == nil {
                fields = [ev.string("name"), ev.string("proc")]
            } else if rule.scope != kindScope {
                continue
            } else if rule.scope == "proc" {
                fields = [ev.string("name"), ev.string("target")]
            } else {
                let target = ev.string("target")
                let port = target.split(separator: ":", omittingEmptySubsequences: false).last.map(String.init) ?? target
                let host = ev.string("host")
                fields = [target, host.isEmpty ? "" : "\(host):\(port)"]
            }
            if fields.contains(where: { matches(rule, $0) }) { return true }
        }
        return false
    }

    // MARK: Command lines

    private static let secretPatterns: [(NSRegularExpression, String)] = [
        (#"(?i)(authorization:\s*(?:bearer|basic|token)?\s*)[^\s'"]+"#, "$1***"),
        (#"(?i)\b((?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|auth|session)[=:]\s*)[^\s'"&]+"#, "$1***"),
        (#"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"#, "$1***@"),
        (#"\b(gh[pousr]_|glpat-|xox[abp]-|sk-|AKIA)[A-Za-z0-9_-]{8,}"#, "$1***"),
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }

    /// argv -> one shell-like line with obvious secrets masked (it is stored in history).
    static func formatArgs(_ args: [String], limit: Int = 400) -> String {
        var line = args.prefix(64).map { a in
            a.isEmpty || a.contains(where: { " \t\"'".contains($0) }) ? "'\(a)'" : a
        }.joined(separator: " ")
        for (rx, template) in secretPatterns {
            line = rx.stringByReplacingMatches(in: line, range: NSRange(line.startIndex..., in: line), withTemplate: template)
        }
        let scalars = Array(line.unicodeScalars)
        guard scalars.count > limit else { return line }
        var cut = ""
        cut.unicodeScalars.append(contentsOf: scalars.prefix(limit))
        return cut + "…"
    }

    // MARK: Endpoint Security events (eslogger JSON)

    static func exe(_ proc: [String: Any]?) -> String {
        ((proc?["executable"] as? [String: Any])?["path"] as? String) ?? ""
    }

    static func pid(_ proc: [String: Any]?) -> Int {
        let token = proc?["audit_token"] as? [String: Any]
        let p = intValue(token?["pid"])
        return p != 0 ? p : intValue(proc?["pid"])
    }

    /// One eslogger message -> an event to publish, or nil.
    func normalize(_ raw: [String: Any]) -> AgentEvent? {
        let event = raw["event"] as? [String: Any] ?? [:]
        let caller = raw["process"] as? [String: Any] ?? [:]
        if event["exit"] != nil {
            noteExit(Self.pid(caller))
            return nil
        }
        let callerOurs = isOurs(Self.pid(caller)) || Self.intValue(caller["ppid"]) == selfPid
        if callerOurs && event["exec"] == nil { return nil }

        if let exec = event["exec"] as? [String: Any] {
            let target = exec["target"] as? [String: Any] ?? [:]
            let path = Self.exe(target)
            guard !path.isEmpty else { return nil }
            let pid = Self.pid(target)
            var ppid = Self.intValue(target["ppid"])
            if ppid == 0 { ppid = Self.intValue(caller["ppid"]) }
            rememberPid(pid, path: path, ppid: ppid)
            let callerIgnored = isIgnored(Self.pid(caller))
            if noteExec(pid: pid, ppid: ppid, path: path) || callerIgnored { return nil }
            let args = Self.formatArgs((exec["args"] as? [Any] ?? []).map { "\($0)" })
            rememberArgs(pid, args)
            let name = Self.base(path)
            return AgentEvent([
                ("kind", .str("exec")), ("time", .str(Self.nowHMS())), ("pid", .int(pid)), ("ppid", .int(ppid)),
                ("name", .str(name.isEmpty ? path : name)), ("proc", .str(path)),
                ("target", .str(path)), ("parent", .str(Self.exe(caller))), ("args", .str(args)),
            ])
        }

        if let open = event["open"] as? [String: Any] {
            let fpath = ((open["file"] as? [String: Any])?["path"] as? String) ?? ""
            guard !fpath.isEmpty else { return nil }
            let pid = Self.pid(caller)
            let exe = Self.exe(caller)
            rememberPid(pid, path: exe)
            if recentOpens.seen(PidKey(pid: pid, text: fpath)) { return nil }
            let mode = [1: "r", 2: "w", 3: "rw"][Self.intValue(open["fflag"]) & 3] ?? "r"
            let name = Self.base(exe)
            return AgentEvent([
                ("kind", .str("file")), ("time", .str(Self.nowHMS())), ("pid", .int(pid)),
                ("ppid", .int(Self.intValue(caller["ppid"]))),
                ("name", .str(name.isEmpty ? "?" : name)), ("proc", .str(exe)),
                ("target", .str(fpath)), ("extra", .str(mode)),
            ])
        }
        return nil
    }
}
