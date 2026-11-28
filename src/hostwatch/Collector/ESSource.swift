import EndpointSecurity
import Foundation

// The collector's own Endpoint Security client (ADR 0018): launches, exits and file opens straight from the kernel,
// in place of an eslogger process and its JSON. Each message is turned into the dictionary eslogger would have
// printed, so `Agent.normalize` and everything after it stay one path for both sources (eslogger remains the
// fallback for a build without the entitlement).

/// Why the client didn't start: decides between falling back to eslogger and telling you about Full Disk Access.
enum ESStartFailure: Error, Equatable {
    case notEntitled          // a build signed without the entitlement and its profile: eslogger instead
    case notPermitted         // no Full Disk Access (TCC): eslogger is refused the same way, so the app hears of it
    case notPrivileged        // not root
    case tooManyClients
    case other(String)

    var text: String {
        switch self {
        case .notEntitled: return "not entitled"
        case .notPermitted: return "no Full Disk Access"
        case .notPrivileged: return "not running as root"
        case .tooManyClients: return "too many Endpoint Security clients"
        case .other(let s): return s
        }
    }
}

final class ESSource: @unchecked Sendable {
    private var client: OpaquePointer?

    /// Subscribes to `events` (eslogger's names: exec, exit, open) and calls `handler` with each message in
    /// eslogger's shape, on Endpoint Security's queue, one message at a time.
    static func start(events: [String], handler: @escaping @Sendable ([String: Any]) -> Void) -> Result<ESSource, ESStartFailure> {
        let source = ESSource()
        var client: OpaquePointer?
        let result = es_new_client(&client) { _, message in
            autoreleasepool {
                if let raw = ESSource.raw(message.pointee) { handler(raw) }
            }
        }
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS: break
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return .failure(.notEntitled)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return .failure(.notPermitted)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return .failure(.notPrivileged)
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return .failure(.tooManyClients)
        default: return .failure(.other("es_new_client \(result.rawValue)"))
        }
        guard let client else { return .failure(.other("no client")) }
        source.client = client
        // The collector's own file opens are never reported (normalize drops them anyway): muted here, they don't
        // cross from the kernel at all. Its launches stay: they keep the set of Hostwatch's own processes exact.
        if var token = ESSource.ownAuditToken() {
            var open = ES_EVENT_TYPE_NOTIFY_OPEN
            _ = es_mute_process_events(client, &token, &open, 1)
        }
        var types = events.compactMap(ESSource.eventType)
        guard !types.isEmpty, es_subscribe(client, &types, UInt32(types.count)) == ES_RETURN_SUCCESS else {
            es_delete_client(client)
            source.client = nil
            return .failure(.other("es_subscribe failed"))
        }
        return .success(source)
    }

    /// Unsubscribes and ends the client; no handler call runs after it returns.
    func stop() {
        guard let client else { return }
        self.client = nil
        es_unsubscribe_all(client)
        es_delete_client(client)
    }

    deinit { stop() }

    static func eventType(_ name: String) -> es_event_type_t? {
        switch name {
        case "exec": return ES_EVENT_TYPE_NOTIFY_EXEC
        case "exit": return ES_EVENT_TYPE_NOTIFY_EXIT
        case "open": return ES_EVENT_TYPE_NOTIFY_OPEN
        case "fork": return ES_EVENT_TYPE_NOTIFY_FORK
        default: return nil
        }
    }

    // MARK: Messages in eslogger's shape

    /// The fields `Agent.normalize` reads, nothing more: building the whole of eslogger's JSON would cost for nothing.
    static func raw(_ m: es_message_t) -> [String: Any]? {
        let caller = process(m.process.pointee, version: m.version)
        switch m.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            var exec = m.event.exec
            var args: [String] = []
            let count = es_exec_arg_count(&exec)
            args.reserveCapacity(Int(min(count, 256)))
            for i in 0..<min(count, 256) { args.append(string(es_exec_arg(&exec, i))) }
            return ESShape.exec(caller: caller, target: process(exec.target.pointee, version: m.version), args: args)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return ESShape.exit(caller: caller)
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return ESShape.open(caller: caller, path: string(m.event.open.file.pointee.path), fflag: Int(m.event.open.fflag))
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return ESShape.fork(caller: caller, child: process(m.event.fork.child.pointee, version: m.version))
        default:
            return nil
        }
    }

    private static func process(_ p: es_process_t, version: UInt32) -> ESShape.Process {
        // An audit token's sixth word is the pid, its eighth the pid's generation (a new one with every exec), so
        // the pair names one process exactly, never a later one that reused the pid. Parent and responsible process
        // come with message version 4, the signature the kernel checked with every message.
        let v4 = version >= 4
        return ESShape.Process(path: string(p.executable.pointee.path), pid: Int(p.audit_token.val.5), ppid: Int(p.ppid),
                               generation: Int(p.audit_token.val.7),
                               responsible: v4 ? Int(p.responsible_audit_token.val.5) : 0,
                               responsibleGeneration: v4 ? Int(p.responsible_audit_token.val.7) : 0,
                               parent: v4 ? Int(p.parent_audit_token.val.5) : 0,
                               parentGeneration: v4 ? Int(p.parent_audit_token.val.7) : 0,
                               team: string(p.team_id), signing: string(p.signing_id),
                               csFlags: Int(p.codesigning_flags), originalPpid: Int(p.original_ppid))
    }

    static func string(_ t: es_string_token_t) -> String {
        guard let data = t.data, t.length > 0 else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: t.length), as: UTF8.self)
    }

    static func ownAuditToken() -> audit_token_t? {
        var token = audit_token_t()
        var size = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(size)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &size)
            }
        }
        return kr == KERN_SUCCESS ? token : nil
    }
}

/// eslogger's JSON shape for the three events, as plain values: pure, so the conversion is testable without a
/// kernel client.
enum ESShape {
    struct Process {
        let path: String; let pid: Int; let ppid: Int
        var generation = 0
        var responsible = 0, responsibleGeneration = 0
        var parent = 0, parentGeneration = 0
        var team = "", signing = ""
        var csFlags = 0, originalPpid = 0
    }

    /// eslogger's names for the same fields (`pidversion`, `parent_audit_token`, `team_id`, `signing_id`).
    static func process(_ p: Process) -> [String: Any] {
        var out: [String: Any] = ["executable": ["path": p.path], "audit_token": ["pid": p.pid, "pidversion": p.generation],
                                  "ppid": p.ppid]
        if p.responsible > 0 { out["responsible_audit_token"] = ["pid": p.responsible, "pidversion": p.responsibleGeneration] }
        if p.parent > 0 { out["parent_audit_token"] = ["pid": p.parent, "pidversion": p.parentGeneration] }
        if !p.team.isEmpty { out["team_id"] = p.team }
        if !p.signing.isEmpty { out["signing_id"] = p.signing }
        out["codesigning_flags"] = p.csFlags
        out["original_ppid"] = p.originalPpid
        return out
    }

    static func fork(caller: Process, child: Process) -> [String: Any] {
        ["process": process(caller), "event": ["fork": ["child": process(child)]]]
    }

    static func exec(caller: Process, target: Process, args: [String]) -> [String: Any] {
        ["process": process(caller), "event": ["exec": ["target": process(target), "args": args]]]
    }

    static func exit(caller: Process) -> [String: Any] {
        ["process": process(caller), "event": ["exit": [String: Any]()]]
    }

    static func open(caller: Process, path: String, fflag: Int) -> [String: Any] {
        ["process": process(caller), "event": ["open": ["file": ["path": path], "fflag": fflag]]]
    }
}

/// A client that holds launches (AUTH_EXEC) or opens in protected places (AUTH_OPEN, only those: the kernel is told
/// to deliver opens under these prefixes alone) and passes each to `AgentGuard`. Every message is answered once,
/// and always before macOS's deadline, which would otherwise end the client: a last-resort timer lets it go just
/// before, whatever the guard is doing.
final class ESAuthClient: @unchecked Sendable {
    enum Kind { case exec, open }
    private var client: OpaquePointer?
    /// Held messages not answered yet: stopping answers them first (answering after the client is gone would crash).
    private let lock = NSLock()
    private var outstanding: [ObjectIdentifier: Held] = [:]
    private var stopping = false

    static func start(_ kind: Kind, prefixes: [String] = [], guard g: AgentGuard) -> Result<ESAuthClient, ESStartFailure> {
        let me = ESAuthClient()
        var client: OpaquePointer?
        let result = es_new_client(&client) { c, message in
            me.handle(c, message, kind: kind, guard: g)
        }
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS: break
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return .failure(.notEntitled)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return .failure(.notPermitted)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return .failure(.notPrivileged)
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return .failure(.tooManyClients)
        default: return .failure(.other("es_new_client \(result.rawValue)"))
        }
        guard let client else { return .failure(.other("no client")) }
        me.client = client
        if var token = ESSource.ownAuditToken() { _ = es_mute_process(client, &token) }   // the collector itself
        var type: es_event_type_t
        switch kind {
        case .exec:
            type = ES_EVENT_TYPE_AUTH_EXEC
        case .open:
            type = ES_EVENT_TYPE_AUTH_OPEN
            guard es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_RETURN_SUCCESS else {
                es_delete_client(client); me.client = nil
                return .failure(.other("target path muting isn't supported"))
            }
            for p in prefixes where !p.isEmpty { _ = es_mute_path(client, p, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
        }
        guard es_subscribe(client, &type, 1) == ES_RETURN_SUCCESS else {
            es_delete_client(client); me.client = nil
            return .failure(.other("es_subscribe failed"))
        }
        return .success(me)
    }

    func stop() {
        guard let client else { return }
        es_unsubscribe_all(client)
        lock.lock()
        stopping = true
        let all = Array(outstanding.values)
        lock.unlock()
        for h in all { h.respond(true) }
        self.client = nil
        es_delete_client(client)
    }

    deinit { stop() }

    /// Seconds from now until the message's deadline.
    static func secondsLeft(_ deadline: UInt64) -> TimeInterval {
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        return Double(deadline - now) * Double(tb.numer) / Double(tb.denom) / 1_000_000_000
    }

    private func handle(_ c: OpaquePointer, _ message: UnsafePointer<es_message_t>, kind: Kind, guard g: AgentGuard) {
        let m = message.pointee
        let seconds = ESAuthClient.secondsLeft(m.deadline)
        let caller = m.process.pointee
        let uid = uid_t(caller.audit_token.val.1)
        let request: HoldRequest
        switch kind {
        case .exec:
            var exec = m.event.exec
            let target = exec.target.pointee
            var args: [String] = []
            let count = min(es_exec_arg_count(&exec), 256)
            for i in 0..<count { args.append(ESSource.string(es_exec_arg(&exec, i))) }
            let path = ESSource.string(target.executable.pointee.path)
            var r = HoldRequest(what: .exec, path: path, pid: Int(target.audit_token.val.5), ppid: Int(target.ppid),
                                parent: ESSource.string(caller.executable.pointee.path),
                                args: Agent.formatArgs(args), uid: uid, seconds: seconds)
            if g.packages.isActive {
                r.argv = Array(args.prefix(8))
                let cwd = m.version >= 3 ? ESSource.string(exec.cwd.pointee.path) : ""
                r.installs = InstallContext.targets(path: path, args: args, env: Self.packageEnv(&exec), cwd: cwd,
                                                    read: Self.readHead)
            }
            request = r
        case .open:
            let flags = Int(m.event.open.fflag)
            request = HoldRequest(what: .open, path: ESSource.string(caller.executable.pointee.path),
                                   pid: Int(caller.audit_token.val.5), ppid: Int(caller.ppid),
                                   file: ESSource.string(m.event.open.file.pointee.path),
                                   mode: [1: "r", 2: "w", 3: "rw"][flags & 3] ?? "r", uid: uid, seconds: seconds)
        }
        lock.lock()
        if stopping {
            lock.unlock()
            if kind == .open { es_respond_flags_result(c, message, UInt32.max, false) }
            else { es_respond_auth_result(c, message, ES_AUTH_RESULT_ALLOW, false) }
            return
        }
        es_retain_message(message)
        let held = Held(client: c, message: message, flags: kind == .open)
        let id = ObjectIdentifier(held)
        outstanding[id] = held
        lock.unlock()
        held.onDone = { [weak self] in self?.lock.lock(); self?.outstanding[id] = nil; self?.lock.unlock() }
        let respond: @Sendable (Bool) -> Void = { held.respond($0) }
        // Last resort, whatever happens in the guard: let it go just before macOS's deadline.
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + max(0, seconds - 0.4)) { respond(true) }
        g.request(request, respond: respond)
    }

    /// The few environment variables an install script carries its package in. Every launch on the Mac passes here
    /// while packages are guarded, so a variable is copied only when its first byte could start one of them.
    private static func packageEnv(_ exec: inout es_event_exec_t) -> [String: String] {
        var env: [String: String] = [:]
        let count = min(es_exec_env_count(&exec), 1024)
        for i in 0..<count {
            let token = es_exec_env(&exec, i)
            guard token.length > 8, let first = token.data?.pointee, first == 0x6E || first == 0x43 else { continue }  // n, C
            let pair = ESSource.string(token)
            guard let eq = pair.firstIndex(of: "=") else { continue }
            let name = String(pair[..<eq])
            if InstallContext.envNames.contains(name) { env[name] = String(pair[pair.index(after: eq)...]) }
        }
        return env
    }

    /// The start of a small file (a source package's PKG-INFO), read as root inside the hold: 8 KB at most.
    private static func readHead(_ path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        return (try? h.read(upToCount: 8192)).map { String(decoding: $0, as: UTF8.self) }
    }

    /// One retained message, answered the first time only, then released.
    private final class Held: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private let client: OpaquePointer
        private let message: UnsafePointer<es_message_t>
        private let flags: Bool
        var onDone: (@Sendable () -> Void)?

        init(client: OpaquePointer, message: UnsafePointer<es_message_t>, flags: Bool) {
            self.client = client; self.message = message; self.flags = flags
        }

        func respond(_ allow: Bool) {
            lock.lock()
            guard !done else { lock.unlock(); return }
            done = true
            lock.unlock()
            if flags {
                es_respond_flags_result(client, message, allow ? UInt32.max : 0, false)
            } else {
                es_respond_auth_result(client, message, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
            }
            es_release_message(message)
            onDone?()
        }
    }
}
