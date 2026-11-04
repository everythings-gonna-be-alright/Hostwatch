import Darwin
import Foundation

/// macOS's own per-connection statistics: NetworkStatistics.framework, the library `nettop` is built on. It reports
/// every TCP and UDP socket of every process as it appears (and again as it closes) with the process and both
/// addresses, so even a connection that lasts a few milliseconds is seen with its real destination.
///
/// The framework is private, so it's opened at run time: if this macOS lacks any of the functions below, `load()`
/// returns nil and the collector falls back to running `nettop`.
final class NetStats: @unchecked Sendable {
    struct Flow: Equatable { var pid: Int; var name: String; var tcp: Bool; var local: String; var remote: String }

    /// Every socket as soon as it has a local port, connected or not (who owns a local port, for the firewall's
    /// relay when a socket closes before it can look). Called on the private queue; set before `start`.
    var onSocket: ((_ owner: RecentSockets.Owner, _ tcp: Bool, _ localPort: UInt16) -> Void)?

    private typealias Create = @convention(c) (CFAllocator?, DispatchQueue,
                                               @escaping @convention(block) (OpaquePointer?, OpaquePointer?) -> Void) -> OpaquePointer?
    private typealias ManagerCall = @convention(c) (OpaquePointer?) -> Void
    private typealias SetDictBlock = @convention(c) (OpaquePointer?, @escaping @convention(block) (CFDictionary?) -> Void) -> Void
    private typealias SetVoidBlock = @convention(c) (OpaquePointer?, @escaping @convention(block) () -> Void) -> Void
    private typealias SourceCall = @convention(c) (OpaquePointer?) -> Void

    private struct API {
        let create: Create, addTCP: ManagerCall, addUDP: ManagerCall, destroy: ManagerCall
        let setDescription: SetDictBlock, setRemoved: SetVoidBlock, queryDescription: SourceCall
        let pid: String, name: String, provider: String, local: String, remote: String
    }

    static let path = "/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics"

    private let api: API
    private let queue = DispatchQueue(label: "hostwatch.netstats")
    private var manager: OpaquePointer?
    /// Per source: what was last reported, so a description repeated on close isn't reported twice.
    private var reported: [Int: String] = [:]
    private var nextID = 0

    private init(api: API) { self.api = api }

    /// nil when the framework or any function or key is missing.
    static func load() -> NetStats? {
        guard let h = dlopen(path, RTLD_NOW | RTLD_LOCAL) else { return nil }
        func fn<T>(_ name: String, _ type: T.Type) -> T? { dlsym(h, name).map { unsafeBitCast($0, to: type) } }
        func key(_ name: String) -> String? {
            dlsym(h, name).map { $0.assumingMemoryBound(to: CFString.self).pointee as String }
        }
        guard let create = fn("NStatManagerCreate", Create.self),
              let addTCP = fn("NStatManagerAddAllTCP", ManagerCall.self),
              let addUDP = fn("NStatManagerAddAllUDP", ManagerCall.self),
              let destroy = fn("NStatManagerDestroy", ManagerCall.self),
              let setDescription = fn("NStatSourceSetDescriptionBlock", SetDictBlock.self),
              let setRemoved = fn("NStatSourceSetRemovedBlock", SetVoidBlock.self),
              let queryDescription = fn("NStatSourceQueryDescription", SourceCall.self),
              let pid = key("kNStatSrcKeyPID"), let name = key("kNStatSrcKeyProcessName"),
              let provider = key("kNStatSrcKeyProvider"), let local = key("kNStatSrcKeyLocal"),
              let remote = key("kNStatSrcKeyRemote") else { return nil }
        return NetStats(api: API(create: create, addTCP: addTCP, addUDP: addUDP, destroy: destroy,
                                 setDescription: setDescription, setRemoved: setRemoved, queryDescription: queryDescription,
                                 pid: pid, name: name, provider: provider, local: local, remote: remote))
    }

    /// Starts watching. `onFlow` is called (on a private queue) once per socket and remote end, as soon as the remote
    /// end is known; `existing` is true for sockets that were already open when watching began.
    func start(_ onFlow: @escaping (_ flow: Flow, _ existing: Bool) -> Void) {
        let started = ProcessInfo.processInfo.systemUptime
        // Off our queue: the framework delivers to it, and may wait on it while adding sources.
        guard queue.sync(execute: { manager == nil }) else { return }
        let created = api.create(kCFAllocatorDefault, queue) { [weak self] source, _ in
            guard let self, let source else { return }
            // Sockets open at the start arrive in a burst right away.
            let existing = ProcessInfo.processInfo.systemUptime - started < 1
            nextID += 1
            let id = nextID
            api.setDescription(source) { [weak self] dict in
                guard let self, let dict = dict as? [String: Any] else { return }
                if let onSocket, let s = Self.socket(dict, keys: (api.pid, api.name, api.provider, api.local, api.remote)) {
                    onSocket(s.owner, s.tcp, s.port)
                }
                guard let flow = flow(dict) else { return }
                guard reported[id] != flow.remote else { return }
                reported[id] = flow.remote
                onFlow(flow, existing)
            }
            api.setRemoved(source) { [weak self] in self?.reported[id] = nil }
            api.queryDescription(source)
        }
        guard let created else { return }
        queue.sync { manager = created }
        api.addTCP(created)
        api.addUDP(created)
    }

    func stop() {
        let m: OpaquePointer? = queue.sync { defer { manager = nil; reported = [:] }; return manager }
        if let m { api.destroy(m) }
    }

    var isRunning: Bool { queue.sync { manager != nil } }

    /// A description dictionary as a flow; nil until the socket has a remote end.
    private func flow(_ d: [String: Any]) -> Flow? {
        Self.flow(d, keys: (api.pid, api.name, api.provider, api.local, api.remote))
    }

    /// Who has which local port: (owner, TCP?, port); nil without a process or a port.
    static func socket(_ d: [String: Any], keys k: (pid: String, name: String, provider: String, local: String, remote: String))
        -> (owner: RecentSockets.Owner, tcp: Bool, port: UInt16)? {
        guard let pid = (d[k.pid] as? NSNumber)?.intValue, pid > 0,
              let local = (d[k.local] as? Data).flatMap({ NetAddress.text(sockaddr: $0) }),
              let port = local.split(separator: ":").last.flatMap({ UInt16($0) }), port != 0 else { return nil }
        let provider = (d[k.provider] as? String ?? "").uppercased()
        return (RecentSockets.Owner(pid: Int32(pid), name: d[k.name] as? String ?? ""), provider != "UDP", port)
    }

    static func flow(_ d: [String: Any], keys k: (pid: String, name: String, provider: String, local: String, remote: String)) -> Flow? {
        guard let pid = (d[k.pid] as? NSNumber)?.intValue, pid > 0,
              let remoteData = d[k.remote] as? Data, let remote = NetAddress.text(sockaddr: remoteData),
              !NetAddress.isUnspecified(remote) else { return nil }
        let local = (d[k.local] as? Data).flatMap { NetAddress.text(sockaddr: $0) } ?? ""
        let provider = (d[k.provider] as? String ?? "").uppercased()
        return Flow(pid: pid, name: d[k.name] as? String ?? "", tcp: provider != "UDP", local: local, remote: remote)
    }
}

/// Who recently had which local port, from macOS's connection statistics: the firewall's relay asks when a socket
/// has already closed by the time it looks (a DNS query over UDP lasts a few milliseconds).
final class RecentSockets: @unchecked Sendable {
    struct Owner: Equatable, Sendable { var pid: Int32; var name: String }

    private let lock = NSLock()
    private var owners: [String: (owner: Owner, at: TimeInterval)] = [:]
    let keep: TimeInterval

    init(keep: TimeInterval = 120) { self.keep = keep }

    private static func key(_ tcp: Bool, _ port: UInt16) -> String { "\(tcp ? "T" : "U")\(port)" }

    func note(_ owner: Owner, tcp: Bool, port: UInt16, now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        lock.lock(); defer { lock.unlock() }
        owners[Self.key(tcp, port)] = (owner, now)
        if owners.count > 20_000 { owners = owners.filter { now - $0.value.at < keep } }
    }

    /// The last owner of that port, if seen within `keep` seconds. Waits up to `wait` for the statistics to arrive.
    func owner(tcp: Bool, port: UInt16, wait: TimeInterval = 0, now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) -> Owner? {
        let until = now() + wait
        while true {
            lock.lock()
            let hit = owners[Self.key(tcp, port)]
            lock.unlock()
            if let hit, now() - hit.at < keep { return hit.owner }
            if now() >= until { return nil }
            usleep(10_000)
        }
    }
}
