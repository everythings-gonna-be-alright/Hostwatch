import Foundation
import Network

/// One connection (TCP) or flow (UDP) through the relay.
struct RelayFlow: Sendable {
    let id: Int
    let tcp: Bool
    var program: String = ""
    var name: String = ""         // the process's name, when its path couldn't be read (it had quit)
    var pid: Int32 = 0
    var client: IPEndpoint
    var original: IPEndpoint?
    var method = ""
    var host = ""                 // TLS server name, when the client sent one
    var started = Date()
    var setup: TimeInterval = 0   // until the connection onward was ready
    var duration: TimeInterval = 0
    var up = 0, down = 0
    var blocked = false
    var error = ""
}

/// The firewall's relay: connections pf redirects to 127.0.0.1/::1 on `port` arrive here. It finds where each
/// was going and which program made it, asks `decide`, and passes the bytes on (or closes it). Nothing is
/// decrypted: TLS is relayed as it is; only the server name the client announces is read.
final class FirewallRelay: @unchecked Sendable {
    enum Decision: Sendable { case pass, block }

    let port: UInt16
    /// Called once per new flow, on a background queue.
    var decide: @Sendable (RelayFlow) -> Decision = { _ in .pass }
    /// Called when a flow ends.
    var onEnd: (@Sendable (RelayFlow) -> Void)?
    /// How long to wait for a client's first bytes (to read the TLS server name) before connecting anyway.
    var peekTimeout: TimeInterval = 0.3
    /// Where a redirected connection was going (pf; replaceable in tests).
    var findOriginal: @Sendable (_ tcp: Bool, _ client: IPEndpoint, _ local: IPEndpoint) -> (IPEndpoint, String)? = PFRedirect.original
    /// Who had a local port recently, when its socket is already gone by the time the relay looks.
    var recentOwner: (@Sendable (_ tcp: Bool, _ port: UInt16) -> RecentSockets.Owner?)?

    private var listeners: [NWListener] = []
    private var tcpSockets: [Int32] = []
    private var stopped = false
    private let lock = NSLock()
    private var counter = 0
    private var live = 0
    private var sessions: [Int: AnyObject] = [:]

    init(port: UInt16) { self.port = port }

    var activeCount: Int { lock.lock(); defer { lock.unlock() }; return live }

    /// Listens on loopback only (never reachable from the network): TCP with BSD sockets (exact half-closes),
    /// UDP with Network framework flows; IPv4 and IPv6.
    func start() throws {
        for v6 in [false, true] {
            let fd = try Self.listenTCP(port: port, v6: v6)
            tcpSockets.append(fd)
            Thread.detachNewThread { [self] in acceptTCP(fd, v6: v6) }
        }
        for host in ["127.0.0.1", "::1"] {
            let params = NWParameters.udp
            params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!)
            params.allowLocalEndpointReuse = true
            let listener = try NWListener(using: params)
            let v6 = host == "::1"
            listener.newConnectionHandler = { [weak self] c in self?.accept(c, tcp: false, v6: v6) }
            listener.start(queue: .global(qos: .userInitiated))
            listeners.append(listener)
        }
    }

    /// Every listener ready (call shortly after start).
    var ready: Bool {
        tcpSockets.count == 2 && listeners.count == 2 && listeners.allSatisfy { if case .ready = $0.state { true } else { false } }
    }

    func stop() {
        lock.lock(); stopped = true; lock.unlock()
        tcpSockets.forEach { Darwin.shutdown($0, SHUT_RDWR); close($0) }
        tcpSockets = []
        listeners.forEach { $0.cancel() }
        listeners = []
    }

    struct Failure: Error, CustomStringConvertible { let description: String }

    static func listenTCP(port: UInt16, v6: Bool) throws -> Int32 {
        let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure(description: "socket: \(String(cString: strerror(errno)))") }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        let bound: Int32
        if v6 {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); a.sin6_family = sa_family_t(AF_INET6)
            a.sin6_port = port.bigEndian; a.sin6_addr = in6addr_loopback
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, socklen_t(MemoryLayout<Int32>.size))
            bound = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET)
            a.sin_port = port.bigEndian; a.sin_addr.s_addr = inet_addr("127.0.0.1")
            bound = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard bound == 0, Darwin.listen(fd, 512) == 0 else {
            let e = String(cString: strerror(errno)); close(fd)
            throw Failure(description: "listen on port \(port): \(e)")
        }
        return fd
    }

    private func acceptTCP(_ server: Int32, v6: Bool) {
        while true {
            var ss = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let fd = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.accept(server, $0, &len) } }
            if fd < 0 {
                lock.lock(); let done = stopped; lock.unlock()
                if done { return }
                if errno == EINTR || errno == ECONNABORTED { continue }
                usleep(10_000); continue
            }
            guard let client = Self.endpoint(ss) else { close(fd); continue }
            Thread.detachNewThread { [self] in relayTCP(fd, client: client, v6: v6) }
        }
    }

    private func begin(tcp: Bool, client: IPEndpoint) -> RelayFlow {
        lock.lock(); counter += 1; let id = counter; live += 1; lock.unlock()
        var flow = RelayFlow(id: id, tcp: tcp, client: client)
        if let owner = SocketOwner.find(tcp: tcp, localPort: client.port) {       // now, while it holds the port
            flow.program = owner.path; flow.pid = owner.pid
        } else if let owner = recentOwner?(tcp, client.port) {                   // closed already: who it was
            flow.pid = owner.pid
            flow.name = owner.name
            flow.program = ProcessList.path(Int(owner.pid))
        }
        return flow
    }

    /// TCP: peek at the first bytes (TLS server name), decide, connect onward, copy both ways; a side's end of
    /// data is passed on as a half-close, a reset closes both.
    private func relayTCP(_ c: Int32, client: IPEndpoint, v6: Bool) {
        var flow = begin(tcp: true, client: client)
        var on: Int32 = 1
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        let local = IPEndpoint(ip: (v6 ? IPEndpoint.loopback6 : .loopback4).ip, port: port)
        guard let (dst, method) = findOriginal(true, client, local) else {
            flow.error = "original destination not found"; close(c); ended(flow); return
        }
        flow.original = dst; flow.method = method
        var pfd = pollfd(fd: c, events: Int16(POLLIN), revents: 0)
        if poll(&pfd, 1, Int32(peekTimeout * 1000)) > 0 {
            var buf = [UInt8](repeating: 0, count: 16_384)
            let n = recv(c, &buf, buf.count, MSG_PEEK)
            if n > 0, let host = TLSClientHello.serverName(Array(buf[0..<n])) { flow.host = host }
        }
        if decide(flow) == .block { flow.blocked = true; close(c); ended(flow); return }
        let began = Date()
        guard let up = Self.connect(dst, timeout: 15) else {
            flow.error = "onward: \(String(cString: strerror(errno)))"; close(c); ended(flow); return
        }
        setsockopt(up, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        flow.setup = Date().timeIntervalSince(began)
        let forward = Pump(from: c, to: up)
        let thread = Thread { forward.run() }
        thread.start()
        let back = Pump(from: up, to: c)
        back.run()
        forward.done.wait()
        close(c); close(up)
        flow.up = forward.bytes; flow.down = back.bytes
        flow.error = forward.error.isEmpty ? (back.error.isEmpty ? "" : "onward: " + back.error) : "client: " + forward.error
        ended(flow)
    }

    /// Copies one direction until end of data (then half-closes the other side) or an error (then closes both).
    final class Pump: @unchecked Sendable {
        let from: Int32, to: Int32
        var bytes = 0
        var error = ""
        let done = DispatchSemaphore(value: 0)
        init(from: Int32, to: Int32) { self.from = from; self.to = to }

        func run() {
            defer { done.signal() }
            var buf = [UInt8](repeating: 0, count: 65_536)
            while true {
                let n = recv(from, &buf, buf.count, 0)
                if n == 0 { Darwin.shutdown(to, SHUT_WR); return }
                if n < 0 {
                    if errno == EINTR { continue }
                    if errno != ECONNRESET && errno != ENOTCONN { error = String(cString: strerror(errno)) }
                    Darwin.shutdown(to, SHUT_RDWR); Darwin.shutdown(from, SHUT_RDWR); return
                }
                var sent = 0
                while sent < n {
                    let m = buf.withUnsafeBytes { send(to, $0.baseAddress! + sent, n - sent, 0) }
                    if m < 0 {
                        if errno == EINTR { continue }
                        if errno != EPIPE && errno != ECONNRESET { error = String(cString: strerror(errno)) }
                        Darwin.shutdown(to, SHUT_RDWR); Darwin.shutdown(from, SHUT_RDWR); return
                    }
                    sent += m
                }
                bytes += n
            }
        }
    }

    /// A TCP connection onward, with a timeout.
    static func connect(_ dst: IPEndpoint, timeout: TimeInterval) -> Int32? {
        let fd = socket(dst.isV6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        var rc: Int32
        if dst.isV6 {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); a.sin6_family = sa_family_t(AF_INET6); a.sin6_port = dst.port.bigEndian
            withUnsafeMutableBytes(of: &a.sin6_addr) { for i in 0..<16 { $0[i] = dst.ip[i] } }
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET); a.sin_port = dst.port.bigEndian
            withUnsafeMutableBytes(of: &a.sin_addr) { for i in 0..<4 { $0[i] = dst.ip[i] } }
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        if rc != 0 && errno == EINPROGRESS {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            if poll(&pfd, 1, Int32(timeout * 1000)) <= 0 { close(fd); errno = ETIMEDOUT; return nil }
            var err: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
            if err != 0 { close(fd); errno = err; return nil }
        } else if rc != 0 {
            let e = errno; close(fd); errno = e; return nil
        }
        _ = fcntl(fd, F_SETFL, flags)
        return fd
    }

    static func endpoint(_ ss: sockaddr_storage) -> IPEndpoint? {
        var s = ss
        switch Int32(ss.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                IPEndpoint(ip: withUnsafeBytes(of: $0.pointee.sin_addr) { Array($0) }, port: UInt16(bigEndian: $0.pointee.sin_port)) } }
        case AF_INET6:
            return withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                IPEndpoint(ip: withUnsafeBytes(of: $0.pointee.sin6_addr) { Array($0) }, port: UInt16(bigEndian: $0.pointee.sin6_port)) } }
        default: return nil
        }
    }

    private func accept(_ inbound: NWConnection, tcp: Bool, v6: Bool) {
        // Finding the destination and deciding may wait (pf, the app): not on the framework's shared queue.
        Thread.detachNewThread { [self] in acceptUDP(inbound, v6: v6) }
    }

    private func acceptUDP(_ inbound: NWConnection, v6: Bool) {
        guard let client = Self.endpoint(inbound.endpoint) else { inbound.cancel(); return }
        var flow = begin(tcp: false, client: client)
        let local = IPEndpoint(ip: (v6 ? IPEndpoint.loopback6 : .loopback4).ip, port: port)
        guard let (dst, method) = findOriginal(false, client, local) else {
            flow.error = "original destination not found"
            inbound.cancel()
            ended(flow)
            return
        }
        flow.original = dst
        flow.method = method
        let queue = DispatchQueue(label: "hostwatch.relay.\(flow.id)", target: .global(qos: .userInitiated))
        let session = UDPRelaySession(relay: self, inbound: inbound, flow: flow, queue: queue)
        lock.lock(); sessions[flow.id] = session; lock.unlock()
        session.start()
    }

    fileprivate func ended(_ flow: RelayFlow) {
        var f = flow
        f.duration = Date().timeIntervalSince(flow.started)
        lock.lock(); live -= 1; sessions[flow.id] = nil; lock.unlock()
        onEnd?(f)
    }

    static func endpoint(_ e: NWEndpoint) -> IPEndpoint? {
        guard case let .hostPort(host, port) = e else { return nil }
        switch host {
        case .ipv4(let a): return IPEndpoint(ip: [UInt8](a.rawValue), port: port.rawValue)
        case .ipv6(let a): return IPEndpoint(ip: [UInt8](a.rawValue), port: port.rawValue)
        default: return nil
        }
    }

    static func nwEndpoint(_ e: IPEndpoint) -> NWEndpoint {
        let host: NWEndpoint.Host = e.isV6 ? .ipv6(IPv6Address(Data(e.ip))!) : .ipv4(IPv4Address(Data(e.ip))!)
        return .hostPort(host: host, port: NWEndpoint.Port(rawValue: e.port)!)
    }

    static func parameters(tcp: Bool) -> NWParameters {
        let p: NWParameters = tcp ? .tcp : .udp
        p.preferNoProxies = true
        return p
    }
}

/// UDP: one flow per client address and port; datagrams both ways; ends when quiet.
private final class UDPRelaySession: @unchecked Sendable {
    let relay: FirewallRelay
    let inbound: NWConnection
    var upstream: NWConnection?
    var flow: RelayFlow
    let queue: DispatchQueue
    var last = Date()
    var finished = false
    var idle: TimeInterval { flow.original?.port == 53 ? 10 : 60 }

    init(relay: FirewallRelay, inbound: NWConnection, flow: RelayFlow, queue: DispatchQueue) {
        self.relay = relay; self.inbound = inbound; self.flow = flow; self.queue = queue
    }

    func start() {
        guard let dst = flow.original else { return }
        inbound.start(queue: queue)
        if relay.decide(flow) == .block { flow.blocked = true; end(""); return }
        let up = NWConnection(to: FirewallRelay.nwEndpoint(dst), using: FirewallRelay.parameters(tcp: false))
        upstream = up
        up.stateUpdateHandler = { [self] state in
            if case .failed(let e) = state { end("onward: \(e)") }
        }
        up.start(queue: queue)
        loop(from: inbound, to: up, upward: true)
        loop(from: up, to: inbound, upward: false)
        watchIdle()
    }

    func loop(from: NWConnection, to: NWConnection, upward: Bool) {
        from.receiveMessage { [self] data, _, _, error in
            guard !finished else { return }
            if let data, !data.isEmpty {
                last = Date()
                if upward { flow.up += data.count } else { flow.down += data.count }
                to.send(content: data, completion: .contentProcessed { _ in })
            }
            if error != nil, data == nil { end(upward ? "" : "onward: \(error!)"); return }
            loop(from: from, to: to, upward: upward)
        }
    }

    func watchIdle() {
        queue.asyncAfter(deadline: .now() + 5) { [self] in
            guard !finished else { return }
            if Date().timeIntervalSince(last) > idle { end("") } else { watchIdle() }
        }
    }

    func end(_ error: String) {
        guard !finished else { return }
        finished = true
        if flow.error.isEmpty { flow.error = error }
        upstream?.stateUpdateHandler = nil
        inbound.cancel()
        upstream?.cancel()
        relay.ended(flow)
    }
}
