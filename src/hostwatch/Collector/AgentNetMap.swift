import Darwin
import Foundation

// The network map's facts, gathered passively by the collector: who tried to reach this Mac (incoming connection
// attempts), which programs listen to the network, the devices next to it and the way out (gateway, VPN). Nothing
// is sent to find any of it. source: docs/adr/0017-network-map.md

// MARK: - Parsing (pure; fixtures in tests/swift/NetworkMapTests.swift)

/// A device next to this Mac, as the neighbour tables list it.
struct NetNeighbor: Codable, Equatable, Sendable {
    var mac: String
    var ips: [String]
    var iface: String
    var name = ""
}

/// A program waiting for connections on a TCP port.
struct NetListener: Codable, Equatable, Hashable, Sendable {
    enum Scope: String, Codable, Sendable { case all, network, local }
    var pid: Int
    var name: String
    var proc: String
    var port: Int
    var scope: Scope
}

/// The way out: the default gateway and any VPN carrying traffic.
struct NetRoutes: Codable, Equatable, Sendable {
    struct VPN: Codable, Equatable, Sendable {
        var iface: String
        var routes: [String]
        /// It carries everything by default (a default route or the 0/1 + 128.0/1 pair).
        var full: Bool
    }
    var gateway = ""
    var iface = ""
    var vpns: [VPN] = []
    /// The networks this Mac is on ("192.168.1.0/24", "10.20.0.0/16"), from its own addresses: what "your
    /// network" means here, whatever its range. VPN interfaces are left out.
    var subnets: [String] = []

    /// In one of the networks this Mac is on.
    func onLink(_ ip: String) -> Bool {
        guard let addr = NetMapParse.ipv4(ip) else { return false }
        return subnets.contains { s in
            guard let (base, bits) = NetMapParse.prefix(s) else { return false }
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
            return addr & mask == base & mask
        }
    }

    /// Which interface an IPv4 destination leaves by: the VPN with the longest matching route, else the default.
    func iface(for ip: String) -> String { vpnIface(for: ip) ?? iface }

    /// The VPN that carries a destination, nil when none does. `specificOnly`: only a VPN's own routes (a split
    /// tunnel's 10.1/16), not the catch-all halves of a full one, which would also cover addresses on your network
    /// (their more specific route on the Wi-Fi isn't kept).
    func vpnIface(for ip: String, specificOnly: Bool = false) -> String? {
        guard let addr = NetMapParse.ipv4(ip) else { return specificOnly ? nil : vpns.first(where: \.full)?.iface }
        var best: (bits: Int, iface: String)?
        for v in vpns {
            for r in v.routes {
                guard let (base, bits) = NetMapParse.prefix(r), bits > (best?.bits ?? -1), !specificOnly || bits > 1 else { continue }
                let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
                if addr & mask == base & mask { best = (bits, v.iface) }
            }
        }
        return best?.iface
    }
}

/// What one program sent to and received from one address since the last report.
struct NetTraffic: Codable, Equatable, Sendable {
    var proc: String
    var name: String
    var remote: String
    var host = ""
    var sent: Int64
    var received: Int64
}

/// One remote address's tries at one local port since the last report.
struct NetInbound: Codable, Equatable, Sendable {
    var remote: String
    var port: Int
    var count: Int
    /// A program was listening on that port, so the try could connect (else it was refused).
    var listening: Bool
    var name = ""
}

enum NetMapParse {
    /// "cc:2d:e0:c5:1a:5" -> "cc:2d:e0:c5:1a:05": the tables drop leading zeros, and one device must have one key.
    static func mac(_ raw: String) -> String? {
        let parts = raw.lowercased().split(separator: ":")
        guard parts.count == 6, parts.allSatisfy({ $0.count <= 2 && UInt8($0, radix: 16) != nil }) else { return nil }
        let text = parts.map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":")
        return text == "ff:ff:ff:ff:ff:ff" || text.hasPrefix("01:00:5e") || text.hasPrefix("33:33") ? nil : text
    }

    /// A random (private) hardware address: phones and computers make one up per network.
    static func isRandom(_ mac: String) -> Bool {
        guard let first = UInt8(mac.prefix(2), radix: 16) else { return false }
        return first & 0x02 != 0
    }

    /// `arp -an`: "? (192.168.1.1) at cc:2d:e0:c5:1a:5 on en0 ifscope [ethernet]". This Mac's own addresses
    /// ("permanent") and unanswered ones ("(incomplete)") are left out.
    static func arp(_ text: String) -> [NetNeighbor] {
        text.split(separator: "\n").compactMap { line in
            let words = line.split(separator: " ").map(String.init)
            guard words.count >= 6, words[2] == "at", words[4] == "on", !line.contains("permanent"),
                  let mac = mac(words[3]) else { return nil }
            let ip = words[1].trimmingCharacters(in: CharacterSet(charactersIn: "()"))
            guard !ip.hasPrefix("224."), !ip.hasPrefix("239."), !ip.hasSuffix(".255") else { return nil }
            return NetNeighbor(mac: mac, ips: [ip], iface: words[5])
        }
    }

    /// `ndp -an`: "fe80::1873:3995:7408:6f7e%en0   36:48:71:1a:c0:f3   en0 23h59m29s S". The header, this Mac's
    /// own addresses ("permanent") and unanswered ones are left out.
    static func ndp(_ text: String) -> [NetNeighbor] {
        text.split(separator: "\n").compactMap { line in
            let words = line.split(separator: " ").map(String.init)
            guard words.count >= 4, words[0] != "Neighbor", words[3] != "permanent", let mac = mac(words[1]) else { return nil }
            var ip = words[0]
            if let scope = ip.firstIndex(of: "%") { ip = String(ip[..<scope]) }
            return NetNeighbor(mac: mac, ips: [ip], iface: words[2])
        }
    }

    /// One entry per device (hardware address), its IPv4 addresses first.
    static func merge(_ lists: [NetNeighbor]...) -> [NetNeighbor] {
        var out: [String: NetNeighbor] = [:]
        var order: [String] = []
        for n in lists.joined() {
            if var old = out[n.mac] {
                for ip in n.ips where !old.ips.contains(ip) { old.ips.append(ip) }
                out[n.mac] = old
            } else {
                out[n.mac] = n
                order.append(n.mac)
            }
        }
        return order.compactMap { mac in
            out[mac].map { n in var n = n; n.ips.sort { !$0.contains(":") && $1.contains(":") }; return n }
        }
    }

    static let vpnPrefixes = ["utun", "ipsec", "ppp", "tun", "tap", "wg"]

    /// `netstat -rn` (inet and inet6): the default gateway that isn't tied to one interface (flag I: macOS keeps a
    /// scoped default on every utun for its own services), and routes through VPN interfaces.
    static func routes(_ text: String) -> NetRoutes {
        var out = NetRoutes()
        var vpn: [String: [String]] = [:]
        var order: [String] = []
        for line in text.split(separator: "\n") {
            let w = line.split(separator: " ").map(String.init)
            guard w.count >= 4, w[0] != "Destination", w[0] != "Internet:", w[0] != "Internet6:" else { continue }
            let (dest, gateway, flags, netif) = (w[0], w[1], w[2], w[3])
            guard flags.contains("U"), !flags.contains("I") else { continue }
            if vpnPrefixes.contains(where: netif.hasPrefix), dest != "127", !dest.hasPrefix("fe80"), !dest.hasPrefix("ff0") {
                if vpn[netif] == nil { order.append(netif) }
                vpn[netif, default: []].append(dest == "default" ? "0/0" : dest)
                continue
            }
            if dest == "default", out.gateway.isEmpty, flags.contains("G"), ipv4(gateway) != nil {
                out.gateway = gateway
                out.iface = netif
            }
        }
        out.vpns = order.map { iface in
            let r = vpn[iface] ?? []
            return NetRoutes.VPN(iface: iface, routes: r, full: r.contains("0/0") || (r.contains("0/1") && r.contains("128.0/1")))
        }
        // A VPN that carries everything is the way out.
        if let full = out.vpns.first(where: \.full), out.iface.isEmpty { out.iface = full.iface }
        return out
    }

    static func ipv4(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let b = UInt8(p) else { return nil }
            v = v << 8 | UInt32(b)
        }
        return v
    }

    /// netstat's short prefixes: "10.8/16", "128.0/1", "0/1", "10.8.0.1" (a host), "10.8" (classful: /16).
    static func prefix(_ text: String) -> (base: UInt32, bits: Int)? {
        let pieces = text.split(separator: "/")
        let octets = pieces[0].split(separator: ".")
        guard !octets.isEmpty, octets.count <= 4 else { return nil }
        var v: UInt32 = 0
        for i in 0..<4 {
            guard i < octets.count else { v <<= 8; continue }
            guard let b = UInt8(octets[i]) else { return nil }
            v = v << 8 | UInt32(b)
        }
        let bits = pieces.count > 1 ? Int(pieces[1]) : octets.count * 8
        guard let bits, (0...32).contains(bits) else { return nil }
        return (v, bits)
    }

    /// An incoming connection attempt in packet capture (a SYN marked "in"): the remote address and the local port.
    /// The header's packet metadata ("(in)", "(en0, svc BE, in)") without a process: incoming tries to a closed port
    /// have none, so `AgentParse.metadata` (which wants one) can't tell.
    static func inbound(_ line: String, header: String) -> (remote: String, port: Int)? {
        guard let open = header.firstIndex(of: "("), let close = header[open...].firstIndex(of: ")") else { return nil }
        let meta = String(header[header.index(after: open)..<close])
        guard AgentParse.first(AgentParse.incoming, in: meta) != nil, let m = AgentParse.first(AgentParse.syn, in: line),
              let src = AgentParse.group(m, 1, in: line), let dport = AgentParse.group(m, 4, in: line),
              let port = Int(dport) else { return nil }
        return (src, port)
    }

    /// TCP listeners as one entry per program and port, the widest scope kept.
    static func listeners(_ raw: [NetListener]) -> [NetListener] {
        var out: [String: NetListener] = [:]
        let rank: [NetListener.Scope: Int] = [.local: 0, .network: 1, .all: 2]
        for l in raw {
            let key = "\(l.proc)|\(l.port)"
            if let old = out[key], rank[old.scope]! >= rank[l.scope]! { continue }
            out[key] = l
        }
        return out.values.sorted { ($0.port, $0.name) < ($1.port, $1.name) }
    }
}

// MARK: - The collector's side

/// Incoming attempts gathered between reports, names already looked up, and this Mac's own addresses.
final class NetMapState: @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: [String: NetInbound] = [:]
    private var names: [String: (name: String, at: TimeInterval)] = [:]
    private var own: Set<String> = []
    private var traffic: [String: (pid: Int, name: String, remote: String, sent: Int64, received: Int64)] = [:]

    /// Bytes counted on a connection (macOS's statistics). This Mac talking to itself isn't traffic.
    func addTraffic(pid: Int, name: String, remote: String, sent: Int64, received: Int64) {
        guard !NetAddress.isLocalOnly(remote) else { return }
        let ip = AgentParse.stripHost(remote)
        let key = "\(pid)|\(ip)"
        lock.lock(); defer { lock.unlock() }
        guard traffic.count < 5_000 || traffic[key] != nil else { return }
        var t = traffic[key] ?? (pid, name, ip, 0, 0)
        t.sent += sent; t.received += received
        traffic[key] = t
    }

    func drainTraffic() -> [(pid: Int, name: String, remote: String, sent: Int64, received: Int64)] {
        lock.lock(); defer { lock.unlock() }
        let out = Array(traffic.values)
        traffic.removeAll()
        return out
    }

    func setOwn(_ addresses: Set<String>) { lock.lock(); own = addresses; lock.unlock() }

    /// Counts one try; this Mac reaching itself is not someone else trying.
    func note(remote: String, port: Int) {
        let ip = remote
        guard !ip.hasPrefix("127."), ip != "::1" else { return }
        lock.lock(); defer { lock.unlock() }
        guard !own.contains(ip), inbound.count < 2_000 || inbound["\(ip)|\(port)"] != nil else { return }
        inbound["\(ip)|\(port)", default: NetInbound(remote: ip, port: port, count: 0, listening: false)].count += 1
    }

    func drain() -> [NetInbound] {
        lock.lock(); defer { lock.unlock() }
        let out = Array(inbound.values)
        inbound.removeAll()
        return out
    }

    /// A neighbour's name from reverse DNS (the router's), looked up once an hour.
    func name(for ip: String, now: TimeInterval) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let n = names[ip], now - n.at < 3600 else { return nil }
        return n.name
    }

    func setName(_ name: String, for ip: String, now: TimeInterval) {
        lock.lock(); names[ip] = (name, now); lock.unlock()
    }
}

extension SocketOwner {
    /// TCP sockets waiting for connections, with the program and how widely they listen.
    static func listeners(skip: Int32 = getpid()) -> [NetListener] {
        var out: [NetListener] = []
        forEachSocket(skip: skip) { pid, s in
            guard s.soi_kind == SOCKINFO_TCP, s.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN,
                  let local = endpoint(s.soi_proto.pri_tcp.tcpsi_ini, foreign: false),
                  let colon = local.lastIndex(of: ":"), let port = Int(local[local.index(after: colon)...]), port > 0
            else { return true }
            let ip = AgentParse.stripHost(local)
            let scope: NetListener.Scope = ip == "0.0.0.0" || ip == "::" ? .all
                : ip.hasPrefix("127.") || ip == "::1" ? .local : .network
            let path = ProcessList.path(Int(pid))
            let name = (path as NSString).lastPathComponent
            out.append(NetListener(pid: Int(pid), name: name.isEmpty ? "pid \(pid)" : name, proc: path, port: port, scope: scope))
            return true
        }
        return NetMapParse.listeners(out)
    }
}

extension NetAddress {
    /// The IPv4 networks this Mac is on, from its addresses and netmasks: "192.168.1.0/24". Loopback, link-local
    /// and VPN interfaces are left out.
    static func subnets() -> [String] {
        var out: [String] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return out }
        defer { freeifaddrs(list) }
        var p = list
        while let a = p {
            defer { p = a.pointee.ifa_next }
            let name = String(cString: a.pointee.ifa_name)
            guard let sa = a.pointee.ifa_addr, let nm = a.pointee.ifa_netmask, Int32(sa.pointee.sa_family) == AF_INET,
                  !name.hasPrefix("lo"), !NetMapParse.vpnPrefixes.contains(where: name.hasPrefix) else { continue }
            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let mask = nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let bits = mask.nonzeroBitCount
            guard bits >= 8, bits < 32, addr >> 16 != 0xA9FE else { continue }       // not 169.254 (no DHCP answer)
            let net = addr & mask
            let text = "\(net >> 24).\((net >> 16) & 0xff).\((net >> 8) & 0xff).\(net & 0xff)/\(bits)"
            if !out.contains(text) { out.append(text) }
        }
        return out
    }

    /// This Mac's own addresses, on every interface.
    static func own() -> Set<String> {
        var out: Set<String> = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return out }
        defer { freeifaddrs(list) }
        var p = list
        while let a = p {
            if let sa = a.pointee.ifa_addr {
                let len = Int(sa.pointee.sa_len)
                if let text = text(sockaddr: Data(bytes: sa, count: len)) { out.insert(AgentParse.stripHost(text)) }
            }
            p = a.pointee.ifa_next
        }
        return out
    }
}

extension Agent {
    /// Every 10 s while someone is listening: the listeners, the incoming tries since the last report, and every
    /// 30 s the neighbours and routes. One line, `{"kind":"netmap",…}`, that clients asking for `net` get.
    func runNetMap(interval: TimeInterval = 10) {
        var tick = 0
        var neighbors: [NetNeighbor] = []
        var routes = NetRoutes()
        while !isStopped {
            if daemon, idle || clientCount == 0 { guard waitForClient() else { return } }
            autoreleasepool {
                if tick % 3 == 0 {
                    netMap.setOwn(NetAddress.own())
                    let text = { (path: String, args: [String]) in String(decoding: (try? Spawned.run(path, args)) ?? Data(), as: UTF8.self) }
                    neighbors = NetMapParse.merge(NetMapParse.arp(text("/usr/sbin/arp", ["-an"])),
                                                  NetMapParse.ndp(text("/usr/sbin/ndp", ["-an"])))
                    routes = NetMapParse.routes(text("/usr/sbin/netstat", ["-rn", "-f", "inet"])
                                                + "\n" + text("/usr/sbin/netstat", ["-rn", "-f", "inet6"]))
                    routes.subnets = NetAddress.subnets()
                    let now = ProcessInfo.processInfo.systemUptime
                    for i in neighbors.indices {
                        guard let ip = neighbors[i].ips.first(where: { !$0.contains(":") }) else { continue }
                        if let n = netMap.name(for: ip, now: now) { neighbors[i].name = n; continue }
                        let n = Self.reverseDNS(ip)
                        netMap.setName(n, for: ip, now: now)
                        neighbors[i].name = n
                    }
                }
                tick += 1
                // Byte counts: ask, give the answers a moment on the statistics queue, then take what arrived.
                netStats?.queryCounts()
                usleep(300_000)
                let traffic = trafficReport(netMap.drainTraffic())
                let listeners = SocketOwner.listeners()
                let open = Set(listeners.filter { $0.scope != .local }.map(\.port))
                let inbound = netMap.drain().map { i -> NetInbound in
                    var i = i
                    i.listening = open.contains(i.port)
                    i.name = listeners.first { $0.port == i.port && $0.scope != .local }?.name ?? ""
                    return i
                }
                publish(Self.netMapEvent(listeners: listeners, neighbors: neighbors, routes: routes, inbound: inbound, traffic: traffic))
            }
            if wait(interval) { return }
        }
    }

    /// Per program and address, with the program's path and the name it asked DNS for (already known, no lookups).
    /// The busiest 400: a report stays small however busy the Mac is.
    func trafficReport(_ raw: [(pid: Int, name: String, remote: String, sent: Int64, received: Int64)]) -> [NetTraffic] {
        var merged: [String: NetTraffic] = [:]
        for t in raw where !isOurs(t.pid) {
            let proc = pidPath(t.pid)
            let key = (proc.isEmpty ? t.name : proc) + "|" + t.remote
            var m = merged[key] ?? NetTraffic(proc: proc, name: t.name, remote: t.remote, sent: 0, received: 0)
            m.sent += t.sent; m.received += t.received
            merged[key] = m
        }
        dnsLock.lock()
        for (k, var m) in merged { m.host = dnsNames[m.remote] ?? ""; merged[k] = m }
        dnsLock.unlock()
        return Array(merged.values.sorted { $0.sent + $0.received > $1.sent + $1.received }.prefix(400))
    }

    static func netMapEvent(listeners: [NetListener], neighbors: [NetNeighbor], routes: NetRoutes, inbound: [NetInbound],
                            traffic: [NetTraffic] = []) -> AgentEvent {
        AgentEvent([
            ("kind", .str("netmap")),
            ("listeners", .array(listeners.map {
                .object([("pid", .int($0.pid)), ("name", .str($0.name)), ("proc", .str($0.proc)), ("port", .int($0.port)),
                         ("scope", .str($0.scope.rawValue))])
            })),
            ("neighbors", .array(neighbors.map {
                .object([("mac", .str($0.mac)), ("ips", .array($0.ips.map { .str($0) })), ("iface", .str($0.iface)), ("name", .str($0.name))])
            })),
            ("routes", .object([("gateway", .str(routes.gateway)), ("iface", .str(routes.iface)),
                                ("subnets", .array(routes.subnets.map { .str($0) })),
                                ("vpns", .array(routes.vpns.map {
                                    .object([("iface", .str($0.iface)), ("routes", .array($0.routes.map { .str($0) })), ("full", .bool($0.full))])
                                }))])),
            ("traffic", .array(traffic.map {
                .object([("proc", .str($0.proc)), ("name", .str($0.name)), ("remote", .str($0.remote)), ("host", .str($0.host)),
                         ("sent", .int(Int($0.sent))), ("received", .int(Int($0.received)))])
            })),
            ("inbound", .array(inbound.prefix(500).map {
                .object([("remote", .str($0.remote)), ("port", .int($0.port)), ("count", .int($0.count)),
                         ("listening", .bool($0.listening)), ("name", .str($0.name))])
            })),
        ])
    }
}
