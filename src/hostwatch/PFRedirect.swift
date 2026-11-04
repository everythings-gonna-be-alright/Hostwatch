import Darwin
import Foundation

/// An IPv4 or IPv6 address and port, as raw bytes.
struct IPEndpoint: Hashable, Sendable, CustomStringConvertible {
    var ip: [UInt8]           // 4 or 16 bytes, network order
    var port: UInt16

    var isV6: Bool { ip.count == 16 }
    var address: String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = ip.withUnsafeBytes { inet_ntop(isV6 ? AF_INET6 : AF_INET, $0.baseAddress, &buf, socklen_t(buf.count)) }
        return String(cString: buf)
    }
    var description: String { isV6 ? "[\(address)]:\(port)" : "\(address):\(port)" }

    init(ip: [UInt8], port: UInt16) { self.ip = ip; self.port = port }

    init?(_ text: String, port: UInt16) {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            ip = withUnsafeBytes(of: v4) { Array($0) }
        } else if inet_pton(AF_INET6, text, &v6) == 1 {
            ip = withUnsafeBytes(of: v6) { Array($0) }
        } else { return nil }
        self.port = port
    }

    static let loopback4 = IPEndpoint(ip: [127, 0, 0, 1], port: 0)
    static let loopback6 = IPEndpoint(ip: Array(repeating: 0, count: 15) + [1], port: 0)
}

/// pf's side of the firewall: the redirect rules, and where a redirected connection was really going.
enum PFRedirect {
    static let anchor = "com.apple/hostwatch"

    /// Addresses never redirected: this Mac, the local network, link-local, multicast, carrier-grade NAT.
    static let local4 = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                         "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/8"]
    static let local6 = ["::1/128", "::/128", "fe80::/10", "fc00::/7", "ff00::/8"]

    /// Your programs' outgoing TCP and UDP (not root's, not macOS's DNS service, not the local network) are
    /// sent to the relay on `port`. Only new connections: ones already open keep going as they were.
    static func rules(port: UInt16, exemptUIDs: [uid_t]) -> String {
        let exempt = exemptUIDs.map(String.init).joined(separator: " ")
        return """
        table <hw_local4> const { \(local4.joined(separator: ", ")) }
        table <hw_local6> const { \(local6.joined(separator: ", ")) }
        rdr pass on lo0 inet proto { tcp udp } from any to ! <hw_local4> -> 127.0.0.1 port \(port)
        rdr pass on lo0 inet6 proto { tcp udp } from any to ! <hw_local6> -> ::1 port \(port)
        pass out quick proto { tcp udp } from any to any user { \(exempt) } keep state
        pass out quick proto { tcp udp } from any to any user unknown keep state
        pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto { tcp udp } from any to ! <hw_local4> keep state
        pass out quick on ! lo0 route-to (lo0 ::1) inet6 proto { tcp udp } from any to ! <hw_local6> keep state

        """
    }

    /// Where a redirected connection was going: DIOCNATLOOK (a few variants), else pf's state table.
    static func original(tcp: Bool, client: IPEndpoint, local: IPEndpoint) -> (IPEndpoint, String)? {
        for direction: UInt8 in [2, 1] {                                  // PF_OUT, PF_IN
            for daddr in [local, IPEndpoint(ip: Array(repeating: 0, count: local.ip.count), port: local.port)] {
                if let d = natlook(tcp: tcp, client: client, local: daddr, direction: direction) {
                    return (d, "natlook \(direction == 2 ? "out" : "in")\(daddr.ip.allSatisfy { $0 == 0 } ? " any" : "")")
                }
            }
        }
        if let d = stateTable(tcp: tcp, client: client) { return (d, "state table") }
        return nil
    }

    /// struct pfioc_natlook (xnu with Apple's extensions): saddr, daddr, rsaddr, rdaddr (pf_addr, 16 each),
    /// sxport, dxport, rsxport, rdxport (4 each), af, proto, proto_variant, direction: 84 bytes.
    static func natlook(tcp: Bool, client: IPEndpoint, local: IPEndpoint, direction: UInt8) -> IPEndpoint? {
        let fd = open("/dev/pf", O_RDWR)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var nl = [UInt8](repeating: 0, count: 84)
        for (i, b) in client.ip.enumerated() { nl[i] = b }
        for (i, b) in local.ip.enumerated() { nl[16 + i] = b }
        nl[64] = UInt8(client.port >> 8); nl[65] = UInt8(client.port & 0xFF)
        nl[68] = UInt8(local.port >> 8); nl[69] = UInt8(local.port & 0xFF)
        nl[80] = UInt8(client.isV6 ? AF_INET6 : AF_INET)
        nl[81] = UInt8(tcp ? IPPROTO_TCP : IPPROTO_UDP)
        nl[83] = direction
        let request: UInt = 0xC000_0000 | (UInt(84 & 0x1FFF) << 16) | (UInt(UInt8(ascii: "D")) << 8) | 23
        guard nl.withUnsafeMutableBytes({ ioctl(fd, request, $0.baseAddress!) }) == 0 else { return nil }
        let out = IPEndpoint(ip: Array(nl[48..<(48 + client.ip.count)]), port: UInt16(nl[76]) << 8 | UInt16(nl[77]))
        guard out.port != 0, out.port != local.port || out.ip != local.ip, !out.ip.allSatisfy({ $0 == 0 }) else { return nil }
        return out
    }

    /// `pfctl -s state`: "ALL udp 127.0.0.1:46100 <- 1.1.1.1:53 <- 192.168.1.50:57916 …" (IPv6 as addr[port]).
    static func stateTable(tcp: Bool, client: IPEndpoint) -> IPEndpoint? {
        let proto = tcp ? " tcp " : " udp "
        let me = client.isV6 ? "\(client.address)[\(client.port)]" : "\(client.address):\(client.port)"
        let out = run("/sbin/pfctl", ["-s", "state"]).out
        for line in out.split(separator: "\n") where line.contains(proto) && (line.hasSuffix(me) || line.contains("<- \(me) ")) {
            let parts = line.components(separatedBy: " <- ")
            guard parts.count >= 3, let e = parseEndpoint(parts[1].trimmingCharacters(in: .whitespaces)) else { continue }
            return e
        }
        return nil
    }

    static func parseEndpoint(_ s: String) -> IPEndpoint? {
        if s.hasSuffix("]"), let open = s.lastIndex(of: "["), let port = UInt16(s[s.index(after: open)..<s.index(before: s.endIndex)]) {
            return IPEndpoint(String(s[..<open]), port: port)
        }
        guard let colon = s.lastIndex(of: ":"), let port = UInt16(s[s.index(after: colon)...]) else { return nil }
        return IPEndpoint(String(s[..<colon]), port: port)
    }

    // MARK: Loading

    struct Loaded { var token: String; var watchdog: pid_t }

    /// When the rules go away on their own: after a time, or when a process (the collector) is gone.
    enum Failsafe { case after(TimeInterval), whenGone(pid_t) }

    /// Enables pf (reference-counted token), loads the rules, and starts a watchdog in its own session (so it
    /// outlives a crash of this process and of its launchd job) that removes them per `failsafe`.
    static func load(_ rules: String, failsafe: Failsafe) -> (Loaded?, String) {
        let enable = run("/sbin/pfctl", ["-E"])
        let token = (enable.out + enable.err).split(separator: "\n").first { $0.contains("Token") }?
            .split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
        let wait: String
        switch failsafe {
        case .after(let seconds): wait = "sleep \(Int(seconds))"
        case .whenGone(let pid): wait = "while /bin/kill -0 \(pid) 2>/dev/null; do sleep 2; done"
        }
        let script = "trap '' INT HUP TERM; \(wait); /sbin/pfctl -a '\(anchor)' -F all >/dev/null 2>&1; "
            + (token.isEmpty ? "true" : "/sbin/pfctl -X \(token) >/dev/null 2>&1")
        let watchdog = (try? Spawned.start("/bin/sh", ["-c", script], stdout: .null))?.pid ?? 0
        let load = run("/sbin/pfctl", ["-a", anchor, "-f", "-"], input: rules)
        let shown = run("/sbin/pfctl", ["-a", anchor, "-s", "rules"]).out
        guard load.status == 0, shown.contains("route-to") else {
            unload(Loaded(token: token, watchdog: watchdog))
            return (nil, load.err + shown)
        }
        return (Loaded(token: token, watchdog: watchdog), "")
    }

    static func unload(_ l: Loaded) {
        _ = run("/sbin/pfctl", ["-a", anchor, "-F", "all"])
        if !l.token.isEmpty { _ = run("/sbin/pfctl", ["-X", l.token]) }
        if l.watchdog > 0 { kill(l.watchdog, SIGKILL); var st: Int32 = 0; waitpid(l.watchdog, &st, WNOHANG) }
    }

    /// Rules left by a collector that crashed (its watchdog normally removes them).
    static func clearStale() { _ = run("/sbin/pfctl", ["-a", anchor, "-F", "all"]) }

    static var isLoaded: Bool { !run("/sbin/pfctl", ["-a", anchor, "-s", "rules"]).out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    static func run(_ path: String, _ args: [String], input: String? = nil) -> (status: Int32, out: String, err: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe(), inp = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = input == nil ? FileHandle.nullDevice : inp
        do { try p.run() } catch { return (-1, "", "\(error)") }
        if let input { inp.fileHandleForWriting.write(Data(input.utf8)); try? inp.fileHandleForWriting.close() }
        var o = Data(), e = Data()
        let group = DispatchGroup()
        group.enter(); DispatchQueue.global().async { e = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        o = out.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self))
    }
}

/// The host name a TLS client asks for (SNI), from the first bytes of a connection.
enum TLSClientHello {
    static func serverName(_ d: [UInt8]) -> String? {
        // Record: type 22 (handshake), version (2), length (2); handshake: type 1 (ClientHello), length (3).
        guard d.count > 43, d[0] == 0x16, d[5] == 0x01 else { return nil }
        var i = 9 + 2 + 32                                            // client version, random
        func u8() -> Int? { guard i < d.count else { return nil }; defer { i += 1 }; return Int(d[i]) }
        func u16() -> Int? { guard i + 1 < d.count else { return nil }; defer { i += 2 }; return Int(d[i]) << 8 | Int(d[i + 1]) }
        guard let sid = u8() else { return nil }; i += sid
        guard let suites = u16() else { return nil }; i += suites
        guard let comp = u8() else { return nil }; i += comp
        guard let extLen = u16() else { return nil }
        let end = min(d.count, i + extLen)
        while i + 4 <= end {
            guard let type = u16(), let len = u16() else { return nil }
            if type == 0 {                                            // server_name
                var j = i + 2                                         // list length
                while j + 3 <= i + len {
                    let nameType = d[j], nameLen = Int(d[j + 1]) << 8 | Int(d[j + 2])
                    j += 3
                    if nameType == 0, j + nameLen <= d.count {
                        let name = String(decoding: d[j..<(j + nameLen)], as: UTF8.self).lowercased()
                        return name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }) ? name : nil
                    }
                    j += nameLen
                }
                return nil
            }
            i += len
        }
        return nil
    }
}
