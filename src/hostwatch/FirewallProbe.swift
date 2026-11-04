import Darwin
import Foundation

/// `sudo Hostwatch --firewall-probe`: proves the firewall's relay works on this Mac, on two test destinations
/// only (HTTP to example.com, DNS to 1.1.1.1), for about 15 seconds. pf sends your user's connections to those
/// two through a relay here; the relay finds where each was going (from pf) and which program made it (from its
/// port), passes it on, and reports. The rules sit in their own anchor inside Apple's (which /etc/pf.conf loads),
/// are removed at the end, and a watchdog removes them after 60 s even if this crashes. Changes nothing else.
enum FirewallProbe {
    static let flag = "--firewall-probe"
    static let anchor = "com.apple/hostwatch-probe"
    static let relayPort: UInt16 = 46_100

    struct Seen { var proto: String; var client: String; var original: String; var method: String; var program: String; var bytes: Int }
    nonisolated(unsafe) static var seen: [Seen] = []
    static let lock = NSLock()

    static func run() -> Never {
        setvbuf(stdout, nil, _IOLBF, 0)
        guard geteuid() == 0 else {
            print("Run it with sudo:  sudo '\(CommandLine.arguments[0])' \(flag)")
            exit(1)
        }
        guard let uid = ProcessInfo.processInfo.environment["SUDO_UID"], uid != "0" else {
            print("Run it with sudo from your own account (it tests your user's connections)."); exit(1)
        }
        let iface = sh("/sbin/route", ["-n", "get", "default"]).out.split(separator: "\n")
            .first { $0.contains("interface:") }?.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
        guard !iface.isEmpty else { print("No default network interface: are you online?"); exit(1) }
        guard let webIP = ipv4("example.com") else { print("Can't resolve example.com: are you online?"); exit(1) }
        let dnsIP = "1.1.1.1"
        print("Hostwatch firewall probe · interface \(iface) · test destinations \(webIP):80 (example.com) and \(dnsIP):53")

        // Before: both work without the relay?
        let before = (web: web(uid, webIP), dns: dns(uid, dnsIP))
        print("Before:  HTTP \(before.web)  ·  DNS \(before.dns)")

        // Relay listeners.
        guard let tcp = listen(SOCK_STREAM), let udp = listen(SOCK_DGRAM) else { print("Can't listen on 127.0.0.1:\(relayPort)"); exit(1) }
        Thread.detachNewThread { acceptTCP(tcp) }
        Thread.detachNewThread { serveUDP(udp) }

        // pf: enable (reference-counted token), load the anchor, watchdog.
        let enable = sh("/sbin/pfctl", ["-E"])
        let token = (enable.out + enable.err).split(separator: "\n").first { $0.contains("Token") }?
            .split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
        let watchdog = Process()
        watchdog.executableURL = URL(fileURLWithPath: "/bin/sh")
        watchdog.arguments = ["-c", "trap '' INT HUP TERM; sleep 60; /sbin/pfctl -a '\(anchor)' -F all >/dev/null 2>&1; "
                              + (token.isEmpty ? "" : "/sbin/pfctl -X \(token) >/dev/null 2>&1")]
        try? watchdog.run()
        let rules = """
        rdr pass on lo0 inet proto tcp from any to \(webIP) port 80 -> 127.0.0.1 port \(relayPort)
        rdr pass on lo0 inet proto udp from any to \(dnsIP) port 53 -> 127.0.0.1 port \(relayPort)
        pass out quick on \(iface) route-to (lo0 127.0.0.1) inet proto tcp from any to \(webIP) port 80 user != 0 keep state
        pass out quick on \(iface) route-to (lo0 127.0.0.1) inet proto udp from any to \(dnsIP) port 53 user != 0 keep state

        """
        let load = sh("/sbin/pfctl", ["-a", anchor, "-f", "-"], input: rules)
        let loaded = sh("/sbin/pfctl", ["-a", anchor, "-s", "all"])
        func cleanUp() {
            _ = sh("/sbin/pfctl", ["-a", anchor, "-F", "all"])
            if !token.isEmpty { _ = sh("/sbin/pfctl", ["-X", token]) }
            watchdog.terminate()
        }
        signal(SIGINT, SIG_IGN)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        interrupt.setEventHandler { cleanUp(); print("\nInterrupted: pf rules removed."); exit(1) }
        interrupt.resume()
        if load.status != 0 || !loaded.out.contains("route-to") {
            print("pf didn't accept the rules:\n\(load.err)\(loaded.out)")
            cleanUp(); exit(1)
        }

        // During: the same requests, now through the relay.
        let during = (web: web(uid, webIP), dns: dns(uid, dnsIP))
        cleanUp()
        let after = sh("/sbin/pfctl", ["-a", anchor, "-s", "rules"]).out.trimmingCharacters(in: .whitespacesAndNewlines)

        print("Through the relay:  HTTP \(during.web)  ·  DNS \(during.dns)")
        lock.lock(); let log = seen; lock.unlock()
        for s in log {
            print("  relay saw \(s.proto) from \(s.client) → original \(s.original) [\(s.method)] · program \(s.program) · \(s.bytes) bytes back")
        }
        let tcpOK = log.contains { $0.proto == "TCP" && $0.original == "\(webIP):80" } && (during.web.hasPrefix("HTTP 2") || during.web.hasPrefix("HTTP 3"))
        let udpOK = log.contains { $0.proto == "UDP" && $0.original == "\(dnsIP):53" } && !during.dns.hasPrefix("failed")
        let named = log.contains { !$0.program.hasPrefix("?") }
        print("")
        print("TCP through the relay:     \(tcpOK ? "works" : "FAILED")")
        print("UDP through the relay:     \(udpOK ? "works" : "FAILED")")
        print("Program behind each flow:  \(named ? "found" : "NOT found")")
        print("pf rules removed:          \(after.isEmpty ? "yes" : "NO — run: sudo pfctl -a \(anchor) -F all")")
        exit(tcpOK && udpOK ? 0 : 2)
    }

    // MARK: Test clients (as you)

    static func web(_ uid: String, _ ip: String) -> String {
        let r = sh("/usr/bin/sudo", ["-u", "#\(uid)", "/usr/bin/curl", "-s", "-m", "8", "--resolve", "example.com:80:\(ip)",
                                     "-o", "/dev/null", "-w", "%{http_code}", "http://example.com/"])
        return r.out.isEmpty || r.out == "000" ? "failed" : "HTTP \(r.out)"
    }

    static func dns(_ uid: String, _ server: String) -> String {
        let r = sh("/usr/bin/sudo", ["-u", "#\(uid)", "/usr/bin/dig", "@\(server)", "example.com", "+short", "+time=3", "+tries=1"])
        let answer = r.out.split(separator: "\n").first.map(String.init) ?? ""
        return answer.isEmpty || answer.contains(";;") ? "failed" : "answer \(answer)"
    }

    // MARK: Relay

    static func listen(_ type: Int32) -> Int32? {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return nil }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = relayPort.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard ok == 0, type == SOCK_DGRAM || Darwin.listen(fd, 16) == 0 else { close(fd); return nil }
        return fd
    }

    static func acceptTCP(_ server: Int32) {
        while true {
            var peer = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let fd = withUnsafeMutablePointer(to: &peer) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(server, $0, &len) } }
            guard fd >= 0 else { continue }
            Thread.detachNewThread { relayTCP(fd, peer) }
        }
    }

    static func relayTCP(_ client: Int32, _ peer: sockaddr_in) {
        defer { close(client) }
        let (cip, cport) = (ip(peer.sin_addr), UInt16(bigEndian: peer.sin_port))
        guard let (dst, method) = original(proto: IPPROTO_TCP, client: peer, localPort: relayPort) else {
            record(Seen(proto: "TCP", client: "\(cip):\(cport)", original: "?", method: "not found", program: program("TCP", cport), bytes: 0)); return
        }
        let up = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(up) }
        var to = dst
        let ok = withUnsafePointer(to: &to) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(up, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var back = 0
        if ok == 0 {
            let forward = Thread { pump(client, up) }
            forward.start()
            back = pump(up, client)
        }
        record(Seen(proto: "TCP", client: "\(cip):\(cport)", original: "\(ip(dst.sin_addr)):\(UInt16(bigEndian: dst.sin_port))",
                    method: method, program: program("TCP", cport), bytes: back))
    }

    @discardableResult
    static func pump(_ from: Int32, _ to: Int32) -> Int {
        var buf = [UInt8](repeating: 0, count: 32_768), total = 0
        while true {
            let n = recv(from, &buf, buf.count, 0)
            if n <= 0 { shutdown(to, SHUT_WR); return total }
            if send(to, buf, n, 0) <= 0 { return total }
            total += n
        }
    }

    static func serveUDP(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 65_536)
        while true {
            var peer = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &peer) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
            guard n > 0 else { continue }
            let packet = Array(buf[0..<n]), client = peer
            Thread.detachNewThread {
                let cport = UInt16(bigEndian: client.sin_port)
                guard let (dst, method) = original(proto: IPPROTO_UDP, client: client, localPort: relayPort) else {
                    record(Seen(proto: "UDP", client: "\(ip(client.sin_addr)):\(cport)", original: "?", method: "not found",
                                program: program("UDP", cport), bytes: 0)); return
                }
                let up = socket(AF_INET, SOCK_DGRAM, 0)
                defer { close(up) }
                var tv = timeval(tv_sec: 3, tv_usec: 0)
                setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                var to = dst
                _ = withUnsafePointer(to: &to) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(up, packet, packet.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                var reply = [UInt8](repeating: 0, count: 65_536)
                let r = recv(up, &reply, reply.count, 0)
                var back = client
                if r > 0 {
                    _ = withUnsafePointer(to: &back) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, reply, r, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                }
                record(Seen(proto: "UDP", client: "\(ip(client.sin_addr)):\(cport)", original: "\(ip(dst.sin_addr)):\(UInt16(bigEndian: dst.sin_port))",
                            method: method, program: program("UDP", cport), bytes: max(r, 0)))
            }
        }
    }

    static func record(_ s: Seen) { lock.lock(); seen.append(s); lock.unlock() }

    // MARK: Where it was going, and who sent it

    /// The destination before pf redirected it: DIOCNATLOOK on /dev/pf, else pf's state table.
    static func original(proto: Int32, client: sockaddr_in, localPort: UInt16) -> (sockaddr_in, String)? {
        for direction: UInt8 in [2, 1] {                       // PF_OUT, PF_IN
            if let d = natlook(proto: proto, client: client, localPort: localPort, direction: direction) {
                return (d, "pf natlook \(direction == 2 ? "out" : "in")")
            }
        }
        if let d = stateTable(proto: proto, client: client) { return (d, "pf state table") }
        return nil
    }

    /// struct pfioc_natlook (xnu, with Apple's extensions): 4 × pf_addr (16), 4 × pf_state_xport (4),
    /// af, proto, proto_variant, direction = 84 bytes. DIOCNATLOOK = _IOWR('D', 23, that).
    static func natlook(proto: Int32, client: sockaddr_in, localPort: UInt16, direction: UInt8) -> sockaddr_in? {
        let fd = open("/dev/pf", O_RDWR)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var nl = [UInt8](repeating: 0, count: 84)
        withUnsafeBytes(of: client.sin_addr.s_addr) { for i in 0..<4 { nl[i] = $0[i] } }                 // saddr
        withUnsafeBytes(of: inet_addr("127.0.0.1")) { for i in 0..<4 { nl[16 + i] = $0[i] } }            // daddr
        withUnsafeBytes(of: client.sin_port) { nl[64] = $0[0]; nl[65] = $0[1] }                            // sxport
        withUnsafeBytes(of: localPort.bigEndian) { nl[68] = $0[0]; nl[69] = $0[1] }                       // dxport
        nl[80] = UInt8(AF_INET); nl[81] = UInt8(proto); nl[83] = direction
        let request: UInt = 0xC000_0000 | (UInt(84 & 0x1FFF) << 16) | (UInt(UInt8(ascii: "D")) << 8) | 23
        let ok = nl.withUnsafeMutableBytes { ioctl(fd, request, $0.baseAddress!) }
        guard ok == 0 else { return nil }
        var out = sockaddr_in()
        out.sin_family = sa_family_t(AF_INET)
        out.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutableBytes(of: &out.sin_addr.s_addr) { for i in 0..<4 { $0[i] = nl[48 + i] } }        // rdaddr
        withUnsafeMutableBytes(of: &out.sin_port) { $0[0] = nl[76]; $0[1] = nl[77] }                       // rdxport
        guard out.sin_addr.s_addr != 0, out.sin_port != 0, out.sin_port != localPort.bigEndian else { return nil }
        return out
    }

    /// `pfctl -s state`: "ALL tcp 127.0.0.1:46100 <- 93.184.215.14:80 <- 192.168.1.50:51234 …".
    static func stateTable(proto: Int32, client: sockaddr_in) -> sockaddr_in? {
        let name = proto == IPPROTO_TCP ? "tcp" : "udp"
        let me = "\(ip(client.sin_addr)):\(UInt16(bigEndian: client.sin_port))"
        for line in sh("/sbin/pfctl", ["-s", "state"]).out.split(separator: "\n") where line.contains(" \(name) ") && (line.hasSuffix(me) || line.contains("<- \(me) ")) {
            let parts = line.components(separatedBy: " <- ")
            guard parts.count >= 3 else { continue }
            let mid = parts[1].trimmingCharacters(in: .whitespaces)
            guard let colon = mid.lastIndex(of: ":"), let port = UInt16(mid[mid.index(after: colon)...]) else { continue }
            var out = sockaddr_in()
            out.sin_family = sa_family_t(AF_INET)
            out.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            out.sin_addr.s_addr = inet_addr(String(mid[..<colon]))
            out.sin_port = port.bigEndian
            return out
        }
        return nil
    }

    /// The program with a socket on that local port (not this relay).
    static func program(_ proto: String, _ port: UInt16) -> String {
        let out = sh("/usr/sbin/lsof", ["-nP", "-i\(proto):\(port)", "-Fpc"]).out
        var pid = "", name = ""
        for line in out.split(separator: "\n") {
            if line.hasPrefix("p") { pid = String(line.dropFirst()) }
            if line.hasPrefix("c"), pid != String(getpid()) { name = String(line.dropFirst()); break }
        }
        guard let p = Int32(pid), !name.isEmpty, p != getpid() else { return "? (port \(port))" }
        var path = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(p, &path, UInt32(path.count)) > 0 ? "\(String(cString: path)) (pid \(p))" : "\(name) (pid \(p))"
    }

    // MARK: Helpers

    static func ip(_ a: in_addr) -> String { String(cString: inet_ntoa(a)) }

    static func ipv4(_ host: String) -> String? {
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "80", &hints, &res) == 0, let r = res else { return nil }
        defer { freeaddrinfo(res) }
        return r.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ip($0.pointee.sin_addr) }
    }

    static func sh(_ path: String, _ args: [String], input: String? = nil) -> (status: Int32, out: String, err: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe(), inp = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = input == nil ? FileHandle.nullDevice : inp
        do { try p.run() } catch { return (-1, "", "\(error)") }
        if let input { inp.fileHandleForWriting.write(Data(input.utf8)); try? inp.fileHandleForWriting.close() }
        let o = out.fileHandleForReading.readDataToEndOfFile(), e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self))
    }
}
