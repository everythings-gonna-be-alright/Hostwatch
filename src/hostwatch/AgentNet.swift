import Darwin
import Foundation

// MARK: - Parsing (pure; fixtures in tests/swift/AgentTests.swift)

enum AgentParse {
    private static func rx(_ p: String, _ options: NSRegularExpression.Options = []) -> NSRegularExpression {
        try! NSRegularExpression(pattern: p, options: options)
    }

    static let dnsQuestion = rx(#" q: \S+\? (\S+?)\.? "#)
    static let dnsAnswer = rx(#"(?:^|[ ,])\S+? (?:\[\S+\] )?(A|AAAA) ([0-9a-fA-F:.]+?)(?=[, ]|\s*\(|$)"#)
    static let meta = rx(#"\(([^()]*\b(?:proc|pid) [^()]*)\)"#)
    static let metaProc = rx(#"\bproc ([^,:)]+?):(\d+)"#)
    static let metaPid = rx(#"\bpid (\d+)"#)
    static let syn = rx(#"(\S+)\.(\d+) > (\S+)\.(\d+): Flags \[S\]"#)
    static let incoming = rx(#"(^|[ ,])in([ ,]|$)"#)
    static let hostish = rx(#"(?:\b([a-z][a-z0-9+.-]*)://)?(?:[^\s/@'"]+@)?((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?"#,
                            .caseInsensitive)
    static let ipv4 = rx(#"^\d{1,3}(?:\.\d{1,3}){3}$"#)
    static let schemePorts = ["http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21", "ssh": "22", "git": "9418"]

    static func group(_ m: NSTextCheckingResult, _ i: Int, in s: String) -> String? {
        let r = m.range(at: i)
        guard r.location != NSNotFound, let range = Range(r, in: s) else { return nil }
        return String(s[range])
    }

    static func first(_ re: NSRegularExpression, in s: String) -> NSTextCheckingResult? {
        re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s))
    }

    /// "... q: A? www.google.com. 2/0/0 www.google.com. A 1.2.3.4, ..." -> ("www.google.com", ["1.2.3.4"]).
    static func dnsLine(_ line: String) -> (name: String, ips: [String])? {
        guard let q = first(dnsQuestion, in: line), let name = group(q, 1, in: line),
              let qEnd = Range(q.range, in: line)?.upperBound else { return nil }
        let answers = String(line[qEnd...])
        let ips = dnsAnswer.matches(in: answers, range: NSRange(answers.startIndex..., in: answers))
            .compactMap { group($0, 2, in: answers) }
        var trimmed = name
        while trimmed.hasSuffix(".") { trimmed.removeLast() }
        return (trimmed.lowercased(), ips)
    }

    /// Packet metadata "(en0, proc curl:123, out, …)" from a tcpdump header line.
    static func metadata(_ line: String) -> String {
        first(meta, in: line).flatMap { group($0, 1, in: line) } ?? ""
    }

    /// SYN line + packet metadata -> (pid, process name hint, remote, outgoing).
    static func synLine(_ line: String, meta: String) -> (pid: Int, hint: String, remote: String, outgoing: Bool)? {
        guard let m = first(syn, in: line), let src = group(m, 1, in: line), let sport = group(m, 2, in: line),
              let dst = group(m, 3, in: line), let dport = group(m, 4, in: line) else { return nil }
        let pm = first(metaProc, in: meta)
        var pid = pm.flatMap { group($0, 2, in: meta) }.flatMap { Int($0) } ?? 0
        if pm == nil { pid = first(metaPid, in: meta).flatMap { group($0, 1, in: meta) }.flatMap { Int($0) } ?? 0 }
        guard pid != 0 else { return nil }
        let outgoing = first(incoming, in: meta) == nil
        let remote = outgoing ? lsofAddr(dst, dport) : lsofAddr(src, sport)
        let hint = pm.flatMap { group($0, 1, in: meta) }?.trimmingCharacters(in: .whitespaces) ?? ""
        return (pid, hint, remote, outgoing)
    }

    static func lsofAddr(_ ip: String, _ port: String) -> String { ip.contains(":") ? "[\(ip)]:\(port)" : "\(ip):\(port)" }

    /// "[2a00::1]:443" / "1.2.3.4:80" -> the IP.
    static func stripHost(_ remote: String) -> String {
        let colons = remote.filter { $0 == ":" }.count
        var host = remote
        if colons == 1 || remote.hasPrefix("["), let i = remote.lastIndex(of: ":") { host = String(remote[..<i]) }
        return host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }

    /// A public (globally routed) address: worth a reverse DNS lookup.
    static func isPublic(_ ip: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, ip, &v4) == 1 {
            let a = UInt32(bigEndian: v4.s_addr)
            let o1 = a >> 24, o2 = (a >> 16) & 0xFF
            if o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224 { return false }          // this, private, loopback, multicast/reserved
            if o1 == 169 && o2 == 254 { return false }                                   // link-local
            if o1 == 172 && (16...31).contains(o2) { return false }
            if o1 == 192 && o2 == 168 { return false }
            if o1 == 100 && (64...127).contains(o2) { return false }                     // carrier-grade NAT
            if (o1 == 192 && o2 == 0) || (o1 == 198 && (o2 == 18 || o2 == 19 || o2 == 51)) || (o1 == 203 && o2 == 0) {
                return false                                                             // protocol/benchmark/documentation
            }
            return true
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, ip, &v6) == 1 else { return false }
        let b = withUnsafeBytes(of: v6) { Array($0) }
        if b.allSatisfy({ $0 == 0 }) { return false }                                    // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }              // ::1
        if b[0] == 0xFF { return false }                                                 // multicast
        if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 { return false }                        // fe80::/10
        if (b[0] & 0xFE) == 0xFC { return false }                                        // fc00::/7
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8 { return false } // 2001:db8::/32
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF {         // ::ffff:a.b.c.d
            return isPublic("\(b[12]).\(b[13]).\(b[14]).\(b[15])")
        }
        return true
    }

    /// "05:28:30.5,curl.44636,,,10053,343,…" -> ("curl", 44636, 10053, 343); nil for headers and flows.
    static func nettopLine(_ line: String) -> (name: String, pid: Int, rx: Int, tx: Int)? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 6, parts[0] != "time", parts[1].contains("."), !parts[1].contains("<->"),
              let dot = parts[1].lastIndex(of: "."), !parts[1][parts[1].index(after: dot)...].contains(" "),
              let pid = Int(parts[1][parts[1].index(after: dot)...]) else { return nil }
        let rx = parts[4].isEmpty ? 0 : Int(parts[4])
        let tx = parts[5].isEmpty ? 0 : Int(parts[5])
        guard let rx, let tx else { return nil }
        return (String(parts[1][..<dot]), pid, rx, tx)
    }

    /// A connection line under a process in `nettop` (without -P):
    /// "tcp4 192.168.1.5:64046<->17.57.146.20:5223,en0,Established,7311,6130,…" -> ("17.57.146.20:5223", 13441).
    /// IPv6 ("tcp6 fe80::1%en0.62889<->2a00::1.443") becomes "[2a00::1]:443". Listening sockets have no remote.
    static func nettopFlow(_ line: String) -> (remote: String, bytes: Int)? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 6, let arrow = parts[1].range(of: "<->") else { return nil }
        let head = parts[1][..<arrow.lowerBound]
        var remote = String(parts[1][arrow.upperBound...])
        guard !remote.hasPrefix("*") else { return nil }
        if head.hasPrefix("tcp6") || head.hasPrefix("udp6") {
            guard let dot = remote.lastIndex(of: ".") else { return nil }
            var ip = String(remote[..<dot])
            if let scope = ip.firstIndex(of: "%") { ip = String(ip[..<scope]) }
            remote = lsofAddr(ip, String(remote[remote.index(after: dot)...]))
        }
        return (remote, (Int(parts[4]) ?? 0) + (Int(parts[5]) ?? 0))
    }

    /// `lsof -F pcRPn` output -> {(pid, proto, local, remote): (ppid, command)}.
    static func lsof(_ text: String) -> [LsofConnection: (ppid: Int, command: String)] {
        var out: [LsofConnection: (Int, String)] = [:]
        var pid = 0, ppid = 0, cmd = "", proto = ""
        for line in text.split(separator: "\n") {
            guard let tag = line.first else { continue }
            let value = String(line.dropFirst())
            switch tag {
            case "p": pid = Int(value) ?? 0; ppid = 0; cmd = ""; proto = ""
            case "c": cmd = value
            case "R": ppid = Int(value) ?? 0
            case "P": proto = value
            case "n":
                guard let arrow = value.range(of: "->") else { continue }
                out[LsofConnection(pid: pid, proto: proto, local: String(value[..<arrow.lowerBound]),
                                   remote: String(value[arrow.upperBound...]))] = (ppid, cmd)
            default: break
            }
        }
        return out
    }
}

struct LsofConnection: Hashable { let pid: Int; let proto: String; let local: String; let remote: String }

// MARK: - Names for addresses

extension Agent {
    func rememberDNS(_ name: String, _ ips: [String]) {
        dnsLock.lock(); defer { dnsLock.unlock() }
        dnsByName[name] = (ips, ProcessInfo.processInfo.systemUptime)
        for ip in ips { dnsNames[ip] = name }
    }

    private static let ptrQueue = DispatchQueue(label: "hostwatch.agent.ptr", attributes: .concurrent)
    private static let ptrSlots = DispatchSemaphore(value: 8)

    static func reverseDNS(_ ip: String) -> String {
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: 0, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ip, nil, &hints, &res) == 0, let info = res else { return "" }
        defer { freeaddrinfo(res) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0,
                          NI_NAMEREQD) == 0 else { return "" }
        var name = String(cString: host).lowercased()
        while name.hasSuffix(".") { name.removeLast() }
        return name
    }

    /// ip -> (name, "dns" | "ptr"). DNS names are instant; reverse DNS runs in parallel for at most
    /// `budget` seconds so a slow resolver never stalls the stream (late answers are kept for next time).
    func resolveHosts(_ ips: [String], budget: TimeInterval = 0.8) -> [String: (String, String)] {
        var out: [String: (String, String)] = [:]
        var pending: [String] = []
        for ip in Set(ips) {
            dnsLock.lock()
            let name = dnsNames[ip], ptr = ptrNames[ip]
            dnsLock.unlock()
            if let name { out[ip] = (name, "dns") } else if let ptr { if !ptr.isEmpty { out[ip] = (ptr, "ptr") } }
            else if AgentParse.isPublic(ip) { pending.append(ip) }
        }
        guard !pending.isEmpty else { return out }
        let group = DispatchGroup()
        for ip in pending {
            group.enter()
            Self.ptrQueue.async { [self] in
                Self.ptrSlots.wait()
                let name = Self.reverseDNS(ip)
                Self.ptrSlots.signal()
                dnsLock.lock(); ptrNames[ip] = name; dnsLock.unlock()
                group.leave()
            }
        }
        _ = group.wait(timeout: .now() + budget)
        dnsLock.lock()
        for ip in pending { if let ptr = ptrNames[ip], !ptr.isEmpty { out[ip] = (ptr, "ptr") } }
        dnsLock.unlock()
        return out
    }

    /// "curl https://google.ua/x" -> ("142.251.110.94:443", "google.ua", "dns"). Prefers names whose DNS
    /// answer was just seen; falls back to the name itself.
    func inferDestination(_ args: String) -> (target: String, host: String, source: String) {
        var fallback: (String, String, String)?
        let tool = Agent.base(String(args.split(separator: " ", maxSplits: 1).first ?? "")).lowercased()
        let webTool = ["curl", "wget", "http", "https"].contains(tool)
        for m in AgentParse.hostish.matches(in: args, range: NSRange(args.startIndex..., in: args)) {
            guard var host = AgentParse.group(m, 2, in: args)?.lowercased() else { continue }
            while host.hasSuffix(".") { host.removeLast() }
            if [".plist", ".json", ".txt", ".log", ".sh", ".py", ".app"].contains(where: host.hasSuffix) { continue }
            let scheme = AgentParse.group(m, 1, in: args)?.lowercased() ?? ""
            let port = AgentParse.group(m, 3, in: args)
                ?? AgentParse.schemePorts[scheme] ?? (scheme.isEmpty && webTool ? "80" : "?")
            if AgentParse.first(AgentParse.ipv4, in: host) != nil { return ("\(host):\(port)", "", "") }
            dnsLock.lock()
            let hit = dnsByName[host]
            dnsLock.unlock()
            if let hit, ProcessInfo.processInfo.systemUptime - hit.1 < 120, let ip = hit.0.first {
                return (AgentParse.lsofAddr(ip, port), host, "dns")
            }
            if fallback == nil { fallback = ("\(host):\(port)", host, "args") }
        }
        return fallback ?? ("?:?", "", "")
    }

    /// A net event, unless this (pid, remote) was already reported.
    func publishConnection(pid: Int, remote: String, proto: String, nameHint: String = "", host: String = "",
                           budget: TimeInterval = 0.3, blocked: Bool = false) {
        guard !isOurs(pid), !seenConns.seen(PidKey(pid: pid, text: remote)) else { return }
        markNetPid(pid)
        let exe = pidPath(pid)
        let ip = AgentParse.stripHost(remote)
        let name = Agent.base(exe)
        var ev = AgentEvent([("kind", .str("net")), ("time", .str(Agent.nowHMS())), ("pid", .int(pid)),
                             ("ppid", .int(pidParent(pid))), ("name", .str(name.isEmpty ? (nameHint.isEmpty ? "?" : nameHint) : name)),
                             ("proc", .str(exe)), ("target", .str(remote)), ("extra", .str(proto))])
        if !host.isEmpty {
            ev.set("host", .str(host)); ev.set("host_src", .str("dns"))          // the name it asked for (TLS)
        } else if let (host, source) = resolveHosts([ip], budget: budget)[ip] {
            ev.set("host", .str(host)); ev.set("host_src", .str(source))
        }
        if blocked { ev.set("note", .str("blocked by the firewall")) }
        publish(ev)
    }
}

// MARK: - Sources

extension Agent {
    static let pcapFilter = "(udp src port 53 or tcp src port 53)"
        + " or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
        + " or (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)"

    /// One tcpdump for both DNS answers and TCP SYNs, so a DNS answer is always handled before the
    /// connection it led to; pktap adds the owning process. Falls back to DNS-only capture.
    func runPacketSniffer() {
        let dnsOnly = "udp src port 53 or tcp src port 53"
        let attempts: [([String], String, Bool)] = [(["-i", "pktap,all", "-k", "NPD"], Self.pcapFilter, true),
                                                    (["-i", "any"], dnsOnly, false), ([], dnsOnly, false)]
        var choice = 0, failures = 0
        while !isStopped {
            let (args, filter, connects) = attempts[choice]
            let child: Spawned
            do {
                // -Z nobody: tcpdump drops root right after opening the capture device, so packet
                // decoding (DNS answers from anyone on the network) never runs as root.
                child = try Spawned.start("/usr/sbin/tcpdump", ["-l", "-n", "-vv", "-s", "0", "-Z", "nobody"] + args + [filter])
            } catch {
                Agent.logError("packet capture disabled: \(error)")
                return
            }
            ignore(Int(child.pid))
            onShutdown { child.terminate() }
            Agent.log("packet capture: \(args.isEmpty ? "default" : args.joined(separator: " ")) (\(connects ? "DNS + connections" : "DNS only"))")
            let started = ProcessInfo.processInfo.systemUptime
            var parsed = 0, meta = "", header = "", unparsedLogged = 0
            let reader = LineReader(fd: child.stdout!)
            while let line = reader.nextString() {
                if isStopped { break }
                parsed += 1
                // Metadata "(en0, proc curl:123, out, …)" is on the packet's first line.
                if line.first?.isNumber == true { header = line; meta = AgentParse.metadata(line) }
                if let dns = AgentParse.dnsLine(line), !dns.ips.isEmpty {
                    rememberDNS(dns.name, dns.ips)
                    continue
                }
                guard connects else { continue }
                let syn = AgentParse.synLine(line, meta: meta)
                if line.contains("Flags [S]"), syn == nil, !header.contains("(in)"), unparsedLogged < 3 {
                    unparsedLogged += 1
                    Agent.log("packet capture: unattributed SYN; header=\(header.prefix(300)) line=\(line.prefix(200))")
                }
                if let syn, syn.outgoing {                   // incoming is left to lsof
                    publishConnection(pid: syn.pid, remote: syn.remote, proto: "TCP", nameHint: syn.hint)
                }
            }
            child.wait()
            unignore(Int(child.pid))
            if isStopped { return }
            if ProcessInfo.processInfo.systemUptime - started < 3 && parsed == 0 {
                choice += 1                                  // unsupported here: try the next mode
                failures += 1
                if choice >= attempts.count || failures >= 6 {
                    Agent.logError("packet capture disabled: tcpdump keeps failing")
                    return
                }
            }
            if wait(2) { return }
        }
    }

    /// Security products that take over TCP flows in the kernel can hide a short connection from
    /// packet capture and lsof; nettop's statistics still count its traffic, so a new process with
    /// TCP traffic nobody reported gets an inferred event.
    func runNettopBackstop(settle: TimeInterval = 1.5) {
        let child: Spawned
        do {
            // stdin must be a pipe that stays open: nettop polls stdin for key presses, and with
            // /dev/null every poll returns at once (~1.4 cores busy instead of ~1%).
            // Per connection (no -P): each process line is followed by its connections and their addresses.
            child = try Spawned.start("/usr/bin/nettop", ["-L", "0", "-s", "1", "-m", "tcp", "-n", "-x"],
                                      stdin: .pipe)
        } catch {
            Agent.logError("nettop backstop disabled: \(error)")
            return
        }
        ignore(Int(child.pid))
        onShutdown { child.terminate() }
        Agent.log("nettop backstop: watching for connections that close before they can be seen")
        let started = ProcessInfo.processInfo.systemUptime
        var known = Set<Int>()
        var pending: [Int: (seen: TimeInterval, name: String, rx: Int, tx: Int)] = [:]
        // Remote addresses nettop listed under each process (the busiest kept), for the inferred event.
        var flows: [Int: [String: Int]] = [:]
        var current = 0
        let reader = LineReader(fd: child.stdout!)
        while let line = reader.nextString() {
            if isStopped { break }
            if let flow = AgentParse.nettopFlow(line) {
                if current > 0, pending[current] != nil || !known.contains(current) {
                    flows[current, default: [:]][flow.remote] = max(flow.bytes, flows[current]?[flow.remote] ?? 0)
                }
                continue
            }
            guard let p = AgentParse.nettopLine(line) else { continue }
            current = p.pid
            let now = ProcessInfo.processInfo.systemUptime
            if !known.contains(p.pid), p.rx + p.tx > 0 {
                known.insert(p.pid)
                if now - started > 3, !isOurs(p.pid) { pending[p.pid] = (now, p.name, p.rx, p.tx) }   // first samples = baseline
            }
            // Anything lsof or packet capture did not report within `settle` seconds gets inferred.
            for (pid, info) in pending where now - info.seen >= settle {
                pending[pid] = nil
                netLock.lock()
                let reported = netPids[pid] != nil
                let args = pidArgs[pid] ?? ""
                netLock.unlock()
                if reported { continue }
                // The address nettop saw (busiest connection), else a guess from the command line.
                let seen = flows.removeValue(forKey: pid)?.filter { !AgentParse.stripHost($0.key).hasPrefix("127.") && $0.key != "[::1]" }
                    .max { $0.value < $1.value }?.key
                var dest = inferDestination(args)
                if let seen {
                    let ip = AgentParse.stripHost(seen)
                    let host = resolveHosts([ip], budget: 0.3)[ip]
                    dest = (seen, host?.0 ?? (dest.host.isEmpty ? "" : dest.host), host?.1 ?? (dest.host.isEmpty ? "" : dest.source))
                }
                let exe = pidPath(pid)
                let name = Agent.base(exe)
                var ev = AgentEvent([("kind", .str("net")), ("time", .str(Agent.nowHMS())), ("pid", .int(pid)),
                                     ("ppid", .int(pidParent(pid))),
                                     ("name", .str(name.isEmpty ? (info.name.isEmpty ? "?" : info.name) : name)),
                                     ("proc", .str(exe)), ("target", .str(dest.target)), ("extra", .str("TCP")),
                                     ("inferred", .bool(true)),
                                     ("note", .str("closed before it could be read; \(info.rx) B in / \(info.tx) B out"))])
                if !dest.host.isEmpty { ev.set("host", .str(dest.host)); ev.set("host_src", .str(dest.source)) }
                markNetPid(pid)
                publish(ev)
            }
            if known.count > 50_000 { known.removeAll() }
            if flows.count > 5_000 { flows = flows.filter { pending[$0.key] != nil } }
        }
        child.wait()
    }

    /// `lsof -i` every `interval` s: new connections since the previous snapshot.
    func pollNetwork(interval: TimeInterval) {
        var previous: [LsofConnection: (ppid: Int, command: String)]?
        while !isStopped {
            let current: [LsofConnection: (ppid: Int, command: String)]
            do {
                let out = try Spawned.run("/usr/sbin/lsof", ["-nP", "-i", "-R", "+c", "0", "-F", "pcRPn"])
                current = AgentParse.lsof(String(decoding: out, as: UTF8.self))
            } catch {
                Agent.logError("lsof failed: \(error)")
                if wait(interval * 4) { return }
                continue
            }
            if let previous {
                let new = current.keys.filter {
                    previous[$0] == nil && !isOurs($0.pid) && !seenConns.seen(PidKey(pid: $0.pid, text: $0.remote))
                }
                let hosts = new.isEmpty ? [:] : resolveHosts(new.map { AgentParse.stripHost($0.remote) })
                for key in new {
                    guard let info = current[key] else { continue }
                    markNetPid(key.pid)
                    let exe = pidPath(key.pid)
                    let name = info.command.isEmpty ? Agent.base(exe) : info.command
                    var ev = AgentEvent([("kind", .str("net")), ("time", .str(Agent.nowHMS())), ("pid", .int(key.pid)),
                                         ("ppid", .int(info.ppid)), ("name", .str(name.isEmpty ? "?" : name)),
                                         ("proc", .str(exe)), ("target", .str(key.remote)), ("extra", .str(key.proto))])
                    if let (host, source) = hosts[AgentParse.stripHost(key.remote)] {
                        ev.set("host", .str(host)); ev.set("host_src", .str(source))
                    }
                    publish(ev)
                }
            }
            previous = current
            if wait(interval) { return }
        }
    }
}

// MARK: - Entry

/// `Hostwatch --collector [--no-files] [--no-net] [--net-interval s] [--socket path] [--owner-pid pid]
/// [--token-file path]`, as root.
func runCollectorAgent(_ args: [String]) -> Never {
    var noFiles = false, noNet = false, netInterval = 1.0, socketPath = CollectorSocket.path
    var ownerPid = 0, tokenFile = ""
    var i = 0
    while i < args.count {
        let a = args[i]
        func value() -> String { i += 1; return i < args.count ? args[i] : "" }
        switch a {
        case "--no-files": noFiles = true
        case "--no-net": noNet = true
        case "--net-interval": netInterval = Double(value()) ?? 1
        case "--socket": socketPath = value()
        case "--owner-pid": ownerPid = Int(value()) ?? 0
        case "--token-file": tokenFile = value()
        default: Agent.logError("unknown option \(a)"); exit(64)
        }
        i += 1
    }
    signal(SIGPIPE, SIG_IGN)
    let agent = Agent()
    if !tokenFile.isEmpty {
        do {
            agent.shutdownToken = try String(contentsOfFile: tokenFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            Agent.logError("cannot read token file: \(error.localizedDescription)")
        }
    }
    guard geteuid() == 0 else { Agent.logError("Run this collector as root (sudo)."); exit(1) }
    guard FileManager.default.fileExists(atPath: "/usr/bin/eslogger") else {
        Agent.logError("This macOS installation does not provide /usr/bin/eslogger."); exit(1)
    }
    var kinds = Set(Agent.allKinds)
    if noFiles { kinds.remove("file") }
    if noNet { kinds.remove("net") }

    // Who may connect: the app that launched us, or (started by hand) the user who ran sudo.
    let clientUID: uid_t? = ownerPid > 0 ? ProcessList.uid(ownerPid)
        : uid_t(ProcessInfo.processInfo.environment["SUDO_UID"] ?? "0") ?? 0
    let server: Int32
    do {
        server = try AgentSocket.create(path: socketPath, clientUID: clientUID)
    } catch {
        Agent.logError("cannot create the collector socket: \(error)"); exit(1)
    }
    agent.onShutdown { unlink(socketPath) }
    PFRedirect.clearStale()                                  // a firewall redirect left by a crashed collector
    agent.onShutdown { agent.firewall.shutdown() }
    Thread.detachNewThread { agent.acceptClients(server, ownerPid: ownerPid, clientUID: clientUID) }

    agent.adoptOwnProcesses(ownerPid: ownerPid)              // before events flow: Hostwatch's own processes
    // "exit" only keeps the set of Hostwatch's own pids exact; it is never published.
    let events = ["exec", "exit"] + (kinds.contains("file") ? ["open"] : [])
    let eslogger: Spawned
    do {
        eslogger = try Spawned.start("/usr/bin/eslogger", events, stderr: .inherit)
    } catch {
        Agent.logError("cannot start eslogger: \(error)"); exit(1)
    }
    agent.ignore(Int(eslogger.pid))
    agent.onShutdown { eslogger.terminate() }
    Agent.log("eslogger \(events.joined(separator: " ")) started (PID \(eslogger.pid))")
    if ownerPid > 0 { Thread.detachNewThread { agent.watchOwner(ownerPid) } }
    Thread.detachNewThread { agent.runTopSampler() }
    if kinds.contains("net") {
        Thread.detachNewThread { agent.runPacketSniffer() }
        Thread.detachNewThread { agent.runNettopBackstop() }
        Thread.detachNewThread { agent.pollNetwork(interval: netInterval) }
    }
    Agent.log("Hostwatch agent listening on \(socketPath) for \(ownerPid > 0 ? "pid \(ownerPid)" : "uid \(clientUID ?? 0)") "
              + "(\(kinds.sorted().joined(separator: ", ")))")

    var signalSources: [DispatchSourceSignal] = []
    for sig in [SIGINT, SIGTERM] {
        signal(sig, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
        source.setEventHandler { agent.requestShutdown() }
        source.resume()
        signalSources.append(source)
    }

    let reader = LineReader(fd: eslogger.stdout!)
    while let line = reader.next() {
        if agent.isStopped { break }
        guard let raw = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
              let ev = agent.normalize(raw) else { continue }
        agent.publish(ev)
    }
    agent.requestShutdown()
    eslogger.terminate()
    eslogger.wait()
    close(server)
    agent.closeAllClients()
    withExtendedLifetime(signalSources) {}
    exit(0)
}
