import Darwin
import Foundation
import Testing
@testable import Hostwatch

/// The collector (`Hostwatch --collector`). Fixtures are real lines captured on a Mac (tcpdump -vv with
/// pktap metadata, nettop -P), the same ones the Python collector was tested with.
@Suite struct CollectorParsing {
    // MARK: DNS answers: the question name is kept even behind CNAMEs.

    @Test func dnsARecords() throws {
        let line = "    192.168.1.1.53 > 192.168.1.5.61234: [udp sum ok] 4660 q: A? www.google.com. 2/0/0 "
            + "www.google.com. A 142.250.154.100, www.google.com. A 142.250.154.101 (92)"
        let r = try #require(AgentParse.dnsLine(line))
        #expect(r.name == "www.google.com" && r.ips == ["142.250.154.100", "142.250.154.101"])
    }

    @Test func dnsCNAMEKeepsTheQuestion() throws {
        let line = "    192.168.1.1.53 > 192.168.1.5.61234: [no cksum] 8738 q: A? api.github.com. 2/0/0 "
            + "api.github.com. CNAME lb.github.com., lb.github.com. A 140.82.121.6 (102)"
        let r = try #require(AgentParse.dnsLine(line))
        #expect(r.name == "api.github.com" && r.ips == ["140.82.121.6"])
    }

    @Test func dnsAAAA() throws {
        let line = "    192.168.1.1.53 > 192.168.1.5.61234: [no cksum] 13107 q: AAAA? www.google.com. 1/0/0 "
            + "www.google.com. AAAA 2a00:1450:4001:82a::2004 (74)"
        let r = try #require(AgentParse.dnsLine(line))
        #expect(r.ips == ["2a00:1450:4001:82a::2004"])
    }

    @Test func notDNS() {
        #expect(AgentParse.dnsLine("05:23:10.048273 (in) IP (tos 0x0, ttl 64)") == nil)
    }

    // MARK: pktap SYNs: outgoing ones carry the process; incoming "(in)" ones are not attributed.

    @Test func chromeOutgoingSYN() throws {
        let header = "05:26:08.309646 (proc Google Chrome He:10131, out) IP (tos 0x0, ttl 64, id 0, offset 0, "
            + "flags [DF], proto TCP (6), length 48)"
        let line = "192.168.1.5.62881 > 198.51.100.7.443: Flags [S], cksum 0x4dd3 (correct), seq 3763702289, "
            + "win 65535, options [mss 1460,sackOK,eol], length 0"
        let s = try #require(AgentParse.synLine(line, meta: AgentParse.metadata(header)))
        #expect(s.pid == 10131 && s.hint == "Google Chrome He" && s.remote == "198.51.100.7:443" && s.outgoing)
    }

    @Test func processNameWithDigits() throws {
        let header = "05:27:56.666477 (proc python3.12:44449, out) IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], "
            + "proto TCP (6), length 64, bad cksum 0 (->3cb6)!)"
        let line = "127.0.0.1.63355 > 127.0.0.1.60328: Flags [S], cksum 0xfe34 (incorrect -> 0x5aff), seq 1, length 0"
        let s = try #require(AgentParse.synLine(line, meta: AgentParse.metadata(header)))
        #expect(s.pid == 44449 && s.hint == "python3.12" && s.remote == "127.0.0.1:60328" && s.outgoing)
    }

    @Test func incomingIsNotAttributed() {
        let header = "05:23:10.048273 (in) IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), "
            + "length 64, bad cksum 0 (->3cb6)!)"
        let line = "127.0.0.1.63280 > 127.0.0.1.47831: Flags [S], cksum 0xfe34 (incorrect -> 0x427a), seq 1, length 0"
        #expect(AgentParse.synLine(line, meta: AgentParse.metadata(header)) == nil)
    }

    @Test func synAckIgnored() {
        let line = "142.250.154.100.80 > 192.168.1.5.61235: Flags [S.], seq 9, ack 2, win 65535, length 0"
        #expect(AgentParse.synLine(line, meta: "proc curl:28169, svc BE, in") == nil)
    }

    @Test func ipv6WithPidMetadata() throws {
        let line = "05:20:31.000000 (en0, pid 30001 e_pid 30001, out) IP6 (hlim 64, next-header TCP (6) payload "
            + "length: 44) 2a02:1::5.50000 > 2a00:1450:4001:82a::2004.443: Flags [S], seq 1, length 0"
        let s = try #require(AgentParse.synLine(line, meta: AgentParse.metadata(line)))
        #expect(s.pid == 30001 && s.hint == "" && s.remote == "[2a00:1450:4001:82a::2004]:443" && s.outgoing)
    }

    // MARK: nettop

    @Test func nettopConnectionLines() throws {
        let v4 = try #require(AgentParse.nettopFlow("17:04:48.3,tcp4 192.168.1.5:64046<->17.57.146.20:5223,en0,Established,7311,6130,0,0,0,"))
        #expect(v4.remote == "17.57.146.20:5223" && v4.bytes == 13441)
        let v6 = try #require(AgentParse.nettopFlow("17:04:48.3,tcp6 fe80::1c88%en0.62889<->2a00:1450:4001::65.443,en0,Established,10,20,0,0,0,"))
        #expect(v6.remote == "[2a00:1450:4001::65]:443")
        #expect(AgentParse.nettopFlow("17:04:48.3,tcp4 *:62889<->*:*,,Listen,,,,,,") == nil)     // listening: no remote
        #expect(AgentParse.nettopFlow("05:28:30.5,curl.44636,,,10053,343,0,0,0,,") == nil)      // a process line
        // An IPv6 connection line ends in ".<port>": it must not be read as a process with that pid.
        #expect(AgentParse.nettopLine("17:04:48.3,tcp6 fe80::1%en0.62889<->fe80::2%en0.51554,en0,Established,10,20,0,0,0,") == nil)
    }

    @Test func nettopLines() throws {
        let a = try #require(AgentParse.nettopLine("05:28:30.557179,curl.44636,,,10053,343,0,0,0,,,,,,,,,,,,"))
        #expect(a.name == "curl" && a.pid == 44636 && a.rx == 10053 && a.tx == 343)
        let b = try #require(AgentParse.nettopLine("05:28:30.5,com.apple.WebKit.Networking.812,,,10,20,0,0,0,,"))
        #expect(b.name == "com.apple.WebKit.Networking" && b.pid == 812 && b.rx == 10 && b.tx == 20)
        #expect(AgentParse.nettopLine("time,,interface,state,bytes_in,bytes_out,rx_dupe,") == nil)
        #expect(AgentParse.nettopLine("05:27:42.8,tcp4 192.168.1.5:51423<->17.242.218.132:5223,en0,Established,1601676,6255400,") == nil)
    }

    // MARK: Inferred destinations: command line + recent DNS answers

    @Test func inferredDestinations() {
        let agent = Agent()
        agent.rememberDNS("google.ua", ["142.251.110.94"])
        func check(_ args: String, _ target: String, _ host: String, _ source: String) {
            let d = agent.inferDestination(args)
            #expect(d.target == target && d.host == host && d.source == source, "\(args) -> \(d)")
        }
        check("curl google.ua", "142.251.110.94:80", "google.ua", "dns")
        check("curl -s https://google.ua/search?q=1", "142.251.110.94:443", "google.ua", "dns")
        check("curl http://user:pw@api.example.com:8080/x", "api.example.com:8080", "api.example.com", "args")
        check("nc evil.example 4444", "evil.example:?", "evil.example", "args")
        check("wget 1.2.3.4", "1.2.3.4:80", "", "")
        check("ls /etc/hosts.plist", "?:?", "", "")
    }

    // MARK: Secrets in command lines (they go to history)

    @Test func secretMasking() {
        #expect(Agent.formatArgs(["curl", "-H", "Authorization: Bearer abc.def", "https://h/x?token=zzz&b=1"])
                == "curl -H 'Authorization: Bearer ***' https://h/x?token=***&b=1")
        #expect(Agent.formatArgs(["curl", "https://user:pa55@api.example.com/x"]).contains("https://user:***@api.example.com"))
        #expect(Agent.formatArgs(["git", "push", "https://ghp_ABCDEFGHIJKLMNOP@github.com/x"]) == "git push https://ghp_***@github.com/x")
        #expect(Agent.formatArgs(["xattr", "-d", "com.apple.quarantine", "/Users/x/Downloads/Evil App.app"])
                == "xattr -d com.apple.quarantine '/Users/x/Downloads/Evil App.app'")
        #expect(Agent.formatArgs([String(repeating: "a", count: 500)]).count == 401)
    }

    // MARK: Exclusions and addresses

    @Test func exclusionsAndAddresses() {
        let rules = Agent.compileRules(["net:*.google.com:*"])
        let hit = AgentEvent([("kind", .str("net")), ("name", .str("curl")), ("proc", .str("/usr/bin/curl")),
                              ("target", .str("142.250.154.100:80")), ("host", .str("www.google.com"))])
        var miss = hit
        miss.set("target", .str("140.82.121.6:443")); miss.set("host", .str("api.github.com"))
        #expect(Agent.isExcluded(rules, hit))
        #expect(!Agent.isExcluded(rules, miss))
        #expect(AgentParse.stripHost("[2a00:1450:4001:82a::2004]:443") == "2a00:1450:4001:82a::2004")
        #expect(AgentParse.stripHost("142.250.154.100:80") == "142.250.154.100")
        #expect(AgentParse.lsofAddr("2a00::1", "443") == "[2a00::1]:443")
        #expect(AgentParse.isPublic("142.250.154.100") && AgentParse.isPublic("2a00:1450:4001:82a::2004"))
        #expect(!AgentParse.isPublic("192.168.1.5") && !AgentParse.isPublic("10.1.2.3") && !AgentParse.isPublic("127.0.0.1")
                && !AgentParse.isPublic("fe80::1") && !AgentParse.isPublic("198.51.100.7") && !AgentParse.isPublic("::1"))
    }

    // MARK: JSON output, as the Python collector wrote it (history files stay the same format)

    @Test func jsonLinesMatchThePythonFormat() {
        let ev = AgentEvent([("kind", .str("exec")), ("pid", .int(5)), ("name", .str("Café \"x\"\n/a")),
                             ("cpu", .double(12.5)), ("inferred", .bool(true)), ("ts", .str("2026-11-01T05:41:56.360+02:00"))])
        let line = String(decoding: ev.jsonLine(), as: UTF8.self)
        #expect(line == #"{"kind":"exec","pid":5,"name":"Caf\u00e9 \"x\"\n/a","cpu":12.5,"inferred":true,"ts":"2026-11-01T05:41:56.360+02:00"}"# + "\n")
        let stamped = String(decoding: AgentEvent([("kind", .str("file"))]).jsonLine(), as: UTF8.self)
        #expect(stamped.hasPrefix(#"{"kind":"file","ts":""#))                   // ts added last
        let ts = HistoryArchive.timestamp(Data(stamped.utf8))
        #expect(ts.map { abs($0.timeIntervalSinceNow) < 5 } == true)
    }
}

@Suite struct CollectorProcesses {
    // MARK: Busiest processes

    @Test func cpuPercentDiskRatesAndNewProcesses() {
        let sec = 1e9
        let before: [ProcessInstance: ProcessUsage] = [
            ProcessInstance(pid: 10, start: 1): ProcessUsage(cpuNanos: 0, footprint: 100, read: 0, written: 0),
            ProcessInstance(pid: 20, start: 2): ProcessUsage(cpuNanos: 5 * sec, footprint: 900, read: 1000, written: 0),
            ProcessInstance(pid: 30, start: 3): ProcessUsage(cpuNanos: 0, footprint: 50, read: 0, written: 0)]
        let after: [ProcessInstance: ProcessUsage] = [
            ProcessInstance(pid: 10, start: 1): ProcessUsage(cpuNanos: 2.5 * sec, footprint: 100, read: 0, written: 5000),
            ProcessInstance(pid: 20, start: 2): ProcessUsage(cpuNanos: 5 * sec, footprint: 900, read: 6000, written: 0),
            ProcessInstance(pid: 30, start: 4): ProcessUsage(cpuNanos: 9 * sec, footprint: 70, read: 0, written: 0)]   // pid reused
        let r = TopSampler.top(before: before, after: after, seconds: 5, limit: 1)
        #expect(r.rows.map(\.pid) == [10, 20])               // top CPU, then top memory not already listed
        #expect(abs(r.rows[0].cpu - 50) < 0.001)
        #expect(abs(r.read - 1000) < 0.001 && abs(r.write - 1000) < 0.001)
    }

    @Test func snapshotReadsThisProcess() {
        let snap = TopSampler.snapshot()
        let mine = snap.filter { $0.key.pid == Int(getpid()) }
        #expect(mine.count == 1)
        #expect((mine.first?.value.footprint ?? 0) > 0)
    }

    @Test func onlyClientsThatAskedGetTopSamples() {
        let client = AgentClient(fd: -1)
        let top = AgentEvent([("kind", .str("top"))])
        #expect(!client.wants(top))                          // history recorder, default
        client.configure(["top": true])
        #expect(client.wants(top))
        client.configure(["kinds": ["exec"]])                // kinds don't affect top
        #expect(client.wants(top))
    }

    @Test func fileEventsAreRateLimitedPerClientUnlessAskedNotTo() {
        let client = AgentClient(fd: -1)
        let file = AgentEvent([("kind", .str("file")), ("name", .str("x")), ("proc", .str("/x")), ("target", .str("/t"))])
        let passed = (0..<100).filter { _ in client.wants(file, now: 1000.5) }.count
        #expect(passed == AgentClient.fileRate)
        client.configure(["rate_limit": false])
        #expect((0..<100).allSatisfy { _ in client.wants(file, now: 1000.5) })
    }

    // MARK: Hostwatch's own activity

    static let app = "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch"

    func agentWithOwner() -> Agent {
        let agent = Agent()
        agent.addToOurTree(500)                              // the verified owner app
        return agent
    }

    func exec(_ pid: Int, _ ppid: Int, _ path: String) -> [String: Any] {
        ["event": ["exec": ["target": ["audit_token": ["pid": pid], "ppid": ppid, "executable": ["path": path]], "args": [path]]],
         "process": ["audit_token": ["pid": pid], "ppid": ppid, "executable": ["path": "/bin/sh"]]]
    }

    func open(_ pid: Int, _ path: String) -> [String: Any] {
        ["event": ["open": ["file": ["path": path], "fflag": 2]],
         "process": ["audit_token": ["pid": pid], "ppid": 1, "executable": ["path": "/x"]]]
    }

    func exit(_ pid: Int) -> [String: Any] {
        ["event": ["exit": ["stat": 0]], "process": ["audit_token": ["pid": pid], "ppid": 1, "executable": ["path": "/x"]]]
    }

    @Test func appAndItsChildrenAreHidden() {
        let agent = agentWithOwner()
        #expect(agent.normalize(open(500, "/tmp/metrics-a")) == nil)            // the app's own writes
        #expect(agent.normalize(exec(501, 500, "/usr/bin/codesign")) == nil)
        #expect(agent.normalize(open(501, "/tmp/metrics-b")) == nil)            // its child too
        #expect(agent.isOurs(501))
    }

    @Test func otherRunsOfTheSameProgramAreReported() {
        // `DYLD_INSERT_LIBRARIES=evil.dylib Hostwatch --mcp` must not become invisible: only the
        // verified app's own process tree is hidden, never "anything running the Hostwatch binary".
        let agent = agentWithOwner()
        #expect(agent.normalize(exec(710, 700, Self.app))?.kind == "exec")
        #expect(agent.normalize(open(710, "/tmp/evil"))?.kind == "file")
        #expect(agent.normalize(exec(711, 710, "/bin/sh"))?.kind == "exec")   // and its children
        #expect(!agent.isOurs(710) && !agent.isOurs(711))
    }

    @Test func reusedPidIsReportedAgain() {
        let agent = agentWithOwner()
        #expect(agent.normalize(exec(501, 500, "/usr/bin/codesign")) == nil)
        #expect(agent.normalize(exit(501)) == nil)                              // exit: never published
        #expect(!agent.isOurs(501))
        #expect(agent.normalize(open(501, "/tmp/after-reuse")) != nil)
        _ = agent.normalize(exec(502, 500, "/usr/bin/true"))
        #expect(agent.normalize(exec(502, 1, "/usr/bin/curl")) != nil)          // reused by an unrelated exec
        #expect(!agent.isOurs(502))
    }

    @Test func execAndOpenEventsLookLikeThePythonOnes() throws {
        let agent = Agent()
        let ev = try #require(agent.normalize(exec(42, 1, "/usr/bin/curl")))
        #expect(ev.pairs.map(\.0) == ["kind", "time", "pid", "ppid", "name", "proc", "target", "parent", "args"])
        #expect(ev.string("name") == "curl" && ev.string("parent") == "/bin/sh" && ev.string("args") == "/usr/bin/curl")
        let f = try #require(agent.normalize(open(43, "/etc/hosts")))
        // The parent program is named for file events too (the Events table's Parent column).
        #expect(f.pairs.map(\.0) == ["kind", "time", "pid", "ppid", "parent", "name", "proc", "target", "extra"])
        #expect(f.string("extra") == "w")
        #expect(agent.normalize(open(43, "/etc/hosts")) == nil)                 // same open again within 2 min
    }

    // MARK: Helpers

    @Test func nettopGetsAnOpenPipeAsStdin() throws {
        // With /dev/null as stdin, nettop spins at ~140% CPU polling for key presses.
        let child = try Spawned.start("/bin/sh", ["-c", "if [ -p /dev/stdin ]; then echo pipe; else echo other; fi"], stdin: .pipe)
        let out = LineReader(fd: child.stdout!).nextString()
        child.wait()
        #expect(out == "pipe")
        let plain = try Spawned.run("/bin/sh", ["-c", "if [ -p /dev/stdin ]; then echo pipe; else echo other; fi"])
        #expect(String(decoding: plain, as: UTF8.self) == "other\n")
    }

    @Test func helpersDontInheritOurFiles() throws {
        let fd = Darwin.open("/dev/null", O_RDONLY)          // e.g. a client socket
        defer { close(fd) }
        let out = try Spawned.run("/bin/sh", ["-c", "[ -e /dev/fd/\(fd) ] && echo leaked || echo closed"])
        #expect(String(decoding: out, as: UTF8.self) == "closed\n")
    }
}

/// The socket: only the owning app (or the sudo user) may connect, in a folder only its creator can write.
@Suite(.serialized) struct CollectorSocketFile {
    @Test func peerRules() {
        #expect(AgentSocket.peerAllowed(pid: 500, uid: 501, ownerPid: 500, clientUID: 501))
        #expect(!AgentSocket.peerAllowed(pid: 777, uid: 501, ownerPid: 500, clientUID: 501))   // same user, other process
        #expect(!AgentSocket.peerAllowed(pid: 500, uid: 502, ownerPid: 500, clientUID: 501))   // pid reused by another user
        #expect(AgentSocket.peerAllowed(pid: 777, uid: 501, ownerPid: 0, clientUID: 501))      // started by hand
        #expect(!AgentSocket.peerAllowed(pid: 777, uid: 502, ownerPid: 0, clientUID: 501))
    }

    /// Unix socket paths are limited to 104 bytes: a short folder in /tmp.
    func tempPath() -> (base: String, path: String) {
        let base = "/tmp/hw\(UUID().uuidString.prefix(8))"
        return (base, base + "/run/collector.sock")
    }

    @Test func permissionsAndStaleSockets() throws {
        let (base, path) = tempPath()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let fd = try AgentSocket.create(path: path, clientUID: getuid())
        var st = stat()
        lstat(path, &st)
        #expect(st.st_mode & 0o777 == 0o600 && st.st_mode & S_IFMT == S_IFSOCK)
        lstat((path as NSString).deletingLastPathComponent, &st)
        #expect(st.st_mode & 0o777 == 0o755)
        close(fd)
        close(try AgentSocket.create(path: path, clientUID: getuid()))           // stale socket replaced
        unlink(path)
        try "not a socket".write(toFile: path, atomically: false, encoding: .utf8)
        #expect(throws: AgentSocket.Failure.self) { _ = try AgentSocket.create(path: path, clientUID: getuid()) }
    }

    func connect(_ path: String) -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let bytes = Array(path.utf8); raw.copyBytes(from: bytes); raw[bytes.count] = 0
        }
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        return fd
    }

    @Test func ownerConnectsAndReceivesEvents() throws {
        let (base, path) = tempPath()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let agent = Agent()
        let server = try AgentSocket.create(path: path, clientUID: getuid())
        Thread.detachNewThread { agent.acceptClients(server, ownerPid: Int(getpid()), clientUID: getuid()) }   // we are the "app"
        let client = connect(path)
        defer { close(client); agent.requestShutdown(); close(server) }
        for _ in 0..<100 where agent.clientCount == 0 { Thread.sleep(forTimeInterval: 0.02) }
        agent.publish(AgentEvent([("kind", .str("exec")), ("pid", .int(1)), ("ppid", .int(0)), ("name", .str("x")),
                                  ("proc", .str("/x")), ("target", .str("/x"))]))
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = recv(client, &buf, buf.count, 0)
        #expect(n > 0 && String(decoding: buf.prefix(max(0, n)), as: UTF8.self).contains(#""kind":"exec""#))
    }

    @Test func otherProcessesAreCutOff() throws {
        let (base, path) = tempPath()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let agent = Agent()
        let server = try AgentSocket.create(path: path, clientUID: getuid())
        Thread.detachNewThread { agent.acceptClients(server, ownerPid: 1, clientUID: getuid()) }   // owner is launchd: not us
        let client = connect(path)
        defer { close(client); agent.requestShutdown(); close(server) }
        var buf = [UInt8](repeating: 0, count: 64)
        #expect(recv(client, &buf, buf.count, 0) == 0)                          // closed without any data
        #expect(agent.clientCount == 0)
    }
}
