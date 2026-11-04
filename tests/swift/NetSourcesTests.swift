import Darwin
import Foundation
import Testing
@testable import Hostwatch

/// The collector's native connection sources: the socket list (libproc, instead of lsof) and macOS's connection
/// statistics (instead of nettop), plus the watchdog that keeps the nettop fallback from outliving the collector.
@Suite(.serialized) struct NetSources {
    func run(_ path: String, _ args: [String]) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardInput = Pipe()
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        return p
    }

    /// A TCP connection between two `nc`s on 127.0.0.1.
    func connectedPair() throws -> (server: Process, client: Process, port: UInt16) {
        let port = UInt16.random(in: 48_100...49_000)
        let server = try run("/usr/bin/nc", ["-l", "127.0.0.1", "\(port)"])
        Thread.sleep(forTimeInterval: 0.3)
        let client = try run("/usr/bin/nc", ["127.0.0.1", "\(port)"])
        Thread.sleep(forTimeInterval: 0.3)
        return (server, client, port)
    }

    @Test func socketListHasBothEndsOfAConnection() throws {
        let (server, client, port) = try connectedPair()
        defer { client.terminate(); server.terminate() }
        let conns = SocketOwner.connections()
        let out = try #require(conns.first { $0.key.pid == Int(client.processIdentifier) && $0.key.remote == "127.0.0.1:\(port)" })
        #expect(out.key.proto == "TCP" && out.key.local.hasPrefix("127.0.0.1:"))
        #expect(out.value.command == "nc" && out.value.ppid == Int(getpid()))
        #expect(conns.keys.contains { $0.pid == Int(server.processIdentifier) && $0.local == "127.0.0.1:\(port)" })
        #expect(!conns.keys.contains { $0.remote.hasSuffix(":0") || $0.remote.hasPrefix("0.0.0.0") || $0.remote.hasPrefix("[::]") })
    }

    @Test func socketListIsQuick() {
        let start = Date()
        for _ in 0..<5 { _ = SocketOwner.connections() }
        let each = Date().timeIntervalSince(start) / 5
        print("socket list: \(Int(each * 1000)) ms")
        #expect(each < 0.25)
    }

    @Test func addressesReadTheSameFromEverySource() {
        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = UInt16(443).bigEndian
        inet_pton(AF_INET, "142.250.154.100", &sin.sin_addr)
        #expect(NetAddress.text(sockaddr: Data(bytes: &sin, count: MemoryLayout<sockaddr_in>.size)) == "142.250.154.100:443")

        var sin6 = sockaddr_in6()
        sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); sin6.sin6_family = sa_family_t(AF_INET6)
        sin6.sin6_port = UInt16(443).bigEndian
        inet_pton(AF_INET6, "2a00:1450:4001:82a::2004", &sin6.sin6_addr)
        let v6 = Data(bytes: &sin6, count: MemoryLayout<sockaddr_in6>.size)
        #expect(NetAddress.text(sockaddr: v6) == "[2a00:1450:4001:82a::2004]:443")
        #expect(AgentParse.stripHost(NetAddress.text(sockaddr: v6)!) == "2a00:1450:4001:82a::2004")
        inet_pton(AF_INET6, "::ffff:142.250.154.100", &sin6.sin6_addr)          // IPv4 on an IPv6 socket
        #expect(NetAddress.text(sockaddr: Data(bytes: &sin6, count: MemoryLayout<sockaddr_in6>.size)) == "142.250.154.100:443")
        #expect(NetAddress.text(sockaddr: Data([2, 2])) == nil)                 // too short

        #expect(NetAddress.isUnspecified("0.0.0.0:0") && NetAddress.isUnspecified("[::]:0") && NetAddress.isUnspecified("1.2.3.4:0"))
        #expect(!NetAddress.isUnspecified("1.2.3.4:443"))
        #expect(NetAddress.isLocalOnly("127.0.0.1:80") && NetAddress.isLocalOnly("[::1]:53") && NetAddress.isLocalOnly("[fe80::1]:5353"))
        #expect(!NetAddress.isLocalOnly("142.250.154.100:443") && !NetAddress.isLocalOnly("[2a00::1]:443"))
    }

    @Test func statisticsDescriptionsBecomeFlows() {
        let keys = (pid: "p", name: "n", provider: "v", local: "l", remote: "r")
        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = UInt16(443).bigEndian
        inet_pton(AF_INET, "104.20.23.154", &sin.sin_addr)
        let remote = Data(bytes: &sin, count: MemoryLayout<sockaddr_in>.size)
        sin.sin_addr = in_addr(s_addr: 0); sin.sin_port = 0
        let unset = Data(bytes: &sin, count: MemoryLayout<sockaddr_in>.size)

        let flow = NetStats.flow(["p": NSNumber(value: 4242), "n": "curl", "v": "TCP", "r": remote], keys: keys)
        #expect(flow == NetStats.Flow(pid: 4242, name: "curl", tcp: true, local: "", remote: "104.20.23.154:443"))
        #expect(NetStats.flow(["p": NSNumber(value: 4242), "v": "UDP", "r": remote], keys: keys)?.tcp == false)
        #expect(NetStats.flow(["p": NSNumber(value: 4242), "v": "TCP", "r": unset], keys: keys) == nil)     // not connected yet
        #expect(NetStats.flow(["v": "TCP", "r": remote], keys: keys) == nil)                               // no process
    }

    /// The real framework on this Mac: a new connection is reported with its process and destination, even one
    /// that closes at once; connections open before watching began are marked as such.
    @Test func statisticsSeeANewShortConnection() throws {
        let stats = try #require(NetStats.load(), "NetworkStatistics.framework is missing on this macOS")
        let lock = NSLock()
        var seen: [(NetStats.Flow, Bool)] = []
        stats.start { flow, existing in lock.lock(); seen.append((flow, existing)); lock.unlock() }
        defer { stats.stop() }
        #expect(stats.isRunning)
        Thread.sleep(forTimeInterval: 1.5)
        let (server, client, port) = try connectedPair()
        client.terminate(); server.terminate()
        var found: (NetStats.Flow, Bool)?
        for _ in 0..<30 where found == nil {
            Thread.sleep(forTimeInterval: 0.1)
            lock.lock()
            found = seen.first { $0.0.pid == Int(client.processIdentifier) && $0.0.remote == "127.0.0.1:\(port)" }
            lock.unlock()
        }
        let (flow, existing) = try #require(found)
        #expect(flow.tcp && flow.name == "nc" && !existing)
        lock.lock(); let count = seen.filter { $0.0 == flow }.count; lock.unlock()
        #expect(count == 1)                                                       // once, not again when it closes
    }

    /// The nettop fallback runs under a shell that stops it when the collector is gone, however it ended.
    @Test func fallbackStopsWhenItsOwnerIsGone() throws {
        let owner = try run("/bin/sleep", ["60"])
        let shell = try Spawned.start("/bin/sh", ["-c", Agent.whileAlive("/bin/sleep 77", owner: owner.processIdentifier, every: 1)],
                                      stdin: .pipe)
        defer { kill(-shell.pid, SIGKILL); shell.wait() }
        Thread.sleep(forTimeInterval: 0.5)
        let child = try #require(children(of: shell.pid).first)
        #expect(kill(child, 0) == 0)
        kill(owner.processIdentifier, SIGKILL)                                     // the collector dies
        owner.waitUntilExit()                                                      // (and is reaped, as launchd would)
        var gone = false
        for _ in 0..<40 where !gone { Thread.sleep(forTimeInterval: 0.1); gone = kill(child, 0) != 0 }
        #expect(gone)
    }

    /// The collector ignores SIGTERM (it handles it itself); its helpers mustn't inherit that, or they can't be stopped.
    @Test func helpersCanBeStoppedEvenIfWeIgnoreSIGTERM() throws {
        let previous = signal(SIGTERM, SIG_IGN)
        defer { signal(SIGTERM, previous) }
        let child = try Spawned.start("/bin/sleep", ["30"])
        child.terminate()
        var status: Int32 = 0
        var done = false
        for _ in 0..<30 where !done { Thread.sleep(forTimeInterval: 0.1); done = waitpid(child.pid, &status, WNOHANG) == child.pid }
        if !done { kill(child.pid, SIGKILL); waitpid(child.pid, &status, 0) }
        #expect(done && (status & 0x7f) == SIGTERM)
    }

    func children(of pid: pid_t) -> [pid_t] {
        let out = (try? Spawned.run("/usr/bin/pgrep", ["-P", "\(pid)"])) ?? Data()
        return String(decoding: out, as: UTF8.self).split(separator: "\n").compactMap { pid_t($0) }
    }
}

/// The relay's fallback when a socket is gone before it can look (a DNS query over UDP lasts milliseconds):
/// who had that local port, from macOS's connection statistics.
@Suite(.serialized) struct RecentSocketOwners {
    @Test func remembersTheLastOwnerOfAPortForAWhile() {
        let s = RecentSockets(keep: 60)
        var clock: TimeInterval = 1000
        s.note(.init(pid: 42, name: "dig"), tcp: false, port: 53_000, now: clock)
        #expect(s.owner(tcp: false, port: 53_000, now: { clock }) == .init(pid: 42, name: "dig"))
        #expect(s.owner(tcp: true, port: 53_000, now: { clock }) == nil)          // same number, other protocol
        clock += 61
        #expect(s.owner(tcp: false, port: 53_000, now: { clock }) == nil)         // too old
    }

    @Test func waitsBrieflyForTheStatisticsToArrive() {
        let s = RecentSockets()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { s.note(.init(pid: 7, name: "curl"), tcp: true, port: 50_001) }
        #expect(s.owner(tcp: true, port: 50_001, wait: 0.5)?.pid == 7)
        #expect(s.owner(tcp: true, port: 50_002, wait: 0.05) == nil)
    }

    @Test func statisticsDescribeEverySocketsLocalPort() {
        let keys = (pid: "p", name: "n", provider: "v", local: "l", remote: "r")
        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = UInt16(61_234).bigEndian
        let local = Data(bytes: &sin, count: MemoryLayout<sockaddr_in>.size)
        let s = NetStats.socket(["p": NSNumber(value: 99), "n": "dig", "v": "UDP", "l": local], keys: keys)
        #expect(s?.owner == RecentSockets.Owner(pid: 99, name: "dig") && s?.tcp == false && s?.port == 61_234)
        #expect(NetStats.socket(["n": "dig", "v": "UDP", "l": local], keys: keys) == nil)            // no process
    }

    /// The real framework: a UDP socket that sends one datagram and closes at once is still known by its port.
    @Test func aOneShotUDPSocketIsKnownByItsPort() throws {
        let stats = try #require(NetStats.load())
        let recent = RecentSockets()
        stats.onSocket = { owner, tcp, port in recent.note(owner, tcp: tcp, port: port) }
        stats.start { _, _ in }
        defer { stats.stop() }
        Thread.sleep(forTimeInterval: 1.2)
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        var to = sockaddr_in()
        to.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); to.sin_family = sa_family_t(AF_INET)
        to.sin_port = UInt16(9).bigEndian; inet_pton(AF_INET, "127.0.0.1", &to.sin_addr)
        let byte: [UInt8] = [0]
        _ = withUnsafePointer(to: &to) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, byte, 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var me = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &me) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        close(fd)
        let port = UInt16(bigEndian: me.sin_port)
        #expect(recent.owner(tcp: false, port: port, wait: 2)?.pid == getpid())
    }
}

@Suite struct RelayNames {
    @Test func aFlowWithoutAPathUsesTheProcessName() {
        var f = RelayFlow(id: 1, tcp: false, client: IPEndpoint(ip: [127, 0, 0, 1], port: 5000))
        #expect(AgentFirewall.name(f) == "?")
        f.name = "dig"
        #expect(AgentFirewall.name(f) == "dig")
        f.program = "/usr/bin/dig"
        #expect(AgentFirewall.name(f) == "dig")
        f.program = ""; f.original = IPEndpoint(ip: [8, 8, 8, 8], port: 53)
        #expect(AgentFirewall.key(f) == "dig|UDP|8.8.8.8|53")
    }
}
