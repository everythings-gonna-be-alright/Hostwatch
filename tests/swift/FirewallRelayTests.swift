import Foundation
import Network
import Testing
@testable import Hostwatch

/// The relay without pf: a stand-in "original destination" (a local echo server) proves TCP and UDP pass
/// through both ways, the TLS server name is read, a block closes the flow, and every flow ends.
@Suite(.serialized) struct FirewallRelayPath {
    /// An echo server on loopback; returns its port.
    final class Echo: @unchecked Sendable {
        let listener: NWListener
        let lock = NSLock()
        var open: [NWConnection] = []               // kept until the end, like a real server
        init(tcp: Bool) throws {
            listener = try NWListener(using: tcp ? .tcp : .udp, on: .any)
            listener.newConnectionHandler = { [unowned self] c in
                lock.lock(); open.append(c); lock.unlock()
                c.start(queue: .global())
                func loop() {
                    if tcp {
                        c.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { d, _, done, _ in
                            if let d, !d.isEmpty { c.send(content: d, completion: .contentProcessed { _ in }) }
                            if done { c.send(content: nil, contentContext: .defaultStream, isComplete: true, completion: .contentProcessed { _ in }) } else { loop() }
                        }
                    } else {
                        c.receiveMessage { d, _, _, e in
                            if let d { c.send(content: d, completion: .contentProcessed { _ in }) }
                            if e == nil { loop() }
                        }
                    }
                }
                loop()
            }
            listener.start(queue: .global())
        }
        var port: UInt16 { listener.port?.rawValue ?? 0 }
    }

    final class Ended: @unchecked Sendable { let lock = NSLock(); var flows: [RelayFlow] = [] }

    func relay(to echo: UInt16, decide: @escaping @Sendable (RelayFlow) -> FirewallRelay.Decision = { _ in .pass }) throws -> (FirewallRelay, Ended) {
        let r = FirewallRelay(port: UInt16.random(in: 50_000...59_000))
        let ended = Ended()
        r.findOriginal = { _, _, _ in (IPEndpoint(ip: [127, 0, 0, 1], port: echo), "test") }
        r.decide = decide
        r.onEnd = { f in ended.lock.lock(); ended.flows.append(f); ended.lock.unlock() }
        r.peekTimeout = 0.2
        try r.start()
        return (r, ended)
    }

    func waitFor(_ cond: () -> Bool) async throws {
        for _ in 0..<200 where !cond() { try await Task.sleep(nanoseconds: 10_000_000) }
    }

    static func clientHello(_ host: String) -> [UInt8] {
        let name = Array(host.utf8)
        let sni: [UInt8] = [0, 0] + be16(name.count + 5) + be16(name.count + 3) + [0] + be16(name.count) + name
        var body: [UInt8] = [3, 3] + Array(repeating: 7, count: 32) + [0] + be16(2) + [0x13, 0x01] + [1, 0]
        body += be16(sni.count) + sni
        let hs: [UInt8] = [1, 0] + be16(body.count) + body
        return [0x16, 3, 1] + be16(hs.count) + hs
    }
    static func be16(_ n: Int) -> [UInt8] { [UInt8(n >> 8), UInt8(n & 0xFF)] }

    @Test func readsTheTLSServerName() {
        #expect(TLSClientHello.serverName(Self.clientHello("api.example.com")) == "api.example.com")
        #expect(TLSClientHello.serverName(Array("GET / HTTP/1.1\r\n".utf8)) == nil)
        #expect(TLSClientHello.serverName(Array(Self.clientHello("x.io").prefix(20))) == nil)
        #expect(PFRedirect.parseEndpoint("2606:4700::1[443]") == IPEndpoint("2606:4700::1", port: 443))
        #expect(PFRedirect.parseEndpoint("1.1.1.1:53")?.description == "1.1.1.1:53")
        let rules = PFRedirect.rules(port: 46_100, exemptUIDs: [0, 65])
        #expect(rules.contains("user { 0 65 }") && rules.contains("route-to (lo0 ::1) inet6") && rules.contains("-> 127.0.0.1 port 46100"))
    }

    @Test func tcpPassesBothWaysAndEnds() async throws {
        let echo = try Echo(tcp: true)
        try await waitFor { echo.port != 0 }
        let (r, ended) = try relay(to: echo.port)
        defer { r.stop(); echo.listener.cancel(); echo.open.forEach { $0.cancel() } }
        try await waitFor { r.ready }
        #expect(r.ready)
        let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: r.port)!, using: .tcp)
        c.start(queue: .global())
        let hello = Data(Self.clientHello("api.example.com")) + Data(repeating: 0x41, count: 100_000)
        c.send(content: hello, contentContext: .defaultStream, isComplete: true, completion: .contentProcessed { _ in })   // a half-close
        let echoed = Ended()
        var got = Data()
        func read() {
            c.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { d, _, done, _ in
                echoed.lock.lock(); if let d { got.append(d) }; echoed.lock.unlock()
                if !done { read() }
            }
        }
        read()
        try await waitFor { echoed.lock.lock(); defer { echoed.lock.unlock() }; return got.count >= hello.count }
        echoed.lock.lock(); let total = got; echoed.lock.unlock()
        #expect(total == hello)
        try await waitFor { ended.lock.lock(); defer { ended.lock.unlock() }; return !ended.flows.isEmpty }
        let flow = try #require(ended.flows.first)
        #expect(flow.tcp && flow.host == "api.example.com" && flow.up == hello.count && flow.down == hello.count, "error=\(flow.error) up=\(flow.up) down=\(flow.down) of \(hello.count) setup=\(flow.setup)")
        #expect(flow.error.isEmpty, "\(flow.error)"); #expect(flow.method == "test" && r.activeCount == 0)
        c.cancel()
    }

    @Test func udpPassesBothWays() async throws {
        let echo = try Echo(tcp: false)
        try await waitFor { echo.port != 0 }
        let (r, _) = try relay(to: echo.port)
        defer { r.stop(); echo.listener.cancel(); echo.open.forEach { $0.cancel() } }
        try await waitFor { r.ready }
        let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: r.port)!, using: .udp)
        c.start(queue: .global())
        let box = Ended()
        var replies: [Data] = []
        for i in 0..<3 { c.send(content: Data("ping \(i)".utf8), completion: .contentProcessed { _ in }) }
        func read() { c.receiveMessage { d, _, _, e in if let d { box.lock.lock(); replies.append(d); box.lock.unlock() }; if e == nil { read() } } }
        read()
        try await waitFor { box.lock.lock(); defer { box.lock.unlock() }; return replies.count >= 3 }
        box.lock.lock(); let all = Set(replies.map { String(decoding: $0, as: UTF8.self) }); box.lock.unlock()
        #expect(all == ["ping 0", "ping 1", "ping 2"])
        c.cancel()
    }

    @Test func aBlockedFlowIsClosed() async throws {
        let echo = try Echo(tcp: true)
        try await waitFor { echo.port != 0 }
        let (r, ended) = try relay(to: echo.port, decide: { _ in .block })
        defer { r.stop(); echo.listener.cancel(); echo.open.forEach { $0.cancel() } }
        try await waitFor { r.ready }
        let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: r.port)!, using: .tcp)
        c.start(queue: .global())
        c.send(content: Data("hello".utf8), completion: .contentProcessed { _ in })
        try await waitFor { ended.lock.lock(); defer { ended.lock.unlock() }; return !ended.flows.isEmpty }
        #expect(ended.flows.first?.blocked == true && ended.flows.first?.down == 0)
        c.cancel()
    }
}
