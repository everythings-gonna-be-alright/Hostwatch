import Foundation
import Testing
@testable import Hostwatch

/// The program behind a local port: what the firewall's relay needs for every connection it receives.
@Suite(.serialized) struct SocketOwnerLookup {
    func holding(_ args: [String]) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nc")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        Thread.sleep(forTimeInterval: 0.3)
        return p
    }

    @Test func findsTheProgramOnATCPAndAUDPPort() throws {
        let port = UInt16.random(in: 47_000...48_000)
        let tcp = try holding(["-l", "127.0.0.1", "\(port)"])
        let udp = try holding(["-u", "-l", "127.0.0.1", "\(port + 1)"])
        defer { tcp.terminate(); udp.terminate() }
        #expect(SocketOwner.find(tcp: true, localPort: port) == SocketOwner.Owner(pid: tcp.processIdentifier, path: "/usr/bin/nc"))
        #expect(SocketOwner.find(tcp: false, localPort: port + 1)?.pid == udp.processIdentifier)
        #expect(SocketOwner.find(tcp: false, localPort: port) == nil)          // TCP port, asked as UDP
        #expect(SocketOwner.find(tcp: true, localPort: port + 2) == nil)
    }

    @Test func isFastEnoughForEveryConnection() {
        let start = Date()
        for _ in 0..<5 { _ = SocketOwner.find(tcp: true, localPort: 1) }
        #expect(Date().timeIntervalSince(start) / 5 < 0.25)
        print("SocketOwner lookup: \(Int(Date().timeIntervalSince(start) / 5 * 1000)) ms")
    }
}
