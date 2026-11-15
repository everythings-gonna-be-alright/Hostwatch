import Foundation
import Testing
@testable import Hostwatch

/// The network map's collector facts. Fixtures are real `arp -an`, `ndp -an`, `netstat -rn` and tcpdump lines.
@Suite struct NetworkMapParsing {
    @Test func arpKeepsNeighboursAndDropsThisMac() {
        let text = """
        ? (192.168.1.1) at cc:2d:e0:c5:1a:5 on en0 ifscope [ethernet]
        ? (192.168.1.19) at fa:b0:c8:3f:2a:c8 on en0 ifscope permanent [ethernet]
        ? (192.168.1.44) at (incomplete) on en0 ifscope [ethernet]
        ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
        ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
        """
        let n = NetMapParse.arp(text)
        #expect(n == [NetNeighbor(mac: "cc:2d:e0:c5:1a:05", ips: ["192.168.1.1"], iface: "en0")])
    }

    @Test func ndpAndMergeByHardwareAddress() {
        let ndp = """
        Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
        fe80::1%lo0                             (incomplete)         lo0 permanent R
        fe80::1873:3995:7408:6f7e%en0           36:48:71:1a:c0:f3    en0 23h59m29s S
        fe80::aaaa%en0                          fa:b0:c8:3f:2a:c8    en0 permanent R
        """
        let arp = "? (192.168.1.9) at 36:48:71:1a:c0:f3 on en0 ifscope [ethernet]"
        let merged = NetMapParse.merge(NetMapParse.ndp(ndp), NetMapParse.arp(arp))
        #expect(merged.count == 1)
        #expect(merged.first?.ips == ["192.168.1.9", "fe80::1873:3995:7408:6f7e"])
    }

    @Test func randomHardwareAddress() {
        #expect(NetMapParse.isRandom("36:48:71:1a:c0:f3"))
        #expect(!NetMapParse.isRandom("cc:2d:e0:c5:1a:05"))
    }

    @Test func routesIgnoreScopedUtunDefaults() {
        let text = """
        Destination        Gateway            Flags               Netif Expire
        default            192.168.1.1        UGScg                 en0
        127                127.0.0.1          UCS                   lo0
        default                                 fe80::%utun0                            UGcIg               utun0
        """
        let r = NetMapParse.routes(text)
        #expect(r.gateway == "192.168.1.1" && r.iface == "en0" && r.vpns.isEmpty)
    }

    @Test func splitAndFullVPN() {
        let split = NetMapParse.routes("""
        default            192.168.1.1        UGScg                 en0
        10.8/16            10.8.0.1           UGSc                  utun4
        """)
        #expect(split.vpns == [NetRoutes.VPN(iface: "utun4", routes: ["10.8/16"], full: false)])
        #expect(split.iface(for: "10.8.3.4") == "utun4")
        #expect(split.iface(for: "1.1.1.1") == "en0")
        let full = NetMapParse.routes("""
        0/1                10.8.0.1           UGSc                  utun4
        default            192.168.1.1        UGScg                 en0
        128.0/1            10.8.0.1           UGSc                  utun4
        """)
        #expect(full.vpns.first?.full == true)
        #expect(full.iface(for: "1.1.1.1") == "utun4")
    }

    @Test func prefixes() {
        #expect(NetMapParse.prefix("10.8/16")! == (0x0A08_0000, 16))
        #expect(NetMapParse.prefix("0/1")! == (0, 1))
        #expect(NetMapParse.prefix("10.8.0.1")! == (0x0A08_0001, 32))
    }

    @Test func incomingTryToAClosedPort() throws {
        let header = "05:23:10.048273 (in) IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 64)"
        let line = "192.168.1.23.51544 > 192.168.1.19.22: Flags [S], cksum 0x1234 (correct), seq 1, length 0"
        let t = try #require(NetMapParse.inbound(line, header: header))
        #expect(t.remote == "192.168.1.23" && t.port == 22)
        let out = "05:26:08.309646 (proc curl:10131, out) IP (tos 0x0)"
        #expect(NetMapParse.inbound(line, header: out) == nil)
    }

    @Test func listenersKeepTheWidestScope() {
        let raw = [NetListener(pid: 5, name: "Python", proc: "/usr/bin/python3", port: 8000, scope: .local),
                   NetListener(pid: 5, name: "Python", proc: "/usr/bin/python3", port: 8000, scope: .all),
                   NetListener(pid: 9, name: "sshd", proc: "/usr/sbin/sshd", port: 22, scope: .all)]
        #expect(NetMapParse.listeners(raw).map(\.port) == [22, 8000])
        #expect(NetMapParse.listeners(raw).last?.scope == .all)
    }

    @Test func stateCountsTriesButNotThisMac() {
        let s = NetMapState()
        s.setOwn(["192.168.1.19"])
        s.note(remote: "192.168.1.23", port: 22)
        s.note(remote: "192.168.1.23", port: 22)
        s.note(remote: "192.168.1.19", port: 22)
        s.note(remote: "127.0.0.1", port: 22)
        let d = s.drain()
        #expect(d.count == 1 && d.first?.count == 2)
        #expect(s.drain().isEmpty)
    }

    @Test func eventIsOneLineForNetClients() {
        let e = Agent.netMapEvent(listeners: [], neighbors: [], routes: NetRoutes(), inbound: [])
        #expect(String(decoding: e.jsonLine(), as: UTF8.self).hasPrefix(#"{"kind":"netmap""#))
    }
}

/// The map's model: the builder's columns and edges, the store's devices, tries and alerts.
@Suite @MainActor struct NetworkMapModel {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func message(neighbors: [NetNeighbor] = [], inbound: [NetInbound] = [], listeners: [NetListener] = [],
                 routes: NetRoutes = NetRoutes(gateway: "192.168.1.1", iface: "en0")) -> NetMapMessage {
        NetMapMessage(listeners: listeners, neighbors: neighbors, routes: routes, inbound: inbound)
    }

    let router = NetNeighbor(mac: "cc:2d:e0:c5:1a:05", ips: ["192.168.1.1"], iface: "en0")
    let stranger = NetNeighbor(mac: "3a:5f:00:00:00:9c", ips: ["192.168.1.23"], iface: "en0")
    let python = NetListener(pid: 7, name: "Python", proc: "/usr/bin/python3", port: 8000, scope: .all)

    @Test func firstReportIsTheBaseline() {
        let store = NetworkMapStore(fileURL: nil)
        store.apply(message(neighbors: [router]), now: now)
        store.apply(message(neighbors: [router, stranger]), now: now.addingTimeInterval(10))
        #expect(store.devices[router.mac]?.baseline == true)
        #expect(NetworkMapPolicy.isNew(store.devices[stranger.mac]!, now: now.addingTimeInterval(20)))
        store.markMine(stranger.mac)
        #expect(!NetworkMapPolicy.isNew(store.devices[stranger.mac]!, now: now.addingTimeInterval(20)))
    }

    @Test func scanFromYourNetworkIsRaisedOnce() {
        let store = NetworkMapStore(fileURL: nil)
        var alerts: [NetworkAlert] = []
        store.onAlert = { alerts.append($0) }
        store.apply(message(neighbors: [router]), now: now)
        let tries = (1...12).map { NetInbound(remote: "192.168.1.23", port: 1000 + $0, count: 1, listening: false) }
        store.apply(message(neighbors: [router, stranger], inbound: tries), now: now.addingTimeInterval(10))
        store.apply(message(neighbors: [router, stranger], inbound: tries), now: now.addingTimeInterval(20))
        #expect(alerts == [.portScan(remote: "192.168.1.23", device: "Unknown device", ports: 12)])
    }

    @Test func internetScansAreShownNotRaised() {
        let store = NetworkMapStore(fileURL: nil)
        var alerts: [NetworkAlert] = []
        store.onAlert = { alerts.append($0) }
        let tries = (1...20).map { NetInbound(remote: "203.0.113.7", port: $0, count: 1, listening: false) }
        store.apply(message(inbound: tries), now: now)
        #expect(alerts.isEmpty && store.inbound.count == 20)
    }

    @Test func newDeviceReachingAListenerIsRaised() {
        let store = NetworkMapStore(fileURL: nil)
        var alerts: [NetworkAlert] = []
        store.onAlert = { alerts.append($0) }
        store.apply(message(neighbors: [router]), now: now)
        store.apply(message(neighbors: [router, stranger],
                            inbound: [NetInbound(remote: "192.168.1.23", port: 8000, count: 2, listening: true, name: "Python")],
                            listeners: [python]), now: now.addingTimeInterval(10))
        #expect(alerts == [.newDeviceReached(remote: "192.168.1.23", device: "Unknown device", port: 8000)])
    }

    @Test func routerHardwareAddressChange() {
        let store = NetworkMapStore(fileURL: nil)
        var alerts: [NetworkAlert] = []
        store.onAlert = { alerts.append($0) }
        store.apply(message(neighbors: [router]), now: now)
        var impostor = router
        impostor.mac = "de:ad:be:ef:00:01"
        store.apply(message(neighbors: [impostor]), now: now.addingTimeInterval(10))
        #expect(alerts == [.routerChanged(ip: "192.168.1.1", old: router.mac, new: "de:ad:be:ef:00:01")])
    }

    @Test func graphColumnsAndEdges() throws {
        let store = NetworkMapStore(fileURL: nil)
        store.apply(message(neighbors: [router]), now: now)
        store.apply(message(neighbors: [router, stranger],
                            inbound: [NetInbound(remote: "192.168.1.23", port: 8000, count: 2, listening: true, name: "Python"),
                                      NetInbound(remote: "192.168.1.23", port: 22, count: 1, listening: false),
                                      NetInbound(remote: "203.0.113.7", port: 22, count: 5, listening: false)],
                            listeners: [python]), now: now.addingTimeInterval(10))
        let out = [MapOutgoing(program: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari", group: "apple.com",
                               ip: "17.1.1.1", count: 40, firstSeen: now.addingTimeInterval(-9 * 86400), lastSeen: now, blocked: false, isNew: false),
                   MapOutgoing(program: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari", group: "tracker.example",
                               ip: "198.51.100.9", count: 2, firstSeen: now.addingTimeInterval(-9 * 86400), lastSeen: now, blocked: true, isNew: false)]
        let g = store.graph(outgoing: out, filter: .everything, range: .hour, now: now.addingTimeInterval(20), interfaceName: { _ in "Wi-Fi" })
        let devices = g.columns[0][0].nodes
        #expect(devices.first?.title == "Unknown device" && devices.first?.badge == .new)
        #expect(devices.contains { $0.title == "Router" })
        #expect(g.columns[0][1].nodes.first?.badge == .refused)
        #expect(g.columns[1][0].nodes.map(\.kind) == [.listener, .closedPorts])
        #expect(g.edges.contains(MapEdge(from: "dev:3a:5f:00:00:00:9c", to: "lis:/usr/bin/python3|8000", weight: 2, style: .new)))
        #expect(g.edges.contains(MapEdge(from: "net:203.0.113.7", to: "closed", weight: 5, style: .blocked)))
        #expect(g.columns[2][0].nodes.map(\.title) == ["Wi-Fi"])
        #expect(g.columns[3][0].nodes.first { $0.title == "tracker.example" }?.badge == .blocked)
        #expect(g.edges.contains(MapEdge(from: "way:en0", to: "dst:tracker.example", weight: 2, style: .blocked)))
        #expect(g.summary.hasPrefix("Last hour: 1 programs went out to 2 destinations. 1 program listens on all networks."))
    }

    @Test func filtersHideColumns() {
        let store = NetworkMapStore(fileURL: nil)
        store.apply(message(neighbors: [router]), now: now)
        let out = [MapOutgoing(program: "curl", path: "/usr/bin/curl", group: "example.com", ip: "93.184.216.34", count: 1,
                               firstSeen: now, lastSeen: now, blocked: false, isNew: true)]
        let goingOut = store.graph(outgoing: out, filter: .goingOut, range: .hour, now: now, interfaceName: { $0 })
        #expect(goingOut.columns[0].isEmpty && !goingOut.columns[3].isEmpty)
        let comingIn = store.graph(outgoing: out, filter: .comingIn, range: .hour, now: now, interfaceName: { $0 })
        #expect(!comingIn.columns[0].isEmpty && comingIn.columns[3].isEmpty)
    }

    @Test func localAddresses() {
        #expect(NetworkMapPolicy.isLocal("192.168.1.23") && NetworkMapPolicy.isLocal("100.100.1.1") && NetworkMapPolicy.isLocal("fe80::1"))
        #expect(!NetworkMapPolicy.isLocal("203.0.113.7") && !NetworkMapPolicy.isLocal("2a00::1"))
    }
}
