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
        let phone = NetNeighbor(mac: "aa:00:00:00:00:01", ips: ["192.168.1.30"], iface: "en0")
        let tv = NetNeighbor(mac: "aa:00:00:00:00:02", ips: ["192.168.1.31"], iface: "en0")
        store.apply(message(neighbors: [router, phone, tv]), now: now.addingTimeInterval(5))
        var impostor = router
        impostor.mac = "de:ad:be:ef:00:01"
        // The same phone and TV around the router's address, now answering from another hardware address.
        store.apply(message(neighbors: [impostor, phone, tv]), now: now.addingTimeInterval(10))
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

    @Test func everyOutgoingConnectionIsRecorded() {
        let store = NetworkMapStore(fileURL: nil)
        store.apply(message(neighbors: [router, NetNeighbor(mac: "c0:cd:d6:79:e7:a4", ips: ["192.168.1.13"], iface: "en0", name: "nas.lan")]),
                    now: now)
        func net(_ proc: String, _ target: String, host: String = "") -> ActivityEvent {
            ActivityEvent(kind: .net, time: "", pid: 1, ppid: 1, name: (proc as NSString).lastPathComponent, proc: proc, target: target,
                          extra: "TCP", parent: "", host: host, hostSource: host.isEmpty ? "" : "dns")
        }
        store.observeOutgoing(net("/usr/bin/ssh", "192.168.1.13:22"), blocked: false, now: now)
        store.observeOutgoing(net("/usr/bin/curl", "93.184.216.34:443", host: "www.example.com"), blocked: false, now: now)
        store.observeOutgoing(net("/usr/bin/curl", "93.184.216.34:443", host: "www.example.com"), blocked: false, now: now)
        store.observeOutgoing(net("/usr/bin/curl", "127.0.0.1:8080"), blocked: false, now: now)
        let list = store.outgoingList(.hour, now: now)
        #expect(Set(list.map(\.group)) == ["192.168.1.13", "example.com"])
        #expect(list.first { $0.group == "example.com" }?.count == 2)
        let g = NetworkMapBuilder.build(.init(devices: Array(store.devices.values), routes: store.routes, outgoing: list, now: now))
        let nas = g.columns[3][0].nodes.first { $0.ref == "192.168.1.13" }
        #expect(nas?.title == "nas" && nas?.subtitle == "192.168.1.13")
        #expect(g.edges.contains { $0.from == "prog:/usr/bin/ssh" && $0.to == "way:local" })
    }

    @Test func programsLastConnectionForItsProcessDetails() throws {
        let store = NetworkMapStore(fileURL: nil)
        let e = ActivityEvent(kind: .net, time: "", pid: 4242, ppid: 1, name: "curl", proc: "/usr/bin/curl", target: "93.184.216.34:443",
                              extra: "TCP", parent: "/bin/zsh", host: "www.example.com", hostSource: "dns")
        store.observeOutgoing(e, blocked: false, now: now)
        let last = try #require(store.lastEvent(program: "/usr/bin/curl"))
        #expect(last.pid == 4242 && last.ppid == 1 && last.parent == "/bin/zsh" && last.host == "www.example.com" && last.kind == .net)
        #expect(store.lastEvent(program: "/usr/bin/none") == nil)
    }

    @Test func localAddresses() {
        #expect(NetworkMapPolicy.isLocal("192.168.1.23") && NetworkMapPolicy.isLocal("100.100.1.1") && NetworkMapPolicy.isLocal("fe80::1"))
        #expect(!NetworkMapPolicy.isLocal("203.0.113.7") && !NetworkMapPolicy.isLocal("2a00::1"))
    }
}

/// Naming devices: the maker table, announced models, and what the map calls them.
@Suite @MainActor struct DeviceIdentityTests {
    @Test func makerFromHardwareAddress() {
        let table = MakerTable(text: "a4c361\tApple\ncc2de0\tRouterboard.com\n")
        #expect(table.maker(for: "a4:c3:61:12:34:56") == "Apple")
        #expect(table.maker(for: "36:48:71:1a:c0:f3") == nil)         // private: made up, no maker
        #expect(table.maker(for: "00:11:22:33:44:55") == nil)
    }

    @Test func shippedTableIsReadable() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../assets/oui.tsv")
        #expect(MakerTable(url: url).maker(for: "cc:2d:e0:c5:1a:05") == "Routerboard.com")
    }

    @Test func announcedModels() {
        #expect(DeviceModels.friendly("iPhone15,2") == "iPhone")
        #expect(DeviceModels.friendly("MacBookPro18,3") == "MacBook Pro")
        #expect(DeviceModels.friendly("AudioAccessory5,1") == "HomePod")
        #expect(DeviceModels.friendly("Macmini9,1") == "Mac mini")
        #expect(DeviceModels.model(txt: ["md": "Chromecast Ultra", "fn": "Living Room TV"]) == "Chromecast Ultra")
        #expect(DeviceModels.model(txt: ["ty": "HP LaserJet M110w"]) == "HP LaserJet M110w")
        #expect(DeviceModels.name(service: "A1B2C3D4E5F6@Kitchen", txt: [:]) == "Kitchen")
        #expect(DeviceModels.symbol(model: "iPhone", maker: "") == "iphone")
        #expect(DeviceModels.symbol(model: "HP LaserJet M110w", maker: "") == "printer")
    }

    @Test func titleUsesWhatIsKnown() {
        let now = Date()
        var d = MapDevice(mac: "a4:c3:61:12:34:56", ips: ["192.168.1.30"], iface: "en0", firstSeen: now, lastSeen: now)
        #expect(d.title == "Unknown device")
        d.maker = "Apple"
        #expect(d.title == "Apple device")
        d.model = "iPhone"
        #expect(d.title == "iPhone" && d.kind == "Apple" && d.symbol == "iphone")
        d.announcedName = "Kitchen iPad"
        #expect(d.title == "Kitchen iPad" && d.kind == "iPhone · Apple")
    }

    @Test func storeIdentifiesDevices() {
        let store = NetworkMapStore(fileURL: nil)
        store.makerFor = { $0.hasPrefix("cc:2d:e0") ? "Routerboard.com" : nil }
        store.announced = { $0 == "192.168.1.9" ? AnnouncedDevice(name: "Living Room", model: "Apple TV") : nil }
        store.apply(NetMapMessage(listeners: [], neighbors: [
            NetNeighbor(mac: "cc:2d:e0:c5:1a:05", ips: ["192.168.1.1"], iface: "en0"),
            NetNeighbor(mac: "36:48:71:1a:c0:f3", ips: ["192.168.1.9"], iface: "en0"),
        ], routes: NetRoutes(), inbound: []))
        #expect(store.devices["cc:2d:e0:c5:1a:05"]?.maker == "Routerboard.com")
        #expect(store.devices["36:48:71:1a:c0:f3"]?.title == "Living Room")
        #expect(store.devices["36:48:71:1a:c0:f3"]?.symbol == "tv")
    }
}

/// A split-tunnel VPN as a way out of its own, and searching the map.
@Suite @MainActor struct NetworkMapRoutesAndSearch {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    // The real split tunnel: company ranges through utun8, the rest through Wi-Fi.
    let split = NetMapParse.routes("""
    default            192.168.1.1        UGScg                 en0
    10.1/16            100.96.1.145       UGSc                utun8
    100.80/12          100.96.1.145       UGSc                utun8
    79.127.241.165/32  192.168.1.1        UGSc                  en0
    """)

    func out(_ program: String, _ group: String, _ ip: String) -> MapOutgoing {
        MapOutgoing(program: program, path: "/usr/bin/" + program, group: group, ip: ip, count: 3,
                    firstSeen: now.addingTimeInterval(-9 * 86400), lastSeen: now, blocked: false, isNew: false)
    }

    @Test func splitTunnelIsItsOwnWayOut() {
        #expect(!NetworkMapPolicy.isYourNetwork("10.1.4.20", routes: split))
        #expect(NetworkMapPolicy.isYourNetwork("192.168.1.13", routes: split))
        let g = NetworkMapBuilder.build(.init(routes: split, outgoing: [out("ssh", "git.corp.example", "10.1.4.20"),
                                                                         out("ssh", "192.168.1.13", "192.168.1.13"),
                                                                         out("curl", "example.com", "93.184.216.34")], now: now,
                                              interfaceName: { _ in "Wi-Fi" }))
        let ways = g.columns[2][0].nodes
        #expect(Set(ways.map(\.id)) == ["way:utun8", "way:local", "way:en0"])
        #expect(ways.first { $0.id == "way:utun8" }?.title == "VPN")
        #expect(ways.first { $0.id == "way:utun8" }?.subtitle == "utun8, some destinations")
        #expect(g.edges.contains { $0.from == "way:utun8" && $0.to == "dst:git.corp.example" })
    }

    @Test func fullTunnelLeavesYourNetworkDirect() {
        let full = NetMapParse.routes("""
        default            192.168.1.1        UGScg                 en0
        0/1                10.8.0.1           UGSc                  utun4
        128.0/1            10.8.0.1           UGSc                  utun4
        """)
        #expect(NetworkMapPolicy.isYourNetwork("192.168.1.13", routes: full))
        #expect(full.iface(for: "93.184.216.34") == "utun4")
    }

    @Test func searchKeepsWhatMatchesAndItsLinks() {
        let input = NetworkMapBuilder.Input(
            devices: [MapDevice(mac: "c0:cd:d6:79:e7:a4", ips: ["192.168.1.13"], iface: "en0", name: "nas.lan", firstSeen: now, lastSeen: now)],
            routes: split,
            outgoing: [out("ssh", "192.168.1.13", "192.168.1.13"), out("curl", "example.com", "93.184.216.34")],
            now: now, query: "nas")
        let g = NetworkMapBuilder.build(input)
        #expect(g.columns[0][0].nodes.map(\.title) == ["nas"])
        #expect(g.columns[1].last?.nodes.map(\.title) == ["ssh"])
        #expect(g.columns[3][0].nodes.map(\.ref) == ["192.168.1.13"])
        var curl = input
        curl.query = "CURL"
        #expect(NetworkMapBuilder.build(curl).columns[3][0].nodes.map(\.title) == ["example.com"])
    }
}


/// Moving between networks, blocking from the map, and showing a whole section.
@Suite @MainActor struct NetworkMapNetworksAndBlocks {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let home = NetNeighbor(mac: "cc:2d:e0:c5:1a:05", ips: ["192.168.1.1"], iface: "en0")
    let homePhone = NetNeighbor(mac: "aa:00:00:00:00:01", ips: ["192.168.1.30"], iface: "en0")
    // Work's router at the same address, another hardware address, another subnet size.
    let work = NetNeighbor(mac: "00:11:22:33:44:55", ips: ["192.168.1.1"], iface: "en0")
    let workPrinter = NetNeighbor(mac: "00:11:22:33:44:66", ips: ["192.168.1.30"], iface: "en0")

    func at(_ neighbors: [NetNeighbor], subnet: String = "192.168.1.0/24", inbound: [NetInbound] = []) -> NetMapMessage {
        NetMapMessage(listeners: [], neighbors: neighbors,
                      routes: NetRoutes(gateway: "192.168.1.1", iface: "en0", subnets: [subnet]), inbound: inbound)
    }

    @Test func goingToWorkIsNotARouterChangeAndShowsWorksDevices() {
        let store = NetworkMapStore(fileURL: nil)
        var alerts: [NetworkAlert] = []
        store.onAlert = { alerts.append($0) }
        store.apply(at([home, homePhone]), now: now)
        store.apply(at([work, workPrinter]), now: now.addingTimeInterval(3600))
        #expect(alerts.isEmpty)
        #expect(store.network == work.mac)
        // Work's first look is its baseline: nothing there is new.
        #expect(store.devices[workPrinter.mac]?.baseline == true)
        let g = store.graph(outgoing: [], filter: .everything, range: .week, now: now.addingTimeInterval(3600), interfaceName: { $0 })
        #expect(Set(g.columns[0][0].nodes.map(\.ref)) == [work.mac, workPrinter.mac])
        store.apply(at([home, homePhone]), now: now.addingTimeInterval(7200))
        #expect(alerts.isEmpty && store.network == home.mac)
    }

    @Test func anyPrivateRangeIsYourNetworkWhenThisMacIsOnIt() {
        let r = NetRoutes(gateway: "10.20.0.1", iface: "en0", subnets: ["10.20.0.0/16"])
        #expect(NetworkMapPolicy.isYourNetwork("10.20.5.6", routes: r))
        #expect(!NetworkMapPolicy.isYourNetwork("192.168.1.30", routes: r))      // private, but not here
        let company = NetRoutes(gateway: "130.10.0.1", iface: "en0", subnets: ["130.10.0.0/16"])
        #expect(NetworkMapPolicy.isYourNetwork("130.10.4.4", routes: company))  // a public range used as the office LAN
    }

    @Test func blockingADeviceFollowsItsAddressAndNeverTheRouter() {
        let store = NetworkMapStore(fileURL: nil)
        var sent: [([String], [Int])] = []
        store.onBlocks = { sent.append(($0, $1)) }
        store.apply(at([home, homePhone]), now: now)
        store.setBlocked(device: home.mac, true)
        #expect(store.blockList.addresses.isEmpty)
        store.setBlocked(device: homePhone.mac, true)
        store.setBlocked(port: 8000, true)
        #expect(store.blockList.addresses == ["192.168.1.30"] && store.blockList.ports == [8000])
        var moved = homePhone
        moved.ips = ["192.168.1.44"]
        store.apply(at([home, moved]), now: now.addingTimeInterval(10))
        #expect(sent.last?.0 == ["192.168.1.44"])
        // At work the home phone's old address is someone else's: not blocked there.
        store.apply(at([work, workPrinter]), now: now.addingTimeInterval(20))
        #expect(store.blockList.addresses.isEmpty)
    }

    @Test func badgeCountsWhoTriedUntilSeenOrCleared() {
        let store = NetworkMapStore(fileURL: nil)
        let tries = [NetInbound(remote: "192.168.1.30", port: 22, count: 3, listening: false),
                     NetInbound(remote: "192.168.1.30", port: 8000, count: 1, listening: true),
                     NetInbound(remote: "203.0.113.7", port: 22, count: 5, listening: false)]
        store.apply(at([home, homePhone], inbound: tries), now: now)
        #expect(store.badge.count == 2)
        store.markTriesSeen(now: now.addingTimeInterval(1))
        #expect(store.badge.count == 0 && store.inbound.count == 3)
        store.apply(at([home, homePhone], inbound: [tries[2]]), now: now.addingTimeInterval(10))
        #expect(store.badge.count == 1)
        store.clearTries(refusedOnly: true, now: now.addingTimeInterval(11))
        #expect(store.badge.count == 0 && store.inbound.values.map(\.port) == [8000])
        store.clearTries(refusedOnly: false)
        #expect(store.inbound.isEmpty)
    }

    @Test func collectorRulesAreSafe() {
        #expect(AddressBlock.valid(["192.168.1.30", "nonsense", "127.0.0.1", "192.168.1.19", "::"], own: ["192.168.1.19"]) == ["192.168.1.30"])
        let rules = AddressBlock.rules(addresses: ["192.168.1.30"], ports: [8000])
        #expect(rules.contains("block drop in quick from <hw_blocked>"))
        #expect(rules.contains("block drop out quick from any to <hw_blocked>"))
        #expect(rules.contains("on ! lo0") && rules.contains("port { 8000 }"))
        #expect(AddressBlock.rules(addresses: [], ports: []).isEmpty)
    }

    @Test func showAllAndEachWayOutKeepsItsDestinations() {
        let routes = NetMapParse.routes("""
        default            192.168.1.1        UGScg                 en0
        10.1/16            100.96.1.145       UGSc                utun8
        """)
        var out = (1...12).map { i in
            MapOutgoing(program: "Safari", path: "/Applications/Safari.app", group: "site\(i).example", ip: "93.184.216.\(i)", count: 100 + i,
                        firstSeen: now.addingTimeInterval(-9 * 86400), lastSeen: now, blocked: false, isNew: false)
        }
        out.append(MapOutgoing(program: "Chrome", path: "/Applications/Chrome.app", group: "wiki.corp.example", ip: "10.1.2.3", count: 1,
                               firstSeen: now.addingTimeInterval(-9 * 86400), lastSeen: now, blocked: false, isNew: false))
        let folded = NetworkMapBuilder.build(.init(routes: routes, outgoing: out, now: now))
        #expect(folded.columns[3][0].nodes.contains { $0.ref == "wiki.corp.example" })     // the VPN's one, despite its 1
        #expect(folded.columns[3][0].more > 0)
        let all = NetworkMapBuilder.build(.init(routes: routes, outgoing: out, now: now, expanded: ["destinations"]))
        #expect(all.columns[3][0].nodes.count == 13 && all.columns[3][0].more == 0)
    }
}
