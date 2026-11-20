import Darwin
import Foundation
import Testing
@testable import Hostwatch

/// The routing and neighbour tables read from the kernel give what netstat, arp and ndp printed.
@Suite struct KernelTablesDecoding {
    func ipv4(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> [UInt8] {
        [16, UInt8(AF_INET), 0, 0, a, b, c, d] + [UInt8](repeating: 0, count: 8)
    }

    func link(index: UInt16, name: String, mac: [UInt8]) -> [UInt8] {
        let n = Array(name.utf8)
        var sa: [UInt8] = [0, UInt8(AF_LINK), UInt8(index & 0xFF), UInt8(index >> 8), 6, UInt8(n.count), UInt8(mac.count), 0] + n + mac
        while sa.count % 4 != 0 { sa.append(0) }
        sa[0] = UInt8(sa.count)
        return sa
    }

    /// One routing message: the header, then each address (an empty one as a bare 4-byte slot, as the kernel sends it).
    func message(flags: Int32, index: UInt16 = 4, expire: Int32 = 0, _ slots: [(Int32, [UInt8])]) -> [UInt8] {
        var body: [UInt8] = []
        var addrs: Int32 = 0
        for (slot, sa) in slots {
            addrs |= 1 << slot
            body += sa.isEmpty ? [0, 0, 0, 0] : sa
        }
        var h = rt_msghdr()
        h.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count)
        h.rtm_version = UInt8(RTM_VERSION)
        h.rtm_flags = flags
        h.rtm_addrs = addrs
        h.rtm_index = index
        h.rtm_rmx.rmx_expire = expire
        return withUnsafeBytes(of: &h) { Array($0) } + body
    }

    @Test func routesGiveDefaultNetworksAndHosts() {
        let buffer = message(flags: RTF_UP | RTF_GATEWAY, [(RTAX_DST, ipv4(0, 0, 0, 0)), (RTAX_GATEWAY, ipv4(192, 168, 1, 1)),
                                                            (RTAX_NETMASK, [])])
            + message(flags: RTF_UP | RTF_GATEWAY | RTF_IFSCOPE, [(RTAX_DST, ipv4(0, 0, 0, 0)), (RTAX_GATEWAY, ipv4(10, 8, 0, 1)),
                                                                  (RTAX_NETMASK, [])])
            + message(flags: RTF_UP, [(RTAX_DST, ipv4(10, 13, 0, 0)), (RTAX_GATEWAY, link(index: 9, name: "", mac: [])),
                                      (RTAX_NETMASK, [8, UInt8(AF_INET), 0, 0, 255, 255, 0, 0])])          // cut short: /16
            + message(flags: RTF_UP | RTF_HOST, [(RTAX_DST, ipv4(10, 8, 0, 7)), (RTAX_GATEWAY, ipv4(10, 8, 0, 1))])
        let routes = KernelTables.routes(from: KernelTables.messages(buffer))
        #expect(routes.map(\.destination) == ["default", "default", "10.13.0.0/16", "10.8.0.7"])
        #expect(routes[0].gateway == "192.168.1.1" && routes[0].viaGateway && !routes[0].ifScoped)
        #expect(routes[1].ifScoped)
        #expect(routes[2].gateway == "link#9")
    }

    @Test func theSameDecisionsAsFromNetstat() {
        // A split VPN and the Wi-Fi's default, as entries from the kernel and as netstat's text: one answer.
        let entries = [
            KernelTables.Route(destination: "default", gateway: "192.168.1.1", up: true, viaGateway: true, ifScoped: false, iface: "en0"),
            KernelTables.Route(destination: "default", gateway: "link#20", up: true, viaGateway: false, ifScoped: true, iface: "utun8"),
            KernelTables.Route(destination: "10.13.0.0/16", gateway: "link#20", up: true, viaGateway: false, ifScoped: false, iface: "utun8"),
            KernelTables.Route(destination: "127.0.0.0/8", gateway: "127.0.0.1", up: true, viaGateway: false, ifScoped: false, iface: "utun8"),
        ]
        let text = """
        default            192.168.1.1        UGScg                 en0
        default            link#20            UCSIg               utun8
        10.13/16           link#20            UCS                 utun8
        127                127.0.0.1          UCS                 utun8
        """
        let fromKernel = NetMapParse.routes(entries), fromText = NetMapParse.routes(text)
        #expect(fromKernel.gateway == "192.168.1.1" && fromKernel.iface == "en0")
        #expect(fromKernel.gateway == fromText.gateway && fromKernel.iface == fromText.iface)
        #expect(fromKernel.vpns.map(\.iface) == ["utun8"] && fromKernel.vpns[0].routes == ["10.13.0.0/16"])
        #expect(fromKernel.vpnIface(for: "10.13.4.5") == "utun8" && fromText.vpnIface(for: "10.13.4.5") == "utun8")
        // A full tunnel's two halves, as the kernel writes them.
        let full = NetMapParse.routes([
            KernelTables.Route(destination: "0.0.0.0/1", gateway: "link#20", up: true, viaGateway: false, ifScoped: false, iface: "utun3"),
            KernelTables.Route(destination: "128.0.0.0/1", gateway: "link#20", up: true, viaGateway: false, ifScoped: false, iface: "utun3"),
        ])
        #expect(full.vpns.first?.full == true && full.iface == "utun3")
    }

    @Test func neighboursThatAnsweredAndAreNotThisMac() {
        let router = [UInt8]([0xcc, 0x2d, 0xe0, 0xc5, 0x1a, 0x05])
        let buffer = message(flags: RTF_UP | RTF_LLINFO, expire: 1_200,
                             [(RTAX_DST, ipv4(192, 168, 1, 1)), (RTAX_GATEWAY, link(index: 4, name: "en0", mac: router))])
            + message(flags: RTF_UP | RTF_LLINFO, expire: 0,                       // this Mac's own: never expires
                      [(RTAX_DST, ipv4(192, 168, 1, 50)), (RTAX_GATEWAY, link(index: 4, name: "en0", mac: [2, 0, 0, 0, 0, 1]))])
            + message(flags: RTF_UP | RTF_LLINFO, expire: 1_200,                   // asked, not answered yet
                      [(RTAX_DST, ipv4(192, 168, 1, 77)), (RTAX_GATEWAY, link(index: 4, name: "en0", mac: []))])
            + message(flags: RTF_UP | RTF_LLINFO, expire: 1_200,                   // broadcast
                      [(RTAX_DST, ipv4(192, 168, 1, 255)), (RTAX_GATEWAY, link(index: 4, name: "en0", mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))])
        let found = KernelTables.neighbors(from: KernelTables.messages(buffer))
        #expect(found.map(\.mac) == ["cc:2d:e0:c5:1a:05"] && found.first?.ips == ["192.168.1.1"])
    }

    @Test func linkLocalAddressesLoseTheKernelsScope() {
        // fe80:4::1: the kernel's copy carries interface 4 in bytes 2-3.
        var sa: [UInt8] = [28, UInt8(AF_INET6), 0, 0, 0, 0, 0, 0, 0xfe, 0x80, 0, 4] + [UInt8](repeating: 0, count: 11) + [1]
        sa += [0, 0, 0, 0]
        #expect(KernelTables.address(sa) == "fe80::1")
    }

    @Test func theLiveTablesRead() {
        // This Mac's own table: no structure guessed wrong (a default or a route at least, every destination text).
        let routes = KernelTables.routes()
        #expect(!routes.isEmpty)
        #expect(routes.allSatisfy { !$0.destination.isEmpty })
    }
}
