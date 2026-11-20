import Darwin
import Foundation

/// The kernel's routing and neighbour tables, read with sysctl: what `netstat -rn`, `arp -an` and `ndp -an` print,
/// without starting them every half minute. A program the collector starts is, for an instant, its copy holding its
/// sockets (the firewall relay's among them), and parsing their text was the only way in.
enum KernelTables {
    /// One route, as `netstat -rn` shows it: "default" or "10.8.0.0/16" (a host route bare), the gateway, its flags.
    struct Route: Equatable, Sendable {
        var destination: String
        var gateway: String
        var up: Bool            // U
        var viaGateway: Bool    // G
        var ifScoped: Bool      // I: macOS keeps a scoped default on interfaces for its own services
        var iface: String
    }

    static func routes() -> [Route] {
        routes(from: [AF_INET, AF_INET6].flatMap { messages(dump($0, NET_RT_DUMP, 0)) })
    }

    static func routes(from messages: [Message]) -> [Route] {
        messages.compactMap { m -> Route? in
            guard let dst = m.addrs[Int(RTAX_DST)] else { return nil }
            let flags = m.flags
            let host = flags & RTF_HOST != 0
            return Route(destination: destination(dst, mask: m.addrs[Int(RTAX_NETMASK)], host: host),
                         gateway: m.addrs[Int(RTAX_GATEWAY)].map(address) ?? "",
                         up: flags & RTF_UP != 0, viaGateway: flags & RTF_GATEWAY != 0,
                         ifScoped: flags & RTF_IFSCOPE != 0, iface: name(ofIndex: m.index))
        }
    }

    /// Devices next to this Mac (ARP and IPv6 neighbours) that answered, by hardware address. This Mac's own
    /// addresses (entries that never expire) are left out, as `arp` and `ndp` mark them "permanent".
    static func neighbors() -> [NetNeighbor] {
        neighbors(from: [AF_INET, AF_INET6].flatMap { messages(dump($0, NET_RT_FLAGS, RTF_LLINFO)) })
    }

    static func neighbors(from messages: [Message]) -> [NetNeighbor] {
        messages.compactMap { m -> NetNeighbor? in
            guard m.expire != 0, let dst = m.addrs[Int(RTAX_DST)], let link = m.addrs[Int(RTAX_GATEWAY)],
                  let rawMAC = linkAddress(link), let mac = NetMapParse.mac(rawMAC) else { return nil }
            let ip = address(dst)
            guard !ip.isEmpty, !ip.hasPrefix("224."), !ip.hasPrefix("239."), !ip.hasSuffix(".255") else { return nil }
            return NetNeighbor(mac: mac, ips: [ip], iface: name(ofIndex: m.index))
        }
    }

    // MARK: Routing messages

    struct Message {
        var flags: Int32
        var index: UInt16
        var expire: Int32
        var addrs: [Int: [UInt8]]        // RTAX_* -> the sockaddr's bytes
    }

    private static func dump(_ family: Int32, _ what: Int32, _ flags: Int32) -> [UInt8] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, family, what, flags]
        for _ in 0..<3 {                                   // the table can grow between asking its size and reading it
            var size = 0
            guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0 else { return [] }
            if size == 0 { return [] }
            size += size / 8
            var buffer = [UInt8](repeating: 0, count: size)
            if sysctl(&mib, UInt32(mib.count), &buffer, &size, nil, 0) == 0 { return Array(buffer.prefix(size)) }
            guard errno == ENOMEM else { return [] }
        }
        return []
    }

    /// Splits a sysctl buffer into messages: each an `rt_msghdr`, then one sockaddr per bit of `rtm_addrs`, each
    /// rounded up to 4 bytes (Darwin's ROUNDUP).
    static func messages(_ buffer: [UInt8]) -> [Message] {
        var out: [Message] = []
        let header = MemoryLayout<rt_msghdr>.size
        buffer.withUnsafeBytes { raw in
            var offset = 0
            while offset + header <= raw.count {
                let h = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
                let length = Int(h.rtm_msglen)
                guard length >= header, offset + length <= raw.count else { break }
                var addrs: [Int: [UInt8]] = [:]
                var at = offset + header
                for slot in 0..<Int(RTAX_MAX) where h.rtm_addrs & (1 << slot) != 0 {
                    guard at < offset + length else { break }
                    let saLen = Int(raw[at])
                    // An all-zero netmask comes as an empty sockaddr: kept as such, it says "default".
                    if saLen == 0 { addrs[slot] = [] } else if at + saLen <= offset + length { addrs[slot] = Array(raw[at..<(at + saLen)]) }
                    at += saLen > 0 ? (saLen + 3) & ~3 : 4
                }
                out.append(Message(flags: h.rtm_flags, index: h.rtm_index, expire: h.rtm_rmx.rmx_expire, addrs: addrs))
                offset += length
            }
        }
        return out
    }

    // MARK: Addresses

    /// An IPv4 or IPv6 sockaddr as text ("192.168.1.1", "fe80::1"), a link one as "link#4", else "".
    static func address(_ sa: [UInt8]) -> String {
        guard sa.count >= 2 else { return "" }
        switch Int32(sa[1]) {
        case AF_INET where sa.count >= 8:
            return sa[4..<8].map(String.init).joined(separator: ".")
        case AF_INET6 where sa.count >= 24:
            var bytes = Array(sa[8..<24])
            // The kernel keeps a link-local address's scope inside it (bytes 2-3): not part of the address.
            if bytes[0] == 0xfe, bytes[1] & 0xc0 == 0x80 { bytes[2] = 0; bytes[3] = 0 }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard bytes.withUnsafeBytes({ inet_ntop(AF_INET6, $0.baseAddress, &text, socklen_t(text.count)) }) != nil else { return "" }
            return String(cString: text)
        case AF_LINK where sa.count >= 4:
            return "link#\(UInt16(sa[2]) | UInt16(sa[3]) << 8)"
        default:
            return ""
        }
    }

    /// "default", a network with its prefix length ("10.8.0.0/16"), or a host ("10.8.0.1"), from a route's
    /// destination and netmask. A netmask sockaddr may be cut short: what's missing is zeros.
    static func destination(_ dst: [UInt8], mask: [UInt8]?, host: Bool) -> String {
        let text = address(dst)
        guard !text.isEmpty, !host, let mask else { return text }
        let start = Int32(dst[1]) == AF_INET6 ? 8 : 4, width = Int32(dst[1]) == AF_INET6 ? 16 : 4
        var bits = 0
        for i in 0..<width {
            let b = start + Int(i) < mask.count ? mask[start + Int(i)] : 0
            bits += b.nonzeroBitCount
        }
        if bits == 0, text == "0.0.0.0" || text == "::" { return "default" }
        return "\(text)/\(bits)"
    }

    /// A link sockaddr's hardware address as "aa:bb:…", nil when it has none (an entry not answered yet).
    static func linkAddress(_ sa: [UInt8]) -> String? {
        // sockaddr_dl: len, family, index (2), type, nlen, alen, slen, then data: the name, then the address.
        guard sa.count >= 8, Int32(sa[1]) == AF_LINK else { return nil }
        let nameLength = Int(sa[5]), addressLength = Int(sa[6])
        let start = 8 + nameLength
        guard addressLength == 6, start + 6 <= sa.count else { return nil }
        return sa[start..<(start + 6)].map { String(format: "%x", $0) }.joined(separator: ":")
    }

    private static func name(ofIndex index: UInt16) -> String {
        var buffer = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
        return if_indextoname(UInt32(index), &buffer) != nil ? String(cString: buffer) : ""
    }
}
