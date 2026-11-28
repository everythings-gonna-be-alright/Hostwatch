import Foundation

/// Addresses a threat list can't speak for. A list entry is an address seen in someone else's network or sandbox:
/// a private, link-local or loopback one exists in every home and office (`169.254.169.254` is the cloud metadata
/// service, listed by ThreatFox), and a CDN's anycast address fronts millions of sites (Discord's gateway on
/// Cloudflare was "a malware command server"). A match there names this Mac's router or a shared front door, never
/// the attacker. Domain matches still apply: a malware name behind Cloudflare is caught by its name.
extension FeedCheck {
    /// Never a meaningful list match: on this side of the router, or nobody's (0.0.0.0, multicast).
    static func localAddress(_ ip: String) -> Bool {
        let bare = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if NetworkMapPolicy.isLocal(bare) { return true }
        if bare.contains(":") { let l = bare.lowercased(); return l == "::" || l.hasPrefix("ff") }
        guard let v = NetMapParse.ipv4(bare) else { return false }
        let a = v >> 24
        return a == 0 || (224...255).contains(a)
    }

    /// A CDN's shared address range (Cloudflare, Fastly): an IP-only listing there is about one of its customers.
    static func sharedNetwork(_ ip: String) -> Bool {
        let bare = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        if bare.contains(":") { return sharedPrefixes6.contains { bare.hasPrefix($0) } }
        guard let v = NetMapParse.ipv4(bare) else { return false }
        return sharedRanges4.contains { v & $0.mask == $0.base }
    }

    /// Published ranges (cloudflare.com/ips, Fastly's public list).
    private static let sharedRanges4: [(base: UInt32, mask: UInt32)] = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/17",
    ].compactMap { cidr in
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let base = NetMapParse.ipv4(String(parts[0])), let bits = UInt32(parts[1]) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        return (base & mask, mask)
    }
    private static let sharedPrefixes6 = ["2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:", "2a06:98c", "2c0f:f248:",
                                          "2a04:4e40:"]

    /// An IP list entry worth keeping ("1.2.3.4" or "1.2.3.4:443").
    static func matchableIP(_ entry: String) -> Bool {
        var ip = entry
        if !ip.hasPrefix("["), ip.filter({ $0 == ":" }).count == 1 { ip = String(ip.split(separator: ":")[0]) }
        else if ip.hasPrefix("["), let end = ip.firstIndex(of: "]") { ip = String(ip[ip.index(after: ip.startIndex)..<end]) }
        return !localAddress(ip)
    }
}
