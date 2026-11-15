import Darwin
import Foundation

/// What you blocked on the network map: addresses (both ways) and ports (incoming from other machines), as pf rules
/// in an anchor of their own. They hold whatever the firewall's mode, and go when the collector does (the same
/// watchdog as the firewall's). source: docs/adr/0017-network-map.md
final class AddressBlock: @unchecked Sendable {
    static let anchor = "com.apple/hostwatch-block"
    private let lock = NSLock()
    private var loaded: PFRedirect.Loaded?
    private var current: (addresses: [String], ports: [Int]) = ([], [])

    /// Only real addresses, never this Mac's own or loopback: a typo must not become a rule, nor cut this Mac off.
    static func valid(_ addresses: [String], own: Set<String>) -> [String] {
        Array(Set(addresses.filter { a in
            IPEndpoint(a, port: 0) != nil && !own.contains(a) && !a.hasPrefix("127.") && a != "::1" && a != "0.0.0.0" && a != "::"
        })).sorted()
    }

    static func rules(addresses: [String], ports: [Int]) -> String {
        var r = ""
        if !addresses.isEmpty {
            r += "table <hw_blocked> const { \(addresses.joined(separator: ", ")) }\n"
            r += "block drop in quick from <hw_blocked> to any\n"
            r += "block drop out quick from any to <hw_blocked>\n"
        }
        if !ports.isEmpty {
            // Other machines only: this Mac reaching its own server stays as it was.
            r += "block drop in quick on ! lo0 proto { tcp udp } from any to any port { \(ports.map(String.init).joined(separator: " ")) }\n"
        }
        return r
    }

    /// {"block": {"addresses": [...], "ports": [...]}}: the whole list each time.
    func set(_ cfg: [String: Any]) {
        let addresses = Self.valid((cfg["addresses"] as? [String]) ?? [], own: NetAddress.own())
        let ports = Array(Set(((cfg["ports"] as? [Int]) ?? []).filter { (1...65535).contains($0) })).sorted()
        lock.lock(); defer { lock.unlock() }
        guard addresses != current.addresses || ports != current.ports else { return }
        if let l = loaded { PFRedirect.unload(l); loaded = nil }
        current = (addresses, ports)
        guard !addresses.isEmpty || !ports.isEmpty else { Agent.log("network map blocks: none"); return }
        let (l, problem) = PFRedirect.load(Self.rules(addresses: addresses, ports: ports), failsafe: .whenThisProcessEnds,
                                           anchor: Self.anchor, expect: "block")
        loaded = l
        if l == nil { Agent.logError("network map blocks: pf refused the rules: \(problem)") }
        else { Agent.log("network map blocks: \(addresses.count) addresses, \(ports.count) ports") }
    }
}
