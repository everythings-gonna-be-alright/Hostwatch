import AppKit
import SystemConfiguration

// The network map's wiring: its alerts become stories, and the map gets the firewall's outgoing connections and the
// interfaces' names.

extension AppDelegate {
    func raiseNetworkStory(_ alert: NetworkAlert) {
        switch alert {
        case let .portScan(remote, device, ports):
            stories.raise(.portScan, origin: "\(device) (\(remote))",
                          note: "tried \(ports) ports on this Mac within a minute", target: remote)
        case let .newDeviceReached(remote, device, port):
            stories.raise(.newDevice, origin: "\(device) (\(remote))",
                          note: "a device first seen today connected to port \(port) on this Mac", target: "\(remote):\(port)")
        case let .routerChanged(ip, old, new):
            stories.raise(.routerChanged, origin: "Router (\(ip))",
                          note: "the router's hardware address changed from \(old) to \(new). A new router does this, and so "
                              + "does someone on your network posing as it", target: ip)
        }
    }

    /// The firewall's connections as the map draws them.
    func mapOutgoing() -> [MapOutgoing] {
        let now = Date()
        return firewall.list(status: { [signatures] in signatures.status(forKey: $0) }).map { e, d in
            let group = NetworkMapPolicy.isLocal(e.facts.ip) ? "Your network" : NetworkRow.group(e.facts)
            let name = e.name.isEmpty || e.name == "?" ? (e.facts.program as NSString).lastPathComponent : e.name
            let isNew = domains.records[group].map { domains.isNew($0, now: now) } ?? false
            return MapOutgoing(program: SignatureBuilder.vmGateway(e.facts.program) ?? (name.isEmpty ? "Unknown program" : name),
                               path: e.facts.program, group: group, ip: e.facts.ip, count: e.count, firstSeen: e.firstSeen,
                               lastSeen: e.lastSeen, blocked: d.verdict == .block, isNew: isNew)
        }
    }

    /// "en0" -> "Wi-Fi", from System Configuration.
    nonisolated static func interfaceName(_ bsd: String) -> String {
        let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []
        for i in all where SCNetworkInterfaceGetBSDName(i) as String? == bsd {
            if let name = SCNetworkInterfaceGetLocalizedDisplayName(i) as String? { return name }
        }
        return bsd
    }
}
