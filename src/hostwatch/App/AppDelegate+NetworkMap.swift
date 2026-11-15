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

    /// Every outgoing connection in the range, a destination marked new as the domain inventory says.
    func mapOutgoing(_ range: MapRange) -> [MapOutgoing] {
        let now = Date()
        return networkMap.outgoingList(range, now: now) { [domains] group in
            domains.records[group].map { domains.isNew($0, now: now) } ?? false
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
