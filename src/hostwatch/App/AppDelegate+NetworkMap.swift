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
        case let .largeUpload(program, path, destination, bytes):
            // Claude Code sends its context to Anthropic by design (Hostwatch's own AI calls too): not a leak.
            if CodingAgent.of(path) == .claude, destination.lowercased().contains("anthropic") { return }
            let size = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
            stories.raise(.largeUpload, origin: versionedProgramName(path) ?? program,
                          note: "sent \(size) within an hour to \(destination), which it first reached today", target: destination)
        case let .untrustedTry(remote, device, port, network):
            stories.raise(.newDevice, origin: "\(device) (\(remote))",
                          note: "tried to connect to port \(port) on this Mac, on \(network), a network you don't trust",
                          target: "\(remote):\(port)")
        case let .routerChanged(ip, old, new):
            stories.raise(.routerChanged, origin: "Router (\(ip))",
                          note: "the router's hardware address changed from \(old) to \(new). A new router does this, and so "
                              + "does someone on your network posing as it", target: ip)
        }
    }

    /// Every outgoing connection in the range, a destination marked new as the domain inventory says.
    func mapOutgoing(_ window: DateInterval) -> [MapOutgoing] {
        let now = Date()
        return networkMap.outgoingList(window) { [domains] group in
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

// MARK: Network profiles

extension AppDelegate {
    static let restoreModeKey = "untrustedNetworkRestoreMode"

    /// On a network you don't trust (and asked for it), the firewall asks about new connections. Off or Watch go back
    /// to how they were when the Mac is on another network, or you trust this one. A mode you set yourself in the
    /// meantime (Strict) is left alone.
    func applyNetworkProfile(_ p: NetworkProfile?) {
        let defaults = UserDefaults.standard
        if let p, !p.trusted, p.firewallAsks {
            if firewall.mode == .off || firewall.mode == .watch {
                defaults.set(firewall.mode.rawValue, forKey: Self.restoreModeKey)
                firewall.mode = .ask
            }
        } else if let raw = defaults.string(forKey: Self.restoreModeKey), let mode = FirewallMode(rawValue: raw) {
            defaults.removeObject(forKey: Self.restoreModeKey)
            if firewall.mode == .ask { firewall.mode = mode }
        }
    }
}

// MARK: Blocking from the map

/// What the map's right-click menu does beyond the map's own blocks (devices, addresses, ports): a program's
/// connections through their patterns, a domain through your destinations in Protection.
struct NetworkMapActions {
    var blockProgram: (String, Bool) -> Void = { _, _ in }
    var programBlocked: (String) -> Bool = { _ in false }
    var blockDomain: (String, Bool) -> Void = { _, _ in }
    var domainBlocked: (String) -> Bool = { _ in false }
    /// Every domain blocked for any program (your destinations), for drawing them red at once.
    var blockedDomains: () -> Set<String> = { [] }
    /// The firewall stops connections (Ask or Strict): a program's or domain's block needs it, the map's own don't.
    var firewallStops: () -> Bool = { false }
}

extension AppDelegate {
    func mapActions() -> NetworkMapActions {
        NetworkMapActions(
            blockProgram: { [weak self] path, on in
                guard let self else { return }
                let keys = self.networkMap.patternKeys(program: path)
                self.firewall.mark(on ? .suspicious : .safe, keys: keys, in: self.signatures,
                                   note: on ? "blocked on the network map" : "allowed on the network map")
            },
            programBlocked: { [weak self] path in
                guard let self else { return false }
                let keys = self.networkMap.patternKeys(program: path)
                return !keys.isEmpty && keys.allSatisfy { [.suspicious, .dangerous].contains(self.signatures.status(forKey: $0)) }
            },
            blockDomain: { [weak self] domain, on in
                guard let self else { return }
                var list = self.protection.destinations
                if let i = list.firstIndex(where: { $0.target == domain }) {
                    list[i].others = on ? .block : .firewall
                    list[i].on = true
                    if !on, list[i].exceptions.allowed.isEmpty, list[i].exceptions.blocked.isEmpty { list.remove(at: i) }
                } else if on {
                    list.append(Destination(target: domain, others: .block))
                }
                self.protection.destinations = list
            },
            domainBlocked: { [weak self] domain in
                self?.protection.destinations.contains { $0.target == domain && $0.on && $0.others == .block } ?? false
            },
            blockedDomains: { [weak self] in
                Set(self?.protection.destinations.filter { $0.on && $0.others == .block }.map(\.target) ?? [])
            },
            firewallStops: { [weak self] in self?.firewall.mode == .ask || self?.firewall.mode == .strict })
    }
}
