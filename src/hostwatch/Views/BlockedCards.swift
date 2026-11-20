import SwiftUI

/// Protection ▸ Network Firewall ▸ General: the devices and ports you blocked both ways (the network map's
/// right-click). Addresses are destination cards (`BlockedAddressCards`). The collector blocks them itself, both ways, whatever the firewall's mode, so they work
/// on Watch too. source: docs/adr/0017-network-map.md
struct BlockedCards: View {
    @ObservedObject var store: NetworkMapStore
    /// General has nothing else to show: the shared "None yet" is said here, where the blocks are known.
    var noDestinations = false
    var showNetwork: () -> Void = {}

    var body: some View {
        let devices = store.devices.values.filter { $0.blocked == true }.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        let ports = store.blockedPorts.sorted()
        VStack(alignment: .leading, spacing: 10) {
            if noDestinations, devices.isEmpty, store.blockedAddresses.isEmpty, ports.isEmpty {
                HStack {
                    Text("None yet. Block a domain for every program, always allow one app to a server, or block a "
                         + "device from the network map.").font(.callout).foregroundStyle(.secondary)
                    Button("Open the Network Map", action: showNetwork).buttonStyle(.glass).controlSize(.small)
                }
            }
            ForEach(devices) { d in
                let here = d.isOn(store.network)
                card(symbol: d.symbol, title: d.title,
                     subtitle: ([d.ip] + [d.kind]).filter { !$0.isEmpty }.joined(separator: " · ")
                        + (here ? "" : " · on another network, blocked when this Mac is there")) {
                    store.setBlocked(device: d.mac, false)
                }
            }
            ForEach(ports, id: \.self) { p in
                let who = store.listeners.first { $0.port == p }?.name
                card(symbol: "antenna.radiowaves.left.and.right", title: "Port \(p)",
                     subtitle: (who.map { "\($0), " } ?? "") + "other machines can't connect. This Mac still can.",
                     status: "Blocked from outside") {
                    store.setBlocked(port: p, false)
                }
            }
        }
    }

    /// The same card as a destination: icon, name, what it covers, then what it does and remove at the trailing edge.
    private func card(symbol: String, title: String, subtitle: String, data: Bool = false, status: String = "Blocked both ways",
                      unblock: @escaping () -> Void) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium, design: data ? .monospaced : .default))
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            Label(status, systemImage: "nosign").font(.caption).foregroundStyle(.red)
            Button(action: unblock) { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless)
                .help("Unblock \(title)")
                .accessibilityLabel("Unblock \(title)")
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }
}

/// Addresses blocked both ways that aren't destinations yet (blocked from the network map): destination cards with
/// Block both ways chosen, kept as destinations at the first change.
struct BlockedAddressCards<Card: View>: View {
    @ObservedObject var store: NetworkMapStore
    let known: Set<String>
    @ViewBuilder let card: (Destination) -> Card

    var body: some View {
        ForEach(store.blockedAddresses.sorted().filter { !known.contains($0) }, id: \.self) { a in
            card(Destination(id: "blocked|" + a, target: a, others: .block))
        }
    }
}
