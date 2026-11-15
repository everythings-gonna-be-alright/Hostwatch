import SwiftUI

/// Protection ▸ Network: devices, addresses and ports you blocked, wherever you blocked them (the network map's
/// right-click, or here). The collector blocks them itself, both ways, whatever the firewall's mode, so they work
/// on Watch too. source: docs/adr/0017-network-map.md
struct BlockedDevicesSection: View {
    @ObservedObject var store: NetworkMapStore
    var showNetwork: () -> Void = {}
    @StateObject private var adding = DestinationDraft()

    var body: some View {
        let devices = store.devices.values.filter { $0.blocked == true }.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        let addresses = store.blockedAddresses.sorted()
        let ports = store.blockedPorts.sorted()
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Blocked devices and addresses").font(.headline)
                Spacer()
                Button { adding.open = true } label: { Label("Block an Address…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Text("Nothing from them reaches this Mac and nothing goes to them, whatever the firewall's mode. Block more "
                 + "from the network map: right-click a device, an address or a listening program.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if adding.open { addRow }
            if devices.isEmpty && addresses.isEmpty && ports.isEmpty && !adding.open {
                HStack {
                    Text("None yet.").font(.callout).foregroundStyle(.secondary)
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
            ForEach(addresses, id: \.self) { a in
                let device = store.device(forIP: a)
                card(symbol: "number", title: a, subtitle: device.map { "\($0.title) on your network" } ?? "This address", data: true) {
                    store.setBlocked(address: a, false)
                }
            }
            ForEach(ports, id: \.self) { p in
                let who = store.listeners.first { $0.port == p }?.name
                card(symbol: "antenna.radiowaves.left.and.right", title: "Port \(p)",
                     subtitle: (who.map { "\($0), " } ?? "") + "other machines can't connect. This Mac still can.") {
                    store.setBlocked(port: p, false)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    private var addRow: some View {
        let text = adding.text.trimmingCharacters(in: .whitespaces)
        let problem = text.isEmpty ? nil : refusal(text)
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("192.168.1.23 or 203.0.113.9", text: $adding.text)
                    .textFieldStyle(.roundedBorder).font(.system(size: 12, design: .monospaced))
                    .onSubmit(add)
                Button("Cancel") { adding.open = false; adding.text = "" }.controlSize(.small)
                Button("Block", action: add).buttonStyle(.glassProminent).controlSize(.small)
                    .disabled(text.isEmpty || problem != nil)
            }
            if let problem { Label(problem, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
        }
    }

    /// Why this address can't be blocked here, nil when it can.
    private func refusal(_ text: String) -> String? {
        guard IPEndpoint(text, port: 0) != nil else { return "Enter an IP address. To block a domain, add it to your destinations." }
        if text == store.routes.gateway { return "That's the router: blocking it would cut this Mac off the network." }
        if text.hasPrefix("127.") || text == "::1" { return "That's this Mac itself." }
        return nil
    }

    private func add() {
        let text = adding.text.trimmingCharacters(in: .whitespaces)
        guard refusal(text) == nil else { return }
        if let d = store.device(forIP: text), !d.mac.hasPrefix("ip:") { store.setBlocked(device: d.mac, true) }
        else { store.setBlocked(address: text, true) }
        adding.open = false
        adding.text = ""
    }

    /// The same card anatomy as a destination: icon, name, what it covers, then the action at the trailing edge.
    private func card(symbol: String, title: String, subtitle: String, data: Bool = false, unblock: @escaping () -> Void) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.red).frame(width: 22).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium, design: data ? .monospaced : .default))
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            MapBadgeView(badge: .blocked)
            Button("Unblock", action: unblock).buttonStyle(.glass).controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
        .accessibilityElement(children: .combine)
    }
}
