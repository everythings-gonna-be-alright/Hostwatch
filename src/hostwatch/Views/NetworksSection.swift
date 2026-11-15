import SwiftUI

/// Protection ▸ Network: every network this Mac joined (known by its router), its name, and whether you trust it. On
/// one you don't, other machines can't reach programs listening on all networks, and the firewall asks about new
/// connections (your mode comes back when you leave). source: docs/adr/0017-network-map.md
struct NetworksSection: View {
    @ObservedObject var store: NetworkMapStore

    var body: some View {
        let list = store.profiles.values.sorted { a, b in
            a.id == store.network ? true : b.id == store.network ? false : a.lastSeen > b.lastSeen
        }
        VStack(alignment: .leading, spacing: 10) {
            Text("Networks").font(.headline)
            Text("Each network this Mac joins, known by its router. Home and work can be trusted. On a network you don't "
                 + "trust, like a café or an airport, Hostwatch keeps other machines away from this Mac.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if list.isEmpty {
                Text("None yet. The first network appears with the map's first report.").font(.callout).foregroundStyle(.secondary)
            }
            ForEach(list) { p in card(p) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    private func card(_ p: NetworkProfile) -> some View {
        let current = p.id == store.network
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: p.trusted ? "house" : "cup.and.saucer").foregroundStyle(p.trusted ? .green : .orange)
                    .frame(width: 22).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    TextField("Name", text: Binding(get: { p.name }, set: { store.renameNetwork(p.id, $0) }))
                        .textFieldStyle(.plain).font(.system(size: 13, weight: .medium))
                        .accessibilityLabel("Name of this network")
                    Text(([current ? "This Mac is on it now" : "Last here \(p.lastSeen.formatted(.relative(presentation: .named)))"]
                          + [p.router, p.subnet].filter { !$0.isEmpty }).joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if !p.decided { MapBadgeView(badge: .new) }
                IconSegments(selection: Binding(get: { p.trusted }, set: { store.setTrusted(p.id, $0) }), items: [
                    .init(value: true, title: "Trusted", symbol: "checkmark.shield", help: "Home, work: everything as usual"),
                    .init(value: false, title: "Not Trusted", symbol: "exclamationmark.shield",
                          help: "A café, an airport: other machines are kept away from this Mac"),
                ])
                if !current {
                    Button { store.forgetNetwork(p.id) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless).help("Forget \(p.name)").accessibilityLabel("Forget \(p.name)")
                }
            }
            if !p.trusted {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Other machines can't reach programs listening on all networks",
                           isOn: Binding(get: { p.blockListeners }, set: { store.setProtections(p.id, blockListeners: $0) }))
                    Toggle("The firewall asks about new connections here",
                           isOn: Binding(get: { p.firewallAsks }, set: { store.setProtections(p.id, firewallAsks: $0) }))
                }
                .toggleStyle(.switch).controlSize(.mini).font(.caption)
                .padding(.leading, 32)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }
}
