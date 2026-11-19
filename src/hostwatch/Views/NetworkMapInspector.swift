import AppKit
import SwiftUI

/// The map's details panel: what the selected device, address, listener, program, way out or destination did, with
/// what you can do about it.
struct NetworkMapInspector: View {
    @ObservedObject var store: NetworkMapStore
    @ObservedObject var state: NetworkMapViewState
    let graph: NetworkGraph
    let outgoing: [MapOutgoing]
    var openDetails: (String) -> Void
    var openStories: () -> Void
    var interfaceName: (String) -> String = { $0 }
    var actions = NetworkMapActions()
    var showProcess: ((ActivityEvent) -> Void)? = nil

    private var node: MapNode? {
        state.selection.flatMap { id in graph.columns.joined().flatMap(\.nodes).first { $0.id == id } }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if let node { details(node) } else { empty }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .protectionGlass(18)
    }

    private var empty: some View {
        VStack(spacing: 12) {
            Image(systemName: "cursorarrow.click.2")
                .font(.system(size: 22, weight: .medium)).foregroundStyle(.secondary)
                .frame(width: 52, height: 52)
                .glassEffect(.regular, in: Circle())
                .accessibilityHidden(true)
            Text("Select anything on the map").font(.headline)
            Text("On the left, devices on your network and addresses on the internet that tried to reach this Mac. "
                 + "Then what listens and goes out on it, the way out, and where it goes.")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Label("Hostwatch only listens. It never scans your network or sends anything to find these.",
                  systemImage: "ear")
                .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 28)
    }

    // MARK: By kind

    @ViewBuilder private func details(_ node: MapNode) -> some View {
        switch node.kind {
        case .device: device(node)
        case .internet: internet(node)
        case .listener: listener(node)
        case .closedPorts: closedPorts
        case .program: program(node)
        case .wayOut: wayOut(node)
        case .destination: destination(node)
        }
    }

    private func header(_ symbol: String, _ title: String, _ subtitle: String, badge: MapBadge? = nil, tint: Color = .secondary) -> some View {
        // A seal in the item's colour (grey, orange for new, red for blocked), the name, its address in monospace.
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .semibold)).foregroundStyle(.white)
                .frame(width: 38, height: 38)
                .background((tint == .secondary ? Color.gray : tint).gradient, in: Circle())
                .shadow(color: (tint == .secondary ? Color.gray : tint).opacity(0.35), radius: 5, y: 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.semibold)).lineLimit(2)
                if !subtitle.isEmpty {
                    Text(subtitle).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Spacer(minLength: 4)
            if let badge { MapBadgeView(badge: badge) }
        }
        .accessibilityElement(children: .combine)
    }

    /// A fact: its label small above, the value below (a long value no longer squeezed into a narrow column).
    func row(_ label: String, _ value: String, data: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(size: 13, design: data ? .monospaced : .default)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    func when(_ d: Date) -> String { d.formatted(.relative(presentation: .named)) }

    func tries(from ips: [String]) -> [MapInbound] {
        return store.inbound.values.filter { ips.contains($0.remote) && $0.count(in: state.window()) > 0 }.sorted { $0.port < $1.port }
    }

    /// "Tried 40 ports on this Mac. 38 were refused. It reached Python on port 8000."
    private func triesText(_ list: [MapInbound]) -> String {
        let ports = Set(list.map(\.port)).count
        let refused = list.filter { $0.refused >= $0.count }.count
        var text = "Tried \(ports == 1 ? "1 port" : "\(ports) ports") on this Mac."
        if refused > 0 { text += refused == list.count ? " All were refused." : " \(refused) were refused." }
        let reached = list.filter { $0.refused < $0.count }
        if let r = reached.first {
            let n = r.count(in: state.window())
            text += " It reached \(r.listener.isEmpty ? "a program" : r.listener) on port \(r.port)\(n > 1 ? " \(n) times" : "")."
        }
        return text
    }

    private func callout(_ title: String, _ text: String, tint: Color, story: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(tint.gradient, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(text).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if story { Button("Open Stories", action: openStories).buttonStyle(.glass).controlSize(.small) }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(tint.opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(tint.opacity(0.25), lineWidth: 0.5))
        .accessibilityElement(children: .contain)
    }

    // MARK: Device

    @ViewBuilder private func device(_ node: MapNode) -> some View {
        let d = store.devices[node.ref]
        let ips = d?.ips ?? [String(node.ref.dropFirst(3))]
        let list = tries(from: ips)
        let isNew = d.map { NetworkMapPolicy.isNew($0, now: Date()) } ?? true
        header(node.symbol ?? "desktopcomputer", node.title,
               ([ips.first ?? ""] + (d.map { [$0.mac] } ?? [])).joined(separator: " · "), badge: node.badge,
               tint: isNew ? .orange : .secondary)
        if !list.isEmpty {
            let scan = Set(list.map(\.port)).count >= NetworkMapPolicy.scanPorts
            callout(scan ? "Port scan from your network" : "Tried to reach this Mac", triesText(list), tint: .orange, story: scan || isNew)
        }
        VStack(alignment: .leading, spacing: 8) {
            if let d {
                row("First seen", d.baseline ? "Before Hostwatch looked" : when(d.firstSeen))
                row("Last seen", when(d.lastSeen))
                row("Model", d.model ?? "Doesn't announce one")
                row("Maker", d.maker ?? (NetMapParse.isRandom(d.mac) ? "Hidden by a private address" : "Not in the registry"))
                row("Name", [d.announcedName ?? "", d.name].first { !$0.isEmpty } ?? "Doesn't announce one")
                row("Address", NetMapParse.isRandom(d.mac) ? "Private, made up by the device" : "Fixed, set by its maker")
                if !d.iface.isEmpty { row("Interface", d.iface, data: true) }
            } else {
                row("Seen", "Only in its tries, not in the neighbour tables")
            }
            if !list.isEmpty { row("Ports tried", list.prefix(12).map { ":\($0.port)" }.joined(separator: " "), data: true) }
        }
        deviceMore(d, ips: ips, tries: list)
        if let d {
            Divider()
            TextField("Your name for it", text: Binding(get: { state.renaming.isEmpty ? d.yourName : state.renaming },
                                                         set: { state.renaming = $0 }))
                .textFieldStyle(.roundedBorder)
                .onSubmit { store.rename(d.mac, state.renaming); state.renaming = "" }
                .accessibilityLabel("Your name for this device")
            HStack {
                Spacer()
                if store.blockRefusal(device: d.mac) == nil {
                    Button(store.isBlocked(device: d.mac) ? "Unblock" : "Block") { store.setBlocked(device: d.mac, !store.isBlocked(device: d.mac)) }
                        .buttonStyle(.glass)
                        .help("Blocked: nothing from it reaches this Mac, and nothing goes to it")
                }
                Button("Forget") { store.forget(d.mac); state.selection = nil }
                    .buttonStyle(.glass)
                    .help("Forgets this device and its tries. If it is seen again, it comes back as new.")
                if d.mine {
                    Button("Not Mine") { store.markMine(d.mac, false) }.buttonStyle(.glass)
                } else {
                    Button("Mark as Mine") { store.markMine(d.mac) }.buttonStyle(.glassProminent)
                        .help("A device of yours is never shown as new")
                }
            }
            .controlSize(.small)
        } else if !list.isEmpty {
            HStack {
                Spacer()
                Button("Clear Tries") { store.forgetTries(from: ips[0]); state.selection = nil }.buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    // MARK: Internet

    @ViewBuilder private func internet(_ node: MapNode) -> some View {
        let list = tries(from: [node.ref])
        header("globe", node.ref, "", badge: node.badge)
        Text(triesText(list)).font(.system(size: 12))
        Text("Addresses on the internet try every computer they can reach. When nothing listens, each try is refused "
             + "and nothing happens.")
            .font(.caption).foregroundStyle(.secondary)
        VStack(alignment: .leading, spacing: 8) {
            if let first = list.map(\.firstSeen).min() { row("First try", when(first)) }
            if let last = list.map(\.lastSeen).max() { row("Last try", when(last)) }
            row("Status", store.blockedAddresses.contains(node.ref) ? "Blocked by you, both ways" : "Not blocked")
        }
        triesByPort(list)
        HStack {
            Spacer()
            Button("Clear Tries") { store.forgetTries(from: node.ref); state.selection = nil }.buttonStyle(.glass).controlSize(.small)
        }
    }

    // MARK: This Mac

    @ViewBuilder private func listener(_ node: MapNode) -> some View {
        let l = store.listeners.first { "lis:\($0.proc)|\($0.port)" == node.id }
        header("antenna.radiowaves.left.and.right", node.title, l?.proc ?? "", badge: node.badge,
               tint: node.badge == .allNetworks ? .orange : .secondary)
        if let l {
            let port = l.port
            Text(l.scope == .all
                 ? "Anyone on a network this Mac joins can reach it on port \(port). If you only use it on this Mac, it can listen on this Mac alone."
                 : "Devices on your network can reach it on port \(port).")
                .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
            let n = store.inbound.values.filter { $0.port == port }.reduce(0) { $0 + $1.count(in: state.window()) }
            VStack(alignment: .leading, spacing: 8) {
                row("Port", ":\(port)", data: true)
                row("Tries", n == 0 ? "None from other devices" : "\(n) from other devices")
            }
            listenerMore(l)
            if let showProcess {
                let event = store.listenerEvent(l)
                Button(state.showsProcess(event) ? "Hide Process Details" : "Process Details") { showProcess(event) }
                    .buttonStyle(.glass).controlSize(.small)
                    .help("Its launch chain, status and actions, as under Events (again to close)")
            }
        }
    }

    private var closedPorts: some View {
        let list = store.inbound.values.filter { $0.refused >= $0.count && $0.count(in: state.window()) > 0 }
        let ports = Dictionary(grouping: list, by: \.port).map { ($0.key, $0.value.reduce(0) { $0 + $1.count(in: state.window()) }) }
            .sorted { $0.1 > $1.1 }
        return VStack(alignment: .leading, spacing: 12) {
            header("xmark.circle", "Closed ports", "", badge: .refused)
            Text("Tries at ports where nothing listens. This Mac refused them, so nothing happened.")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Clear Refused Tries") { store.clearTries(refusedOnly: true); state.selection = nil }
                    .buttonStyle(.glass).controlSize(.small)
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(ports.prefix(10), id: \.0) { port, n in row(":\(port)", "\(n) \(n == 1 ? "try" : "tries")", data: false) }
            }
        }
    }

    @ViewBuilder private func program(_ node: MapNode) -> some View {
        let since = state.window().start
        let mine = outgoing.filter { $0.path == node.ref && $0.lastSeen >= since }
        let bytes = state.measure == .sent
        let byGroup = Self.destinations(mine, bytes: bytes)
        // The ports belong to the destination: listed under each one this program went to.
        let ports = Dictionary(grouping: mine, by: \.group).mapValues { NetworkMapBuilder.portsList($0.flatMap(\.ports)) }
        header("app", node.title, node.ref, badge: node.badge)
        if let showProcess, let event = store.lastEvent(program: node.ref) {
            Button(state.showsProcess(event) ? "Hide Process Details" : "Process Details") { showProcess(event) }
                .buttonStyle(.glass).controlSize(.small)
                .help("Its launch chain, status and actions, as under Events (again to close)")
        }
        programMore(node, mine)
        Text("Went to \(byGroup.count == 1 ? "1 destination" : "\(byGroup.count) destinations").").font(.system(size: 12))
        VStack(alignment: .leading, spacing: 6) {
            ForEach(byGroup.prefix(10), id: \.0) { group, n, blocked in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(group).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                        if let p = ports[group], !p.isEmpty {
                            Text("port\(p.contains(",") ? "s" : "") \(p)").font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                    Spacer()
                    if blocked { MapBadgeView(badge: .blocked) }
                    Text(bytes ? ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) : n.formatted())
                        .font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
    }

    /// A program's destinations with their connections or bytes sent, and whether any was blocked.
    static func destinations(_ list: [MapOutgoing], bytes: Bool) -> [(String, Int, Bool)] {
        var out: [(String, Int, Bool)] = []
        for (group, l) in Dictionary(grouping: list, by: \.group) {
            var n = 0
            for o in l { n += bytes ? Int(o.sent) : o.count }
            if n > 0 { out.append((group, n, l.contains(where: \.blocked))) }
        }
        return out.sorted { $0.1 != $1.1 ? $0.1 > $1.1 : $0.0 < $1.0 }
    }

    @ViewBuilder private func wayOut(_ node: MapNode) -> some View {
        let vpn = store.routes.vpns.first { $0.iface == node.ref }
        header(node.title == "VPN" ? "lock.shield" : node.ref == "local" ? "house" : "wifi", node.title, node.ref == "local" ? "" : node.ref)
        wayOutMore(node)
        VStack(alignment: .leading, spacing: 8) {
            if let vpn {
                row("Carries", vpn.full ? "Everything" : "Some destinations")
                if !vpn.full { row("Routes", vpn.routes.prefix(6).joined(separator: " "), data: true) }
            } else if node.ref == "local" {
                Text("Connections to devices on your network go to them directly.").font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                if !store.routes.gateway.isEmpty { row("Router", store.routes.gateway, data: true) }
                if store.routes.vpns.contains(where: \.full) {
                    Text("A VPN carries everything else.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private func destination(_ node: MapNode) -> some View {
        let since = state.window().start
        let conns = outgoing.filter { $0.group == node.ref && $0.lastSeen >= since }
        let programs = Dictionary(grouping: conns, by: \.program).map { ($0.key, $0.value.reduce(0) { $0 + $1.count }) }.sorted { $0.1 > $1.1 }
        // The ports connections to this destination went to, all of them and by program.
        let allPorts = NetworkMapBuilder.portsList(conns.flatMap(\.ports))
        let portsBy = Dictionary(grouping: conns, by: \.program).mapValues { NetworkMapBuilder.portsList($0.flatMap(\.ports)) }
        header(node.symbol ?? "globe", node.title, node.subtitle, badge: node.badge,
               tint: node.badge == .blocked ? .red : node.badge == .new ? .orange : .secondary)
        destinationMore(node, conns)
        if !allPorts.isEmpty { row(allPorts.contains(",") ? "Ports" : "Port", allPorts, data: true) }
        if node.badge == .new {
            Text("No program on this Mac had contacted it before.").font(.system(size: 12)).foregroundStyle(.secondary)
        }
        VStack(alignment: .leading, spacing: 6) {
            ForEach(programs.prefix(8), id: \.0) { name, n in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(name).font(.system(size: 12)).lineLimit(1)
                        if let p = portsBy[name], !p.isEmpty, p != allPorts {
                            Text("port\(p.contains(",") ? "s" : "") \(p)").font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                    Spacer()
                    Text(n, format: .number).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
        if !NetworkMapPolicy.isYourNetwork(node.ref, routes: store.routes) {
            HStack {
                Spacer()
                Button("Details…") { openDetails(node.ref) }.buttonStyle(.glass).controlSize(.small)
                    .help("Risk, programs and what to allow or block for this destination")
            }
        }
    }
}
