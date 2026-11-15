import SwiftUI

// The details panel's longer sections: who an item talked to and how much, its addresses, when, which way out, and
// whether you blocked it. Lists keep their top ten with "and N more".

extension NetworkMapInspector {
    /// A titled block of the panel.
    func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
            content()
        }
        .padding(.top, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Name, an optional second word, a count: one line of a list.
    func countRow(_ name: String, _ note: String = "", _ n: Int, data: Bool = false, badge: MapBadge? = nil) -> some View {
        HStack(spacing: 6) {
            Text(name).font(.system(size: 12, design: data ? .monospaced : .default)).lineLimit(1).truncationMode(.middle)
            if !note.isEmpty { Text(note).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1) }
            Spacer(minLength: 4)
            if let badge { MapBadgeView(badge: badge) }
            Text(n, format: .number).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
        }
        .accessibilityElement(children: .combine)
    }

    func more(_ total: Int, shown: Int) -> some View {
        Group {
            if total > shown { Text("and \(total - shown) more").font(.caption).foregroundStyle(.secondary) }
        }
    }

    var since: Date { state.window().start }

    func size(_ b: Int64) -> String { ByteCountFormatter.string(fromByteCount: b, countStyle: .file) }

    /// "1.2 GB sent · 30 MB received", or nil when nothing was counted.
    func traffic(_ list: [MapOutgoing]) -> String? {
        let sent = list.reduce(Int64(0)) { $0 + $1.sent }, received = list.reduce(Int64(0)) { $0 + $1.received }
        return sent + received == 0 ? nil : "\(size(sent)) sent · \(size(received)) received"
    }

    func way(_ ip: String) -> String {
        NetworkMapBuilder.wayTitle(NetworkMapBuilder.wayOut(ip, routes: store.routes), routes: store.routes, interfaceName: interfaceName)
    }

    // MARK: Device

    @ViewBuilder func deviceMore(_ d: MapDevice?, ips: [String], tries list: [MapInbound]) -> some View {
        section("Addresses") {
            ForEach(ips, id: \.self) { ip in Text(ip).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }
            if let d, !d.mac.hasPrefix("ip:") {
                Text(d.mac).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
        if let d {
            VStack(alignment: .leading, spacing: 8) {
                row("Status", d.blocked == true ? "Blocked by you, both ways" : d.mine ? "Yours" : "Not blocked")
                if let n = d.networks?.count, n > 1 { row("Networks", "Seen on \(n) networks") }
            }
        }
        let conns = outgoing.filter { $0.lastSeen >= since && ips.contains($0.ip) }
        if let t = traffic(conns) { row("Data", t) }
        if !conns.isEmpty {
            let byProgram = Dictionary(grouping: conns, by: \.program).map { ($0.key, $0.value.reduce(0) { $0 + $1.count }) }
                .sorted { $0.1 > $1.1 }
            section("This Mac connected to it") {
                ForEach(byProgram.prefix(10), id: \.0) { countRow($0.0, "", $0.1) }
                more(byProgram.count, shown: 10)
            }
        }
        triesByPort(list)
    }

    /// Each port tried, what answered, how many times and when last.
    @ViewBuilder func triesByPort(_ list: [MapInbound]) -> some View {
        if !list.isEmpty {
            let byPort = portRows(list)
            section("Tries by port") {
                ForEach(byPort.prefix(10), id: \.port) { r in
                    countRow(":\(r.port)", r.note, r.count, data: true, badge: store.blockedPorts.contains(r.port) ? .blocked : nil)
                }
                more(byPort.count, shown: 10)
            }
        }
    }

    struct PortRow { var port: Int; var count: Int; var note: String }

    func portRows(_ list: [MapInbound]) -> [PortRow] {
        var out: [PortRow] = []
        for (port, l) in Dictionary(grouping: list, by: \.port) {
            let n = l.reduce(0) { $0 + $1.count(in: state.window()) }
            let refused = l.allSatisfy { $0.refused >= $0.count }
            let listener = l.first { !$0.listener.isEmpty }?.listener ?? "reached"
            let last = when(l.map(\.lastSeen).max() ?? .distantPast)
            out.append(PortRow(port: port, count: n, note: refused ? "refused, \(last)" : "\(listener), \(last)"))
        }
        return out.sorted { $0.count > $1.count }
    }

    // MARK: This Mac

    @ViewBuilder func listenerMore(_ l: NetListener) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            row("Program", l.name)
            row("Process", "\(l.pid)", data: true)
            row("Listens on", l.scope == .all ? "All networks" : l.scope == .network ? "One network" : "This Mac only")
            row("Status", store.blockedPorts.contains(l.port) ? "Other machines blocked" : "Open to other machines")
        }
        let who = store.inbound.values.filter { $0.port == l.port && $0.count(in: state.window()) > 0 }
            .map { ($0.remote, $0.count(in: state.window())) }.sorted { $0.1 > $1.1 }
        if !who.isEmpty {
            section("Who tried") {
                ForEach(who.prefix(10), id: \.0) { remote, n in
                    countRow(store.device(forIP: remote)?.title ?? remote, store.device(forIP: remote) == nil ? "" : remote, n,
                             data: store.device(forIP: remote) == nil)
                }
                more(who.count, shown: 10)
            }
        }
    }

    // MARK: Going out

    @ViewBuilder func programMore(_ node: MapNode, _ mine: [MapOutgoing]) -> some View {
        let total = mine.reduce(0) { $0 + $1.count }
        VStack(alignment: .leading, spacing: 8) {
            row("Connections", "\(total.formatted()) in \(state.windowPhrase)")
            if let t = traffic(mine) { row("Data", t) }
            if let first = mine.map(\.firstSeen).min() { row("First seen", when(first)) }
            if let last = mine.map(\.lastSeen).max() { row("Last seen", when(last)) }
            let ways = Set(mine.map { way($0.ip) }).sorted()
            if !ways.isEmpty { row("Goes out by", ways.joined(separator: ", ")) }
            row("Status", actions.programBlocked(node.ref) ? "Its connections are blocked by you" : "Not blocked")
        }
    }

    @ViewBuilder func wayOutMore(_ node: MapNode) -> some View {
        let through = outgoing.filter { $0.lastSeen >= since && NetworkMapBuilder.wayOut($0.ip, routes: store.routes) == node.ref }
        let dests = Dictionary(grouping: through, by: \.group).map { ($0.key, $0.value.reduce(0) { $0 + $1.count }) }.sorted { $0.1 > $1.1 }
        let programs = Dictionary(grouping: through, by: \.program).map { ($0.key, $0.value.reduce(0) { $0 + $1.count }) }.sorted { $0.1 > $1.1 }
        if node.ref != "local", store.routes.vpns.first(where: { $0.iface == node.ref }) == nil,
           let router = store.device(forIP: store.routes.gateway) {
            VStack(alignment: .leading, spacing: 8) {
                row("Router", [router.maker ?? "", router.model ?? ""].filter { !$0.isEmpty }.joined(separator: " ").isEmpty
                    ? router.title : [router.maker ?? "", router.model ?? ""].filter { !$0.isEmpty }.joined(separator: " "))
                row("Hardware", router.mac, data: true)
                if !store.routes.subnets.isEmpty { row("Network", store.routes.subnets.joined(separator: " "), data: true) }
            }
        }
        if let vpn = store.routes.vpns.first(where: { $0.iface == node.ref }), !vpn.full {
            section("Routes it carries") {
                Text(vpn.routes.prefix(24).joined(separator: "  ")).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                more(vpn.routes.count, shown: 24)
            }
        }
        if !dests.isEmpty {
            section("Destinations through it") {
                ForEach(dests.prefix(10), id: \.0) { countRow($0.0, "", $0.1) }
                more(dests.count, shown: 10)
            }
            section("Programs using it") {
                ForEach(programs.prefix(6), id: \.0) { countRow($0.0, "", $0.1) }
                more(programs.count, shown: 6)
            }
        }
    }

    @ViewBuilder func destinationMore(_ node: MapNode, _ conns: [MapOutgoing]) -> some View {
        let ips = Array(Set(conns.map(\.ip))).sorted()
        VStack(alignment: .leading, spacing: 8) {
            row("Connections", "\(conns.reduce(0) { $0 + $1.count }.formatted()) in \(state.windowPhrase)")
            if let t = traffic(conns) { row("Data", t) }
            if let first = conns.map(\.firstSeen).min() { row("First seen", when(first)) }
            if let last = conns.map(\.lastSeen).max() { row("Last seen", when(last)) }
            if let ip = ips.first { row("Goes out by", way(ip)) }
            if NetMapParse.ipv4(node.ref) == nil, !node.ref.contains(":") {
                row("Status", actions.domainBlocked(node.ref) ? "Blocked by you for any program" : node.badge == .blocked ? "Blocked" : "Not blocked")
            }
        }
        if ips.count > 1 || (ips.first.map { $0 != node.ref } ?? false) {
            section("Addresses") {
                Text(ips.prefix(8).joined(separator: "  ")).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                more(ips.count, shown: 8)
            }
        }
    }
}
