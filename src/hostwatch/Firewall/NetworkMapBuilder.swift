import Foundation

/// The map's columns and edges from the store's values: pure, so every rule here has a test.
enum NetworkMapBuilder {
    struct Input {
        var devices: [MapDevice] = []
        var inbound: [MapInbound] = []
        var listeners: [NetListener] = []
        var routes = NetRoutes()
        var outgoing: [MapOutgoing] = []
        var filter: MapFilter = .everything
        var range: MapRange = .hour
        var now = Date()
        /// "en0" -> "Wi-Fi" (System Configuration in the app, a table in tests).
        var interfaceName: (String) -> String = { $0 }
        /// The window's search: only what matches, with what it connects to.
        var query = ""
        /// The network this Mac is on now (its router), "" when unknown: only its devices and tries are drawn.
        var network = ""
        /// Sections shown whole ("devices", "destinations").
        var expanded: Set<String> = []
        /// Internet addresses and ports you blocked.
        var blockedAddresses: Set<String> = []
        var blockedPorts: Set<Int> = []
    }

    /// What matches a search: a device by any of its names, model, maker or address, a try by its address or port, a
    /// listener by name or port, a connection by its program, destination, address or the device it reached.
    static func matching(_ input: Input) -> Input {
        let q = input.query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return input }
        var out = input
        func has(_ s: String) -> Bool { s.lowercased().contains(q) }
        func deviceMatches(_ d: MapDevice) -> Bool {
            has(d.title) || has(d.name) || has(d.model ?? "") || has(d.maker ?? "") || has(d.mac) || d.ips.contains(where: has)
        }
        let devices = input.devices.filter(deviceMatches)
        let deviceIPs = Set(devices.flatMap(\.ips))
        out.devices = devices
        out.listeners = input.listeners.filter { has($0.name) || has(":\($0.port)") || has($0.proc) }
        let ports = Set(out.listeners.map(\.port))
        out.inbound = input.inbound.filter { deviceIPs.contains($0.remote) || has($0.remote) || has($0.listener) || ports.contains($0.port) }
        out.outgoing = input.outgoing.filter { has($0.program) || has($0.group) || has($0.ip) || deviceIPs.contains($0.ip) }
        return out
    }

    /// The interface a destination leaves by ("en0", "utun8"), or "local" for a device on your network.
    static func wayOut(_ ip: String, routes: NetRoutes) -> String {
        if NetworkMapPolicy.isYourNetwork(ip, routes: routes) { return "local" }
        if let vpn = routes.vpnIface(for: ip, specificOnly: NetworkMapPolicy.isLocal(ip)) { return vpn }
        return NetworkMapPolicy.isLocal(ip) ? routes.iface : routes.iface(for: ip)
    }

    /// How a way out is named: "Your network", "VPN", or the interface's name ("Wi-Fi").
    static func wayTitle(_ iface: String, routes: NetRoutes, interfaceName: (String) -> String) -> String {
        iface == "local" ? "Your network" : iface.isEmpty ? "Internet" : routes.vpns.contains { $0.iface == iface } ? "VPN" : interfaceName(iface)
    }

    static let maxDevices = 6, maxInternet = 4, maxListeners = 4, maxPrograms = 6, maxDestinations = 8
    /// Each way out keeps its busiest destinations in view, so a VPN's few never fold away behind the Wi-Fi's many.
    static let perWayOut = 2

    static func build(_ input: Input) -> NetworkGraph {
        let input = matching(input)
        let since = input.range.since(input.now)
        let showIn = input.filter != .goingOut
        let showOut = input.filter == .everything || input.filter == .goingOut
        func limit(_ key: String, _ n: Int) -> Int { input.expanded.contains(key) ? .max : n }
        var graph = NetworkGraph()
        var edges: [String: MapEdge] = [:]
        func link(_ from: String, _ to: String, _ weight: Int, _ style: MapEdgeStyle) {
            let id = from + ">" + to
            var e = edges[id] ?? MapEdge(from: from, to: to, weight: 0, style: style)
            e.weight += weight
            if style == .blocked || (style == .new && e.style == .allowed) { e.style = style }
            edges[id] = e
        }
        let here = input.devices.filter { $0.isOn(input.network) }
        let deviceFor: [String: MapDevice] = Dictionary(here.flatMap { d in d.ips.map { ($0, d) } }, uniquingKeysWith: { a, _ in a })
        let gatewayMAC = here.first { $0.ips.contains(input.routes.gateway) }?.mac
        let local = { (ip: String) in NetworkMapPolicy.isYourNetwork(ip, routes: input.routes) }

        // Incoming: devices on this network and addresses elsewhere, at listening programs or closed ports.
        let tries = input.inbound.compactMap { i -> (MapInbound, Int)? in
            guard i.network == nil || input.network.isEmpty || i.network == input.network else { return nil }
            let n = i.count(since: since)
            return n > 0 ? (i, n) : nil
        }
        let reachable = input.listeners.filter { $0.scope != .local }
        var newDevices = 0, refusedFromElsewhere = 0
        if showIn {
            var devices = here.filter { d in d.lastSeen >= since || tries.contains { d.ips.contains($0.0.remote) } }
            // An address on this network that isn't in the neighbour tables (a device gone quiet).
            for (t, _) in tries where local(t.remote) && deviceFor[t.remote] == nil && !devices.contains(where: { $0.ips.contains(t.remote) }) {
                devices.append(MapDevice(mac: "ip:" + t.remote, ips: [t.remote], iface: "", firstSeen: t.firstSeen, lastSeen: t.lastSeen,
                                         blocked: input.blockedAddresses.contains(t.remote)))
            }
            newDevices = devices.filter { NetworkMapPolicy.isNew($0, now: input.now) }.count
            let triesBy = Dictionary(grouping: tries) { deviceFor[$0.0.remote]?.mac ?? ("ip:" + $0.0.remote) }
            func rank(_ d: MapDevice) -> Int {
                (d.blocked == true ? 8 : 0) + (NetworkMapPolicy.isNew(d, now: input.now) ? 4 : 0) + (triesBy[d.mac] != nil ? 2 : 0)
                    + (d.mac == gatewayMAC ? 1 : 0)
            }
            let ranked = devices.sorted { rank($0) != rank($1) ? rank($0) > rank($1)
                : $0.title.localizedStandardCompare($1.title) == .orderedAscending }
            let deviceNodes = ranked.prefix(limit("devices", maxDevices)).map { d in
                let isNew = NetworkMapPolicy.isNew(d, now: input.now)
                return MapNode(id: "dev:" + d.mac, kind: .device, title: d.mac == gatewayMAC && d.yourName.isEmpty ? "Router" : d.title,
                               subtitle: d.ip, dataSubtitle: true,
                               badge: d.blocked == true ? .blocked : d.mine ? .mine : isNew ? .new : nil, ref: d.mac,
                               symbol: d.mac == gatewayMAC ? "wifi.router" : isNew && d.title == "Unknown device" ? "questionmark.circle" : d.symbol)
            }
            graph.columns[0].append(MapSection(key: "devices", title: "Your network", nodes: deviceNodes,
                                               more: max(0, ranked.count - deviceNodes.count), moreNoun: "devices"))
            if input.filter != .yourNetwork {
                let elsewhere = Dictionary(grouping: tries.filter { !local($0.0.remote) }, by: { $0.0.remote })
                    .map { (ip: $0.key, n: $0.value.reduce(0) { $0 + $1.1 }, refused: $0.value.allSatisfy { $0.0.refused >= $0.0.count }) }
                    .sorted { $0.n > $1.n }
                refusedFromElsewhere = elsewhere.filter(\.refused).reduce(0) { $0 + $1.n }
                let nodes = elsewhere.prefix(limit("internet", maxInternet)).map {
                    MapNode(id: "net:" + $0.ip, kind: .internet, title: $0.ip,
                            subtitle: "\($0.refused ? "Refused" : "Reached"), \($0.n) \($0.n == 1 ? "try" : "tries")", count: $0.n,
                            badge: input.blockedAddresses.contains($0.ip) ? .blocked : $0.refused ? .refused : nil, ref: $0.ip)
                }
                graph.columns[0].append(MapSection(key: "internet", title: "From other networks", nodes: nodes,
                                                   more: max(0, elsewhere.count - nodes.count), moreNoun: "addresses"))
            }
            let shownSources = Set(graph.columns[0].flatMap(\.nodes).map(\.id))
            let blockedSources = Set(graph.columns[0].flatMap(\.nodes).filter { $0.badge == .blocked }.map(\.id))
            // This Mac: what listens where someone can reach it, and the closed ports they tried.
            let listenerNodes = reachable.prefix(limit("listeners", maxListeners)).map { l in
                MapNode(id: "lis:\(l.proc)|\(l.port)", kind: .listener, title: l.name, subtitle: ":\(l.port)", dataSubtitle: true,
                        badge: input.blockedPorts.contains(l.port) ? .blocked : l.scope == .all ? .allNetworks : .yourNetwork, ref: l.proc)
            }
            var closed = 0
            for (t, n) in tries {
                let source = deviceFor[t.remote].map { "dev:" + $0.mac } ?? (local(t.remote) ? "dev:ip:" + t.remote : "net:" + t.remote)
                guard shownSources.contains(source) else { continue }
                let target = reachable.first { $0.port == t.port }.map { "lis:\($0.proc)|\($0.port)" }
                let refused = t.refused >= t.count || blockedSources.contains(source) || input.blockedPorts.contains(t.port)
                if let target, listenerNodes.contains(where: { $0.id == target }) {
                    let isNew = deviceFor[t.remote].map { NetworkMapPolicy.isNew($0, now: input.now) } ?? true
                    link(source, target, n, refused ? .blocked : isNew ? .new : .allowed)
                } else {
                    closed += n
                    link(source, "closed", n, .blocked)
                }
            }
            var mac = MapSection(key: "listeners", title: "Listening to the network", nodes: listenerNodes,
                                 more: max(0, reachable.count - listenerNodes.count), moreNoun: "programs")
            if closed > 0 {
                mac.nodes.append(MapNode(id: "closed", kind: .closedPorts, title: "Closed ports", subtitle: "\(closed) refused",
                                         count: closed, badge: .refused))
            }
            graph.columns[1].append(mac)
        }

        // Going out: programs, the way out (the router or a VPN), destinations.
        let out = input.outgoing.filter {
            $0.lastSeen >= since && $0.count > 0 && ($0.network == nil || input.network.isEmpty || $0.network == input.network)
        }
        func wayOut(_ o: MapOutgoing) -> String { "way:" + Self.wayOut(o.ip, routes: input.routes) }
        let byProgram = Dictionary(grouping: out, by: \.path).sorted { a, b in
            a.value.reduce(0) { $0 + $1.count } > b.value.reduce(0) { $0 + $1.count }
        }
        let byDestination = Dictionary(grouping: out, by: \.group)
        if showOut {
            let programs = byProgram.prefix(limit("programs", maxPrograms)).map { path, list in
                let first = list.map(\.firstSeen).min() ?? input.now
                return MapNode(id: "prog:" + path, kind: .program, title: list[0].program, count: list.reduce(0) { $0 + $1.count },
                               badge: input.now.timeIntervalSince(first) < NetworkMapPolicy.newFor ? .new : nil, ref: path)
            }
            graph.columns[1].append(MapSection(key: "programs", title: "Programs going out", nodes: programs,
                                               more: max(0, byProgram.count - programs.count), moreNoun: "programs"))
            // Blocked and new destinations, then each way out's busiest, then the busiest overall.
            let ranked = byDestination.map { group, list in
                (group: group, n: list.reduce(0) { $0 + $1.count }, blocked: list.contains(where: \.blocked), isNew: list.contains(where: \.isNew))
            }.sorted { a, b in
                let ra = (a.blocked ? 2 : 0) + (a.isNew ? 1 : 0), rb = (b.blocked ? 2 : 0) + (b.isNew ? 1 : 0)
                return ra != rb ? ra > rb : a.n > b.n
            }
            var picked: [String] = []
            if input.expanded.contains("destinations") {
                picked = ranked.map(\.group)
            } else {
                for d in ranked where (d.blocked || d.isNew) && picked.count < 3 { picked.append(d.group) }
                for (_, list) in Dictionary(grouping: out, by: wayOut) {
                    let top = Dictionary(grouping: list, by: \.group).map { ($0.key, $0.value.reduce(0) { $0 + $1.count }) }
                        .sorted { $0.1 > $1.1 }.prefix(perWayOut)
                    for (g, _) in top where !picked.contains(g) { picked.append(g) }
                }
                for d in ranked where picked.count < maxDestinations && !picked.contains(d.group) { picked.append(d.group) }
            }
            let shownDest = ranked.filter { picked.contains($0.group) }.sorted { $0.n > $1.n }
            graph.columns[3].append(MapSection(key: "destinations", title: "", nodes: shownDest.map { d in
                // A device on your network is named as on the left: "iPhone", with its address.
                let isLocal = local(d.group)
                let device = isLocal ? deviceFor[d.group] : nil
                let blocked = d.blocked || device?.blocked == true || input.blockedAddresses.contains(d.group)
                return MapNode(id: "dst:" + d.group, kind: .destination,
                               title: isLocal ? (device?.mac == gatewayMAC ? "Router" : device?.title ?? "Device on your network") : d.group,
                               subtitle: isLocal ? d.group : "", dataSubtitle: isLocal, count: d.n,
                               badge: blocked ? .blocked : d.isNew ? .new : nil, ref: d.group, symbol: device?.symbol)
            }, more: max(0, ranked.count - shownDest.count), moreNoun: "destinations"))
            let shownPrograms = Set(programs.map(\.id)), shownDests = Set(shownDest.map { "dst:" + $0.group })
            var ways: [String] = []
            for o in out {
                let way = wayOut(o)
                if !ways.contains(way) { ways.append(way) }
                let style: MapEdgeStyle = o.blocked || input.blockedAddresses.contains(o.ip) || deviceFor[o.ip]?.blocked == true ? .blocked
                    : o.isNew ? .new : .allowed
                if shownPrograms.contains("prog:" + o.path) { link("prog:" + o.path, way, o.count, style) }
                if shownDests.contains("dst:" + o.group) { link(way, "dst:" + o.group, o.count, style) }
            }
            graph.columns[2].append(MapSection(title: "", nodes: ways.map { way in
                let iface = String(way.dropFirst(4))
                let vpn = input.routes.vpns.contains { $0.iface == iface }
                let title = iface == "local" ? "Your network" : iface.isEmpty ? "Internet" : vpn ? "VPN" : input.interfaceName(iface)
                let carries = input.routes.vpns.first { $0.iface == iface }.map { $0.full ? "everything" : "some destinations" } ?? ""
                let subtitle = iface == "local" ? "directly" : vpn ? "\(iface), \(carries)"
                    : iface == input.routes.iface && !input.routes.gateway.isEmpty ? "via Router" : ""
                return MapNode(id: way, kind: .wayOut, title: title, subtitle: subtitle, ref: iface)
            }.sorted { ($0.ref == "local" ? 1 : 0, $0.title) < ($1.ref == "local" ? 1 : 0, $1.title) }))
        }
        graph.edges = edges.values.sorted { $0.id < $1.id }

        // One line that agrees with the map: what it counts, before folding.
        var parts: [String] = []
        if showOut { parts.append("\(byProgram.count) programs went out to \(byDestination.count) destinations.") }
        if showIn {
            let wide = reachable.filter { $0.scope == .all }.count
            if wide > 0 { parts.append("\(wide) \(wide == 1 ? "program listens" : "programs listen") on all networks.") }
            if newDevices > 0 { parts.append("\(newDevices) new \(newDevices == 1 ? "device" : "devices") on your network.") }
            if refusedFromElsewhere > 0 { parts.append("\(refusedFromElsewhere) refused tries from other networks.") }
        }
        graph.summary = parts.isEmpty ? "" : "\(input.range.phrase): " + parts.joined(separator: " ")
        return graph
    }
}
