import Foundation

// The network map as values: devices and incoming tries as the store keeps them, and the pure builder that turns
// them (with the firewall's outgoing connections) into four columns of nodes joined by edges.
// source: docs/adr/0017-network-map.md

/// A device seen next to this Mac, by its hardware address.
struct MapDevice: Codable, Equatable, Identifiable {
    var mac: String
    var ips: [String]
    var iface: String
    var name = ""
    /// The name you gave it.
    var yourName = ""
    var firstSeen: Date
    var lastSeen: Date
    /// You said it is yours: never new again.
    var mine = false
    /// Present when Hostwatch first looked: part of the network as it was, never new.
    var baseline = false
    /// Its maker, from the hardware address (nil for a private one).
    var maker: String?
    /// What it announces itself as (Bonjour): a name and a model ("iPhone", "HP LaserJet M110").
    var announcedName: String?
    var model: String?

    var id: String { mac }
    /// Your name, its own, its network name, its model, its maker's: the first that's known.
    var title: String {
        if !yourName.isEmpty { return yourName }
        if let n = announcedName, !n.isEmpty { return n }
        if !name.isEmpty { return name.split(separator: ".").first.map(String.init) ?? name }
        if let m = model, !m.isEmpty { return m }
        if let m = maker, !m.isEmpty { return "\(m) device" }
        return "Unknown device"
    }
    /// What it is, for its second line: "iPhone · Apple".
    var kind: String { [model ?? "", maker ?? ""].filter { !$0.isEmpty && $0 != title }.joined(separator: " · ") }
    var symbol: String { DeviceModels.symbol(model: model ?? "", maker: maker ?? "") }
    var ip: String { ips.first ?? "" }
}

/// One remote address's tries at one local port, counted by the hour.
struct MapInbound: Codable, Equatable, Identifiable {
    var remote: String
    var port: Int
    var firstSeen: Date
    var lastSeen: Date
    var count = 0
    var refused = 0
    var listener = ""
    /// Hours since 1970 -> tries in that hour.
    var hours: [Int: Int] = [:]

    var id: String { "\(remote)|\(port)" }
    func count(since: Date) -> Int { hours.reduce(0) { $1.key >= MapTime.hour(since) ? $0 + $1.value : $0 } }
}

/// Every outgoing connection of one program to one destination, counted by the hour: the map's own record, since the
/// firewall lists only what it wouldn't simply allow.
struct MapConnection: Codable, Equatable, Identifiable {
    var program: String
    var path: String
    var group: String
    var ip: String
    var firstSeen: Date
    var lastSeen: Date
    var blocked = false
    var hours: [Int: Int] = [:]

    var id: String { path + "|" + group }
    func count(since: Date) -> Int { hours.reduce(0) { $1.key >= MapTime.hour(since) ? $0 + $1.value : $0 } }
}

/// An outgoing connection as the builder needs it, its count within the range.
struct MapOutgoing: Equatable {
    var program: String
    var path: String
    var group: String
    var ip: String
    var count: Int
    var firstSeen: Date
    var lastSeen: Date
    var blocked: Bool
    var isNew: Bool
}

enum MapTime {
    static func hour(_ d: Date) -> Int { Int(d.timeIntervalSince1970 / 3600) }
}

enum MapFilter: String, CaseIterable { case everything, goingOut, comingIn, yourNetwork }

enum MapRange: String, CaseIterable {
    case hour, today, week
    var title: String { self == .hour ? "Last Hour" : self == .today ? "Today" : "Last 7 Days" }
    var phrase: String { self == .hour ? "Last hour" : self == .today ? "Today" : "Last 7 days" }
    func since(_ now: Date) -> Date {
        switch self {
        case .hour: return now.addingTimeInterval(-3600)
        case .today: return Calendar.current.startOfDay(for: now)
        case .week: return now.addingTimeInterval(-7 * 86400)
        }
    }
}

enum MapBadge: Equatable { case new, blocked, refused, allNetworks, yourNetwork, mine }

enum MapNodeKind: Equatable { case device, internet, listener, closedPorts, program, wayOut, destination }

struct MapNode: Identifiable, Equatable {
    var id: String
    var kind: MapNodeKind
    var title: String
    var subtitle = ""
    /// The subtitle is data (an address, a port): monospaced.
    var dataSubtitle = false
    var count: Int?
    var badge: MapBadge?
    /// What it stands for: a hardware address, an address, a program's path, a domain, an interface.
    var ref = ""
    /// Its icon, when the kind alone doesn't say (a device: phone, printer, router).
    var symbol: String?
}

struct MapSection: Equatable {
    var title: String
    var nodes: [MapNode]
    /// How many more there are than shown.
    var more = 0
    var moreNoun = ""
}

enum MapEdgeStyle: Equatable { case allowed, blocked, new }

struct MapEdge: Identifiable, Equatable {
    var from: String
    var to: String
    var weight: Int
    var style: MapEdgeStyle
    var id: String { from + ">" + to }
}

struct NetworkGraph: Equatable {
    /// Reaching this Mac, This Mac, Way out, Destinations.
    var columns: [[MapSection]] = [[], [], [], []]
    var edges: [MapEdge] = []
    var summary = ""
    var isEmpty: Bool { columns.allSatisfy { $0.allSatisfy(\.nodes.isEmpty) } }
}

enum NetworkMapPolicy {
    static let newFor: TimeInterval = 86400
    /// Ten different ports from one address within a minute.
    static let scanPorts = 10
    static let scanWindow: TimeInterval = 60

    static func isNew(_ d: MapDevice, now: Date) -> Bool {
        !d.mine && !d.baseline && now.timeIntervalSince(d.firstSeen) < newFor
    }

    static func isScan(_ tries: [(port: Int, at: Date)], now: Date) -> Bool {
        Set(tries.filter { now.timeIntervalSince($0.at) <= scanWindow }.map(\.port)).count >= scanPorts
    }

    /// Private, link-local and carrier-grade addresses: your network (or a VPN peer), not the internet.
    static func isLocal(_ ip: String) -> Bool {
        if ip.contains(":") {
            let l = ip.lowercased()
            return l.hasPrefix("fe80:") || l.hasPrefix("fc") || l.hasPrefix("fd") || l == "::1"
        }
        guard let v = NetMapParse.ipv4(ip) else { return false }
        let a = v >> 24, b = (v >> 16) & 0xff
        return a == 10 || a == 127 || (a == 172 && (16...31).contains(b)) || (a == 192 && b == 168)
            || (a == 169 && b == 254) || (a == 100 && (64...127).contains(b))
    }
}

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
    }

    static let maxDevices = 6, maxInternet = 4, maxListeners = 4, maxPrograms = 6, maxDestinations = 8

    static func build(_ input: Input) -> NetworkGraph {
        let since = input.range.since(input.now)
        let showIn = input.filter != .goingOut
        let showOut = input.filter == .everything || input.filter == .goingOut
        var graph = NetworkGraph()
        var edges: [String: MapEdge] = [:]
        func link(_ from: String, _ to: String, _ weight: Int, _ style: MapEdgeStyle) {
            let id = from + ">" + to
            var e = edges[id] ?? MapEdge(from: from, to: to, weight: 0, style: style)
            e.weight += weight
            if style == .blocked || (style == .new && e.style == .allowed) { e.style = style }
            edges[id] = e
        }

        // Incoming: devices on your network and addresses on the internet, at listening programs or closed ports.
        let tries = input.inbound.compactMap { i -> (MapInbound, Int)? in
            let n = i.count(since: since)
            return n > 0 ? (i, n) : nil
        }
        let deviceFor: [String: MapDevice] = Dictionary(input.devices.flatMap { d in d.ips.map { ($0, d) } }, uniquingKeysWith: { a, _ in a })
        let reachable = input.listeners.filter { $0.scope != .local }
        var newDevices = 0, refusedFromInternet = 0
        if showIn {
            var devices = input.devices.filter { d in d.lastSeen >= since || tries.contains { d.ips.contains($0.0.remote) } }
            // An address on your network that isn't in the neighbour tables (a VPN peer, a device gone quiet).
            for (t, _) in tries where NetworkMapPolicy.isLocal(t.remote) && deviceFor[t.remote] == nil
                && !devices.contains(where: { $0.ips.contains(t.remote) }) {
                devices.append(MapDevice(mac: "ip:" + t.remote, ips: [t.remote], iface: "", firstSeen: t.firstSeen, lastSeen: t.lastSeen))
            }
            newDevices = devices.filter { NetworkMapPolicy.isNew($0, now: input.now) }.count
            let triesBy = Dictionary(grouping: tries) { deviceFor[$0.0.remote]?.mac ?? ("ip:" + $0.0.remote) }
            let gatewayMAC = input.devices.first { $0.ips.contains(input.routes.gateway) }?.mac
            let ranked = devices.sorted {
                let a = (NetworkMapPolicy.isNew($0, now: input.now), triesBy[$0.mac] != nil, $0.mac == gatewayMAC)
                let b = (NetworkMapPolicy.isNew($1, now: input.now), triesBy[$1.mac] != nil, $1.mac == gatewayMAC)
                if a != b { return (a.0 ? 4 : 0) + (a.1 ? 2 : 0) + (a.2 ? 1 : 0) > (b.0 ? 4 : 0) + (b.1 ? 2 : 0) + (b.2 ? 1 : 0) }
                return $0.title.localizedStandardCompare($1.title) == .orderedAscending
            }
            let deviceNodes = ranked.prefix(maxDevices).map { d in
                MapNode(id: "dev:" + d.mac, kind: .device, title: d.mac == gatewayMAC && d.yourName.isEmpty ? "Router" : d.title,
                        subtitle: d.ip, dataSubtitle: true,
                        badge: d.mine ? .mine : NetworkMapPolicy.isNew(d, now: input.now) ? .new : nil, ref: d.mac,
                        symbol: d.mac == gatewayMAC ? "wifi.router" : NetworkMapPolicy.isNew(d, now: input.now) && d.title == "Unknown device"
                            ? "questionmark.circle" : d.symbol)
            }
            graph.columns[0].append(MapSection(title: "Your network", nodes: deviceNodes, more: max(0, ranked.count - maxDevices),
                                               moreNoun: "devices"))
            if input.filter != .yourNetwork {
                let internet = Dictionary(grouping: tries.filter { !NetworkMapPolicy.isLocal($0.0.remote) }, by: { $0.0.remote })
                    .map { (ip: $0.key, n: $0.value.reduce(0) { $0 + $1.1 }, refused: $0.value.allSatisfy { $0.0.refused >= $0.0.count }) }
                    .sorted { $0.n > $1.n }
                refusedFromInternet = internet.filter(\.refused).reduce(0) { $0 + $1.n }
                graph.columns[0].append(MapSection(title: "From the internet", nodes: internet.prefix(maxInternet).map {
                    MapNode(id: "net:" + $0.ip, kind: .internet, title: $0.ip,
                            subtitle: "\($0.refused ? "Refused" : "Reached"), \($0.n) \($0.n == 1 ? "try" : "tries")",
                            count: $0.n, badge: $0.refused ? .refused : nil, ref: $0.ip)
                }, more: max(0, internet.count - maxInternet), moreNoun: "addresses"))
            }
            let shownSources = Set(graph.columns[0].flatMap(\.nodes).map(\.id))
            // This Mac: what listens where someone can reach it, and the closed ports they tried.
            let listenerNodes = reachable.prefix(maxListeners).map { l in
                MapNode(id: "lis:\(l.proc)|\(l.port)", kind: .listener, title: l.name, subtitle: ":\(l.port)", dataSubtitle: true,
                        badge: l.scope == .all ? .allNetworks : .yourNetwork, ref: l.proc)
            }
            var closed = 0
            for (t, n) in tries {
                let source = deviceFor[t.remote].map { "dev:" + $0.mac }
                    ?? (NetworkMapPolicy.isLocal(t.remote) ? "dev:ip:" + t.remote : "net:" + t.remote)
                guard shownSources.contains(source) else { continue }
                let target = reachable.first { $0.port == t.port }.map { "lis:\($0.proc)|\($0.port)" }
                let refused = t.refused >= t.count
                if let target, listenerNodes.contains(where: { $0.id == target }) {
                    let isNew = deviceFor[t.remote].map { NetworkMapPolicy.isNew($0, now: input.now) } ?? true
                    link(source, target, n, refused ? .blocked : isNew ? .new : .allowed)
                } else {
                    closed += n
                    link(source, "closed", n, .blocked)
                }
            }
            var mac = MapSection(title: "Listening to the network", nodes: listenerNodes, more: max(0, reachable.count - maxListeners),
                                 moreNoun: "programs")
            if closed > 0 {
                mac.nodes.append(MapNode(id: "closed", kind: .closedPorts, title: "Closed ports", subtitle: "\(closed) refused",
                                         count: closed, badge: .refused))
            }
            graph.columns[1].append(mac)
        }

        // Going out: programs, the way out (the router or a VPN), destinations.
        let out = input.outgoing.filter { $0.lastSeen >= since && $0.count > 0 }
        let gatewayMACForOut = input.devices.first { $0.ips.contains(input.routes.gateway) }?.mac
        let byProgram = Dictionary(grouping: out, by: \.path).sorted { a, b in
            a.value.reduce(0) { $0 + $1.count } > b.value.reduce(0) { $0 + $1.count }
        }
        let byDestination = Dictionary(grouping: out, by: \.group)
        if showOut {
            let programs = byProgram.prefix(maxPrograms).map { path, list in
                let first = list.map(\.firstSeen).min() ?? input.now
                return MapNode(id: "prog:" + path, kind: .program, title: list[0].program, count: list.reduce(0) { $0 + $1.count },
                               badge: input.now.timeIntervalSince(first) < NetworkMapPolicy.newFor ? .new : nil, ref: path)
            }
            graph.columns[1].append(MapSection(title: "Programs going out", nodes: programs, more: max(0, byProgram.count - maxPrograms),
                                               moreNoun: "programs"))
            // Blocked and new destinations always make the list, then the busiest.
            let ranked = byDestination.map { group, list in
                (group: group, n: list.reduce(0) { $0 + $1.count }, blocked: list.contains(where: \.blocked), isNew: list.contains(where: \.isNew))
            }.sorted { a, b in
                let ra = (a.blocked ? 2 : 0) + (a.isNew ? 1 : 0), rb = (b.blocked ? 2 : 0) + (b.isNew ? 1 : 0)
                return ra != rb ? ra > rb : a.n > b.n
            }
            let urgent = ranked.filter { $0.blocked || $0.isNew }.prefix(3)
            let busiest = ranked.filter { !($0.blocked || $0.isNew) }.prefix(maxDestinations - urgent.count)
            let shownDest = (Array(busiest) + urgent).sorted { $0.n > $1.n }
            graph.columns[3].append(MapSection(title: "", nodes: shownDest.map { d in
                // A device on your network is named as on the left: "iPhone", with its address.
                let local = NetworkMapPolicy.isLocal(d.group)
                let device = local ? deviceFor[d.group] : nil
                return MapNode(id: "dst:" + d.group, kind: .destination,
                               title: local ? (device?.mac == gatewayMACForOut ? "Router" : device?.title ?? "Device on your network") : d.group,
                               subtitle: local ? d.group : "", dataSubtitle: local, count: d.n,
                               badge: d.blocked ? .blocked : d.isNew ? .new : nil, ref: d.group)
            }, more: max(0, ranked.count - shownDest.count), moreNoun: "destinations"))
            let shownPrograms = Set(programs.map(\.id)), shownDests = Set(shownDest.map { "dst:" + $0.group })
            var ways: [String] = []
            for o in out {
                let iface = NetworkMapPolicy.isLocal(o.ip) ? "local" : input.routes.iface(for: o.ip)
                let way = "way:" + iface
                if !ways.contains(way) { ways.append(way) }
                let style: MapEdgeStyle = o.blocked ? .blocked : o.isNew ? .new : .allowed
                if shownPrograms.contains("prog:" + o.path) { link("prog:" + o.path, way, o.count, style) }
                if shownDests.contains("dst:" + o.group) { link(way, "dst:" + o.group, o.count, style) }
            }
            graph.columns[2].append(MapSection(title: "", nodes: ways.map { way in
                let iface = String(way.dropFirst(4))
                let vpn = input.routes.vpns.contains { $0.iface == iface }
                let title = iface == "local" ? "Your network" : iface.isEmpty ? "Internet" : vpn ? "VPN" : input.interfaceName(iface)
                let subtitle = iface == "local" ? "directly" : vpn ? iface
                    : iface == input.routes.iface && !input.routes.gateway.isEmpty ? "via Router" : ""
                return MapNode(id: way, kind: .wayOut, title: title, subtitle: subtitle, dataSubtitle: vpn, ref: iface)
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
            if refusedFromInternet > 0 { parts.append("\(refusedFromInternet) refused tries from the internet.") }
        }
        graph.summary = parts.isEmpty ? "" : "\(input.range.phrase): " + parts.joined(separator: " ")
        return graph
    }
}
