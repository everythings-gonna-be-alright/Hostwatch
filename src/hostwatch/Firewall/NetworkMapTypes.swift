import Foundation

// The network map as values: devices, incoming tries and outgoing connections as the store keeps them, the graph
// the builder makes of them, and the policy both use. source: docs/adr/0017-network-map.md

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
    /// The networks it was seen on (by their router), so home and work each show their own devices.
    var networks: [String]?
    /// You blocked it: nothing from it or to it (on the network it is on now).
    var blocked: Bool?

    var id: String { mac }
    func isOn(_ network: String) -> Bool { network.isEmpty || networks == nil || networks!.contains(network) }
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
    /// The network a try from your network came on (addresses repeat between networks). Nil from the internet.
    var network: String?

    var id: String { (network.map { $0 + "|" } ?? "") + "\(remote)|\(port)" }
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
    /// For a device on your network: which network (its address may mean another device elsewhere).
    var network: String?
    /// Its connections' patterns, for blocking the program from the map.
    var keys: [String]?
    /// The last connection's process and target, for the process details (its launch chain needs the pid).
    var pid: Int?
    var ppid: Int?
    var parent: String?
    var target: String?
    var proto: String?
    var host: String?

    var id: String { path + "|" + group + (network.map { "|" + $0 } ?? "") }
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
    var network: String? = nil
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
    /// Which section, for showing all of it ("devices", "destinations").
    var key = ""
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

    /// On the network this Mac is on now, whatever its range (10.x, 172.16.x, 192.168.x, or a company's own), and not
    /// carried by a VPN (a split tunnel's 10.x is somewhere else). Before the first report knows the subnets, a
    /// private address counts.
    static func isYourNetwork(_ ip: String, routes: NetRoutes) -> Bool {
        guard routes.vpnIface(for: ip, specificOnly: true) == nil else { return false }
        if ip.contains(":") { return isLocal(ip) }
        return routes.subnets.isEmpty ? isLocal(ip) : routes.onLink(ip)
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

