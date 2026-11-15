import Foundation

/// The collector's network map report: `{"kind":"netmap",…}` every 10 s.
struct NetMapMessage: Decodable {
    var listeners: [NetListener]
    var neighbors: [NetNeighbor]
    var routes: NetRoutes
    var inbound: [NetInbound]
}

/// What the network map raises as a story. Only what is rare and worth a look: scans and new devices reaching this
/// Mac from your network, and the router's hardware address changing. source: docs/adr/0017-network-map.md
enum NetworkAlert: Equatable {
    case portScan(remote: String, device: String, ports: Int)
    case newDeviceReached(remote: String, device: String, port: Int)
    case routerChanged(ip: String, old: String, new: String)
}

/// Devices next to this Mac and who tried to reach it, kept sealed (`network-map.json`), with the latest listeners
/// and routes. Owned by AppDelegate, fed by the collector.
@MainActor
final class NetworkMapStore: ObservableObject {
    @Published private(set) var devices: [String: MapDevice] = [:]
    @Published private(set) var inbound: [String: MapInbound] = [:]
    @Published private(set) var listeners: [NetListener] = []
    @Published private(set) var routes = NetRoutes()
    @Published private(set) var revision = 0
    var onAlert: ((NetworkAlert) -> Void)?
    /// A hardware address's maker (the shipped IEEE table; tests give their own).
    var makerFor: (String) -> String? = { MakerTable.shared.maker(for: $0) }
    /// What devices announce about themselves, by address (Bonjour).
    var announced: (String) -> AnnouncedDevice? = { _ in nil }

    private struct Saved: Codable {
        var devices: [MapDevice]
        var inbound: [MapInbound]
        var outgoing: [MapConnection]?
        var routers: [String: String]
        var learned: Bool
    }

    private let fileURL: URL?
    /// Every outgoing connection, by program and destination. Not published: the 10 s report redraws the map.
    private(set) var outgoing: [String: MapConnection] = [:]
    /// Router address -> hardware address last seen.
    private var routers: [String: String] = [:]
    /// The first report teaches the network as it is: nothing in it is new.
    private var learned = false
    private var recent: [String: [(port: Int, at: Date)]] = [:]
    private var alerted: [String: Date] = [:]
    private var dirty = false
    private var lastSave = Date.distantPast

    init(fileURL: URL? = AppPaths.support.appendingPathComponent("network-map.json")) {
        self.fileURL = fileURL
        load()
    }

    // MARK: Reports

    func apply(_ m: NetMapMessage, now: Date = Date()) {
        listeners = m.listeners
        routes = m.routes
        for n in m.neighbors {
            if var d = devices[n.mac] {
                d.ips = n.ips; d.iface = n.iface; d.lastSeen = now
                if !n.name.isEmpty { d.name = n.name }
                devices[n.mac] = d
            } else {
                devices[n.mac] = MapDevice(mac: n.mac, ips: n.ips, iface: n.iface, name: n.name, firstSeen: now, lastSeen: now,
                                           baseline: !learned)
            }
        }
        // An address that moved to another device is that device's now.
        for n in m.neighbors {
            for (mac, d) in devices where mac != n.mac && d.ips.contains(where: n.ips.contains) {
                devices[mac]?.ips.removeAll(where: n.ips.contains)
            }
        }
        for (mac, d) in devices { identify(mac, d) }
        checkRouter(m.neighbors, now: now)
        for t in m.inbound { noteTry(t, now: now) }
        for remote in Set(m.inbound.map(\.remote)) where NetworkMapPolicy.isLocal(remote) { judge(remote, m.inbound, now: now) }
        if !m.neighbors.isEmpty { learned = true }
        trim(now: now)
        dirty = true
        revision += 1
        if now.timeIntervalSince(lastSave) > 60 { save(); lastSave = now }
    }

    /// Its maker from the hardware address, its name and model from what it announces.
    private func identify(_ mac: String, _ d: MapDevice) {
        var d = d
        if d.maker == nil, !mac.hasPrefix("ip:") { d.maker = makerFor(mac) }
        if let a = d.ips.lazy.compactMap(announced).first {
            if !a.name.isEmpty { d.announcedName = a.name }
            if !a.model.isEmpty { d.model = a.model }
        }
        if d != devices[mac] { devices[mac] = d }
    }

    /// Bonjour heard more: names and models are filled in at once.
    func announcementsChanged() {
        for (mac, d) in devices { identify(mac, d) }
        revision += 1
        dirty = true
    }

    private func checkRouter(_ neighbors: [NetNeighbor], now: Date) {
        guard !routes.gateway.isEmpty, let mac = neighbors.first(where: { $0.ips.contains(routes.gateway) })?.mac else { return }
        if let old = routers[routes.gateway], old != mac, learned { onAlert?(.routerChanged(ip: routes.gateway, old: old, new: mac)) }
        routers[routes.gateway] = mac
    }

    private func noteTry(_ t: NetInbound, now: Date) {
        let key = "\(t.remote)|\(t.port)"
        var r = inbound[key] ?? MapInbound(remote: t.remote, port: t.port, firstSeen: now, lastSeen: now)
        r.count += t.count
        if !t.listening { r.refused += t.count }
        r.lastSeen = now
        if !t.name.isEmpty { r.listener = t.name }
        r.hours[MapTime.hour(now), default: 0] += t.count
        inbound[key] = r
        if NetworkMapPolicy.isLocal(t.remote) { recent[t.remote, default: []].append((t.port, now)) }
    }

    /// A report's tries from one address on your network (the internet scans everyone: shown, not raised).
    private func judge(_ remote: String, _ tries: [NetInbound], now: Date) {
        recent[remote]?.removeAll { now.timeIntervalSince($0.at) > NetworkMapPolicy.scanWindow }
        let device = devices.values.first { $0.ips.contains(remote) }
        let name = device?.title ?? "Unknown device"
        if NetworkMapPolicy.isScan(recent[remote] ?? [], now: now) {
            if mayAlert("scan|" + remote, now: now) {
                onAlert?(.portScan(remote: remote, device: name, ports: Set(recent[remote]!.map(\.port)).count))
            }
        } else if let device, NetworkMapPolicy.isNew(device, now: now),
                  let reached = tries.first(where: { $0.remote == remote && $0.listening }), mayAlert("new|" + remote, now: now) {
            onAlert?(.newDeviceReached(remote: remote, device: name, port: reached.port))
        }
    }

    /// A connection out (every one the collector reports, allowed or not). This Mac talking to itself isn't drawn.
    func observeOutgoing(_ e: ActivityEvent, blocked: Bool, now: Date = Date()) {
        guard e.kind == .net, let raw = e.remoteHost?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), !raw.isEmpty, raw != "?",
              !raw.hasPrefix("127."), raw != "::1", !raw.lowercased().hasPrefix("fe80:"), raw != "0.0.0.0" else { return }
        // A device on your network by its address, anything else (a VPN's 10.x included) by its domain.
        let group = NetworkMapPolicy.isYourNetwork(raw, routes: routes) ? raw
            : (DomainRegistry.registrable(e.host) ?? (e.host.isEmpty ? raw : e.host.lowercased()))
        let base = e.name.isEmpty || e.name == "?" ? (e.proc as NSString).lastPathComponent : e.name
        let program = SignatureBuilder.vmGateway(e.proc) ?? (base.isEmpty ? "Unknown program" : base)
        let key = e.proc + "|" + group
        var c = outgoing[key] ?? MapConnection(program: program, path: e.proc, group: group, ip: raw, firstSeen: now, lastSeen: now)
        c.ip = raw
        c.lastSeen = now
        c.blocked = blocked
        c.hours[MapTime.hour(now), default: 0] += 1
        outgoing[key] = c
        dirty = true
    }

    /// Outgoing connections within a range, as the builder takes them.
    func outgoingList(_ range: MapRange, now: Date = Date(), isNew: (String) -> Bool = { _ in false }) -> [MapOutgoing] {
        let since = range.since(now)
        return outgoing.values.compactMap { c in
            let n = c.count(since: since)
            guard n > 0 else { return nil }
            return MapOutgoing(program: c.program, path: c.path, group: c.group, ip: c.ip, count: n, firstSeen: c.firstSeen,
                               lastSeen: c.lastSeen, blocked: c.blocked,
                               isNew: !NetworkMapPolicy.isYourNetwork(c.group, routes: routes) && isNew(c.group))
        }
    }

    /// Once an hour per address and kind.
    private func mayAlert(_ key: String, now: Date) -> Bool {
        if let last = alerted[key], now.timeIntervalSince(last) < 3600 { return false }
        alerted[key] = now
        return true
    }

    /// Tries kept 7 days, devices 30 (yours always).
    private func trim(now: Date) {
        let oldest = MapTime.hour(now.addingTimeInterval(-7 * 86400))
        for (k, var r) in inbound {
            r.hours = r.hours.filter { $0.key >= oldest }
            inbound[k] = r.hours.isEmpty ? nil : r
        }
        for (k, var c) in outgoing where c.hours.keys.contains(where: { $0 < oldest }) {
            c.hours = c.hours.filter { $0.key >= oldest }
            outgoing[k] = c.hours.isEmpty ? nil : c
        }
        if outgoing.count > 10_000 {
            for k in outgoing.values.sorted(by: { $0.lastSeen < $1.lastSeen }).prefix(outgoing.count - 10_000).map(\.id) { outgoing[k] = nil }
        }
        if inbound.count > 5_000 {
            for k in inbound.values.sorted(by: { $0.lastSeen < $1.lastSeen }).prefix(inbound.count - 5_000).map(\.id) { inbound[k] = nil }
        }
        devices = devices.filter { $0.value.mine || now.timeIntervalSince($0.value.lastSeen) < 30 * 86400 }
        alerted = alerted.filter { now.timeIntervalSince($0.value) < 3600 }
        recent = recent.filter { $0.value.contains { now.timeIntervalSince($0.at) <= NetworkMapPolicy.scanWindow } }
    }

    // MARK: Your decisions

    func markMine(_ mac: String, _ mine: Bool = true) {
        devices[mac]?.mine = mine
        changed()
    }

    func rename(_ mac: String, _ name: String) {
        devices[mac]?.yourName = name.trimmingCharacters(in: .whitespaces)
        changed()
    }

    /// Forgets a device and the tries from its addresses. It comes back, new, if it is seen again.
    func forget(_ mac: String) {
        let ips = devices[mac]?.ips ?? [String(mac.dropFirst(3))]
        devices[mac] = nil
        inbound = inbound.filter { !ips.contains($0.value.remote) }
        changed()
    }

    func forgetTries(from remote: String) {
        inbound = inbound.filter { $0.value.remote != remote }
        changed()
    }

    private func changed() {
        revision += 1
        dirty = true
        save()
    }

    // MARK: Map

    func graph(outgoing: [MapOutgoing], filter: MapFilter, range: MapRange, now: Date = Date(), query: String = "",
               interfaceName: @escaping (String) -> String) -> NetworkGraph {
        NetworkMapBuilder.build(.init(devices: Array(devices.values), inbound: Array(inbound.values), listeners: listeners,
                                      routes: routes, outgoing: outgoing, filter: filter, range: range, now: now,
                                      interfaceName: interfaceName, query: query))
    }

    func device(forIP ip: String) -> MapDevice? { devices.values.first { $0.ips.contains(ip) } }

    // MARK: Storage

    private func load() {
        guard let fileURL, let data = Vault.shared.read(fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let s = try? decoder.decode(Saved.self, from: data) else { return }
        devices = Dictionary(s.devices.map { ($0.mac, $0) }, uniquingKeysWith: { a, _ in a })
        inbound = Dictionary(s.inbound.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        outgoing = Dictionary((s.outgoing ?? []).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        routers = s.routers
        learned = s.learned
    }

    func save() {
        guard dirty, let fileURL else { return }
        dirty = false
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let s = Saved(devices: Array(devices.values), inbound: Array(inbound.values), outgoing: Array(outgoing.values),
                      routers: routers, learned: learned)
        if let data = try? encoder.encode(s) { try? Vault.shared.write(data, to: fileURL) }
    }
}
