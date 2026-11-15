import Foundation

/// The collector's network map report: `{"kind":"netmap",…}` every 10 s.
struct NetMapMessage: Decodable {
    var listeners: [NetListener]
    var neighbors: [NetNeighbor]
    var routes: NetRoutes
    var inbound: [NetInbound]
    /// Bytes per program and address since the last report (nil from a collector before the upload watch).
    var traffic: [NetTraffic]?
}

/// What the network map raises as a story. Only what is rare and worth a look: scans and new devices reaching this
/// Mac from your network, and the router's hardware address changing. source: docs/adr/0017-network-map.md
enum NetworkAlert: Equatable {
    case portScan(remote: String, device: String, ports: Int)
    case newDeviceReached(remote: String, device: String, port: Int)
    case routerChanged(ip: String, old: String, new: String)
    case largeUpload(program: String, path: String, destination: String, bytes: Int64)
    case untrustedTry(remote: String, device: String, port: Int, network: String)
}

/// How many addresses tried to connect since you last looked or cleared: the Network tab's badge. Its own object, so
/// the window redraws when the count changes, not on every 10 s report.
@MainActor
final class IncomingBadge: ObservableObject {
    @Published var count = 0
}

/// Devices next to this Mac (on each network it joins), who tried to reach it, where it connects, and what you
/// blocked, kept sealed (`network-map.json`), with the latest listeners and routes. Owned by AppDelegate, fed by the
/// collector and the event stream.
@MainActor
final class NetworkMapStore: ObservableObject {
    @Published private(set) var devices: [String: MapDevice] = [:]
    @Published private(set) var inbound: [String: MapInbound] = [:]
    @Published private(set) var listeners: [NetListener] = []
    @Published private(set) var routes = NetRoutes()
    @Published private(set) var revision = 0
    /// The network this Mac is on now: its router's hardware address ("" until known).
    @Published private(set) var network = ""
    /// Addresses (other networks' and devices' you blocked by address) and ports you blocked.
    @Published private(set) var blockedAddresses: Set<String> = []
    @Published private(set) var blockedPorts: Set<Int> = []
    /// Every network this Mac joined, by its router: name and trust.
    @Published private(set) var profiles: [String: NetworkProfile] = [:]
    /// The network changed, or its trust did: the app turns the firewall's Ask on or back.
    var onProfile: ((NetworkProfile?) -> Void)?
    let badge = IncomingBadge()
    /// Tries before this were seen (Mark as Seen, or cleared).
    private(set) var seenUntil = Date.distantPast
    var onAlert: ((NetworkAlert) -> Void)?
    /// The full block list changed: the collector gets it (addresses both ways, ports incoming).
    var onBlocks: (([String], [Int]) -> Void)?
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
        var networks: [String]?
        var blockedAddresses: [String]?
        var blockedPorts: [Int]?
        var seenUntil: Date?
        var started: Date?
        var profiles: [NetworkProfile]?
    }

    private let fileURL: URL?
    /// Every outgoing connection, by program and destination. Not published: the 10 s report redraws the map.
    private(set) var outgoing: [String: MapConnection] = [:]
    /// Router address -> hardware address last seen.
    private var routers: [String: String] = [:]
    /// Networks whose first report was learned: what was there then is never new. (`learned`: from before networks.)
    private var learnedNetworks: Set<String> = []
    private var learned = false
    private var recent: [String: [(port: Int, at: Date)]] = [:]
    private var alerted: [String: Date] = [:]
    private var dirty = false
    private var lastSave = Date.distantPast
    private var lastBlocks: ([String], [Int])?
    /// When the map first recorded: its first day is the baseline for uploads.
    private(set) var started = Date()
    private var uploadAlerted: [String: Date] = [:]
    /// Address -> the domain a connection event named for it (TLS name or lookup). Byte counts only know the names
    /// the collector saw in DNS answers, so this names the rest, and the two land on one destination.
    private var groupForIP: [String: String] = [:]

    init(fileURL: URL? = AppPaths.support.appendingPathComponent("network-map.json")) {
        self.fileURL = fileURL
        load()
    }

    // MARK: Reports

    func apply(_ m: NetMapMessage, now: Date = Date()) {
        listeners = m.listeners
        let previous = routes
        routes = m.routes
        let net = Self.networkID(m.neighbors, routes: m.routes)
        // The first report on a network is the network as it was. An install from before networks learned its one.
        let firstLook = !net.isEmpty && !learnedNetworks.contains(net) && !(learned && learnedNetworks.isEmpty)
        if !net.isEmpty, learned, learnedNetworks.isEmpty { learnedNetworks.insert(net) }
        for n in m.neighbors {
            if var d = devices[n.mac] {
                d.ips = n.ips; d.iface = n.iface; d.lastSeen = now
                if !n.name.isEmpty { d.name = n.name }
                if !net.isEmpty, !(d.networks ?? []).contains(net) { d.networks = (d.networks ?? []) + [net] }
                devices[n.mac] = d
            } else {
                devices[n.mac] = MapDevice(mac: n.mac, ips: n.ips, iface: n.iface, name: n.name, firstSeen: now, lastSeen: now,
                                           baseline: firstLook || (net.isEmpty && !learned), networks: net.isEmpty ? nil : [net])
            }
        }
        // An address that moved to another device is that device's now.
        for n in m.neighbors {
            for (mac, d) in devices where mac != n.mac && d.ips.contains(where: n.ips.contains) {
                devices[mac]?.ips.removeAll(where: n.ips.contains)
            }
        }
        for (mac, d) in devices { identify(mac, d) }
        checkRouter(m.neighbors, network: net, previous: previous)
        let moved = network != net
        network = net
        noteProfile(now: now, moved: moved)
        if !net.isEmpty { learnedNetworks.insert(net) }
        if !m.neighbors.isEmpty { learned = true }
        for t in m.traffic ?? [] { noteTraffic(t, now: now) }
        for t in m.inbound { noteTry(t, now: now) }
        for remote in Set(m.inbound.map(\.remote)) where NetworkMapPolicy.isYourNetwork(remote, routes: routes) {
            judge(remote, m.inbound, now: now)
        }
        trim(now: now)
        updateBadge()
        sendBlocks()
        dirty = true
        revision += 1
        if now.timeIntervalSince(lastSave) > 60 { save(); lastSave = now }
    }

    /// A network is known by its router's hardware address (two homes can both use 192.168.1.1), else by the router's
    /// address and interface until its hardware address is seen.
    static func networkID(_ neighbors: [NetNeighbor], routes: NetRoutes) -> String {
        guard !routes.gateway.isEmpty else { return "" }
        return neighbors.first { $0.ips.contains(routes.gateway) }?.mac ?? "gw:\(routes.gateway)@\(routes.iface)"
    }

    /// The current network's profile: made on the first visit (the first network ever is trusted, a later one waits
    /// for you, treated as not trusted), kept up to date, and announced when the Mac moved.
    private func noteProfile(now: Date, moved: Bool) {
        guard !network.isEmpty else { if moved { onProfile?(nil) }; return }
        let router = devices[network]?.maker ?? ""
        let subnet = routes.subnets.first ?? ""
        if var p = profiles[network] {
            p.lastSeen = now
            if p.subnet.isEmpty { p.subnet = subnet }
            if p.router.isEmpty { p.router = router }
            profiles[network] = p
        } else {
            let first = profiles.isEmpty
            profiles[network] = NetworkProfile(id: network, name: NetworkProfile.defaultName(router: router, subnet: subnet),
                                               trusted: first, decided: first, firstSeen: now, lastSeen: now, subnet: subnet, router: router)
        }
        if moved { onProfile?(profiles[network]) }
    }

    var profile: NetworkProfile? { profiles[network] }

    func setTrusted(_ id: String, _ trusted: Bool) {
        profiles[id]?.trusted = trusted
        profiles[id]?.decided = true
        changed()
        if id == network { onProfile?(profiles[id]) }
    }

    func renameNetwork(_ id: String, _ name: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        profiles[id]?.name = n
        changed()
    }

    func setProtections(_ id: String, blockListeners: Bool? = nil, firewallAsks: Bool? = nil) {
        if let blockListeners { profiles[id]?.blockListeners = blockListeners }
        if let firewallAsks { profiles[id]?.firewallAsks = firewallAsks }
        changed()
        if id == network { onProfile?(profiles[id]) }
    }

    func forgetNetwork(_ id: String) {
        guard id != network else { return }
        profiles[id] = nil
        changed()
    }

    /// Not trusted here and asked to: programs listening on all networks refuse other machines.
    private var untrustedPorts: Set<Int> {
        guard let p = profile, !p.trusted, p.blockListeners else { return [] }
        return Set(listeners.filter { $0.scope != .local }.map(\.port))
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

    /// The router's address answering from another hardware address is a story only on the same network: most of the
    /// other devices are the ones known there. Arriving at work (another router, maybe at the same 192.168.1.1) or
    /// back home is not.
    private func checkRouter(_ neighbors: [NetNeighbor], network net: String, previous: NetRoutes) {
        guard !routes.gateway.isEmpty, let mac = neighbors.first(where: { $0.ips.contains(routes.gateway) })?.mac else { return }
        defer { routers[routes.gateway] = mac }
        guard let old = routers[routes.gateway], old != mac, learned, !learnedNetworks.contains(mac) else { return }
        let others = neighbors.filter { $0.mac != mac && $0.mac != old }
        let fromOld = others.filter { devices[$0.mac]?.networks?.contains(old) == true }
        guard fromOld.count >= 2, fromOld.count * 2 >= others.count else { return }
        onAlert?(.routerChanged(ip: routes.gateway, old: old, new: mac))
    }

    private func noteTry(_ t: NetInbound, now: Date) {
        let onNetwork = NetworkMapPolicy.isYourNetwork(t.remote, routes: routes) && !network.isEmpty ? network : nil
        let probe = MapInbound(remote: t.remote, port: t.port, firstSeen: now, lastSeen: now, network: onNetwork)
        var r = inbound[probe.id] ?? probe
        r.count += t.count
        if !t.listening { r.refused += t.count }
        r.lastSeen = now
        if !t.name.isEmpty { r.listener = t.name }
        r.hours[MapTime.hour(now), default: 0] += t.count
        inbound[r.id] = r
        if onNetwork != nil || NetworkMapPolicy.isYourNetwork(t.remote, routes: routes) { recent[t.remote, default: []].append((t.port, now)) }
    }

    /// A report's tries from one address on your network (other networks scan everyone: shown, not raised).
    private func judge(_ remote: String, _ tries: [NetInbound], now: Date) {
        recent[remote]?.removeAll { now.timeIntervalSince($0.at) > NetworkMapPolicy.scanWindow }
        let device = devices.values.first { $0.ips.contains(remote) && $0.isOn(network) }
        let name = device?.title ?? "Unknown device"
        if NetworkMapPolicy.isScan(recent[remote] ?? [], now: now) {
            if mayAlert("scan|" + remote, now: now) {
                onAlert?(.portScan(remote: remote, device: name, ports: Set(recent[remote]!.map(\.port)).count))
            }
        } else if let p = profile, !p.trusted, let tried = tries.first(where: { $0.remote == remote }),
                  mayAlert("untrusted|" + remote, now: now) {
            // On a network you don't trust, anyone trying to reach this Mac is worth a look.
            onAlert?(.untrustedTry(remote: remote, device: name, port: tried.port, network: p.name))
        } else if let device, NetworkMapPolicy.isNew(device, now: now),
                  let reached = tries.first(where: { $0.remote == remote && $0.listening }), mayAlert("new|" + remote, now: now) {
            onAlert?(.newDeviceReached(remote: remote, device: name, port: reached.port))
        }
    }

    /// A connection out (every one the collector reports, allowed or not). This Mac talking to itself isn't drawn.
    func observeOutgoing(_ e: ActivityEvent, blocked: Bool, now: Date = Date()) {
        guard e.kind == .net, let raw = e.remoteHost?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), !raw.isEmpty, raw != "?",
              !raw.hasPrefix("127."), raw != "::1", !raw.lowercased().hasPrefix("fe80:"), raw != "0.0.0.0" else { return }
        // A device on your network by its address (on this network), anything else (a VPN's 10.x included) by domain.
        let onNetwork = NetworkMapPolicy.isYourNetwork(raw, routes: routes)
        let group = onNetwork ? raw : (DomainRegistry.registrable(e.host) ?? (e.host.isEmpty ? groupForIP[raw] ?? raw : e.host.lowercased()))
        if group != raw, groupForIP.count < 50_000 { groupForIP[raw] = group }
        let base = e.name.isEmpty || e.name == "?" ? (e.proc as NSString).lastPathComponent : e.name
        let program = SignatureBuilder.vmGateway(e.proc) ?? (base.isEmpty ? "Unknown program" : base)
        let probe = MapConnection(program: program, path: e.proc, group: group, ip: raw, firstSeen: now, lastSeen: now,
                                  network: onNetwork && !network.isEmpty ? network : nil)
        var c = outgoing[probe.id] ?? probe
        c.ip = raw
        c.lastSeen = now
        c.blocked = blocked
        c.hours[MapTime.hour(now), default: 0] += 1
        c.pid = e.pid; c.ppid = e.ppid; c.parent = e.parent; c.target = e.target; c.proto = e.extra; c.host = e.host
        let key = e.signatureKey
        if !key.isEmpty, !(c.keys ?? []).contains(key), (c.keys?.count ?? 0) < 20 { c.keys = (c.keys ?? []) + [key] }
        outgoing[c.id] = c
        dirty = true
    }

    /// Bytes one program moved to one address, into the connection they belong to (made if the event isn't in yet).
    func noteTraffic(_ t: NetTraffic, now: Date = Date()) {
        guard !t.remote.hasPrefix("127."), t.remote != "::1", t.sent > 0 || t.received > 0 else { return }
        let onNetwork = NetworkMapPolicy.isYourNetwork(t.remote, routes: routes)
        let named = DomainRegistry.registrable(t.host) ?? (t.host.isEmpty ? nil : t.host.lowercased())
        let group = onNetwork ? t.remote : (named ?? groupForIP[t.remote] ?? t.remote)
        if !onNetwork, let named, groupForIP.count < 50_000 { groupForIP[t.remote] = named }
        let path = t.proc.isEmpty ? t.name : t.proc
        let name = t.name.isEmpty ? (path as NSString).lastPathComponent : t.name
        let probe = MapConnection(program: SignatureBuilder.vmGateway(path) ?? name, path: path, group: group, ip: t.remote,
                                  firstSeen: now, lastSeen: now, network: onNetwork && !network.isEmpty ? network : nil)
        var c = outgoing[probe.id] ?? probe
        c.lastSeen = now
        let hour = MapTime.hour(now)
        c.sentHours = (c.sentHours ?? [:]).merging([hour: t.sent], uniquingKeysWith: +)
        c.receivedHours = (c.receivedHours ?? [:]).merging([hour: t.received], uniquingKeysWith: +)
        outgoing[c.id] = c
        let lastHour = c.sent(since: now.addingTimeInterval(-3600))
        if NetworkMapPolicy.isLargeUpload(sentLastHour: lastHour, pairFirstSeen: c.firstSeen, mapStarted: started, now: now,
                                          yourNetwork: onNetwork),
           uploadAlerted[c.id].map({ now.timeIntervalSince($0) > 86400 }) ?? true {
            uploadAlerted[c.id] = now
            onAlert?(.largeUpload(program: c.program, path: c.path, destination: group, bytes: lastHour))
        }
        dirty = true
    }

    /// Outgoing connections within a range, as the builder takes them.
    func outgoingList(_ range: MapRange, now: Date = Date(), isNew: (String) -> Bool = { _ in false }) -> [MapOutgoing] {
        outgoingList(DateInterval(start: range.since(now), end: now.addingTimeInterval(3600)), isNew: isNew)
    }

    /// Outgoing connections within a window (an hour of the day when replaying), with whether each is fresh.
    func outgoingList(_ w: DateInterval, isNew: (String) -> Bool = { _ in false }) -> [MapOutgoing] {
        regroupByName()
        return outgoing.values.compactMap { c in
            let n = MapTime.sum(c.hours, w), sent = MapTime.sum(c.sentHours ?? [:], w), received = MapTime.sum(c.receivedHours ?? [:], w)
            guard n > 0 || sent > 0 || received > 0 else { return nil }
            return MapOutgoing(program: c.program, path: c.path, group: c.group, ip: c.ip, count: n, firstSeen: c.firstSeen,
                               lastSeen: c.lastSeen, blocked: c.blocked,
                               isNew: c.network == nil && !NetworkMapPolicy.isYourNetwork(c.group, routes: routes) && isNew(c.group),
                               network: c.network, sent: sent, received: received, fresh: MapTime.fresh(c.hours, before: w.start))
        }
    }

    /// Byte counts recorded under a bare address before its name was known join the named destination.
    private func regroupByName() {
        let strays = outgoing.values.filter { $0.group == $0.ip && $0.network == nil && groupForIP[$0.ip] != nil }
        for var c in strays {
            outgoing[c.id] = nil
            c.group = groupForIP[c.ip]!
            if var into = outgoing[c.id] {
                into.hours.merge(c.hours, uniquingKeysWith: +)
                into.sentHours = (into.sentHours ?? [:]).merging(c.sentHours ?? [:], uniquingKeysWith: +)
                into.receivedHours = (into.receivedHours ?? [:]).merging(c.receivedHours ?? [:], uniquingKeysWith: +)
                into.firstSeen = min(into.firstSeen, c.firstSeen)
                into.lastSeen = max(into.lastSeen, c.lastSeen)
                outgoing[c.id] = into
            } else {
                outgoing[c.id] = c
            }
            dirty = true
        }
    }

    /// Connections out and tries in, hour by hour: the time travel's activity bars.
    func activity(hours: Int = 24, now: Date = Date()) -> [Int] {
        let last = MapTime.hour(now)
        var out = [Int](repeating: 0, count: hours)
        func add(_ h: [Int: Int]) {
            for (hour, n) in h where hour > last - hours && hour <= last { out[hour - (last - hours + 1)] += n }
        }
        outgoing.values.forEach { add($0.hours) }
        inbound.values.filter { $0.network == nil || network.isEmpty || $0.network == network }.forEach { add($0.hours) }
        return out
    }

    /// A program's latest connection as an event, for the process details panel Events shows.
    func lastEvent(program path: String) -> ActivityEvent? {
        guard let c = outgoing.values.filter({ $0.path == path }).max(by: { $0.lastSeen < $1.lastSeen }) else { return nil }
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return ActivityEvent(kind: .net, time: f.string(from: c.lastSeen), pid: c.pid ?? 0, ppid: c.ppid ?? 0, name: c.program,
                             proc: c.path, target: c.target ?? c.ip, extra: c.proto ?? "TCP", parent: c.parent ?? "",
                             host: c.host ?? "", hostSource: (c.host ?? "").isEmpty ? "" : "dns")
    }

    /// A listening program as an event: its process, waiting on its port.
    func listenerEvent(_ l: NetListener) -> ActivityEvent {
        ActivityEvent(kind: .net, time: "", pid: l.pid, ppid: 0, name: l.name, proc: l.proc, target: "*:\(l.port)", extra: "TCP",
                      parent: "")
    }

    /// The patterns of a program's connections, for blocking or allowing it from the map.
    func patternKeys(program path: String) -> [String] {
        Array(Set(outgoing.values.filter { $0.path == path }.flatMap { $0.keys ?? [] }))
    }

    /// Once an hour per address and kind.
    private func mayAlert(_ key: String, now: Date) -> Bool {
        if let last = alerted[key], now.timeIntervalSince(last) < 3600 { return false }
        alerted[key] = now
        return true
    }

    /// Tries and connections kept 7 days, devices 30 (yours and blocked ones always).
    private func trim(now: Date) {
        let oldest = MapTime.hour(now.addingTimeInterval(-7 * 86400))
        for (k, var r) in inbound where r.hours.keys.contains(where: { $0 < oldest }) {
            r.hours = r.hours.filter { $0.key >= oldest }
            inbound[k] = r.hours.isEmpty ? nil : r
        }
        for (k, var c) in outgoing where c.hours.keys.contains(where: { $0 < oldest })
            || (c.sentHours ?? [:]).keys.contains(where: { $0 < oldest }) {
            c.hours = c.hours.filter { $0.key >= oldest }
            c.sentHours = c.sentHours?.filter { $0.key >= oldest }
            c.receivedHours = c.receivedHours?.filter { $0.key >= oldest }
            outgoing[k] = c.hours.isEmpty && (c.sentHours ?? [:]).isEmpty ? nil : c
        }
        uploadAlerted = uploadAlerted.filter { now.timeIntervalSince($0.value) < 86400 }
        if outgoing.count > 10_000 {
            for k in outgoing.values.sorted(by: { $0.lastSeen < $1.lastSeen }).prefix(outgoing.count - 10_000).map(\.id) { outgoing[k] = nil }
        }
        if inbound.count > 5_000 {
            for k in inbound.values.sorted(by: { $0.lastSeen < $1.lastSeen }).prefix(inbound.count - 5_000).map(\.id) { inbound[k] = nil }
        }
        devices = devices.filter { $0.value.mine || $0.value.blocked == true || now.timeIntervalSince($0.value.lastSeen) < 30 * 86400 }
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

    // MARK: Incoming tries

    /// Addresses that tried since you last looked: on this network, or from anywhere else.
    var unseenSources: Int {
        Set(inbound.values.filter { $0.lastSeen > seenUntil && ($0.network == nil || network.isEmpty || $0.network == network) }
            .map(\.remote)).count
    }

    /// Keeps the tries, clears the badge.
    func markTriesSeen(now: Date = Date()) {
        seenUntil = now
        changed()
    }

    /// Forgets incoming tries: the refused ones only (nothing listened), or all. The badge clears.
    func clearTries(refusedOnly: Bool, now: Date = Date()) {
        inbound = refusedOnly ? inbound.filter { $0.value.refused < $0.value.count } : [:]
        recent = [:]
        seenUntil = now
        changed()
    }

    private func updateBadge() {
        let n = unseenSources
        if badge.count != n { badge.count = n }
    }

    // MARK: Blocks

    /// Why this device can't be blocked, nil when it can: the router carries everything this Mac sends.
    func blockRefusal(device mac: String) -> String? {
        if let d = devices[mac], d.ips.contains(routes.gateway) { return "Blocking the router would cut this Mac off the network." }
        return nil
    }

    /// A device, by its hardware address: whatever address it has on the network it's on now. An address-only one
    /// ("ip:…") is blocked by that address.
    func setBlocked(device mac: String, _ on: Bool) {
        if mac.hasPrefix("ip:") { setBlocked(address: String(mac.dropFirst(3)), on); return }
        guard !on || blockRefusal(device: mac) == nil else { return }
        devices[mac]?.blocked = on ? true : nil
        changed()
    }

    func setBlocked(address: String, _ on: Bool) {
        guard !on || address != routes.gateway else { return }
        if on { blockedAddresses.insert(address) } else { blockedAddresses.remove(address) }
        changed()
    }

    /// Incoming connections to a port, from other machines.
    func setBlocked(port: Int, _ on: Bool) {
        if on { blockedPorts.insert(port) } else { blockedPorts.remove(port) }
        changed()
    }

    func isBlocked(device mac: String) -> Bool {
        mac.hasPrefix("ip:") ? blockedAddresses.contains(String(mac.dropFirst(3))) : devices[mac]?.blocked == true
    }

    /// What the collector blocks now: blocked devices' addresses on this network (an address elsewhere may be
    /// another device), the addresses and the ports.
    var blockList: (addresses: [String], ports: [Int]) {
        let fromDevices = devices.values.filter { $0.blocked == true && $0.isOn(network) }.flatMap(\.ips)
        return (Array(Set(fromDevices).union(blockedAddresses)).sorted(), blockedPorts.union(untrustedPorts).sorted())
    }

    /// Sends the block list when it changed (a blocked device's address can change too).
    func sendBlocks(force: Bool = false) {
        let list = blockList
        if !force, let last = lastBlocks, last.0 == list.addresses, last.1 == list.ports { return }
        lastBlocks = (list.addresses, list.ports)
        onBlocks?(list.addresses, list.ports)
    }

    private func changed() {
        updateBadge()
        revision += 1
        dirty = true
        sendBlocks()
        save()
    }

    // MARK: Map

    func graph(outgoing: [MapOutgoing], filter: MapFilter, range: MapRange, now: Date = Date(), query: String = "",
               expanded: Set<String> = [], room: Int? = nil, measure: MapMeasure = .connections, window: DateInterval? = nil,
               changedOnly: Bool = false, interfaceName: @escaping (String) -> String) -> NetworkGraph {
        NetworkMapBuilder.build(.init(devices: Array(devices.values), inbound: Array(inbound.values), listeners: listeners,
                                      routes: routes, outgoing: outgoing, filter: filter, range: range, now: now,
                                      interfaceName: interfaceName, query: query, network: network, expanded: expanded,
                                      blockedAddresses: blockedAddresses, blockedPorts: blockedPorts, room: room, measure: measure,
                                      window: window, changedOnly: changedOnly))
    }

    func device(forIP ip: String) -> MapDevice? { devices.values.first { $0.ips.contains(ip) && $0.isOn(network) } }

    // MARK: Storage

    private func load() {
        guard let fileURL, let data = Vault.shared.read(fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let s = try? decoder.decode(Saved.self, from: data) else { return }
        devices = Dictionary(s.devices.map { ($0.mac, $0) }, uniquingKeysWith: { a, _ in a })
        inbound = Dictionary(s.inbound.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        outgoing = Dictionary((s.outgoing ?? []).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for c in outgoing.values where c.group != c.ip && c.network == nil { groupForIP[c.ip] = c.group }
        routers = s.routers
        learned = s.learned
        learnedNetworks = Set(s.networks ?? [])
        blockedAddresses = Set(s.blockedAddresses ?? [])
        blockedPorts = Set(s.blockedPorts ?? [])
        seenUntil = s.seenUntil ?? .distantPast
        started = s.started ?? Date()
        profiles = Dictionary((s.profiles ?? []).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        updateBadge()
    }

    func save() {
        guard dirty, let fileURL else { return }
        dirty = false
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let s = Saved(devices: Array(devices.values), inbound: Array(inbound.values), outgoing: Array(outgoing.values),
                      routers: routers, learned: learned, networks: Array(learnedNetworks),
                      blockedAddresses: Array(blockedAddresses), blockedPorts: Array(blockedPorts), seenUntil: seenUntil,
                      started: started, profiles: Array(profiles.values))
        if let data = try? encoder.encode(s) { try? Vault.shared.write(data, to: fileURL) }
    }
}
