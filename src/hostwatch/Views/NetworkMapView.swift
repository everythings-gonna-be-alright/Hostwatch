import AppKit
import SwiftUI

// Network ▸ Map: who reaches this Mac (devices on your network, addresses on the internet), what listens and goes
// out on it, the way out, and where it goes. Lines join them, thicker for more, red dashed when blocked or refused,
// orange when new. Selecting anything dims the rest and opens its details on the right. source: docs/adr/0017-network-map.md

/// The map's filter, range and selection (no @State macro with the command line tools).
@MainActor
final class NetworkMapViewState: ObservableObject {
    @Published var filter = MapFilter(rawValue: UserDefaults.standard.string(forKey: "networkMapFilter") ?? "") ?? .everything {
        didSet { UserDefaults.standard.set(filter.rawValue, forKey: "networkMapFilter"); allOf = nil; mapOrder = [:] }
    }
    @Published var range = MapRange(rawValue: UserDefaults.standard.string(forKey: "networkMapRange") ?? "") ?? .hour {
        didSet { UserDefaults.standard.set(range.rawValue, forKey: "networkMapRange"); mapOrder = [:]; listOrder = [] }
    }
    @Published var selection: String?
    /// The moment Time Travel shows (the window's own Time Travel, on the Network tab), nil for live.
    var travel: DateInterval?
    /// Only what wasn't there in the 7 days before.
    @Published var changedOnly = false { didSet { mapOrder = [:]; listOrder = [] } }

    /// The time the map shows: Time Travel's moment, else the range up to now.
    func window(now: Date = Date()) -> DateInterval {
        travel ?? DateInterval(start: range.since(now), end: now.addingTimeInterval(3600))
    }

    /// "14:00–15:00" or "last hour", for the details panel's sentences.
    var windowPhrase: String {
        guard let travel else { return range.title.lowercased() }
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return "\(f.string(from: travel.start))–\(f.string(from: travel.end))"
    }
    /// Lines, counts and order by connections or by data sent.
    @Published var measure = MapMeasure(rawValue: UserDefaults.standard.string(forKey: "networkMapMeasure") ?? "") ?? .connections {
        didSet { UserDefaults.standard.set(measure.rawValue, forKey: "networkMapMeasure"); mapOrder = [:]; listOrder = [] }
    }
    /// How many rows fit in a column of the map's area (the window's height), for showing more when there's room.
    @Published var room: Int?
    /// The section shown whole as a list in place of the map ("devices", "destinations"), nil for the map.
    @Published var allOf: String? { didSet { if allOf != oldValue { listOrder = [] } } }
    /// Each map section's order when first drawn, the same way: nodes keep their place as counts change.
    var mapOrder: [String: [String]] = [:]

    /// Nodes in the order this section first showed them, newcomers at the end.
    func stable(_ nodes: [MapNode], section: String) -> [MapNode] {
        var order = mapOrder[section] ?? []
        let present = Set(nodes.map(\.id))
        if order.count > 200 { order.removeAll { !present.contains($0) } }
        let index = Dictionary(order.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let known = nodes.filter { index[$0.id] != nil }.sorted { index[$0.id]! < index[$1.id]! }
        let fresh = nodes.filter { index[$0.id] == nil }
        order += fresh.map(\.id)
        mapOrder[section] = order
        return known + fresh
    }

    /// The full list's order when it opened: rows keep their place while counts change, new ones go to the end.
    var listOrder: [String] = []
    /// The process whose details show under the map, as under Events.
    @Published var process: ActivityEvent?
    @Published var renaming = ""
}

/// Where each node is drawn, for the lines between them.
private struct NodeFrames: PreferenceKey {
    static let defaultValue: [String: Anchor<CGRect>] = [:]
    static func reduce(value: inout [String: Anchor<CGRect>], nextValue: () -> [String: Anchor<CGRect>]) {
        value.merge(nextValue()) { $1 }
    }
}

struct NetworkMapView: View {
    @ObservedObject var store: NetworkMapStore
    @ObservedObject var state: NetworkMapViewState
    /// The firewall's outgoing connections (read each time the map is drawn).
    let outgoing: [MapOutgoing]
    var interfaceName: (String) -> String = { $0 }
    var openDetails: (String) -> Void = { _ in }
    var openStories: () -> Void = {}
    /// The window's search field.
    var search = ""
    var actions = NetworkMapActions()
    /// The window's actions and the patterns, for the process details panel.
    var hud: HUDActions?
    var signatures: SignatureStore?

    private static let headers = ["Reaching this Mac", "This Mac", "Way out", "Destinations"]

    var body: some View {
        let _ = store.revision
        // A whole section as a list in place of the map: the same page, the same details panel.
        // Your blocks, red at once: a domain or a program is the firewall's to stop on its next try.
        let blockedPrograms = Set(outgoing.map(\.path)).filter(actions.programBlocked)
        let graph = store.graph(outgoing: outgoing, filter: state.allOf == nil ? state.filter : .everything, range: state.range,
                                query: search, expanded: state.allOf.map { [$0] } ?? [], room: state.room,
                                measure: state.measure, window: state.travel,
                                changedOnly: state.changedOnly, blockedDomains: actions.blockedDomains(),
                                blockedPrograms: blockedPrograms, selected: state.selection, interfaceName: interfaceName)
        VStack(spacing: 0) {
            controls
            Divider()
            if let p = store.profile, !p.decided { newNetworkBanner(p) }
            HStack(alignment: .top, spacing: 16) {
                Group {
                    if let key = state.allOf {
                        NetworkMapListView(store: store, state: state, key: key, graph: graph, search: search, actions: actions)
                    } else if graph.isEmpty, !search.trimmingCharacters(in: .whitespaces).isEmpty {
                        ContentUnavailableView.search(text: search)
                    } else if graph.isEmpty {
                        ContentUnavailableView {
                            Label("Nothing on the Map Yet", systemImage: "point.3.connected.trianglepath.dotted")
                        } description: {
                            Text("The map fills in as programs connect and devices answer on your network. "
                                 + "It updates every 10 seconds.")
                        }
                    } else {
                        ScrollView { map(graph).padding(.vertical, 12) }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .onGeometryChange(for: Int.self) { max(1, Int(($0.size.height - 70) / 48)) } action: { rows in
                    if state.room != rows { state.room = rows }
                }
                NetworkMapInspector(store: store, state: state, graph: graph, outgoing: outgoing, openDetails: openDetails,
                                    openStories: openStories, interfaceName: interfaceName, actions: actions,
                                    showProcess: hud == nil ? nil : { state.process = $0 })
                    .frame(width: 300)
                    .padding(.vertical, 12)
            }
            .padding(.horizontal, 16)
            if let event = state.process, let hud, let signatures {
                Divider()
                EventDetailPanel(event: event, signatures: signatures, actions: hud) { state.process = nil }
                    .frame(maxHeight: 280)
            }
            Divider()
            footer(graph)
        }
    }

    // MARK: Controls

    /// How many items the map holds with each Show choice (what the buttons count).
    private var counts: (all: Int, new: Int) {
        func items(_ changed: Bool) -> Int {
            store.graph(outgoing: outgoing, filter: state.filter, range: state.range, query: search, window: state.travel,
                        changedOnly: changed, interfaceName: interfaceName)
                .columns.enumerated().filter { $0.offset != 2 }.flatMap(\.element)
                .reduce(0) { $0 + $1.nodes.filter { $0.kind != .closedPorts }.count + $1.more }
        }
        return (items(false), items(true))
    }

    private var controls: some View {
        HStack(spacing: 12) {
            IconSegments(selection: $state.filter, items: [
                .init(value: .everything, title: "Everything", symbol: "circle.grid.cross"),
                .init(value: .goingOut, title: "Going Out", symbol: "arrow.up.right"),
                .init(value: .comingIn, title: "Coming In", symbol: "arrow.down.left"),
                .init(value: .yourNetwork, title: "Your Network", symbol: "house"),
            ])
            IconSegments(selection: $state.measure, items: [
                .init(value: .connections, title: "Connections", symbol: "arrow.left.arrow.right",
                      help: "Lines and counts by how many connections"),
                .init(value: .sent, title: "Data Sent", symbol: "arrow.up.circle", help: "Lines and counts by how much was sent"),
            ])
            Divider().frame(height: 16)
            Text("Show").font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).fixedSize()
            ShowButtons(selection: $state.changedOnly, items: [
                .init(value: false, title: "All", symbol: "square.stack", help: "Everything in this time", count: counts.all),
                .init(value: true, title: "New", symbol: "sparkles",
                      help: "Only connections, devices and tries that weren't there in the 7 days before", count: counts.new),
            ])
            Spacer()
            triesMenu
            if let travel = state.travel {
                Label(state.windowPhrase, systemImage: "clock.arrow.circlepath")
                    .foregroundStyle(.tint)
                    .help("Time Travel: the map as it was around \(travel.end.formatted(date: .abbreviated, time: .shortened))")
            } else {
                Picker("Range", selection: $state.range) {
                    ForEach(MapRange.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .help("How far back the map looks")
            }
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    /// A network Hostwatch hasn't seen before: treated as not trusted until you say.
    private func newNetworkBanner(_ p: NetworkProfile) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "wifi.exclamationmark").foregroundStyle(.orange).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("A new network: \(p.name)").font(.system(size: 13, weight: .semibold))
                Text("Hostwatch treats it as not trusted until you decide: other machines are kept away from this Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Keep Not Trusted") { store.setTrusted(p.id, false) }.buttonStyle(.glass)
            Button("Trust It") { store.setTrusted(p.id, true) }.buttonStyle(.glassProminent)
        }
        .controlSize(.small)
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Color.orange.opacity(0.08))
        .accessibilityElement(children: .contain)
    }

    /// Who tried to reach this Mac: Mark as Seen (the badge), or clear the refused tries or all of them.
    @ViewBuilder private var triesMenu: some View {
        let unseen = store.badge.count
        if !store.inbound.isEmpty {
            Menu {
                Button("Mark as Seen") { store.markTriesSeen() }.disabled(unseen == 0)
                Divider()
                Button("Clear Refused Tries") { store.clearTries(refusedOnly: true) }
                Button("Clear All Incoming Tries") { store.clearTries(refusedOnly: false) }
            } label: {
                Label(unseen > 0 ? "\(unseen) Tried to Connect" : "Incoming Tries",
                      systemImage: unseen > 0 ? "exclamationmark.circle" : "arrow.down.left.circle")
            }
            .menuStyle(.button)
            .buttonStyle(.glass)
            .tint(unseen > 0 ? .orange : nil)
            .fixedSize()
            .help(unseen > 0 ? "\(unseen) addresses tried to connect to this Mac since you last looked" : "Clear the tries the map remembers")
        }
    }

    private func footer(_ graph: NetworkGraph) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 18) { legend; Spacer(minLength: 12); Text(graph.summary).lineLimit(1) }
            HStack(spacing: 18) { legend; Spacer(minLength: 0) }
        }
        .font(.system(size: 11))
        .foregroundStyle(.secondary)
        .monospacedDigit()
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .help(graph.summary)
    }

    private var legend: some View {
        HStack(spacing: 14) {
            LegendLine(style: .allowed, title: "Allowed")
            LegendLine(style: .blocked, title: "Blocked or refused")
            LegendLine(style: .new, title: "New in the last day")
            LegendLine(style: .allowed, title: state.measure == .sent ? "More data sent" : "More connections", width: 4)
        }
        .fixedSize()
    }

    // MARK: Map

    private func map(_ graph: NetworkGraph) -> some View {
        let shown = graph.columns.indices.filter { !graph.columns[$0].isEmpty }
        // The selection's whole flow when the builder knows it (a destination lights its programs), else its neighbours.
        let related = graph.related ?? state.selection.map { id in
            Set(graph.edges.filter { $0.from == id || $0.to == id }.flatMap { [$0.from, $0.to] } + [id])
        }
        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 56) {
                ForEach(shown, id: \.self) { c in
                    Text(Self.headers[c].uppercased())
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            HStack(alignment: .center, spacing: 56) {
                ForEach(shown, id: \.self) { c in
                    column(graph.columns[c], index: c, related: related)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .backgroundPreferenceValue(NodeFrames.self) { anchors in
            GeometryReader { proxy in
                Canvas { context, _ in
                    for edge in graph.edges {
                        guard let a = anchors[edge.from], let b = anchors[edge.to] else { continue }
                        let from = proxy[a], to = proxy[b]
                        let start = CGPoint(x: from.maxX, y: from.midY), end = CGPoint(x: to.minX, y: to.midY)
                        var path = Path()
                        path.move(to: start)
                        let mid = (start.x + end.x) / 2
                        path.addCurve(to: end, control1: CGPoint(x: mid, y: start.y), control2: CGPoint(x: mid, y: end.y))
                        let dim = related.map { !($0.contains(edge.from) && $0.contains(edge.to)) } ?? false
                        // Bytes from 100 KB up, connections from one: both reach the widest line at about the same mass.
                        let scaled = state.measure == .sent ? Double(edge.weight) / 100_000 : Double(edge.weight)
                        let width = min(5, 1 + log2(max(1, scaled)) / 2)
                        context.stroke(path, with: .color(LegendLine.color(edge.style).opacity(dim ? 0.15 : edge.style == .allowed ? 0.55 : 0.9)),
                                       style: StrokeStyle(lineWidth: width, lineCap: .round,
                                                          dash: edge.style == .blocked ? [4, 3] : []))
                    }
                }
            }
            .accessibilityHidden(true)
        }
        .padding(.trailing, 4)
    }

    private func column(_ sections: [MapSection], index: Int, related: Set<String>?) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(sections.enumerated()), id: \.offset) { _, section in
                if !section.nodes.isEmpty || section.more > 0 {
                    if section.key == "devices", let p = store.profile {
                        // Your network by its name and trust: "Home · Trusted".
                        HStack(spacing: 6) {
                            Text(p.name).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            MapBadgeView(badge: p.trusted ? .trusted : .untrusted)
                        }
                        .padding(.top, 4)
                    } else if !section.title.isEmpty {
                        Text(section.title).font(.caption).foregroundStyle(.secondary).padding(.top, 4)
                    }
                    ForEach(state.stable(section.nodes, section: section.key.isEmpty ? "\(index)|\(section.title)" : section.key)) { node in
                        MapNodeView(node: node, selected: state.selection == node.id,
                                    dimmed: related.map { !$0.contains(node.id) } ?? false) {
                            state.selection = state.selection == node.id ? nil : node.id
                        }
                        .contextMenu {
                            NetworkMapMenu(node: node, store: store, actions: actions, select: { state.selection = node.id },
                                           showProcess: hud == nil ? nil : { state.process = $0 })
                        }
                        .anchorPreference(key: NodeFrames.self, value: .bounds) { [node.id: $0] }
                    }
                    if section.more > 0 {
                        Button { state.selection = nil; state.allOf = section.key } label: {
                            HStack(spacing: 3) {
                                Text("and \(section.more) more \(section.moreNoun)")
                                Image(systemName: "chevron.right").font(.system(size: 8, weight: .semibold))
                            }
                            .font(.caption).foregroundStyle(.secondary)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .disabled(section.key.isEmpty)
                        .help("All \(section.moreNoun), in a list")
                        .accessibilityLabel("Show all \(section.moreNoun)")
                    }
                }
            }
        }
        .padding(index == 1 ? 8 : 0)
        .background {
            if index == 1 {
                RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.primary.opacity(0.04))
            }
        }
    }
}

// MARK: - Pieces

struct LegendLine: View {
    let style: MapEdgeStyle
    let title: String
    var width: CGFloat = 2

    static func color(_ style: MapEdgeStyle) -> Color {
        switch style {
        case .allowed: return .secondary
        case .blocked: return .red
        case .new: return .orange
        }
    }

    var body: some View {
        HStack(spacing: 5) {
            Canvas { context, size in
                var p = Path()
                p.move(to: CGPoint(x: 0, y: size.height / 2))
                p.addLine(to: CGPoint(x: size.width, y: size.height / 2))
                context.stroke(p, with: .color(Self.color(style)), style: StrokeStyle(lineWidth: width, dash: style == .blocked ? [4, 3] : []))
            }
            .frame(width: 24, height: 8)
            .accessibilityHidden(true)
            Text(title)
        }
    }
}

struct MapBadgeView: View {
    let badge: MapBadge

    var body: some View {
        let (text, color): (String, Color) = {
            switch badge {
            case .new: return ("New", .orange)
            case .blocked: return ("Blocked", .red)
            case .refused: return ("Refused", .red)
            case .allNetworks: return ("All networks", .orange)
            case .yourNetwork: return ("Your network", .secondary)
            case .mine: return ("Yours", .secondary)
            case .trusted: return ("Trusted", .green)
            case .untrusted: return ("Not trusted", .orange)
            }
        }()
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.14)))
            .lineLimit(1).fixedSize()
    }
}

struct MapNodeView: View {
    let node: MapNode
    let selected: Bool
    let dimmed: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let symbol {
                    Image(systemName: symbol)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(blocked ? Color.red : node.badge == .new ? Color.orange : Color.secondary)
                        .frame(width: 18)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(node.title)
                        .font(.system(size: 13, weight: selected ? .semibold : .medium,
                                      design: node.kind == .internet ? .monospaced : .default))
                        .lineLimit(1).truncationMode(.middle)
                    if !node.subtitle.isEmpty {
                        Text(node.subtitle)
                            .font(.system(size: 11, design: node.dataSubtitle ? .monospaced : .default))
                            .foregroundStyle(node.kind == .internet && node.badge == .refused ? Color.red : Color.secondary)
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 4)
                if let badge = node.badge, node.kind != .internet { MapBadgeView(badge: badge) }
                else if let count = node.count, node.kind == .program || node.kind == .destination {
                    Text(node.bytes ? ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file) : count.formatted())
                        .font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
            }
            .padding(.horizontal, 10)
            .frame(minHeight: node.kind == .listener || node.kind == .program || node.kind == .closedPorts ? 32 : 40)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(blocked ? Color.red.opacity(0.08) : Color(nsColor: .controlBackgroundColor)))
            .overlay {
                // Blocked: a red outline (the selection's own outline wins while selected).
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(selected ? Color.primary : blocked ? Color.red.opacity(0.7) : Color.primary.opacity(0.1),
                                  lineWidth: selected ? 2 : blocked ? 1.5 : 0.5)
            }
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .opacity(dimmed ? 0.45 : 1)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .help(node.title + (node.subtitle.isEmpty ? "" : ", " + node.subtitle))
    }

    private var blocked: Bool { node.badge == .blocked }

    private var symbol: String? {
        switch node.kind {
        case .device: return node.symbol ?? "desktopcomputer"
        case .internet: return "globe"
        case .listener: return "antenna.radiowaves.left.and.right"
        case .closedPorts: return "xmark.circle"
        case .program: return nil
        case .wayOut:
            if node.ref == "local" { return "house" }
            return node.title == "VPN" ? "lock.shield" : node.title.localizedCaseInsensitiveContains("wi-fi") ? "wifi" : "cable.connector"
        case .destination: return nil
        }
    }
}
