import AppKit
import SwiftUI

// Network ▸ Map: who reaches this Mac (devices on your network, addresses on the internet), what listens and goes
// out on it, the way out, and where it goes. Lines join them, thicker for more, red dashed when blocked or refused,
// orange when new. Selecting anything dims the rest and opens its details on the right. source: docs/adr/0017-network-map.md

/// The map's filter, range and selection (no @State macro with the command line tools).
@MainActor
final class NetworkMapViewState: ObservableObject {
    @Published var filter = MapFilter(rawValue: UserDefaults.standard.string(forKey: "networkMapFilter") ?? "") ?? .everything {
        didSet { UserDefaults.standard.set(filter.rawValue, forKey: "networkMapFilter") }
    }
    @Published var range = MapRange(rawValue: UserDefaults.standard.string(forKey: "networkMapRange") ?? "") ?? .hour {
        didSet { UserDefaults.standard.set(range.rawValue, forKey: "networkMapRange") }
    }
    @Published var selection: String?
    /// The section shown whole in its own sheet ("devices", "destinations"), nil when none.
    @Published var allOf: String?
    @Published var allSearch = ""
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

    private static let headers = ["Reaching this Mac", "This Mac", "Way out", "Destinations"]

    var body: some View {
        let _ = store.revision
        let graph = store.graph(outgoing: outgoing, filter: state.filter, range: state.range, query: search, interfaceName: interfaceName)
        VStack(spacing: 0) {
            controls
            Divider()
            HStack(alignment: .top, spacing: 16) {
                Group {
                    if graph.isEmpty, !search.trimmingCharacters(in: .whitespaces).isEmpty {
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
                NetworkMapInspector(store: store, state: state, graph: graph, outgoing: outgoing, openDetails: openDetails,
                                    openStories: openStories)
                    .frame(width: 300)
                    .padding(.vertical, 12)
            }
            .padding(.horizontal, 16)
            Divider()
            footer(graph)
        }
        .sheet(isPresented: Binding(get: { state.allOf != nil }, set: { if !$0 { state.allOf = nil } })) {
            if let key = state.allOf {
                NetworkMapAllView(store: store, state: state, key: key, outgoing: outgoing, interfaceName: interfaceName,
                                  openDetails: openDetails, openStories: openStories, actions: actions)
            }
        }
    }

    // MARK: Controls

    private var controls: some View {
        HStack(spacing: 12) {
            IconSegments(selection: $state.filter, items: [
                .init(value: .everything, title: "Everything", symbol: "circle.grid.cross"),
                .init(value: .goingOut, title: "Going Out", symbol: "arrow.up.right"),
                .init(value: .comingIn, title: "Coming In", symbol: "arrow.down.left"),
                .init(value: .yourNetwork, title: "Your Network", symbol: "house"),
            ])
            Spacer()
            Picker("Range", selection: $state.range) {
                ForEach(MapRange.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .fixedSize()
            .help("How far back the map looks")
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
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
            LegendLine(style: .allowed, title: "More connections", width: 4)
        }
        .fixedSize()
    }

    // MARK: Map

    private func map(_ graph: NetworkGraph) -> some View {
        let shown = graph.columns.indices.filter { !graph.columns[$0].isEmpty }
        let related = state.selection.map { id in Set(graph.edges.filter { $0.from == id || $0.to == id }.flatMap { [$0.from, $0.to] } + [id]) }
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
                        let width = min(5, 1 + log2(Double(max(1, edge.weight))) / 2)
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
                    if !section.title.isEmpty {
                        Text(section.title).font(.caption).foregroundStyle(.secondary).padding(.top, 4)
                    }
                    ForEach(section.nodes) { node in
                        MapNodeView(node: node, selected: state.selection == node.id,
                                    dimmed: related.map { !$0.contains(node.id) } ?? false) {
                            state.selection = state.selection == node.id ? nil : node.id
                        }
                        .contextMenu { NetworkMapMenu(node: node, store: store, actions: actions, select: { state.selection = node.id }) }
                        .anchorPreference(key: NodeFrames.self, value: .bounds) { [node.id: $0] }
                    }
                    if section.more > 0 {
                        Button { state.allSearch = ""; state.allOf = section.key } label: {
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
                        .foregroundStyle(node.badge == .new ? Color.orange : Color.secondary)
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
                    Text(count, format: .number).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
            }
            .padding(.horizontal, 10)
            .frame(minHeight: node.kind == .listener || node.kind == .program || node.kind == .closedPorts ? 32 : 40)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color(nsColor: .controlBackgroundColor)))
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(selected ? Color.primary : Color.primary.opacity(0.1), lineWidth: selected ? 2 : 0.5)
            }
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .opacity(dimmed ? 0.45 : 1)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .help(node.title + (node.subtitle.isEmpty ? "" : ", " + node.subtitle))
    }

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
