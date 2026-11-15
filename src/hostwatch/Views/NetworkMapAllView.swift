import SwiftUI

/// Every item of one map section ("and 40 more devices"), in a list made for many: a search field, a table, and the
/// selected item's details beside it, with the map's right-click menu.
struct NetworkMapAllView: View {
    @ObservedObject var store: NetworkMapStore
    @ObservedObject var state: NetworkMapViewState
    let key: String
    let outgoing: [MapOutgoing]
    var interfaceName: (String) -> String
    var openDetails: (String) -> Void
    var openStories: () -> Void
    var actions: NetworkMapActions
    @Environment(\.dismiss) private var dismiss

    private static let titles = ["devices": "Devices on Your Network", "internet": "Addresses From Other Networks",
                                 "listeners": "Programs Listening to the Network", "programs": "Programs Going Out",
                                 "destinations": "Destinations"]

    var body: some View {
        let _ = store.revision
        let graph = store.graph(outgoing: outgoing, filter: .everything, range: state.range, expanded: [key], interfaceName: interfaceName)
        let all = graph.columns.joined().first { $0.key == key }?.nodes ?? []
        let q = state.allSearch.trimmingCharacters(in: .whitespaces).lowercased()
        let rows = q.isEmpty ? all : all.filter { ($0.title + " " + $0.subtitle + " " + $0.ref).lowercased().contains(q) }
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Self.titles[key] ?? "All").font(.headline)
                    Text("\(all.count) in \(state.range.title.lowercased())").font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer()
                TextField("Search", text: $state.allSearch)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                    .accessibilityLabel("Search this list")
                Button("Done") { dismiss() }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
            }
            .padding(16)
            Divider()
            HStack(alignment: .top, spacing: 16) {
                Table(rows, selection: $state.selection) {
                    TableColumn("Name") { n in
                        HStack(spacing: 8) {
                            if let symbol = n.symbol { Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 18) }
                            Text(n.title).lineLimit(1).truncationMode(.middle)
                        }
                    }
                    TableColumn("Detail") { n in
                        Text(n.subtitle).font(.system(size: 12, design: n.dataSubtitle ? .monospaced : .default))
                            .foregroundStyle(.secondary).lineLimit(1)
                    }
                    TableColumn("Count") { n in
                        Text(n.count.map { $0.formatted() } ?? "").monospacedDigit().foregroundStyle(.secondary)
                    }
                    .width(min: 50, ideal: 70, max: 90)
                    TableColumn("Status") { n in
                        if let badge = n.badge { MapBadgeView(badge: badge) }
                    }
                    .width(min: 70, ideal: 100, max: 130)
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, let node = all.first(where: { $0.id == id }) {
                        NetworkMapMenu(node: node, store: store, actions: actions, select: { state.selection = id })
                    }
                }
                .overlay {
                    if rows.isEmpty { ContentUnavailableView.search(text: state.allSearch) }
                }
                NetworkMapInspector(store: store, state: state, graph: graph, outgoing: outgoing, openDetails: openDetails,
                                    openStories: openStories)
                    .frame(width: 300)
            }
            .padding(16)
        }
        .frame(minWidth: 860, idealWidth: 960, minHeight: 520, idealHeight: 640)
    }
}
