import SwiftUI

/// One map section in full ("and 40 more devices"), in place of the map: a back button, the section's title and
/// count, and a table of every item. The window's search filters it, the details panel beside it is the map's.
struct NetworkMapListView: View {
    @ObservedObject var store: NetworkMapStore
    @ObservedObject var state: NetworkMapViewState
    let key: String
    let graph: NetworkGraph
    let search: String
    var actions: NetworkMapActions

    static let titles = ["devices": "Devices on Your Network", "internet": "Addresses From Other Networks",
                         "listeners": "Programs Listening to the Network", "programs": "Programs Going Out",
                         "destinations": "Destinations"]

    var body: some View {
        let rows = stable(graph.columns.joined().first { $0.key == key }?.nodes ?? [])
        // On a glass card like the map it replaces: the header inside, the table's own background off so the glass
        // shows through.
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Button { state.selection = nil; state.allOf = nil } label: { Label("Map", systemImage: "chevron.left") }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .keyboardShortcut(.cancelAction)
                    .help("Back to the map")
                Text((Self.titles[key] ?? "All").uppercased())
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                Text("\(rows.count)").font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                Spacer()
            }
            Table(rows, selection: selection) {
                TableColumn("Name") { n in
                    HStack(spacing: 8) {
                        if let symbol = n.symbol { Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 18) }
                        Text(n.title).font(.system(size: 13, design: n.kind == .internet ? .monospaced : .default))
                            .lineLimit(1).truncationMode(.middle)
                    }
                    .modifier(RowClick { clicked(n.id) })
                }
                if rows.contains(where: { !($0.kind == .program ? $0.ref : $0.subtitle).isEmpty }) {
                    TableColumn("Detail") { n in
                        // A program's line is its path: which binary it is.
                        Text(n.kind == .program ? n.ref : n.subtitle)
                            .font(.system(size: 12, design: n.dataSubtitle || n.kind == .program ? .monospaced : .default))
                            .foregroundStyle(n.kind == .internet && n.badge == .refused ? Color.red : Color.secondary).lineLimit(1)
                            .modifier(RowClick { clicked(n.id) })
                    }
                }
                TableColumn(state.measure == .sent ? "Sent" : "Connections") { n in
                    Text(n.count.map { n.bytes ? ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .file) : $0.formatted() } ?? "")
                        .monospacedDigit().foregroundStyle(.secondary)
                        .modifier(RowClick { clicked(n.id) })
                }
                .width(min: 60, ideal: 90, max: 110)
                // Programs and destinations: where their connections went, with what usually speaks there.
                if key == "programs" || key == "destinations" {
                    TableColumn("Ports") { n in
                        Text(NetworkMapBuilder.portsList(n.ports))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.tail)
                            .help(NetworkMapBuilder.portsList(n.ports))
                            .modifier(RowClick { clicked(n.id) })
                    }
                    .width(min: 90, ideal: 200)
                }
                TableColumn("Status") { n in
                    Group { if let badge = n.badge { MapBadgeView(badge: badge) } }
                        .modifier(RowClick { clicked(n.id) })
                }
                .width(min: 70, ideal: 100, max: 130)
            }
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first, let node = rows.first(where: { $0.id == id }) {
                    NetworkMapMenu(node: node, store: store, actions: actions, select: { state.selection = id },
                                   showProcess: { state.process = $0 }, showDetailsItem: false)
                }
            }
            // Rows straight on the glass: the inset style's alternating backgrounds are opaque and drew black bars.
            .scrollContentBackground(.hidden)
            .tableStyle(.inset)
            .alternatingRowBackgrounds(.disabled)
            .overlay {
                if rows.isEmpty, !search.trimmingCharacters(in: .whitespaces).isEmpty { ContentUnavailableView.search(text: search) }
            }
        }
        .padding(14)
        .protectionGlass(22)
    }

    /// The selection, remembering when it changed: a click on the row already selected (it was before this click)
    /// clears it, as on the map. The table selects on mouse-down, so the first click never undoes itself.
    private var selection: Binding<String?> {
        Binding(get: { state.selection }, set: { new in
            state.selection = new
            state.selectedAt = Date()
        })
    }

    /// A click on a row: the second one on the same row deselects it.
    private func clicked(_ id: String) {
        if state.selection == id, Date().timeIntervalSince(state.selectedAt) > 0.3 { state.selection = nil }
    }

    /// The order the list opened with, kept: a row never moves under the pointer because its count grew. Rows that
    /// appear later go to the end, in the map's order.
    private func stable(_ nodes: [MapNode]) -> [MapNode] {
        if state.listOrder.isEmpty { state.listOrder = nodes.map(\.id) }
        let index = Dictionary(state.listOrder.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let known = nodes.filter { index[$0.id] != nil }.sorted { index[$0.id]! < index[$1.id]! }
        let fresh = nodes.filter { index[$0.id] == nil }
        if !fresh.isEmpty { state.listOrder += fresh.map(\.id) }
        return known + fresh
    }
}

/// A cell that passes a click on to its row (alongside the table's own selection): the whole cell answers, not just
/// its text.
private struct RowClick: ViewModifier {
    let action: () -> Void
    func body(content: Content) -> some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .simultaneousGesture(TapGesture().onEnded(action))
    }
}
