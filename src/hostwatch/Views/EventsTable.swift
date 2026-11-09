import AppKit
import Combine
import SwiftUI

/// The Events list as an AppKit outline view: plain cells that AppKit reuses, so a busy Mac's rows cost little.
/// source: docs/adr/0010-appkit-event-list.md
struct EventsTable: NSViewRepresentable {
    var rows: [EventItem]
    /// Changes when `rows` was rebuilt (the window's body runs far more often than the rows change).
    var version: Int
    /// Live: the list follows the feed itself (`derive` gives the rows), so a batch doesn't re-render the window.
    var feed: LiveFeed?
    var derive: (() -> TravelRowsCache.Result)?
    var withDay: Bool
    var grouped: Bool
    @Binding var selection: Set<UUID>
    @Binding var sortOrder: [KeyPathComparator<EventItem>]
    var flag: (ActivityEvent) -> String?
    var badge: (ActivityEvent) -> ProcessVitals.Badge?
    /// The last row came into view (Time Travel loads its next older page).
    var onReachEnd: (() -> Void)?
    var onDoubleClick: (EventItem) -> Void
    /// The right-clicked row, or the whole selection when the click is inside it (events only, groups left out).
    var menu: ([EventItem]) -> NSMenu
    /// Links shown in a group's band ("Only this session", "Patterns").
    var groupLinks: (EventItem) -> [BandLink] = { _ in [] }

    struct Column {
        let id: String
        let title: String
        let width: CGFloat
        let min: CGFloat
        let max: CGFloat
        let keyPath: PartialKeyPath<EventItem>
    }

    static let columns: [Column] = [
        Column(id: "time", title: "Time", width: 108, min: 72, max: 240, keyPath: \EventItem.seq),
        Column(id: "kind", title: "Kind", width: 56, min: 20, max: 120, keyPath: \EventItem.kind),
        Column(id: "status", title: "Status", width: 116, min: 100, max: 240, keyPath: \EventItem.statusRank),
        Column(id: "process", title: "Process", width: 110, min: 60, max: 600, keyPath: \EventItem.name),
        Column(id: "pid", title: "PID", width: 48, min: 38, max: 140, keyPath: \EventItem.pid),
        Column(id: "ppid", title: "PPID", width: 48, min: 38, max: 140, keyPath: \EventItem.ppid),
        Column(id: "parent", title: "Parent", width: 100, min: 50, max: 400, keyPath: \EventItem.parentName),
        Column(id: "detail", title: "Detail", width: 400, min: 120, max: 10_000, keyPath: \EventItem.detail),
    ]

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let outline = OutlineView()
        // The inset look with alternating rows, like the other lists (Running Now, Patterns). Group rows are
        // ordinary rows with their own row view, not AppKit group items (those float and get a gap above).
        outline.style = .inset
        outline.rowSizeStyle = .custom                  // else AppKit picks its own, taller rows
        outline.intercellSpacing = NSSize(width: 3, height: 2)
        outline.usesAlternatingRowBackgroundColors = true
        outline.allowsMultipleSelection = true
        outline.allowsColumnReordering = false
        outline.indentationPerLevel = 12
        outline.floatsGroupRows = true
        for c in Self.columns {
            let column = NSTableColumn(identifier: .init(c.id))
            column.title = c.title
            column.width = c.width
            column.minWidth = c.min
            column.maxWidth = c.max
            column.sortDescriptorPrototype = NSSortDescriptor(key: c.id, ascending: true)
            outline.addTableColumn(column)
        }
        outline.outlineTableColumn = outline.tableColumns.first
        outline.headerView = LegendHeaderView(frame: NSRect(x: 0, y: 0, width: 0, height: 28))
        outline.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle   // Detail takes what's left
        outline.dataSource = context.coordinator
        outline.delegate = context.coordinator
        // Column widths come back from the last run; the sort order it saved with them is the model's to decide.
        context.coordinator.restoring = true
        outline.autosaveName = "EventsTable"
        outline.autosaveTableColumns = true
        context.coordinator.restoring = false
        outline.target = context.coordinator
        outline.doubleAction = #selector(Coordinator.doubleClicked)
        outline.menuProvider = { [weak coordinator = context.coordinator] id in coordinator?.menu(for: id) }

        let scroll = NSScrollView()
        scroll.borderType = .noBorder                   // the bezel drew a line above the header (and left of it)
        scroll.documentView = outline
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.contentView.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(context.coordinator, selector: #selector(Coordinator.scrolled),
                                               name: NSView.boundsDidChangeNotification, object: scroll.contentView)
        context.coordinator.outline = outline
        outline.rowHeight = 24
        context.coordinator.apply(self, reload: true)
        outline.sizeLastColumnToFit()
        return scroll
    }

    func updateNSView(_ view: NSScrollView, context: Context) {
        context.coordinator.apply(self, reload: context.coordinator.version != version)
    }

    /// Row lookups by id; the outline keeps selection and expansion by these ids across reloads.
    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate {
        var parent: EventsTable
        weak var outline: OutlineView?
        var version = -1
        var restoring = false
        /// Groups you folded: every other group opens when it appears, and stays open through each batch.
        private var folded: Set<UUID> = []
        private var expanding = false
        private var withDay: Bool?
        private var order: [UUID] = []                  // top-level ids as shown, for incremental updates
        private var feedWatch: AnyCancellable?
        private weak var feed: LiveFeed?
        private var byID: [UUID: EventItem] = [:]
        private var topLevel: [NSUUID] = []
        private var children: [UUID: [NSUUID]] = [:]
        private var applyingSelection = false
        private var reachedEnd = false

        init(_ parent: EventsTable) { self.parent = parent }

        func apply(_ next: EventsTable, reload: Bool) {
            parent = next
            guard outline != nil else { return }
            if next.feed !== feed {
                feed = next.feed
                feedWatch = next.feed?.objectWillChange.sink { [weak self] _ in
                    DispatchQueue.main.async { self?.followFeed() }       // after the change, not before it
                }
            }
            if reload || withDay != next.withDay {
                withDay = next.withDay
                load(next.rows, version: next.version)
            }
            syncSortIndicator()
            syncSelection(scroll: reload == false)
        }

        /// A batch arrived: the rows come from the same cache the window uses, so the two agree.
        private func followFeed() {
            guard let derive = parent.derive else { return }
            let result = derive()
            if result.version != version { load(result.rows, version: result.version) }
        }

        private func load(_ rows: [EventItem], version: Int) {
            guard let outline else { return }
            self.version = version
            let previous = order
            let hadGroups = !children.isEmpty
            byID.removeAll(keepingCapacity: true)
            topLevel = rows.map { NSUUID(uuidString: $0.id.uuidString)! }
            order = rows.map(\.id)
            children.removeAll(keepingCapacity: true)
            for row in rows {
                byID[row.id] = row
                if let kids = row.children {
                    children[row.id] = kids.map { NSUUID(uuidString: $0.id.uuidString)! }
                    for k in kids { byID[k.id] = k }
                }
            }
            reachedEnd = false
            // A reload keeps the selected row *numbers*: with new rows above, another row (or none) would be selected
            // until the window's next update put it back, so the selection flickered. It goes back by id at once.
            applyingSelection = true
            defer {
                applyingSelection = false
                syncSelection(scroll: false, reveal: false)
            }
            // A batch on a flat list prepends rows and drops some at the end: tell the outline just that, so the
            // rows in between keep their views (a reload makes every visible cell again).
            if !hadGroups, children.isEmpty, let edit = Self.prependAndTrim(from: previous, to: order) {
                outline.beginUpdates()
                if !edit.removed.isEmpty { outline.removeItems(at: edit.removed, inParent: nil, withAnimation: []) }
                if edit.inserted > 0 { outline.insertItems(at: IndexSet(0..<edit.inserted), inParent: nil, withAnimation: []) }
                outline.endUpdates()
                let visible = outline.rows(in: outline.visibleRect)
                if visible.length > 0 {                 // statuses or badges of kept rows may have changed
                    outline.reloadData(forRowIndexes: IndexSet(integersIn: visible.location..<(visible.location + visible.length)),
                                       columnIndexes: IndexSet(integersIn: 0..<outline.numberOfColumns))
                }
            } else {
                outline.reloadData()
            }
            openGroups()
        }

        /// Opens every group you didn't fold (new ones included).
        private func openGroups() {
            guard let outline, !children.isEmpty else { return }
            expanding = true
            defer { expanding = false }
            for id in topLevel where children[id as UUID] != nil && !folded.contains(id as UUID) && !outline.isItemExpanded(id) {
                outline.expandItem(id)
            }
        }

        func outlineViewItemDidCollapse(_ notification: Notification) {
            guard !expanding, let id = notification.userInfo?["NSObject"] as? NSUUID else { return }
            folded.insert(id as UUID)
        }

        func outlineViewItemDidExpand(_ notification: Notification) {
            guard !expanding, let id = notification.userInfo?["NSObject"] as? NSUUID else { return }
            folded.remove(id as UUID)
        }

        /// `new` = some rows, then `old` minus a tail: how many were put in front, and which old positions went.
        nonisolated static func prependAndTrim(from old: [UUID], to new: [UUID]) -> (inserted: Int, removed: IndexSet)? {
            guard let first = old.first, let start = new.firstIndex(of: first), start <= 2000 else { return nil }
            let kept = new.count - start
            guard kept >= 0, kept <= old.count, Array(new[start...]) == Array(old[..<kept]) else { return nil }
            return (start, kept < old.count ? IndexSet(integersIn: kept..<old.count) : IndexSet())
        }

        private func syncSortIndicator() {
            guard let outline, let first = parent.sortOrder.first else { return }
            guard let column = EventsTable.columns.first(where: { $0.keyPath == first.keyPath }) else { return }
            let wanted = NSSortDescriptor(key: column.id, ascending: first.order == .forward)
            if outline.sortDescriptors.first?.key != wanted.key || outline.sortDescriptors.first?.ascending != wanted.ascending {
                applyingSelection = true           // the indicator change must not write the binding back
                outline.sortDescriptors = [wanted]
                applyingSelection = false
            }
        }

        /// The binding's selection into the view, when they differ (a reveal from elsewhere selects a row).
        /// `reveal`: open a folded group to show a selected event in it (a selection made elsewhere). Not after a
        /// batch: a group you folded stays folded.
        private func syncSelection(scroll: Bool, reveal: Bool = true) {
            guard let outline else { return }
            let current = Set(outline.selectedRowIndexes.compactMap { (outline.item(atRow: $0) as? NSUUID).map { $0 as UUID } })
            guard current != parent.selection else { return }
            applyingSelection = true
            defer { applyingSelection = false }
            var indexes = IndexSet()
            for id in parent.selection {
                var row = outline.row(forItem: NSUUID(uuidString: id.uuidString)!)
                if reveal, row < 0, let group = children.first(where: { $0.value.contains(NSUUID(uuidString: id.uuidString)!) })?.key {
                    outline.expandItem(NSUUID(uuidString: group.uuidString)!)
                    row = outline.row(forItem: NSUUID(uuidString: id.uuidString)!)
                }
                if row >= 0 { indexes.insert(row) }
            }
            outline.selectRowIndexes(indexes, byExtendingSelection: false)
            if scroll, let first = indexes.first { outline.scrollRowToVisible(first) }
        }

        private func item(_ any: Any?) -> EventItem? { (any as? NSUUID).flatMap { byID[$0 as UUID] } }

        // MARK: Data source

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            guard let item = item as? NSUUID else { return topLevel.count }
            return children[item as UUID]?.count ?? 0
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            guard let item = item as? NSUUID else { return topLevel[index] }
            return children[item as UUID]![index]
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            (item as? NSUUID).map { children[$0 as UUID] != nil } ?? false
        }

        // Group rows are not AppKit "group items": that style floats them and puts a row-high gap above each.
        // The band is the row view itself (`GroupRowView`), with no cells in the columns.

        func outlineView(_ outlineView: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
            self.item(item)?.isGroup == true ? 32 : 24
        }

        func outlineView(_ outlineView: NSOutlineView, rowViewForItem item: Any) -> NSTableRowView? {
            guard let row = self.item(item) else { return nil }
            if row.isGroup {
                let view = outlineView.makeView(withIdentifier: GroupRowView.identifier, owner: nil) as? GroupRowView
                    ?? { let r = GroupRowView(); r.identifier = GroupRowView.identifier; return r }()
                view.set(row, links: parent.groupLinks(row))
                return view
            }
            return nil                                      // plain rows, like the Patterns list
        }

        func outlineView(_ outlineView: NSOutlineView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard !applyingSelection, !restoring, let d = outlineView.sortDescriptors.first, let key = d.key,
                  let make = EventItem.sortColumns[key] else { return }
            parent.sortOrder = [make(d.ascending ? .forward : .reverse)]
        }

        // MARK: Cells

        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let row = self.item(item), !row.isGroup, tableColumn != nil else { return nil }   // a group is its row view
            let cell = outlineView.makeView(withIdentifier: EventCellView.identifier, owner: nil) as? EventCellView
                ?? { let c = EventCellView(frame: .zero); c.identifier = EventCellView.identifier; return c }()
            configure(cell, row, column: tableColumn!.identifier.rawValue)
            return cell
        }

        private static let mono = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        private static let monoBold = NSFont.monospacedSystemFont(ofSize: 12, weight: .semibold)

        private func configure(_ cell: EventCellView, _ row: EventItem, column: String) {
            let e = row.event, badges = BadgeImages.shared
            switch column {
            case "time":
                cell.set(text: parent.withDay ? e.dayTime : e.shortTime, color: .secondaryLabelColor, font: Self.mono, toolTip: e.time)
            case "kind":
                var icons = [EventCellView.Icon(image: badges.kindTile(e.kind), toolTip: e.kind.title)]
                if let agent = row.agent {
                    icons.append(.init(image: badges.agent(agent, size: 11), toolTip: "In the \(agent.short) session: \(row.session)"))
                }
                cell.set(icons: icons, font: Self.mono)
            case "status":
                var icons: [EventCellView.Icon] = []
                if let bad = parent.flag(e) {
                    icons.append(.init(image: badges.knownBadPill(),
                                       toolTip: "On a threat list: \(bad)\nThe pattern itself is \(row.status.title.lowercased())."))
                } else {
                    icons.append(.init(image: badges.statusPill(row.status)))
                    if case .heavy = parent.badge(e) {
                        icons.append(.init(image: badges.symbol("flame.fill", size: 11), tint: .systemOrange,
                                           toolTip: "Still running and using a lot of CPU or memory"))
                    } else if !e.beacon.isEmpty {
                        icons.append(.init(image: badges.symbol("dot.radiowaves.right", size: 11), tint: .systemRed,
                                           toolTip: "BEACON: connects \(e.beacon)"))
                    } else if e.rawIP {
                        icons.append(.init(image: badges.symbol("number", size: 11), tint: .systemOrange,
                                           toolTip: "RAW IP: public IP on an unusual port with no DNS lookup"))
                    } else if !e.newDomain.isEmpty {
                        icons.append(.init(image: badges.symbol("globe.badge.chevron.backward", size: 11), tint: .systemPurple,
                                           toolTip: "NEW DOMAIN: first contact with \(e.newDomain)"))
                    } else if e.isFirst {
                        icons.append(.init(image: badges.symbol("sparkle", size: 11), tint: .systemYellow,
                                           toolTip: "First time this pattern was ever seen"))
                    }
                }
                cell.set(icons: icons, font: Self.mono)
            case "process":
                cell.set(text: e.name, font: parent.grouped ? Self.mono : Self.monoBold, toolTip: e.proc)
            case "pid":
                cell.set(text: String(e.pid), color: .secondaryLabelColor, font: Self.mono)
            case "ppid":
                cell.set(text: String(e.ppid), color: .secondaryLabelColor, font: Self.mono)
            case "parent":
                cell.set(text: row.parentName.isEmpty ? nil : row.parentName, color: .secondaryLabelColor, font: Self.mono,
                         toolTip: row.parentName.isEmpty ? nil : "Started by \(e.parent) (pid \(e.ppid))")
            default:
                var icons: [EventCellView.Icon] = []
                if let bad = parent.flag(e) { icons.append(.init(image: badges.knownBadTag(bad), toolTip: bad)) }
                if let b = parent.badge(e) { icons.append(.init(image: badges.vital(b))) }
                let text: String
                if e.kind == .file {
                    icons.append(.init(image: badges.fileMode(e.extra), toolTip: FileModeIcon.title(e.extra)))
                    text = e.target
                } else if e.kind == .net, !e.extra.isEmpty {
                    icons.append(.init(image: badges.proto(e.extra)))
                    text = e.fullDetail.dropFirst(e.extra.count).trimmingCharacters(in: .whitespaces)
                } else {
                    text = e.fullDetail
                }
                cell.set(icons: icons, text: text, font: Self.mono, truncation: .byTruncatingMiddle, toolTip: e.target)
            }
        }

        // MARK: Selection, clicks, scrolling

        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard !applyingSelection, let outline else { return }
            let ids = Set(outline.selectedRowIndexes.compactMap { (outline.item(atRow: $0) as? NSUUID).map { $0 as UUID } })
            if ids != parent.selection { parent.selection = ids }
        }

        @objc func doubleClicked() {
            guard let outline, outline.clickedRow >= 0, let row = item(outline.item(atRow: outline.clickedRow)), !row.isGroup else { return }
            parent.onDoubleClick(row)
        }

        func menu(for id: UUID) -> NSMenu? {
            guard let clicked = byID[id] else { return nil }
            // Inside a selection of several: the menu acts on all of them (Mark Safe on one row only was a bug).
            if !clicked.isGroup, parent.selection.count > 1, parent.selection.contains(id) {
                let picked = parent.selection.compactMap { byID[$0] }.filter { !$0.isGroup }.sorted { $0.seq > $1.seq }
                if picked.count > 1 { return parent.menu(picked) }
            }
            return parent.menu([clicked])
        }

        @objc func scrolled() {
            guard let onReachEnd = parent.onReachEnd, !reachedEnd, let outline, outline.numberOfRows > 0 else { return }
            let visible = outline.rows(in: outline.visibleRect)
            if visible.location + visible.length >= outline.numberOfRows {
                reachedEnd = true
                onReachEnd()
            }
        }
    }
}

/// The column legend drawn like SwiftUI's on the Patterns tab: on the table's own ground, bold titles, dim
/// separators between columns only (none before the first), the sort chevron at the sorted column's right.
/// Sorting by click and resizing by drag stay NSTableHeaderView's.
final class LegendHeaderView: NSTableHeaderView {
    private static let font = NSFont.systemFont(ofSize: 11, weight: .bold)

    override func draw(_ dirtyRect: NSRect) {
        guard let table = tableView else { return }
        table.backgroundColor.setFill()
        dirtyRect.fill()
        let sorted = table.sortDescriptors.first
        for (i, column) in table.tableColumns.enumerated() {
            let rect = headerRect(ofColumn: i)
            guard rect.intersects(dirtyRect) else { continue }
            if i > 0 {
                NSColor.separatorColor.setFill()
                NSRect(x: rect.minX, y: rect.minY + 6, width: 1, height: rect.height - 12).fill()
            }
            let title = NSAttributedString(string: column.title, attributes: [.font: Self.font, .foregroundColor: NSColor.labelColor])
            let size = title.size()
            let left = rect.minX + (i == 0 ? 17 : 10)
            var right = rect.maxX - 8
            if let sorted, sorted.key == column.sortDescriptorPrototype?.key,
               let chevron = NSImage(systemSymbolName: sorted.ascending ? "chevron.up" : "chevron.down", accessibilityDescription: nil)?
                .withSymbolConfiguration(.init(pointSize: 9, weight: .semibold)) {
                let tinted = chevron.tinted(.secondaryLabelColor)
                let c = tinted.size
                tinted.draw(in: NSRect(x: rect.maxX - 8 - c.width, y: rect.midY - c.height / 2, width: c.width, height: c.height))
                right -= c.width + 6
            }
            let box = NSRect(x: left, y: rect.midY - size.height / 2, width: max(0, right - left), height: size.height)
            title.draw(with: box, options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine])
        }
    }
}

private extension NSImage {
    /// A template symbol drawn in one colour.
    func tinted(_ color: NSColor) -> NSImage {
        let image = NSImage(size: size, flipped: false) { rect in
            self.draw(in: rect)
            color.set()
            rect.fill(using: .sourceAtop)
            return true
        }
        return image
    }
}

/// An outline view whose context menu comes from the clicked row, and whose zebra stops at the last row.
final class OutlineView: NSOutlineView {
    var menuProvider: ((UUID) -> NSMenu?)?

    /// Alternating rows only where there are rows: the space below the list stays plain.
    override func drawBackground(inClipRect clipRect: NSRect) {
        let used = numberOfRows > 0 ? rect(ofRow: numberOfRows - 1).maxY : 0
        if clipRect.minY >= used {
            backgroundColor.setFill()
            clipRect.fill()
            return
        }
        if clipRect.maxY > used {
            backgroundColor.setFill()
            NSRect(x: clipRect.minX, y: used, width: clipRect.width, height: clipRect.maxY - used).fill()
            super.drawBackground(inClipRect: NSRect(x: clipRect.minX, y: clipRect.minY, width: clipRect.width, height: used - clipRect.minY))
        } else {
            super.drawBackground(inClipRect: clipRect)
        }
    }

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        let r = row(at: point)
        guard r >= 0, let id = item(atRow: r) as? NSUUID else { return nil }
        if !selectedRowIndexes.contains(r) { selectRowIndexes([r], byExtendingSelection: false) }
        return menuProvider?(id as UUID)
    }
}
