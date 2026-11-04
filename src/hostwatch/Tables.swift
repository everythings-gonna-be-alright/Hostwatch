import Foundation
import SwiftUI

// Row models for the Events and Patterns tables: each flattens what a column shows into a
// sortable property, so a column header click is just a KeyPathComparator.

struct PatternItem: Identifiable {
    let entry: SignatureEntry
    let status: SignatureStatus
    let statusRank: Int          // dangerous 0 … safe 3
    let source: String?
    let note: String?
    let decidedBy: String
    /// A program's row (grouped by process): its patterns.
    var children: [PatternItem]? = nil
    /// A program's row: the kinds of activity among its patterns, and how many are New.
    var kinds: [EventKind] = []
    var newCount = 0

    var id: String { entry.id }
    var isGroup: Bool { children != nil }
    static let groupPrefix = "group:"

    /// One row per program (by name) with its patterns under it; a program with a single pattern stays a plain row.
    /// The program's row shows the most serious status and risk among its patterns, the total count and the span.
    static func grouped(_ items: [PatternItem], order: [KeyPathComparator<PatternItem>]) -> [PatternItem] {
        let byName = Dictionary(grouping: items) { displayProcessName($0.entry.process) }
        return byName.map { name, list -> PatternItem in
            guard list.count > 1 else { return list[0] }
            let children = list.sorted(using: order)
            let worst = list.min { $0.statusRank != $1.statusRank ? $0.statusRank < $1.statusRank : $0.entry.risk > $1.entry.risk }!
            let new = list.filter { $0.status == .unclassified }.count
            var e = worst.entry
            e.id = groupPrefix + name
            e.pattern = "\(list.count) patterns" + (new > 0 ? " · \(new) New" : "")
            e.count = list.reduce(0) { $0 + $1.entry.count }
            e.firstSeen = list.map(\.entry.firstSeen).min() ?? e.firstSeen
            e.lastSeen = list.map(\.entry.lastSeen).max() ?? e.lastSeen
            e.risk = list.map(\.entry.risk).max() ?? e.risk
            e.note = nil; e.suggestion = nil
            let deciders = Set(list.map(\.decidedBy))
            let kinds = EventKind.allCases.filter { k in list.contains { $0.entry.kind == k } }
            return PatternItem(entry: e, status: worst.status, statusRank: worst.statusRank, source: nil, note: nil,
                               decidedBy: deciders.count == 1 ? deciders.first! : "Mixed", children: children,
                               kinds: kinds, newCount: new)
        }
        .sorted(using: order)
    }
    /// Status, then high-risk first within it.
    var priority: Int { statusRank * 10 + (2 - entry.risk.rawValue) }
    var kind: String { entry.kind.rawValue }
    var processName: String { displayProcessName(entry.process).lowercased() }
    var pattern: String { entry.pattern }
    /// Why: the decision's note, or the AI's reason for its suggestion.
    var reason: String {
        if let note, !note.isEmpty { return note }
        return entry.suggestion?.note ?? ""
    }
    /// Who signed the binary this pattern is about (cached facts only; never touches disk).
    var signer: String { SigningCache.shared.cached(SignatureStore.subjectPath(entry))?.label ?? "" }
    var count: Int { entry.count }
    var firstSeen: Date { entry.firstSeen }
    var lastSeen: Date { entry.lastSeen }

    static let sortColumns: [String: (SortOrder) -> KeyPathComparator<PatternItem>] = [
        "status": { KeyPathComparator(\.priority, order: $0) },
        "kind": { KeyPathComparator(\.kind, order: $0) },
        "process": { KeyPathComparator(\.processName, order: $0) },
        "pattern": { KeyPathComparator(\.pattern, order: $0) },
        "reason": { KeyPathComparator(\.reason, order: $0) },
        "decided": { KeyPathComparator(\.decidedBy, order: $0) },
        "signer": { KeyPathComparator(\.signer, order: $0) },
        "count": { KeyPathComparator(\.count, order: $0) },
        "first": { KeyPathComparator(\.firstSeen, order: $0) },
        "last": { KeyPathComparator(\.lastSeen, order: $0) },
    ]
}

struct EventItem: Identifiable {
    let event: ActivityEvent
    let status: SignatureStatus
    let statusRank: Int

    var id: UUID { event.id }
    var seq: Int { event.seq }             // arrival order: the Time column
    var kind: String { event.kind.rawValue }
    var name: String { event.name.lowercased() }
    var pid: Int { event.pid }
    var ppid: Int { event.ppid }
    var detail: String { event.fullDetail }

    static let sortColumns: [String: (SortOrder) -> KeyPathComparator<EventItem>] = [
        "time": { KeyPathComparator(\.seq, order: $0) },
        "kind": { KeyPathComparator(\.kind, order: $0) },
        "status": { KeyPathComparator(\.statusRank, order: $0) },
        "process": { KeyPathComparator(\.name, order: $0) },
        "pid": { KeyPathComparator(\.pid, order: $0) },
        "ppid": { KeyPathComparator(\.ppid, order: $0) },
        "detail": { KeyPathComparator(\.detail, order: $0) },
    ]
}

/// Remembers a table's primary sort column and direction in UserDefaults ("count:desc").
enum SortMemory {
    static func load<Row>(key: String, columns: [String: (SortOrder) -> KeyPathComparator<Row>],
                          fallback: KeyPathComparator<Row>) -> [KeyPathComparator<Row>] {
        guard let saved = UserDefaults.standard.string(forKey: key) else { return [fallback] }
        let parts = saved.split(separator: ":").map(String.init)
        guard parts.count == 2, let make = columns[parts[0]] else { return [fallback] }
        return [make(parts[1] == "desc" ? .reverse : .forward)]
    }

    static func save<Row>(_ order: [KeyPathComparator<Row>], key: String,
                          columns: [String: (SortOrder) -> KeyPathComparator<Row>]) {
        guard let first = order.first,
              let name = columns.first(where: { $0.value(.forward).keyPath == first.keyPath })?.key else { return }
        UserDefaults.standard.set("\(name):\(first.order == .reverse ? "desc" : "asc")", forKey: key)
    }
}
