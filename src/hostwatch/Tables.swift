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

    var id: String { entry.id }
    /// Status, then high-risk first within it.
    var priority: Int { statusRank * 10 + (2 - entry.risk.rawValue) }
    var kind: String { entry.kind.rawValue }
    var processName: String { displayProcessName(entry.process).lowercased() }
    var pattern: String { entry.pattern }
    var reason: String {
        if let note, !note.isEmpty { return "\(source ?? "note"): \(note)" }
        return source.map { "marked by \($0)" } ?? ""
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
