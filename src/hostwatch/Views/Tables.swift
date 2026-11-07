import Foundation
import SwiftUI

// Row models for the Events and Patterns tables: each flattens what a column shows into a
// sortable property, so a column header click is just a KeyPathComparator.

struct PatternItem: Identifiable, @unchecked Sendable {
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

    // Sort keys, worked out once (sorting compares them many times).
    /// Status, then high-risk first within it.
    let priority: Int
    let kind: String
    let processName: String
    /// Why: the decision's note, or the AI's reason for its suggestion.
    let reason: String
    /// Who signed the binary this pattern is about (cached facts only; never touches disk).
    let signer: String

    init(entry: SignatureEntry, status: SignatureStatus, statusRank: Int, source: String?, note: String?, decidedBy: String,
         children: [PatternItem]? = nil, kinds: [EventKind] = [], newCount: Int = 0) {
        self.entry = entry; self.status = status; self.statusRank = statusRank
        self.source = source; self.note = note; self.decidedBy = decidedBy
        self.children = children; self.kinds = kinds; self.newCount = newCount
        priority = statusRank * 10 + (2 - entry.risk.rawValue)
        kind = entry.kind.rawValue
        processName = displayProcessName(entry.process).lowercased()
        if let note, !note.isEmpty { reason = note } else { reason = entry.suggestion?.note ?? "" }
        signer = SigningCache.shared.cached(SignatureStore.subjectPath(entry))?.label ?? ""
    }

    var id: String { entry.id }
    var isGroup: Bool { children != nil }
    var pattern: String { entry.pattern }
    var count: Int { entry.count }
    var firstSeen: Date { entry.firstSeen }
    var lastSeen: Date { entry.lastSeen }
    static let groupPrefix = "group:"

    /// One row per program (by name) with its patterns under it; a program with a single pattern stays a plain row.
    /// The program's row shows the most serious status and risk among its patterns, the total count and the span.
    static func grouped(_ items: [PatternItem], order: [KeyPathComparator<PatternItem>]) -> [PatternItem] {
        // `items` arrive sorted: each program's patterns keep that order.
        var byName: [String: [PatternItem]] = [:]
        for item in items { byName[displayProcessName(item.entry.process), default: []].append(item) }
        let groups = byName.map { name, list -> PatternItem in
            guard list.count > 1 else { return list[0] }
            let children = list
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
        return sorted(groups, by: order)
    }

    /// Sorted by the table's first sort column. Plain comparisons on the values worked out once (a
    /// KeyPathComparator compares text the localized way, many times slower on thousands of rows).
    static func sorted(_ items: [PatternItem], by order: [KeyPathComparator<PatternItem>]) -> [PatternItem] {
        guard let first = order.first else { return items }
        let up = first.order == .forward
        func by<T: Comparable>(_ key: (PatternItem) -> T) -> [PatternItem] {
            items.sorted { a, b in
                let x = key(a), y = key(b)
                if x != y { return up ? x < y : x > y }
                return a.id < b.id                                              // ties: always the same order
            }
        }
        switch first.keyPath {
        case \PatternItem.priority: return by(\.priority)
        case \PatternItem.kind: return by(\.kind)
        case \PatternItem.processName: return by(\.processName)
        case \PatternItem.pattern: return by(\.pattern)
        case \PatternItem.reason: return by(\.reason)
        case \PatternItem.decidedBy: return by(\.decidedBy)
        case \PatternItem.signer: return by(\.signer)
        case \PatternItem.count: return by(\.count)
        case \PatternItem.firstSeen: return by(\.firstSeen)
        case \PatternItem.lastSeen: return by(\.lastSeen)
        default: return items.sorted(using: order)
        }
    }

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

/// The Patterns tab's inputs, copied from the store: rows and counts are worked out from it on any thread.
struct PatternListInput: @unchecked Sendable {
    let entries: [String: SignatureEntry]
    let processRules: [String: SignatureEntry]
    let combined: Set<String>
    let search: String                 // lowercased, trimmed
    let scope: Set<String>?
    let showSeenOnce: Bool
    let filter: SignatureFilter

    /// One pass: the rows (unsorted) and every count. Same rules as the store's status, note and Decided By.
    func compute() -> (items: [PatternItem], counts: PatternCounts) {
        var items: [PatternItem] = []
        var c = PatternCounts()
        items.reserveCapacity(entries.count)
        for e in entries.values {
            let rule = e.status == .unclassified ? processRules[SignatureBuilder.processRuleKey(kind: e.kind, process: e.process)] : nil
            let status = e.status != .unclassified ? e.status : rule?.status ?? .unclassified
            let reviewed = e.status != .unclassified ? (e.source == "you" || e.source == "rule") : rule != nil
            c.byStatus[status, default: 0] += 1
            let oneOff = SignatureStore.isOneOff(e, status: status, reviewed: reviewed, combined: combined.contains(e.id))
            if oneOff && filter.admits(status, risk: e.risk, reviewed: reviewed) { c.oneOffs += 1 }
            guard scope.map({ $0.contains(e.id) }) ?? true,
                  search.isEmpty || e.process.lowercased().contains(search) || e.pattern.lowercased().contains(search)
                    || e.exampleName.lowercased().contains(search),
                  showSeenOnce || !search.isEmpty || scope != nil || !oneOff else { continue }
            if scope != nil || SignatureFilter.unclassified.admits(status, risk: e.risk, reviewed: reviewed) { c.new += 1 }
            if scope != nil || SignatureFilter.important.admits(status, risk: e.risk, reviewed: reviewed) { c.important += 1 }
            guard scope != nil || filter.admits(status, risk: e.risk, reviewed: reviewed) else { continue }
            let note: (String?, String?) = e.status != .unclassified ? (e.source, e.note)
                : (rule.map { "\($0.source ?? "you"), whole process" }, rule?.note)
            items.append(PatternItem(entry: e, status: status, statusRank: SignatureStore.rank(status),
                                     source: note.0, note: note.1, decidedBy: SignatureStore.decidedBy(e, status: status)))
        }
        return (items, c)
    }
}

/// The Patterns tab's counts, from the same pass as its rows.
struct PatternCounts: Equatable, Sendable {
    var new = 0                  // Show ▸ New (same search and scope)
    var important = 0            // Show ▸ Important
    var oneOffs = 0              // Seen Once, for the current Show choice
    var byStatus: [SignatureStatus: Int] = [:]   // every pattern, for the footer tally
}

/// The Patterns table's rows, rebuilt only when something changed and at most a few times a second; the sorting
/// and grouping run off the main thread, so scrolling and clicking never wait for them.
@MainActor
final class PatternListModel: ObservableObject {
    @Published private(set) var rows: [PatternItem] = []
    @Published private(set) var shown = 0
    @Published private(set) var counts = PatternCounts()
    private(set) var built = false
    private var generation = 0
    private var scheduled = false
    private var lastBuild: TimeInterval = -1
    /// At most this often while patterns stream in.
    var interval: TimeInterval = 0.3
    private static let queue = DispatchQueue(label: "hostwatch.patterns.sort", qos: .userInitiated)

    /// Something changed: rebuild soon (at once, unless the last rebuild was just now).
    func request(_ store: SignatureStore, filter: @escaping @MainActor () -> SignatureFilter) {
        guard !scheduled else { return }
        scheduled = true
        let wait = max(0, interval - (ProcessInfo.processInfo.systemUptime - lastBuild))
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self, weak store] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.scheduled = false
                guard let store else { return }
                self.build(store, filter: filter())
            }
        }
    }

    /// Rebuilds in the background from a copy of the store's state (`wait`: here and now, e.g. the first show).
    func build(_ store: SignatureStore, filter: SignatureFilter, wait: Bool = false) {
        lastBuild = ProcessInfo.processInfo.systemUptime
        built = true
        let input = store.patternInput(filter: filter)                       // copies only: the main thread's share
        let order = store.patternOrder, group = store.groupByProcess
        generation += 1
        let g = generation
        let work: @Sendable () -> (rows: [PatternItem], shown: Int, counts: PatternCounts) = {
            let (items, counts) = input.compute()
            let sorted = PatternItem.sorted(items, by: order)
            return (group ? PatternItem.grouped(sorted, order: order) : sorted, items.count, counts)
        }
        if wait {
            let r = work()
            apply(r.rows, shown: r.shown, counts: r.counts)
            return
        }
        Self.queue.async { [weak self] in
            let r = work()
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, g == self.generation else { return }            // a newer rebuild is coming
                    self.apply(r.rows, shown: r.shown, counts: r.counts)
                }
            }
        }
    }

    private func apply(_ rows: [PatternItem], shown: Int, counts: PatternCounts) {
        self.rows = rows
        if self.shown != shown { self.shown = shown }
        if self.counts != counts { self.counts = counts }
    }
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
