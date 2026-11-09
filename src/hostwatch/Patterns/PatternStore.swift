import AppKit
import Combine
import Foundation

// MARK: - Store

@MainActor
final class SignatureStore: ObservableObject {
    /// Bumped (throttled) when entries change; views re-read through accessors.
    @Published private(set) var revision = 0
    @Published var selection = Set<String>()
    @Published var search = ""
    /// Exactly these patterns (from the baseline review), shown as a removable chip in Patterns.
    struct Scope: Equatable { var title: String; var keys: Set<String> }
    @Published var scope: Scope?
    /// Patterns table sort (click a column header); remembered across launches.
    @Published var patternOrder: [KeyPathComparator<PatternItem>] {
        didSet { SortMemory.save(patternOrder, key: "patternTableSort", columns: PatternItem.sortColumns) }
    }

    private(set) var entries: [String: SignatureEntry] = [:]
    /// Whole-process rules: key = processRuleKey, value = status/source/note.
    private(set) var processRules: [String: SignatureEntry] = [:]

    private let fileURL: URL
    private var dirty = false
    /// Only counters, last-seen times, examples and newly learned patterns changed: saved every 5 minutes, not every
    /// 10 s. Every event marks this, and rewriting the whole store (10 MB with ~20,000 patterns) every 10 s wrote
    /// ~1 MB/s to disk and made the app's memory jump while encoding it.
    private var statsDirty = false
    nonisolated static let statsSaveEvery = 300
    private var pendingRevision = false
    private var timer: Timer?
    private let maxEntries = 50_000

    /// `directory`: where signatures-v2.json lives (tests use a temporary folder).
    init(directory: URL = AppPaths.support) {
        patternOrder = SortMemory.load(key: "patternTableSort", columns: PatternItem.sortColumns,
                                       fallback: KeyPathComparator(\.priority))
        let dir = directory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // v2: zone-based patterns with risk; the old per-folder format is not migrated.
        fileURL = dir.appendingPathComponent("signatures-v2.json")
        load()
        PatternMerges.shared.set(merges)                 // this store's combined patterns (none for a new one)
        dropInterpreterTrust()
        regroup()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    // MARK: Learned rules

    /// Active rules you approved (Rules tab). Authority: you > your rules > Claude/on-device > auto.
    private(set) var learnedRules: [LearnedRule] = []
    /// Called after you mark something, so rules can re-check themselves against your decisions.
    var onDecisionsChanged: (() -> Void)?
    /// You decided these patterns (Safe, Suspicious or Dangerous): the firewall stops asking again about them.
    var onYouDecided: (([String]) -> Void)?

    var allEntries: [SignatureEntry] { Array(entries.values) }
    var entriesByKey: [String: SignatureEntry] { entries }

    /// Sources a rule may override (never you or the baseline you trusted).
    private static let ruleOverridable: Set<String?> = [nil, "auto", "claude", "on-device", "rule"]

    /// Re-applies rules everywhere: patterns a removed or paused rule had classified go back to their
    /// own state first, then each eligible pattern takes the first matching active rule.
    func applyRules(_ rules: [LearnedRule]) {
        learnedRules = rules.filter(\.isActive)
        for (key, var e) in entries where Self.ruleOverridable.contains(e.source) {
            if e.source == "rule" {
                let routine = e.risk == .routine
                e.status = routine ? .safe : .unclassified
                e.source = routine ? "auto" : nil
                e.note = nil
            }
            applyRule(to: &e)
            entries[key] = e
        }
        changedNow()
    }

    private func applyRule(to e: inout SignatureEntry) {
        guard e.reopened == nil, Self.ruleOverridable.contains(e.source),
              let rule = learnedRules.first(where: { $0.matches(e) }) else { return }
        e.status = rule.action
        e.source = "rule"
        e.note = rule.name
    }

    // MARK: Observing events

    /// Records an event; returns true when this is the first time a non-routine pattern is seen.
    @discardableResult
    func observe(_ e: ActivityEvent) -> Bool {
        let now = Date()
        if var entry = entries[e.signatureKey] {
            // Risk only goes up: a swapped or tampered binary must reach patterns already
            // auto-marked Safe.
            if e.signatureRisk > entry.risk { raise(&entry, to: e.signatureRisk, reason: e.signatureReason) }
            entry.count += 1
            entry.lastSeen = now
            entry.examplePid = e.pid
            entry.exampleTarget = e.target
            if !e.host.isEmpty { entry.exampleHost = e.host; entry.exampleHostSource = e.hostSource }
            entries[e.signatureKey] = entry
            changedKeys.insert(e.signatureKey)
            markDirty()
            return false
        }
        // Routine patterns (system daemons reading system files, scratch writes…) are decided locally,
        // so "New" only holds things worth a look.
        let routine = e.signatureRisk == .routine
        entries[e.signatureKey] = SignatureEntry(
            id: e.signatureKey, kind: e.kind, process: e.signatureProcess, pattern: e.signaturePattern,
            count: 1, risk: e.signatureRisk, firstSeen: now, lastSeen: now,
            status: routine ? .safe : .unclassified, source: routine ? "auto" : nil,
            note: routine ? e.signatureReason : (e.signatureReason.isEmpty ? nil : "⚠︎ " + e.signatureReason),
            exampleName: e.name, examplePid: e.pid, exampleProc: e.proc, exampleTarget: e.target,
            exampleExtra: e.extra, exampleParent: e.parent,
            exampleHost: e.host.isEmpty ? nil : e.host, exampleHostSource: e.host.isEmpty ? nil : e.hostSource)
        if !learnedRules.isEmpty, var created = entries[e.signatureKey] {
            applyRule(to: &created)
            entries[e.signatureKey] = created
        }
        if entries.count > maxEntries { evict() }
        changedKeys.insert(e.signatureKey)
        markDirty()
        return !routine
    }

    private func raise(_ entry: inout SignatureEntry, to risk: PatternRisk, reason: String) {
        entry.risk = risk
        if entry.status == .safe, entry.source == "auto", risk != .routine {
            entry.status = .unclassified
            entry.source = nil
            entry.note = reason.isEmpty ? nil : "⚠︎ " + reason
        } else if entry.status == .safe, risk == .high {
            // Decided Safe (by anyone, you included) and now high-risk: a swapped or quarantined binary, code
            // from a download… back to you.
            reopen(&entry, "now high-risk" + (reason.isEmpty ? "" : ": " + reason))
        }
        dirty = true                                  // a raised risk (maybe a reopened decision) is saved soon
        pendingRevision = true
    }

    private func reopen(_ e: inout SignatureEntry, _ reason: String) {
        e.status = .unclassified
        e.source = nil
        e.suggestion = nil
        e.reopened = reason
        e.note = "Reopened: " + reason
    }

    /// Sends decided-Safe patterns back to you, with why (a story, a known-bad match, an untrusted binary).
    /// Returns how many were reopened.
    @discardableResult
    func reopen(keys: [String], reason: String) -> Int {
        var n = 0
        for key in keys {
            let k = resolve(key)
            guard var e = entries[k], e.status == .safe else { continue }
            reopen(&e, reason)
            entries[k] = e
            n += 1
        }
        if n > 0 { changedNow() }
        return n
    }

    /// Every decided-Safe pattern of a program (what runs for a launch, what acts otherwise).
    func safeKeys(program path: String) -> [String] {
        entries.values.filter { $0.status == .safe && Self.subjectPath($0) == path }.map(\.id)
    }

    /// Re-scores patterns after signing facts or trusted developers change. Auto-Safe patterns
    /// that are no longer routine become New; New patterns that became routine are auto-Safe.
    func reassess(where matches: (SignatureEntry) -> Bool = { _ in true }) {
        for (key, var e) in entries where matches(e) {
            // Built-in safe, by the stored pattern itself (the stored example has no command line).
            if e.status == .unclassified, e.source == nil, e.reopened == nil, e.risk != .high,
               let why = BuiltInSafe.reason(kind: e.kind, parent: e.kind == .exec ? e.exampleParent : e.exampleProc, pattern: e.pattern) {
                e.risk = .routine; e.status = .safe; e.source = "auto"; e.note = why
                entries[key] = e
                continue
            }
            // A binary that's gone (an updated app's old version, a deleted installer) can't be judged again.
            let subject = Self.subjectPath(e)
            guard subject.hasPrefix("/"), FileManager.default.fileExists(atPath: subject) else { continue }
            let sig = SignatureBuilder.signature(for: e.exampleEvent)
            // The stored example lacks the command line and may predate today's pattern rules: when it no
            // longer rebuilds this exact pattern, its risk says nothing about this entry, so leave it alone.
            guard sig.key == key else { continue }
            if sig.risk == e.risk { continue }
            if sig.risk > e.risk {
                raise(&e, to: sig.risk, reason: sig.reason)
            } else {
                e.risk = sig.risk
                if sig.risk == .routine, e.status == .unclassified {
                    e.status = .safe; e.source = "auto"; e.note = sig.reason
                }
            }
            entries[key] = e
        }
        changedNow()
    }

    /// The binary a pattern is about: what runs (exec) or what acts (file/net).
    nonisolated static func subjectPath(_ e: SignatureEntry) -> String { e.kind == .exec ? e.exampleTarget : e.exampleProc }

    /// Pattern status, falling back to a whole-process rule.
    /// A pattern combined into a shared one answers for it (rows already on screen keep their status).
    func resolve(_ key: String) -> String { entries[key] == nil ? aliases[key] ?? key : key }

    func status(forKey key: String) -> SignatureStatus {
        let key = resolve(key)
        if let entry = entries[key], entry.status != .unclassified { return entry.status }
        if let entry = entries[key] {
            return processRules[SignatureBuilder.processRuleKey(kind: entry.kind, process: entry.process)]?.status ?? .unclassified
        }
        return .unclassified
    }

    func status(for e: ActivityEvent) -> SignatureStatus {
        if let s = entries[resolve(e.signatureKey)]?.status, s != .unclassified { return s }
        return processRules[SignatureBuilder.processRuleKey(kind: e.kind, process: e.signatureProcess)]?.status ?? .unclassified
    }

    func entry(_ key: String) -> SignatureEntry? { entries[resolve(key)] }

    /// Safe because *you* said so (pattern or whole-process rule). Claude/baseline/auto verdicts
    /// judge one pattern alone, which is exactly what stories look past.
    func markedSafeByYou(_ e: ActivityEvent) -> Bool {
        if let entry = entries[resolve(e.signatureKey)], entry.status != .unclassified {
            // A rule you approved counts as your decision.
            return entry.status == .safe && (entry.source == "you" || entry.source == "rule")
        }
        return processRules[SignatureBuilder.processRuleKey(kind: e.kind, process: e.signatureProcess)]?.status == .safe
    }

    func note(forKey key: String) -> (source: String?, note: String?) {
        guard let e = entries[resolve(key)] else { return (nil, nil) }
        if e.status != .unclassified { return (e.source, e.note) }
        let rule = processRules[SignatureBuilder.processRuleKey(kind: e.kind, process: e.process)]
        return (rule.map { "\($0.source ?? "you"), whole process" }, rule?.note)
    }

    // MARK: Classifying

    func set(_ status: SignatureStatus, keys: [String], source: String = "you", note: String? = nil) {
        for key in keys {
            guard var e = entries[key] else { continue }
            e.status = status
            e.source = status == .unclassified ? nil : source
            if status != .unclassified { e.reopened = nil }      // decided again
            if let note { e.note = note } else if status == .unclassified { e.note = nil }
            if status == .unclassified { applyRule(to: &e) }   // cleared by you: your rules apply again
            entries[key] = e
        }
        changedNow()
        if source == "you" { onDecisionsChanged?() }
        if source == "you", status != .unclassified { onYouDecided?(keys) }
    }

    /// Accept AI suggestions by itself (Settings ▸ AI), for patterns that aren't high risk. Off: AI only suggests.
    var autoAcceptAI: Bool = UserDefaults.standard.bool(forKey: "autoAcceptAISuggestions") {
        didSet { UserDefaults.standard.set(autoAcceptAI, forKey: "autoAcceptAISuggestions") }
    }

    /// An AI verdict (Claude or on-device), only where nobody (you or a rule) has decided yet. It is kept
    /// as a suggestion for you, or applied when you let AI accept by itself. Never Safe for a high-risk
    /// pattern: event text (paths, names, hosts) can be crafted to talk a model into it.
    func suggest(_ status: SignatureStatus, key: String, source: String, note: String?) {
        guard status != .unclassified, self.status(forKey: key) == .unclassified, var e = entries[key] else { return }
        if status == .safe, e.risk == .high || SignatureBuilder.runsAnyCode(e) { return }
        if autoAcceptAI, e.risk != .high, e.reopened == nil {
            set(status, keys: [key], source: source, note: note)
            return
        }
        e.suggestion = AISuggestion(status: status, source: source, note: note)
        entries[key] = e
        changedNow()
    }

    /// Your decision: applies the AI's suggestions for these patterns (where still New). Returns how many.
    @discardableResult
    func acceptSuggestions(keys: [String], yours: Bool = true) -> Int {
        var n = 0
        for key in keys {
            // Automatic runs (`yours: false`) leave reopened patterns to you.
            guard status(forKey: key) == .unclassified, let e = entries[resolve(key)], yours || e.reopened == nil, let s = e.suggestion,
                  !(s.status == .safe && (e.risk == .high || SignatureBuilder.runsAnyCode(e))) else { continue }
            set(s.status, keys: [key], source: s.source, note: s.note)
            n += 1
        }
        return n
    }

    /// "You", "Rule: …", "Baseline: Slack", "AI (on-device)", "AI suggests Safe", or "New".
    func decidedBy(_ key: String) -> String {
        guard let e = entries[key] else { return "" }
        return Self.decidedBy(e, status: status(forKey: key))
    }

    nonisolated static func decidedBy(_ e: SignatureEntry, status: SignatureStatus) -> String {
        if status == .unclassified {
            if e.reopened != nil { return "Reopened" }
            if let s = e.suggestion { return "AI suggests \(s.status.title)" }
            return "New"
        }
        if e.status == .unclassified { return "You (whole process)" }
        switch e.source {
        case "you": return e.note?.hasPrefix("Baseline: ") == true ? "You · " + (e.note?.dropFirst(10) ?? "") : "You"
        case "rule": return "Rule: " + (e.note ?? "")
        case "baseline": return e.note.map { $0.hasPrefix("Baseline: ") ? "Baseline: " + $0.dropFirst(10) : $0 } ?? "Baseline"
        case "claude": return "AI (Claude)"
        case "on-device": return "AI (on-device)"
        case "auto": return "Automatic (routine)"
        default: return e.source ?? ""
        }
    }

    /// "Everything python does is Safe" would trust any script: not allowed for interpreters and shells.
    // MARK: Combined patterns

    /// Shared patterns you made from similar ones, and the old keys they now answer for.
    private(set) var merges: [PatternMerge] = []
    private var aliases: [String: String] = [:]

    func isCombined(_ key: String) -> Bool { merges.contains { $0.key == key } }

    /// Every existing pattern a shared one would cover.
    func covered(kind: EventKind, process: String, pattern: String) -> [SignatureEntry] {
        entries.values.filter { $0.kind == kind && Glob.match(process, $0.process) && Glob.match(pattern, $0.pattern) }
    }

    /// Why a shared pattern can't be made, or nothing: it must cover all the chosen patterns and stay specific
    /// (the general rule: no whole areas, no bare wildcards).
    func combineProblems(keys: [String], process: String, pattern: String) -> [String] {
        let chosen = keys.compactMap { entries[$0] }
        guard let kind = chosen.first?.kind else { return ["nothing chosen"] }
        var problems: [String] = []
        if Set(chosen.map(\.kind)).count > 1 { problems.append("they must all be the same kind (launch, connection or file)") }
        if !chosen.allSatisfy({ Glob.match(process, $0.process) && Glob.match(pattern, $0.pattern) }) {
            problems.append("it must cover every chosen pattern")
        }
        if Glob.literalCount(pattern) < 4 || pattern.trimmingCharacters(in: .whitespaces) == "*" {
            problems.append("too general: the pattern must name something specific")
        }
        if kind == .file, SignatureBuilder.isTooWide(filePattern: pattern) {
            problems.append("too wide: it would cover a whole folder area")
        }
        if process.contains("*"), Glob.literalCount(process) < 4 { problems.append("the program must name something specific") }
        return problems
    }

    /// Makes one shared pattern from similar ones (and any other it covers): counts added up, the most serious
    /// status kept (New when Safe and New are mixed), future events matching it join it.
    @discardableResult
    func combine(keys: [String], process: String, pattern: String, automatic: Bool = false) -> String? {
        guard combineProblems(keys: keys, process: process, pattern: pattern).isEmpty,
              let kind = keys.compactMap({ entries[$0] }).first?.kind else { return nil }
        let key = "\(kind.rawValue)|\(process)|\(pattern)"
        let parts = covered(kind: kind, process: process, pattern: pattern) + keys.compactMap { entries[$0] }
        var seen = Set<String>(), group: [SignatureEntry] = []
        for e in parts where seen.insert(e.id).inserted { group.append(e) }
        guard let latest = group.max(by: { $0.lastSeen < $1.lastSeen }) else { return nil }
        let statuses = Set(group.map(\.status))
        let status: SignatureStatus = statuses.contains(.dangerous) ? .dangerous : statuses.contains(.suspicious) ? .suspicious
            : statuses == [.safe] ? .safe : .unclassified
        let sources = Set(group.filter { $0.status == status }.compactMap(\.source))
        var merged = latest
        merged.id = key
        merged.process = process
        merged.pattern = pattern
        merged.count = group.reduce(0) { $0 + $1.count }
        merged.firstSeen = group.map(\.firstSeen).min() ?? latest.firstSeen
        merged.risk = group.map(\.risk).max() ?? latest.risk
        merged.status = status
        merged.source = status == .unclassified ? nil : sources.contains("you") ? "you" : sources.first
        merged.note = automatic ? (merged.note ?? "routine") : "Combined from \(group.count) patterns"
        merged.suggestion = nil
        for e in group where e.id != key {
            entries[e.id] = nil
            aliases[e.id] = key
            selection.remove(e.id)
        }
        for (old, target) in aliases where seen.contains(target) { aliases[old] = key }
        entries[key] = merged
        merges.removeAll { $0.key == key }
        merges.append(PatternMerge(kind: kind, process: process, pattern: pattern, automatic: automatic))
        PatternMerges.shared.set(merges)
        if !automatic { changedNow() }
        return key
    }

    // MARK: Tidying (routine Safe noise only)

    static let pruneAfter: TimeInterval = 30 * 24 * 3600
    /// A one-off (seen once, never decided, not risky) is forgotten after this long without happening again.
    static let oneOffAfter: TimeInterval = 7 * 24 * 3600
    /// Patterns an open story uses (wired by the app): never forgotten while it's open.
    var inUse: () -> Set<String> = { [] }
    /// The Patterns tab shows one-offs only when asked (or when searching or scoped).
    @Published var showSeenOnce = UserDefaults.standard.bool(forKey: "patternsShowSeenOnce") {
        didSet { UserDefaults.standard.set(showSeenOnce, forKey: "patternsShowSeenOnce") }
    }

    /// Seen once, not high risk, not Suspicious or Dangerous, not decided by you or a rule of yours: a command typed
    /// once, a one-time connection. Recorded when it happens (detection works the first time); hidden in Patterns.
    func isOneOff(_ e: SignatureEntry) -> Bool {
        e.count <= 1 && isOneOff(e, status: status(forKey: e.id), reviewed: reviewedByYou(e.id))
    }

    private func isOneOff(_ e: SignatureEntry, status: SignatureStatus, reviewed: Bool) -> Bool {
        Self.isOneOff(e, status: status, reviewed: reviewed, combined: isCombined(e.id))
    }

    nonisolated static func isOneOff(_ e: SignatureEntry, status: SignatureStatus, reviewed: Bool, combined: Bool) -> Bool {
        e.count <= 1 && e.risk != .high && e.reopened == nil && !reviewed && (status == .unclassified || status == .safe)
            && !combined
    }

    /// A one-off nobody decided, or decided Safe only automatically (routine): forgotten after a week. Ones an AI
    /// or the baseline decided stay (deciding again would cost a model call).
    func isForgettableOneOff(_ e: SignatureEntry) -> Bool {
        isOneOff(e) && (e.status == .unclassified || e.source == "auto")
    }
    static let foldMinimum = 3
    /// "Tidied: removed 1,204 old routine patterns, folded 3,410 into 212."
    @Published private(set) var tidySummary = ""
    /// One-offs the last tidy forgot.
    private(set) var lastOneOffs = 0
    private var lastTidy: Date?

    /// Decided automatically as ordinary (system reads, caches, scratch writes), and nothing since.
    private func isRoutineNoise(_ e: SignatureEntry) -> Bool {
        e.status == .safe && e.source == "auto" && e.risk == .routine && e.reopened == nil
    }

    /// A part that's random from one run to the next: a cache hash, a temp name ("tmp.aB#dE#", "<hex>").
    static func looksRandom(_ token: String) -> Bool {
        if token.contains("<hex>") || token.contains("<uuid>") { return true }
        let letters = token.filter(\.isLetter).count
        if token.contains("#"), letters > 0 { return true }
        guard token.count >= 10, !token.contains(where: { !$0.isLetter && !$0.isNumber }) else { return false }
        let upper = token.filter(\.isUppercase).count, lower = token.filter(\.isLowercase).count
        let vowels = token.lowercased().filter { "aeiou".contains($0) }.count
        return upper >= 2 && lower >= 2 && Double(vowels) / Double(token.count) < 0.25
    }

    /// The pattern with its random parts as `*` (token by token, split at / . : and spaces).
    static func shape(_ pattern: String) -> String {
        var out = "", cur = ""
        func flush() { out += looksRandom(cur) ? "*" : cur; cur = "" }
        for c in pattern {
            if "/.: ".contains(c) { flush(); out.append(c) } else { cur.append(c) }
        }
        flush()
        return out
    }

    /// Housekeeping, at launch and daily: routine Safe patterns not seen for 30 days are removed (they come
    /// back if they happen again), and those of one program that differ only in random parts are folded into
    /// one (only when the fold covers nothing but routine Safe patterns and isn't too wide). Nothing you, a
    /// rule or an AI decided, nothing New and nothing reopened is touched.
    @discardableResult
    func tidy(now: Date = Date()) -> (pruned: Int, folded: Int, into: Int) {
        lastTidy = now
        var pruned = 0
        for (key, e) in entries where isRoutineNoise(e) && now.timeIntervalSince(e.lastSeen) > Self.pruneAfter && !isCombined(key) {
            entries[key] = nil
            pruned += 1
        }
        // One-offs that didn't happen again within a week: if they do later, they're simply new again.
        let protected = inUse()
        var oneOffs = 0
        for (key, e) in entries where isForgettableOneOff(e) && now.timeIntervalSince(e.lastSeen) > Self.oneOffAfter && !protected.contains(key) {
            entries[key] = nil
            oneOffs += 1
        }
        if pruned + oneOffs > 0 { aliases = aliases.filter { entries[$0.value] != nil } }
        var groups: [String: [SignatureEntry]] = [:]
        for e in entries.values where isRoutineNoise(e) && !isCombined(e.id) {
            let shaped = Self.shape(e.pattern)
            guard shaped != e.pattern else { continue }
            groups["\(e.kind.rawValue)|\(e.process)|\(shaped)", default: []].append(e)
        }
        var folded = 0, into = 0
        for (_, group) in groups where group.count >= Self.foldMinimum {
            let first = group[0]
            let pattern = Self.shape(first.pattern)
            let keys = group.map(\.id)
            guard combineProblems(keys: keys, process: first.process, pattern: pattern).isEmpty,
                  covered(kind: first.kind, process: first.process, pattern: pattern).allSatisfy(isRoutineNoise),
                  combine(keys: keys, process: first.process, pattern: pattern, automatic: true) != nil else { continue }
            folded += group.count
            into += 1
        }
        if pruned + folded + oneOffs > 0 {
            tidySummary = "Tidied: removed \(pruned.formatted()) old routine pattern\(pruned == 1 ? "" : "s") and "
                + "\(oneOffs.formatted()) one-off\(oneOffs == 1 ? "" : "s") (seen once, a week ago), folded "
                + "\(folded.formatted()) into \(into.formatted())."
            changedNow()
        }
        lastOneOffs = oneOffs
        return (pruned, folded, into)
    }

    // MARK: Regrouping (patterns today's rules write as one)

    /// Decided automatically (routine Safe) or not at all (New, untouched): what regrouping may move.
    nonisolated static func mayRegroup(_ e: SignatureEntry) -> Bool {
        e.kind != .net && e.reopened == nil && e.risk != .high
            && (e.source == "auto" || e.source == nil && e.status == .unclassified)
    }

    /// Patterns from earlier versions that today's rules write as one (system programs' ordinary reads, random temp
    /// names), by the key they now belong to. Rebuilt from each pattern's stored example, so it matches what new
    /// events make. Nothing you, a rule or an AI decided moves, nor anything combined, reopened or high-risk.
    nonisolated static func regroupPlan(_ entries: [SignatureEntry], combined: Set<String> = []) -> [String: [SignatureEntry]] {
        var groups: [String: [SignatureEntry]] = [:]
        for e in entries where mayRegroup(e) && !combined.contains(e.id) && !e.exampleTarget.isEmpty {
            let actor = e.kind == .exec ? e.exampleParent : e.exampleProc
            let pattern = Self.rebuilt(e).pattern
            guard pattern != e.pattern, SignatureBuilder.isRegrouped(pattern), !actor.isEmpty,
                  SignatureBuilder.normalizeExecutable(actor) == e.process else { continue }
            groups["\(e.kind.rawValue)|\(e.process)|\(pattern)", default: []].append(e)
        }
        return groups
    }

    /// The pattern today's rules make from a saved pattern's example (a launch's example has no command line, which
    /// plain tools don't need).
    nonisolated static func rebuilt(_ e: SignatureEntry) -> (pattern: String, risk: PatternRisk, reason: String) {
        if e.kind == .file { return SignatureBuilder.fileTarget(e.exampleTarget, mode: e.exampleExtra, actor: e.exampleProc) }
        let s = SignatureBuilder.baseSignature(for: e.exampleEvent)
        return (s.pattern, s.risk, s.reason)
    }

    /// Moves earlier patterns into the ones today's rules write (see `regroupPlan`), at launch: counts add up, the
    /// first and last time seen are kept. Safe when all were Safe, New otherwise; a pattern already there keeps
    /// its decision. Old keys of temp files answer for the new one (stories may point at them).
    @discardableResult
    func regroup() -> (moved: Int, into: Int) {
        let plan = Self.regroupPlan(Array(entries.values), combined: Set(merges.map(\.key)))
        var moved = 0
        for (key, group) in plan {
            let pattern = String(key.split(separator: "|", maxSplits: 2)[2])
            let (_, risk, reason) = Self.rebuilt(group[0])
            let existing = entries[key]
            let all = group + (existing.map { [$0] } ?? [])
            guard let latest = all.max(by: { $0.lastSeen < $1.lastSeen }) else { continue }
            var merged = existing ?? latest
            merged.id = key
            merged.pattern = pattern
            merged.count = all.reduce(0) { $0 + $1.count }
            merged.firstSeen = all.map(\.firstSeen).min() ?? latest.firstSeen
            merged.lastSeen = latest.lastSeen
            merged.examplePid = latest.examplePid
            merged.exampleName = latest.exampleName
            merged.exampleProc = latest.exampleProc
            merged.exampleTarget = latest.exampleTarget
            merged.exampleExtra = latest.exampleExtra
            merged.exampleParent = latest.exampleParent
            merged.risk = max(risk, all.map(\.risk).max() ?? risk)
            if existing.map(Self.mayRegroup) ?? true {
                let safe = all.allSatisfy { $0.status == .safe } && merged.risk == .routine
                merged.status = safe ? .safe : .unclassified
                merged.source = safe ? "auto" : nil
                merged.note = safe ? reason : all.compactMap(\.note).first
                merged.suggestion = nil
            }
            let temp = !pattern.hasSuffix("[\(SignatureBuilder.ordinaryFiles)]")
            for e in group where e.id != key {
                entries[e.id] = nil
                if temp { aliases[e.id] = key }
                selection.remove(e.id)
            }
            let gone = Set(group.map(\.id))
            for (old, target) in aliases where gone.contains(target) { aliases[old] = key }
            entries[key] = merged
            moved += group.count
        }
        if moved > 0 { changedNow() }
        return (moved, plan.count)
    }

    /// Once a day (checked by the store's timer).
    private func tidyIfDue() {
        if lastTidy.map({ Date().timeIntervalSince($0) > 24 * 3600 }) ?? true { tidy() }
    }

    /// Undoes a combined pattern: future events make their own patterns again.
    func separate(_ key: String) {
        merges.removeAll { $0.key == key }
        PatternMerges.shared.set(merges)
        aliases = aliases.filter { $0.value != key }
        entries[key] = nil
        selection.remove(key)
        changedNow()
    }

    /// "Everything this program does is Safe" is the widest pattern there is: never for any program
    /// (Suspicious or Dangerous for a whole program is fine: that only flags more).
    static func canTrustWholeProcess(_ process: String) -> Bool { false }

    /// Puts an entry back as it was (tests, and loading entries made by older versions).
    func restore(_ e: SignatureEntry) {
        entries[e.id] = e
        changedNow()
    }

    /// Interpreters and shells run any script, so blanket trust in them is undone: whole-process Safe
    /// rules, and Safe set by AI or the baseline (your own per-pattern decisions stay).
    private func dropInterpreterTrust() {
        var changed = false
        // Wide patterns from earlier versions (r ~/Documents/**, zsh → r /*, python → internet:443) that weren't
        // your decision: dropped, they come back specific (file, folder, domain) when seen again.
        // Kept only when you (or a rule you approved) decided them.
        // Any program: file patterns that cover a whole area (the general rule, `isTooWide`).
        for (key, e) in entries where !["you", "rule"].contains(e.source ?? "") {
            let interpreter = SignatureBuilder.runsAnyCode(e)
            let wide = e.kind == .file ? SignatureBuilder.isTooWide(filePattern: e.pattern)
                    || interpreter && e.pattern.hasSuffix("/**") && !e.pattern.contains(" /opt/homebrew/Cellar/")
                : e.kind == .exec ? interpreter && e.pattern.hasPrefix("/") && !e.pattern.contains(" ")   // "bash → /usr/bin/perl"
                : e.kind == .net ? interpreter && (e.pattern.contains(" internet:") || e.pattern.contains(".*.*:"))
                : false
            if wide { entries[key] = nil; changed = true }
        }
        for (key, rule) in processRules where rule.status == .safe && !Self.canTrustWholeProcess(rule.process) {
            processRules[key] = nil; changed = true
        }
        for (key, e) in entries where e.status == .safe && ["claude", "on-device", "baseline"].contains(e.source ?? "")
            && SignatureBuilder.runsAnyCode(e) {
            var e = e; e.status = .unclassified; e.source = nil; e.note = nil
            entries[key] = e; changed = true
        }
        if changed { changedNow() }
    }

    func setProcessRule(_ status: SignatureStatus, kind: EventKind, process: String) {
        if status == .safe, !Self.canTrustWholeProcess(process) { return }
        let key = SignatureBuilder.processRuleKey(kind: kind, process: process)
        if status == .unclassified {
            processRules[key] = nil
        } else {
            processRules[key] = SignatureEntry(
                id: key, kind: kind, process: process, pattern: "*", count: 0, firstSeen: Date(), lastSeen: Date(),
                status: status, source: "you", note: nil, exampleName: "", examplePid: 0, exampleProc: process,
                exampleTarget: "", exampleExtra: "", exampleParent: "")
        }
        changedNow()
    }

    func delete(keys: [String]) {
        for key in keys { entries[key] = nil }
        selection.subtract(keys)
        changedNow()
    }

    func resetAll() {
        entries.removeAll()
        processRules.removeAll()
        selection.removeAll()
        changedNow()
    }

    // MARK: Queries for views

    /// What the Patterns tab's rows are made from: copies of the store's state (cheap: copy-on-write), so the
    /// work can run off the main thread.
    func patternInput(filter: SignatureFilter) -> PatternListInput {
        PatternListInput(entries: entries, processRules: processRules, combined: Set(merges.map(\.key)),
                         search: search.trimmingCharacters(in: .whitespaces).lowercased(), scope: scope?.keys,
                         showSeenOnce: showSeenOnce, filter: filter)
    }

    /// Everything the Patterns tab shows, in one pass over the patterns: the rows (unsorted) and every count.
    func patternSnapshot(filter: SignatureFilter) -> (items: [PatternItem], counts: PatternCounts) {
        patternInput(filter: filter).compute()
    }

    /// How many rows the Patterns table shows for a Show choice (same search and scope).
    func patternCount(filter: SignatureFilter) -> Int {
        switch filter {
        case .all: return patternSnapshot(filter: .all).items.count
        case .unclassified: return patternSnapshot(filter: .all).counts.new
        case .important: return patternSnapshot(filter: .all).counts.important
        }
    }

    /// One-offs the table would show with Seen Once on (same Show filter).
    func oneOffCount(filter: SignatureFilter) -> Int { patternSnapshot(filter: filter).counts.oneOffs }

    /// Rows for the Patterns table: filtered by the shared Show filter and search, sorted by columns.
    func patternItems(filter: SignatureFilter) -> [PatternItem] {
        PatternItem.sorted(patternSnapshot(filter: filter).items, by: patternOrder)
    }

    /// What the Patterns table's rows depend on (not the selection: clicking a row rebuilds nothing).
    private(set) lazy var listChanges: AnyPublisher<Void, Never> = {
        Publishers.MergeMany([$revision.map { _ in () }.eraseToAnyPublisher(),
                              $search.map { _ in () }.eraseToAnyPublisher(),
                              $scope.map { _ in () }.eraseToAnyPublisher(),
                              $patternOrder.map { _ in () }.eraseToAnyPublisher(),
                              $showSeenOnce.map { _ in () }.eraseToAnyPublisher(),
                              $groupByProcess.map { _ in () }.eraseToAnyPublisher(),
                              $groupBySession.map { _ in () }.eraseToAnyPublisher()])
            .dropFirst(7)                                                    // each sends its current value at once
            .eraseToAnyPublisher()
    }()

    /// The Patterns tab groups patterns under their program.
    @Published var groupByProcess = UserDefaults.standard.object(forKey: "patternsGroupByProcess") as? Bool ?? true {
        didSet { UserDefaults.standard.set(groupByProcess, forKey: "patternsGroupByProcess") }
    }
    /// …or under the coding-agent session that produced them (instead of by program).
    @Published var groupBySession = UserDefaults.standard.bool(forKey: "patternsGroupBySession") {
        didSet { UserDefaults.standard.set(groupBySession, forKey: "patternsGroupBySession") }
    }
    /// A session's pattern keys, by its id (wired by the app; the store doesn't know sessions).
    var sessionKeys: (Int) -> Set<String> = { _ in [] }

    /// A selection as pattern keys: a program's row (grouped) stands for its listed patterns.
    func keys(forSelection ids: Set<String>) -> [String] {
        var out: [String] = []
        let searching = !search.trimmingCharacters(in: .whitespaces).isEmpty
        for id in ids {
            if id.hasPrefix(PatternItem.groupPrefix) {
                let name = String(id.dropFirst(PatternItem.groupPrefix.count))
                out += entries.values.filter { displayProcessName($0.process) == name && listed($0, searching: searching) }.map(\.id)
            } else if id.hasPrefix(PatternItem.sessionPrefix) {
                let keys = Int(id.dropFirst(PatternItem.sessionPrefix.count)).map(sessionKeys) ?? []
                out += entries.values.filter { keys.contains($0.id) && listed($0, searching: searching) }.map(\.id)
            } else {
                out.append(id)
            }
        }
        return Array(Set(out)).sorted()
    }

    /// One-offs are listed when asked for, or when you search or look at a scope.
    private func listed(_ e: SignatureEntry, searching: Bool) -> Bool {
        showSeenOnce || searching || scope != nil || !isOneOff(e)
    }

    /// You decided this pattern: on the pattern itself, or through a whole-process rule you set.
    func reviewedByYou(_ key: String) -> Bool {
        guard let e = entries[resolve(key)] else { return false }
        if e.status != .unclassified { return e.source == "you" || e.source == "rule" }
        return processRules[SignatureBuilder.processRuleKey(kind: e.kind, process: e.process)] != nil
    }

    func count(_ status: SignatureStatus) -> Int {
        entries.values.filter { self.status(forKey: $0.id) == status }.count
    }

    var total: Int { entries.count }

    func newHighRiskCount() -> Int {
        entries.values.filter { $0.risk == .high && status(forKey: $0.id) == .unclassified }.count
    }

    /// High-risk first, then most recent.
    func unclassifiedForReview(limit: Int) -> [SignatureEntry] {
        entries.values
            .filter { status(forKey: $0.id) == .unclassified }
            .sorted { $0.risk != $1.risk ? $0.risk > $1.risk : $0.lastSeen > $1.lastSeen }
            .prefix(limit)
            .map { $0 }
    }

    func rank(_ s: SignatureStatus) -> Int { Self.rank(s) }

    nonisolated static func rank(_ s: SignatureStatus) -> Int {
        switch s {
        case .dangerous: return 0
        case .suspicious: return 1
        case .unclassified: return 2
        case .safe: return 3
        }
    }

    // MARK: Persistence

    private struct Snapshot: Codable {
        var entries: [SignatureEntry]
        var processRules: [SignatureEntry]
        var merges: [PatternMerge]?
        var aliases: [String: String]?
        /// Which journal lines belong to this snapshot (nil: written before the journal existed).
        var generation: Int?
    }

    /// One journal line: a pattern as it is now, for the snapshot of generation `g`.
    private struct JournalLine: Codable {
        var g: Int
        var e: SignatureEntry
    }

    // The store is a snapshot (signatures-v2.json) plus a journal of patterns changed since (one JSON line each).
    // Events only change counters and add patterns: those go to the journal every 5 minutes, a few hundred KB
    // instead of rewriting the whole 10 MB file. Decisions, removals and a journal grown past the snapshot's size
    // write a new snapshot. Crash-safe: the snapshot is replaced atomically and carries a generation; journal lines
    // of an older generation (a crash between the two writes) are ignored.
    private var generation = 0
    private var snapshotKeys = Set<String>()
    private var changedKeys = Set<String>()
    private var journalBytes = 0
    private var hasSnapshot = false
    private var journalURL: URL { fileURL.deletingPathExtension().appendingPathExtension("journal") }
    private static let writer = DispatchQueue(label: "hostwatch.patterns.save", qos: .utility)

    private func load() {
        guard let data = Vault.shared.read(fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let snap = try? decoder.decode(Snapshot.self, from: data) else { return }
        entries = Dictionary(snap.entries.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        processRules = Dictionary(snap.processRules.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        merges = snap.merges ?? []
        aliases = snap.aliases ?? [:]
        generation = snap.generation ?? 0
        snapshotKeys = Set(entries.keys)
        hasSnapshot = true
        if let journal = try? Data(contentsOf: journalURL) {
            journalBytes = journal.count
            for raw in journal.split(separator: 0x0A) {
                guard let line = Vault.shared.openLine(Data(raw)),
                      let j = try? decoder.decode(JournalLine.self, from: line), j.g == generation else { continue }
                entries[j.e.id] = j.e
            }
        }
        PatternMerges.shared.set(merges)
    }

    /// The saved patterns and process rules, snapshot plus journal, without a store (MCP server, command-line tools:
    /// they read while the app runs). nil when nothing is saved.
    nonisolated static func readSaved(from directory: URL) -> (entries: [SignatureEntry], processRules: [SignatureEntry])? {
        let file = directory.appendingPathComponent("signatures-v2.json")
        guard let data = Vault.shared.read(file) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let snap = try? decoder.decode(Snapshot.self, from: data) else { return nil }
        var entries = Dictionary(snap.entries.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let g = snap.generation ?? 0
        if let journal = try? Data(contentsOf: file.deletingPathExtension().appendingPathExtension("journal")) {
            for raw in journal.split(separator: 0x0A) {
                if let line = Vault.shared.openLine(Data(raw)), let j = try? decoder.decode(JournalLine.self, from: line), j.g == g { entries[j.e.id] = j.e }
            }
        }
        return (Array(entries.values), snap.processRules)
    }

    /// Saves: changed patterns to the journal, or a new snapshot when needed (see above). `sync` at quit.
    func save(sync: Bool = false) {
        SigningCache.shared.save()
        guard dirty || statsDirty else { return }
        // A full snapshot after a decision, when the journal outgrew the snapshot (~500 bytes a pattern), or when
        // any pattern of the snapshot is gone (a removal the journal can't express).
        let full = dirty || !hasSnapshot || journalBytes > max(entries.count * 500, 1_000_000) || !snapshotKeys.isSubset(of: entries.keys)
        dirty = false
        statsDirty = false
        let url = fileURL, journal = journalURL
        let write: () -> Void
        if full {
            generation += 1
            let snap = Snapshot(entries: Array(entries.values), processRules: Array(processRules.values),
                                merges: merges, aliases: aliases, generation: generation)
            snapshotKeys = Set(entries.keys)
            journalBytes = 0
            hasSnapshot = true
            write = {
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                guard let data = try? encoder.encode(snap), (try? Vault.shared.write(data, to: url)) != nil else { return }
                try? FileManager.default.removeItem(at: journal)       // its lines were for the previous generation
            }
        } else {
            let changed = changedKeys.compactMap { entries[$0] }, g = generation
            journalBytes += changed.count * 600
            write = {
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                var out = Data()
                for e in changed {
                    guard let line = try? encoder.encode(JournalLine(g: g, e: e)) else { continue }
                    out += Vault.shared.sealLine(line)
                }
                guard !out.isEmpty else { return }
                if let h = try? FileHandle(forWritingTo: journal) {
                    _ = try? h.seekToEnd()
                    try? h.write(contentsOf: out)
                    try? h.close()
                } else {
                    FileManager.default.createFile(atPath: journal.path, contents: out, attributes: [.posixPermissions: 0o600])
                }
            }
        }
        changedKeys.removeAll()
        // One queue: a journal append never lands after (or interleaved with) a newer snapshot.
        if sync { Self.writer.sync(execute: write) } else { Self.writer.async(execute: write) }
    }

    /// What every observed event changes (counts, last seen, new patterns): saved on the slow schedule.
    private func markDirty() {
        statsDirty = true
        pendingRevision = true
    }

    /// When the store will be written next: soon after a decision, later for statistics only.
    enum SaveUrgency { case none, soon, later }
    var saveUrgency: SaveUrgency { dirty ? .soon : statsDirty ? .later : .none }

    private func changedNow() {
        dirty = true
        revision += 1
    }

    private var ticks = 0
    private func tick() {
        // Counts and last-seen times reach the views every few seconds: each publish re-renders the window.
        if pendingRevision, ticks % 5 == 0 { pendingRevision = false; revision += 1 }
        ticks += 1
        if ticks % 10 == 0, dirty { save() }
        if ticks % Self.statsSaveEvery == 0, statsDirty { save() }
        if ticks % 3600 == 30 { tidyIfDue() }        // 30 s after launch, then hourly checks for "a day passed"
    }

    /// Drops the oldest unclassified patterns when the store is full.
    private func evict() {
        let victims = entries.values
            .filter { $0.status == .unclassified }
            .sorted { $0.lastSeen < $1.lastSeen }
            .prefix(entries.count - maxEntries + 1000)
        for v in victims { entries[v.id] = nil }
        dirty = true                                  // removals need a new snapshot
    }
}
