import AppKit
import Foundation
import SwiftUI

// MARK: - Policy

/// One baseline rule's identity: an app with its signer, or the macOS system.
struct BaselineKey: Equatable, Hashable {
    let id: String              // "system", or "app:/Applications/Slack.app|team:BQR82RBBHL"
    let name: String            // "macOS system", "Slack"
    let signer: String          // "Apple (sealed system volume)", "Slack Technologies"
}

/// What the baseline does with one New pattern.
enum BaselineDecision: Equatable {
    case trust(BaselineKey)                     // ordinary activity of a trusted, signed app (or macOS itself)
    case onDevice(app: String)                  // signed, developer not yet trusted: the on-device model decides
    case review(app: String, reason: String, homebrew: Bool = false)   // stays New: your decision
    case ignore                                 // Hostwatch's own activity: never listed
}

/// Decides, from signing facts only, which New patterns are ordinary enough to trust. Anything that
/// could be malware already on the Mac (unsigned, downloaded, temp, high-risk, a third-party app touching
/// login items or credentials) is left for you, so the baseline can't be poisoned.
enum BaselinePolicy {
    typealias Identify = (String) -> (identity: CodeIdentity?, trusted: Bool)

    static let dropZones = ["/Downloads/", "/Users/Shared/", "/var/folders/", "/Volumes/"]
    static let tempPrefixes = ["/tmp/", "/private/tmp/"]

    /// `allowSensitive`: for an app you trusted yourself, its own sensitive reads are fine too.
    static func decide(_ e: SignatureEntry, identify: Identify, allowSensitive: Bool = false) -> BaselineDecision {
        let subject = SignatureStore.subjectPath(e)
        let actor = e.kind == .exec ? e.exampleParent : e.exampleProc
        let paths = Array(Set([subject, actor]).filter { !$0.isEmpty })
        if paths.contains(where: StoryEngine.isOwn) { return .ignore }
        let app = appName(subject.isEmpty ? e.process : subject)
        if e.risk == .high { return .review(app: app, reason: "high risk" + (e.note.map { ": \($0.replacingOccurrences(of: "⚠︎ ", with: ""))" } ?? "")) }
        // macOS itself: Apple programs on the sealed, read-only system volume. Reading keychains, Mail or
        // Messages is their job (indexing, sync, malware scanning), and nothing can modify them.
        let system = !paths.isEmpty && paths.allSatisfy(SignatureBuilder.isSealedSystem)
        // Only system services (daemons, agents) may touch sensitive places: command-line tools like cat,
        // sqlite3 or a shell run whatever a script tells them to, so their sensitive reads stay for you.
        let systemService = system && !paths.contains { isCommandLineTool($0) || SignatureBuilder.isLolbin($0) }
        if e.pattern.hasSuffix("]"), !systemService, !allowSensitive {
            return .review(app: app, reason: sensitiveText(e.pattern))
        }
        var allTrusted = true
        var subjectID: CodeIdentity?
        for path in paths {
            if dropZones.contains(where: path.contains) || tempPrefixes.contains(where: path.hasPrefix) {
                return .review(app: app, reason: "runs from Downloads or a temporary folder")
            }
            let (id, trusted) = identify(path)
            guard let id else { return .review(app: app, reason: "\(appName(path)): program not found") }
            if id.valid == false { return .review(app: app, reason: "\(appName(path)): invalid signature") }
            if id.untrustedCode && !trusted {
                let brew = isHomebrew(path)
                return .review(app: app, reason: brew ? "Homebrew tool (ad-hoc signed by Homebrew)"
                                                     : "\(appName(path)): \(id.label.lowercased())", homebrew: brew)
            }
            if id.quarantined { return .review(app: app, reason: "\(appName(path)): downloaded (quarantined)") }
            if !trusted { allTrusted = false }
            if path == subject { subjectID = id }
        }
        if system { return .trust(BaselineKey(id: "system", name: "macOS system", signer: "Apple (sealed system volume)")) }
        guard allTrusted, let id = subjectID ?? paths.first.flatMap({ identify($0).identity }) else { return .onDevice(app: app) }
        guard let signer = signerKey(id) else {
            // Homebrew builds are ad-hoc signed; once you trust Homebrew tools they share one rule.
            if paths.allSatisfy(isHomebrew) { return .trust(BaselineKey(id: "homebrew", name: "Homebrew tools", signer: "Homebrew (ad-hoc)")) }
            return .onDevice(app: app)
        }
        let root = appRoot(subject.isEmpty ? (paths.first ?? "") : subject)
        return .trust(BaselineKey(id: "app:\(root)|\(signer)", name: appName(root), signer: id.label))
    }

    static func isCommandLineTool(_ path: String) -> Bool {
        path.hasPrefix("/bin/") || path.hasPrefix("/usr/bin/")
    }

    static func isHomebrew(_ path: String) -> Bool {
        path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/Cellar/") || path.hasPrefix("/usr/local/opt/")
    }

    /// "reads keychains" from a pattern like "r ~/Library/Keychains/*  [keychain]".
    static func sensitiveText(_ pattern: String) -> String {
        let label = pattern.range(of: "[", options: .backwards).map { String(pattern[$0.upperBound...].dropLast()) } ?? pattern
        let mode = pattern.hasPrefix("rw ") ? "reads and writes" : pattern.hasPrefix("w ") ? "writes" : "reads"
        return "\(mode) \(label)"
    }

    /// Who signed it: Apple, or one developer (Team ID).
    static func signerKey(_ id: CodeIdentity) -> String? {
        if id.apple { return "apple" }
        return id.teamID.map { "team:" + $0 }
    }

    /// The outermost app bundle ("/Applications/Cursor.app") or the program itself.
    static func appRoot(_ path: String) -> String {
        if let range = path.range(of: ".app/") { return String(path[..<range.lowerBound]) + ".app" }
        return path
    }

    /// "Cursor" for anything inside Cursor.app (helpers included); otherwise the file name.
    static func appName(_ path: String) -> String {
        if let range = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app") : nil) {
            return (String(path[..<range.lowerBound]) as NSString).lastPathComponent
        }
        return (path as NSString).lastPathComponent
    }
}

// MARK: - Report

/// What needs your review, one row per app (with all its reasons).
struct BaselineReport: Codable, Equatable {
    struct Group: Codable, Equatable, Identifiable {
        var app: String
        var reasons: [String]
        var keys: [String]
        var homebrew = false
        var id: String { app }
    }
    var date = Date()
    var onDevice: [Group] = []
    var review: [Group] = []
    /// Patterns you dismissed: they stay New but aren't listed again.
    var dismissed: Set<String> = []

    var onDeviceCount: Int { onDevice.reduce(0) { $0 + $1.keys.count } }
    var reviewCount: Int { review.reduce(0) { $0 + $1.keys.count } }

    mutating func add(_ decision: BaselineDecision, key: String) {
        guard !dismissed.contains(key) else { return }
        func put(_ list: inout [Group], _ app: String, _ reason: String, _ homebrew: Bool) {
            if let i = list.firstIndex(where: { $0.app == app }) {
                if !list[i].keys.contains(key) { list[i].keys.append(key) }
                if !list[i].reasons.contains(reason) { list[i].reasons.append(reason) }
                list[i].homebrew = list[i].homebrew || homebrew
            } else {
                list.append(Group(app: app, reasons: [reason], keys: [key], homebrew: homebrew))
            }
        }
        switch decision {
        case .trust, .ignore: break
        case .onDevice(let app): put(&onDevice, app, "signed, developer not yet trusted", false)
        case .review(let app, let reason, let homebrew): put(&review, app, reason, homebrew)
        }
    }

    /// Drops keys that are no longer New, or that you dismissed.
    mutating func prune(_ stillNew: (String) -> Bool) {
        let dismissed = self.dismissed
        func kept(_ list: [Group]) -> [Group] {
            list.map { g in var g = g; g.keys = g.keys.filter { stillNew($0) && !dismissed.contains($0) }; return g }
                .filter { !$0.keys.isEmpty }
        }
        review = kept(review)
        onDevice = kept(onDevice)
        review.sort { $0.keys.count != $1.keys.count ? $0.keys.count > $1.keys.count : $0.app < $1.app }
    }
}

// MARK: - Baseline rules

/// "This app's ordinary activity is fine": one per app and signer, or one for the macOS system. Made by
/// the learning waves (or by you with Trust), it keeps applying to future normal-risk patterns, always
/// through `BaselinePolicy`. Low weight: your markings and learned rules win, and stories ignore it.
struct BaselineRule: Codable, Identifiable, Equatable {
    var id: String              // BaselineKey.id
    var name: String            // "Slack", "macOS system"
    var signer: String          // "Slack Technologies", "Apple (sealed system volume)"
    var approvedByYou = false   // made with Trust: also covers the app's own sensitive reads
    var paused = false
    var created = Date()

    /// The note on patterns this rule trusted (also how they're found again).
    var note: String { "Baseline: \(name) (\(signer))" }
}

// MARK: - Learner

/// Learns this Mac's normal behaviour in waves after the first launch (5, 15 and 60 minutes). Each
/// wave sorts New patterns with `BaselinePolicy`, making a rule per trusted app; the rules then keep
/// trusting their future normal-risk patterns.
@MainActor
final class BaselineLearner: ObservableObject {
    static let waves: [TimeInterval] = [5 * 60, 15 * 60, 60 * 60]
    static let applyInterval: TimeInterval = 30

    enum Phase: Equatable { case idle, learning(wave: Int, at: Date), done }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var report: BaselineReport?
    @Published private(set) var rules: [BaselineRule] = []
    @Published private(set) var running = false
    @Published private(set) var message = ""

    private let store: SignatureStore
    private let classifier: PatternClassifier?
    private let defaults: UserDefaults
    private var timer: Timer?
    private var applyTimer: Timer?
    private var migrated = false
    var identify: BaselinePolicy.Identify = { path in
        guard let id = SigningCache.shared.identity(path) else { return (nil, false) }
        return (id, SigningCache.shared.trusts(path, id))
    }
    var now: () -> Date = { Date() }

    init(store: SignatureStore, classifier: PatternClassifier?, defaults: UserDefaults = .standard, freshInstall: Bool) {
        self.store = store
        self.classifier = classifier
        self.defaults = defaults
        if let data = defaults.data(forKey: "baselineReport2") {
            report = try? JSONDecoder().decode(BaselineReport.self, from: data)
        }
        if let data = defaults.data(forKey: "baselineRules2") {
            rules = (try? JSONDecoder().decode([BaselineRule].self, from: data)) ?? []
        }
        // The first version kept one rule per developer and a report per reason: undo it and sort again.
        if defaults.object(forKey: "baselineRules") != nil || defaults.object(forKey: "baselineReport") != nil {
            defaults.removeObject(forKey: "baselineRules")
            defaults.removeObject(forKey: "baselineReport")
            store.set(.unclassified, keys: store.allEntries.filter { $0.source == "baseline" }.map(\.id))
            migrated = true
        }
        if freshInstall, defaults.object(forKey: "baselineStartedAt") == nil {
            defaults.set(Date(), forKey: "baselineStartedAt")
            defaults.set(0, forKey: "baselineWavesDone")
        }
        updatePhase()
    }

    private var startedAt: Date? { defaults.object(forKey: "baselineStartedAt") as? Date }
    private var wavesDone: Int { defaults.integer(forKey: "baselineWavesDone") }

    /// Patterns the baseline rules trust right now.
    var trustedCount: Int { store.allEntries.filter { $0.source == "baseline" }.count }

    func keys(_ rule: BaselineRule) -> [String] {
        store.allEntries.filter { $0.note == rule.note && ($0.source == "baseline" || $0.source == "you") }.map(\.id)
    }

    func patternCount(_ rule: BaselineRule) -> Int { keys(rule).count }

    private func updatePhase() {
        guard let startedAt else { phase = (report == nil && rules.isEmpty) ? .idle : .done; return }
        if wavesDone >= Self.waves.count { phase = .done; return }
        phase = .learning(wave: wavesDone + 1, at: startedAt.addingTimeInterval(Self.waves[wavesDone]))
    }

    private func save() {
        if let report, let data = try? JSONEncoder().encode(report) { defaults.set(data, forKey: "baselineReport2") }
        if let data = try? JSONEncoder().encode(rules) { defaults.set(data, forKey: "baselineRules2") }
    }

    /// Runs waves that are due, and keeps baseline rules applying to new patterns.
    func schedule() {
        timer?.invalidate()
        timer = nil
        if applyTimer == nil {
            applyTimer = Timer.scheduledTimer(withTimeInterval: Self.applyInterval, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { guard let self else { return }; Task { await self.applyRules() } }
            }
        }
        if migrated, phase == .done {
            migrated = false
            Task { await runWave() }
        }
        guard case .learning(_, let at) = phase else { return }
        let delay = max(1, at.timeIntervalSince(now()))
        timer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.runWave(); self.schedule() }
            }
        }
    }

    private func decide(_ entries: [SignatureEntry], allowSensitive: Bool = false) async -> [(SignatureEntry, BaselineDecision)] {
        let identify = self.identify
        return await Task.detached(priority: .utility) {
            entries.map { ($0, BaselinePolicy.decide($0, identify: identify, allowSensitive: allowSensitive)) }
        }.value
    }

    private var newPatterns: [SignatureEntry] {
        store.allEntries.filter { $0.status == .unclassified && $0.source == nil }
    }

    private func trust(_ keys: [String], by rule: BaselineRule) {
        store.set(.safe, keys: keys, source: "baseline", note: rule.note)
    }

    @discardableResult
    private func ensureRule(_ key: BaselineKey, approved: Bool = false) -> BaselineRule {
        if let i = rules.firstIndex(where: { $0.id == key.id }) {
            if approved { rules[i].approvedByYou = true; rules[i].paused = false }
            return rules[i]
        }
        let rule = BaselineRule(id: key.id, name: key.name, signer: key.signer, approvedByYou: approved, created: now())
        rules.append(rule)
        rules.sort { $0.id == "system" ? true : $1.id == "system" ? false : $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return rule
    }

    /// One learning wave now (also "Update Baseline"): sorts New patterns, makes rules for trusted apps.
    func runWave() async {
        guard !running else { return }
        running = true
        defer { running = false }
        let decisions = await decide(newPatterns)
        var report = self.report ?? BaselineReport()
        report.date = now()
        var byRule: [String: [String]] = [:]
        var onDeviceKeys: [String] = []
        for (entry, decision) in decisions {
            report.add(decision, key: entry.id)
            switch decision {
            case .trust(let key):
                if !ensureRule(key).paused { byRule[key.id, default: []].append(entry.id) }
            case .onDevice: onDeviceKeys.append(entry.id)
            case .review, .ignore: break
            }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
        if !onDeviceKeys.isEmpty { classifier?.triageOnDevice(keys: onDeviceKeys) }
        report.prune { [store] key in store.status(forKey: key) == .unclassified }
        self.report = report
        if startedAt != nil, wavesDone < Self.waves.count { defaults.set(wavesDone + 1, forKey: "baselineWavesDone") }
        save()
        updatePhase()
        await applyApproved()
    }

    /// Between waves and after learning: active rules trust new patterns of their apps. No new rules here
    /// (new apps wait for you, or for Update Baseline).
    func applyRules() async {
        guard !running, rules.contains(where: { !$0.paused }) else { return }
        let candidates = newPatterns
        guard !candidates.isEmpty else { return }
        var byRule: [String: [String]] = [:]
        for (entry, decision) in await decide(candidates) {
            if case .trust(let key) = decision, rules.contains(where: { $0.id == key.id && !$0.paused }) {
                byRule[key.id, default: []].append(entry.id)
            }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
        await applyApproved()
    }

    /// Apps you trusted also cover their own sensitive reads (never high risk, unsigned or downloaded).
    private func applyApproved() async {
        let approved = rules.filter { $0.approvedByYou && !$0.paused }
        guard !approved.isEmpty else { return }
        let candidates = newPatterns
        guard !candidates.isEmpty else { return }
        var byRule: [String: [String]] = [:]
        for (entry, decision) in await decide(candidates, allowSensitive: true) {
            if case .trust(let key) = decision, approved.contains(where: { $0.id == key.id }) {
                byRule[key.id, default: []].append(entry.id)
            }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        save()
    }

    /// "Update Baseline": for existing installs, or to finish learning early.
    func buildNow() async {
        if startedAt == nil { defaults.set(now(), forKey: "baselineStartedAt") }
        defaults.set(Self.waves.count - 1, forKey: "baselineWavesDone")   // this run is the last wave
        timer?.invalidate()
        await runWave()
    }

    private func revert(_ rule: BaselineRule) {
        let keys = store.allEntries.filter { $0.source == "baseline" && $0.note == rule.note }.map(\.id)
        store.set(.unclassified, keys: keys)
    }

    /// Paused: its automatic patterns go back to New and it stops applying (kept, so updates won't remake it).
    func setPaused(_ rule: BaselineRule, _ paused: Bool) {
        guard let i = rules.firstIndex(where: { $0.id == rule.id }) else { return }
        rules[i].paused = paused
        if paused { revert(rules[i]) }
        save()
        if !paused { Task { await applyRules() } }
    }

    func delete(_ rule: BaselineRule) {
        revert(rule)
        rules.removeAll { $0.id == rule.id }
        save()
    }

    /// Every baseline rule removed and everything they trusted automatically back to New.
    func undo() {
        let keys = store.allEntries.filter { $0.source == "baseline" }.map(\.id)
        store.set(.unclassified, keys: keys)
        rules = []
        save()
    }

    /// Trust (your decision): marks the app's listed patterns Safe and, for a signed app, makes a rule
    /// you can see ("Trusted by you") that keeps covering the app's ordinary activity.
    func trustApp(_ group: BaselineReport.Group) async {
        guard !runsAnyCode(group) else {
            message = "\(group.app) runs any script it's given, so it can't be trusted from here: Dismiss keeps it New."
            return
        }
        let entries = group.keys.compactMap { store.entry($0) }
        var madeRule: BaselineRule?
        for (_, decision) in await decide(entries, allowSensitive: true) {
            if case .trust(let key) = decision { madeRule = ensureRule(key, approved: true); break }
        }
        store.set(.safe, keys: group.keys, source: "you", note: madeRule?.note ?? "Trusted from the baseline review")
        message = madeRule.map { "Added the rule \"\($0.name) (\($0.signer))\" to the baseline." }
            ?? "Trusted \(group.app)'s \(group.keys.count) pattern\(group.keys.count == 1 ? "" : "s"). No rule: "
            + "unsigned, ad-hoc or high-risk activity is trusted pattern by pattern."
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        save()
        await applyApproved()
    }

    /// The group's patterns, high risk first.
    func entries(_ group: BaselineReport.Group) -> [SignatureEntry] {
        group.keys.compactMap { store.entry($0) }
            .sorted { $0.risk != $1.risk ? $0.risk > $1.risk : $0.lastSeen > $1.lastSeen }
    }

    /// Interpreters and shells (python, node, sh, osascript…) run whatever code they're given, so trusting
    /// them would trust any script, a virus's too. The review offers only Dismiss or Mark Suspicious.
    func runsAnyCode(_ group: BaselineReport.Group) -> Bool {
        group.keys.contains { key in
            guard let e = store.entry(key) else { return false }
            return SignatureBuilder.isLolbin(SignatureStore.subjectPath(e))
        }
    }

    func markSuspicious(_ group: BaselineReport.Group) {
        store.set(.suspicious, keys: group.keys, source: "you", note: "Marked suspicious from the baseline review")
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        message = "Marked \(group.app) suspicious."
        save()
    }

    /// Hides the row: the patterns stay New (and still count everywhere else).
    func dismiss(_ group: BaselineReport.Group) {
        report?.dismissed.formUnion(group.keys)
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        message = "Dismissed \(group.app): its patterns stay New."
        save()
    }

    /// Homebrew signs what it builds ad-hoc: trust its Cellar tools (Settings ▸ Detection), then re-sort.
    func trustHomebrew() async {
        SigningCache.shared.trustHomebrew = true
        store.reassess()
        await runWave()
        message = "Homebrew tools are trusted (Settings ▸ Detection); the baseline was updated."
    }

    var statusText: String {
        switch phase {
        case .idle: return "Not built yet"
        case .learning(let wave, let at):
            return "Learning · wave \(wave) of \(Self.waves.count) at \(at.formatted(date: .omitted, time: .shortened))"
        case .done:
            let review = report?.reviewCount ?? 0
            return "\(rules.filter { !$0.paused }.count) rules trust \(trustedCount) patterns · \(review) to review"
        }
    }
}
