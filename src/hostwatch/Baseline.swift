import AppKit
import Combine
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
    case review(app: String, reason: String)    // stays New: your decision
    case ignore                                 // not listed, stays New: Hostwatch itself, interpreters and shells
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
        // Interpreters and shells (python, node, bash, osascript…) run any script they're given: never
        // trusted by a rule, macOS's own included, and nothing to approve. They stay New, visible in
        // Patterns, and stories keep watching them.
        if runsAnyCode(e) { return .ignore }
        return sort(e, identify: identify, allowSensitive: allowSensitive)
    }

    static func runsAnyCode(_ e: SignatureEntry) -> Bool { SignatureBuilder.runsAnyCode(e) }

    private static func sort(_ e: SignatureEntry, identify: Identify, allowSensitive: Bool) -> BaselineDecision {
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
                return .review(app: app, reason: isHomebrew(path) ? "Homebrew tool (ad-hoc signed)"
                                                                  : "\(appName(path)): \(id.label.lowercased())")
            }
            if id.quarantined { return .review(app: app, reason: "\(appName(path)): downloaded (quarantined)") }
            if !trusted { allTrusted = false }
            if path == subject { subjectID = id }
        }
        // macOS itself: all of it sealed, or an Apple tool from the sealed volume started by a trusted program
        // (Cursor running /bin/rm is macOS's rm, not a rule of its own).
        let appleTool = SignatureBuilder.isSealedSystem(subject) && subjectID?.apple == true && allTrusted
        if system || appleTool { return .trust(BaselineKey(id: "system", name: "macOS system", signer: "Apple (sealed system volume)")) }
        guard allTrusted, let id = subjectID ?? paths.first.flatMap({ identify($0).identity }),
              let signer = signerKey(id) else { return .onDevice(app: app) }
        let root = appRoot(subject.isEmpty ? (paths.first ?? "") : subject)
        return .trust(BaselineKey(id: "app:\(root)|\(signer)", name: appName(root), signer: id.label))
    }

    static func isCommandLineTool(_ path: String) -> Bool {
        path.hasPrefix("/bin/") || path.hasPrefix("/usr/bin/")
    }

    static func isHomebrew(_ path: String) -> Bool {
        path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/Cellar/") || path.hasPrefix("/usr/local/opt/")
    }

    /// The kind of behaviour a pattern is, for an app's profile: "launches node", "connects to the web",
    /// "reads ~/Documents", "writes own data". More of the same kind is ordinary; a new kind is worth a look.
    static func behaviour(_ e: SignatureEntry) -> String {
        switch e.kind {
        case .exec:
            return "launches " + (SignatureStore.subjectPath(e) as NSString).lastPathComponent
        case .net:
            let port = e.pattern.split(separator: ":").last.map(String.init) ?? ""
            let proto = e.pattern.split(separator: " ").first.map(String.init) ?? "TCP"
            if e.pattern.contains("loopback") || e.pattern.contains(" lan:") { return "connects locally" }
            switch port {
            case "443", "80": return "connects to the web"
            case "53", "853": return "uses DNS"
            default: return "connects on \(proto) port \(port)"
            }
        case .file:
            let mode = e.pattern.hasPrefix("rw ") ? "reads and writes" : e.pattern.hasPrefix("w ") ? "writes" : "reads"
            if e.pattern.hasSuffix("[own data]") { return "\(mode) its own data" }
            if e.pattern.hasSuffix("]"), let open = e.pattern.range(of: "[", options: .backwards) {
                return "\(mode) \(e.pattern[open.upperBound...].dropLast())"
            }
            let path = e.pattern.split(separator: " ", maxSplits: 1).last.map(String.init) ?? ""
            let parts = path.split(separator: "/").prefix(path.hasPrefix("~") ? 2 : 2)
            return "\(mode) " + (path.hasPrefix("/") ? "/" : "") + parts.joined(separator: "/")
        }
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

// MARK: - Needs you

/// New patterns that need your decision, one row per app (with all its reasons). Rebuilt live from the
/// New patterns; interpreters, shells and Hostwatch itself aren't listed, and nor is what you dismissed.
struct BaselineReport: Codable, Equatable {
    struct Group: Codable, Equatable, Identifiable {
        var app: String
        var reasons: [String]
        var keys: [String]
        var id: String { app }
    }
    var review: [Group] = []
    /// Patterns you dismissed: they stay New but aren't listed again.
    var dismissed: Set<String> = []

    var reviewCount: Int { review.reduce(0) { $0 + $1.keys.count } }

    mutating func add(app: String, reason: String, key: String) {
        guard !dismissed.contains(key) else { return }
        if let i = review.firstIndex(where: { $0.app == app }) {
            if !review[i].keys.contains(key) { review[i].keys.append(key) }
            if !review[i].reasons.contains(reason) { review[i].reasons.append(reason) }
        } else {
            review.append(Group(app: app, reasons: [reason], keys: [key]))
        }
    }

    mutating func sort() {
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
    /// Made by itself (a trusted developer's new app, or macOS itself), not in a learning wave or by you.
    var automatic = false
    /// The kinds of behaviour the app showed in its first week (`BaselinePolicy.behaviour`); after that a
    /// new kind isn't trusted by the rule.
    var profile: Set<String> = []

    static let learningPeriod: TimeInterval = 7 * 24 * 3600
    /// macOS itself can't be modified: its rule trusts every normal-risk kind of behaviour.
    var learnsProfile: Bool { id != "system" }

    init(id: String, name: String, signer: String, approvedByYou: Bool = false, paused: Bool = false,
         created: Date = Date(), automatic: Bool = false, profile: Set<String> = []) {
        (self.id, self.name, self.signer, self.approvedByYou, self.paused) = (id, name, signer, approvedByYou, paused)
        (self.created, self.automatic, self.profile) = (created, automatic, profile)
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        signer = try c.decode(String.self, forKey: .signer)
        approvedByYou = try c.decodeIfPresent(Bool.self, forKey: .approvedByYou) ?? false
        paused = try c.decodeIfPresent(Bool.self, forKey: .paused) ?? false
        created = try c.decodeIfPresent(Date.self, forKey: .created) ?? Date()
        automatic = try c.decodeIfPresent(Bool.self, forKey: .automatic) ?? false
        profile = try c.decodeIfPresent(Set<String>.self, forKey: .profile) ?? []
    }

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
    /// What needs you (always current: rebuilt shortly after patterns change).
    @Published private(set) var report: BaselineReport? = BaselineReport()
    @Published private(set) var rules: [BaselineRule] = []
    @Published private(set) var running = false
    @Published private(set) var message = ""

    private let store: SignatureStore
    private let classifier: PatternClassifier?
    private let defaults: UserDefaults
    private var timer: Timer?
    private var applyTimer: Timer?
    private var migrated = false
    private var refreshScheduled = false
    private var revisionWatch: AnyCancellable?
    var identify: BaselinePolicy.Identify = { path in
        guard let id = SigningCache.shared.identity(path) else { return (nil, false) }
        return (id, SigningCache.shared.trusts(path, id))
    }
    var now: () -> Date = { Date() }

    init(store: SignatureStore, classifier: PatternClassifier?, defaults: UserDefaults = .standard, freshInstall: Bool) {
        self.store = store
        self.classifier = classifier
        self.defaults = defaults
        var dismissed = Set(defaults.stringArray(forKey: "baselineDismissed") ?? [])
        if let data = defaults.data(forKey: "baselineReport2"),
           let old = try? JSONDecoder().decode(BaselineReport.self, from: data) {
            dismissed.formUnion(old.dismissed)
            defaults.removeObject(forKey: "baselineReport2")
        }
        report?.dismissed = dismissed
        if let data = defaults.data(forKey: "baselineRules2") {
            rules = (try? JSONDecoder().decode([BaselineRule].self, from: data)) ?? []
        }
        // Rules from before profiles: what they already trust is their profile (nothing floods in).
        for i in rules.indices where rules[i].learnsProfile && rules[i].profile.isEmpty {
            let note = rules[i].note
            rules[i].profile = Set(store.allEntries.filter { $0.note == note }.map(BaselinePolicy.behaviour))
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
        revisionWatch = store.$revision.dropFirst().sink { [weak self] _ in self?.scheduleRefresh() }
        scheduleRefresh()
    }

    /// Rules you deleted: never made again by themselves (Update Baseline still can).
    private var deleted: Set<String> {
        get { Set(defaults.stringArray(forKey: "baselineDeletedRules") ?? []) }
        set { defaults.set(Array(newValue).sorted(), forKey: "baselineDeletedRules") }
    }
    /// New apps from developers you trust get a rule by themselves (Settings ▸ Detection).
    var autoRules: Bool { defaults.object(forKey: "baselineAutoRules") as? Bool ?? true }
    /// Needs You lists only what happened recently.
    static let activeWindow: TimeInterval = 7 * 24 * 3600

    private var startedAt: Date? { defaults.object(forKey: "baselineStartedAt") as? Date }
    private var wavesDone: Int { defaults.integer(forKey: "baselineWavesDone") }

    /// Patterns the baseline rules trust right now.
    var trustedCount: Int { store.allEntries.filter { $0.source == "baseline" }.count }

    func keys(_ rule: BaselineRule) -> [String] {
        store.allEntries.filter { $0.note == rule.note && ($0.source == "baseline" || $0.source == "you") }.map(\.id)
    }

    func patternCount(_ rule: BaselineRule) -> Int { keys(rule).count }

    private func updatePhase() {
        guard let startedAt else { phase = rules.isEmpty ? .idle : .done; return }
        if wavesDone >= Self.waves.count { phase = .done; return }
        phase = .learning(wave: wavesDone + 1, at: startedAt.addingTimeInterval(Self.waves[wavesDone]))
    }

    private func save() {
        defaults.set(Array(report?.dismissed ?? []).sorted(), forKey: "baselineDismissed")
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
        store.allEntries.filter { $0.status == .unclassified && $0.source == nil && $0.reopened == nil
            && store.status(forKey: $0.id) == .unclassified }
    }

    private func scheduleRefresh() {
        guard !refreshScheduled else { return }
        refreshScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self else { return }
            self.refreshScheduled = false
            Task { await self.refreshReview() }
        }
    }

    /// Rebuilds Needs You from every New pattern. Ones an active rule will trust on its next pass aren't listed.
    func refreshReview() async {
        var report = BaselineReport(dismissed: self.report?.dismissed ?? [])
        // Decided patterns sent back because something changed: always listed, with why.
        for e in store.allEntries where e.reopened != nil && store.status(forKey: e.id) == .unclassified {
            let path = SignatureStore.subjectPath(e)
            report.add(app: BaselinePolicy.appName(path.isEmpty ? e.process : path), reason: "Reopened: " + (e.reopened ?? ""), key: e.id)
        }
        // Only what happened lately: something seen once a week ago stays New in Patterns, not here.
        let active = newPatterns.filter { now().timeIntervalSince($0.lastSeen) < Self.activeWindow }
        for (entry, decision) in await decide(active) {
            switch decision {
            case .ignore: continue
            case .trust(let key):
                if let rule = rules.first(where: { $0.id == key.id }) {
                    if rule.paused {
                        report.add(app: key.name, reason: "its baseline rule is paused", key: entry.id)
                    } else if !admit(entry, ruleID: key.id, record: false) {
                        report.add(app: key.name, reason: "new for \(key.name): \(BaselinePolicy.behaviour(entry))", key: entry.id)
                    }
                } else if !makesItself(key) {
                    report.add(app: key.name, reason: "signed by \(key.signer) (trusted developer, no rule yet)", key: entry.id)
                }
            case .onDevice(let app):
                let signer = identify(SignatureStore.subjectPath(entry)).identity?.label ?? "unknown developer"
                report.add(app: app, reason: "signed by \(signer), a developer you haven't trusted", key: entry.id)
            case .review(let app, let reason):
                // Homebrew's tools are one decision, not one row each.
                if BaselinePolicy.isHomebrew(SignatureStore.subjectPath(entry)) {
                    report.add(app: "Homebrew tools", reason: "\(app): ad-hoc signed by Homebrew", key: entry.id)
                } else {
                    report.add(app: app, reason: reason, key: entry.id)
                }
            }
        }
        report.sort()
        if report != self.report { self.report = report }
    }

    /// May this rule trust this pattern? During the rule's first week it learns the kind of behaviour; after
    /// that only known kinds pass (`record: false` only asks).
    @discardableResult
    private func admit(_ entry: SignatureEntry, ruleID: String, record: Bool = true) -> Bool {
        guard let i = rules.firstIndex(where: { $0.id == ruleID }), !rules[i].paused else { return false }
        guard rules[i].learnsProfile else { return true }
        let kind = BaselinePolicy.behaviour(entry)
        if rules[i].profile.contains(kind) { return true }
        guard now().timeIntervalSince(rules[i].created) < BaselineRule.learningPeriod else { return false }
        if record { rules[i].profile.insert(kind) }
        return true
    }

    /// Would a rule be made by itself for this key (macOS itself, or a trusted developer's app)?
    private func makesItself(_ key: BaselineKey) -> Bool {
        !deleted.contains(key.id) && (key.id == "system" || autoRules)
    }

    private func trust(_ keys: [String], by rule: BaselineRule) {
        store.set(.safe, keys: keys, source: "baseline", note: rule.note)
    }

    @discardableResult
    private func ensureRule(_ key: BaselineKey, approved: Bool = false, automatic: Bool = false) -> BaselineRule {
        if let i = rules.firstIndex(where: { $0.id == key.id }) {
            if approved { rules[i].approvedByYou = true; rules[i].paused = false }
            return rules[i]
        }
        var gone = deleted
        if gone.remove(key.id) != nil { deleted = gone }               // made again on purpose
        let rule = BaselineRule(id: key.id, name: key.name, signer: key.signer, approvedByYou: approved, created: now(),
                                automatic: automatic)
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
        var byRule: [String: [String]] = [:]
        var onDeviceKeys: [String] = []
        for (entry, decision) in decisions {
            switch decision {
            case .trust(let key):
                ensureRule(key)
                if admit(entry, ruleID: key.id) { byRule[key.id, default: []].append(entry.id) }
            case .onDevice: onDeviceKeys.append(entry.id)
            case .review, .ignore: break
            }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
        if !onDeviceKeys.isEmpty { classifier?.triageOnDevice(keys: onDeviceKeys) }   // suggestions for you
        if startedAt != nil, wavesDone < Self.waves.count { defaults.set(wavesDone + 1, forKey: "baselineWavesDone") }
        save()
        updatePhase()
        await applyApproved()
        await refreshReview()
    }

    /// Between waves and after learning: rules trust new patterns of their apps (only kinds of behaviour the
    /// app showed in its first week). macOS itself, and new apps from developers you trust (Settings ▸
    /// Detection), get a rule by themselves; a rule you deleted doesn't come back.
    func applyRules() async {
        guard !running else { return }
        let candidates = newPatterns
        guard !candidates.isEmpty else { return }
        var byRule: [String: [String]] = [:]
        var changed = false
        for (entry, decision) in await decide(candidates) {
            guard case .trust(let key) = decision else { continue }
            if !rules.contains(where: { $0.id == key.id }) {
                guard makesItself(key) else { continue }
                ensureRule(key, automatic: true)
                changed = true
            }
            if admit(entry, ruleID: key.id) { byRule[key.id, default: []].append(entry.id); changed = true }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
        if changed { save() }
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
            if case .trust(let key) = decision, approved.contains(where: { $0.id == key.id }), admit(entry, ruleID: key.id) {
                byRule[key.id, default: []].append(entry.id)
            }
        }
        for (id, keys) in byRule { if let rule = rules.first(where: { $0.id == id }) { trust(keys, by: rule) } }
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
        deleted.insert(rule.id)
        save()
        scheduleRefresh()
    }

    /// Every baseline rule removed and everything they trusted automatically back to New.
    func undo() {
        let keys = store.allEntries.filter { $0.source == "baseline" }.map(\.id)
        store.set(.unclassified, keys: keys)
        deleted.formUnion(rules.map(\.id))
        rules = []
        save()
        scheduleRefresh()
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
        save()
        await applyApproved()
        await refreshReview()
    }

    /// Your decision: applies the AI's suggestions for this app's patterns.
    func acceptSuggestions(_ group: BaselineReport.Group) async {
        let n = store.acceptSuggestions(keys: group.keys)
        message = n == 0 ? "No AI suggestions to accept for \(group.app)."
            : "Accepted \(n) AI suggestion\(n == 1 ? "" : "s") for \(group.app)."
        await refreshReview()
    }

    /// The group's patterns, high risk first.
    func entries(_ group: BaselineReport.Group) -> [SignatureEntry] {
        group.keys.compactMap { store.entry($0) }
            .sorted { $0.risk != $1.risk ? $0.risk > $1.risk : $0.lastSeen > $1.lastSeen }
    }

    /// Interpreters and shells (python, node, sh, osascript…) run whatever code they're given, so trusting
    /// them would trust any script, a virus's too. The review offers only Dismiss or Mark Suspicious.
    func runsAnyCode(_ group: BaselineReport.Group) -> Bool {
        group.keys.contains { key in store.entry(key).map(BaselinePolicy.runsAnyCode) ?? false }
    }

    func markSuspicious(_ group: BaselineReport.Group) {
        store.set(.suspicious, keys: group.keys, source: "you", note: "Marked suspicious from the baseline review")
        report?.review.removeAll { $0.id == group.id }
        message = "Marked \(group.app) suspicious."
        save()
    }

    /// Hides the row: the patterns stay New (and still count everywhere else).
    func dismiss(_ group: BaselineReport.Group) {
        report?.dismissed.formUnion(group.keys)
        report?.review.removeAll { $0.id == group.id }
        message = "Dismissed \(group.app): its patterns stay New."
        save()
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
