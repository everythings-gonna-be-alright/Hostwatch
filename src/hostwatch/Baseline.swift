import AppKit
import Foundation
import SwiftUI

// MARK: - Policy

/// What the baseline does with one New pattern.
enum BaselineDecision: Equatable {
    case trust(app: String, signer: String, key: String)   // signed by Apple or a trusted developer
    case onDevice(app: String)                  // signed, developer not yet trusted: the on-device model decides
    case review(app: String, reason: String)    // stays New: your decision
}

/// Decides, from signing facts only, which New patterns are ordinary enough to trust while learning.
/// Anything that could be malware already on the Mac (unsigned, downloaded, temp, high-risk,
/// touching login items or credentials) is left for you, so the baseline can't be poisoned.
enum BaselinePolicy {
    typealias Identify = (String) -> (identity: CodeIdentity?, trusted: Bool)

    static let dropZones = ["/Downloads/", "/Users/Shared/", "/var/folders/", "/Volumes/"]
    static let tempPrefixes = ["/tmp/", "/private/tmp/"]

    static func decide(_ e: SignatureEntry, identify: Identify) -> BaselineDecision {
        let subject = SignatureStore.subjectPath(e)
        let app = appName(subject.isEmpty ? e.process : subject)
        if e.risk == .high { return .review(app: app, reason: "high risk" + (e.note.map { ": \($0)" } ?? "")) }
        if e.pattern.hasSuffix("]") { return .review(app: app, reason: "touches a sensitive place (\(e.pattern))") }
        // The program that acts, and for a launch the program launched: both must be trusted.
        let actor = e.kind == .exec ? e.exampleParent : e.exampleProc
        var signer = ""
        var key: String?
        var allTrusted = true
        for path in Set([subject, actor]).filter({ !$0.isEmpty }) {
            if dropZones.contains(where: path.contains) || tempPrefixes.contains(where: path.hasPrefix) {
                return .review(app: app, reason: "runs from Downloads or a temporary folder")
            }
            let (id, trusted) = identify(path)
            guard let id else { return .review(app: app, reason: "\(appName(path)): program not found") }
            if id.valid == false { return .review(app: app, reason: "\(appName(path)): invalid signature") }
            if id.untrustedCode { return .review(app: app, reason: "\(appName(path)): \(id.label.lowercased())") }
            if id.quarantined { return .review(app: app, reason: "\(appName(path)): downloaded (quarantined)") }
            if !trusted { allTrusted = false }
            if path == subject { signer = id.label; key = signerKey(id) }
        }
        guard allTrusted, let key else { return .onDevice(app: app) }
        return .trust(app: app, signer: signer.isEmpty ? "trusted" : signer, key: key)
    }

    /// Who a baseline rule is about: Apple, or one developer (Team ID).
    static func signerKey(_ id: CodeIdentity) -> String? {
        if id.apple { return "apple" }
        return id.teamID.map { "team:" + $0 }
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

struct BaselineReport: Codable, Equatable {
    struct Group: Codable, Equatable, Identifiable {
        var app: String
        var detail: String          // signer, or why it needs review
        var keys: [String]
        var id: String { app + "|" + detail }
    }
    var date = Date()
    var onDevice: [Group] = []
    var review: [Group] = []

    var onDeviceCount: Int { onDevice.reduce(0) { $0 + $1.keys.count } }
    var reviewCount: Int { review.reduce(0) { $0 + $1.keys.count } }

    mutating func add(_ decision: BaselineDecision, key: String) {
        func put(_ list: inout [Group], _ app: String, _ detail: String) {
            if let i = list.firstIndex(where: { $0.app == app && $0.detail == detail }) {
                if !list[i].keys.contains(key) { list[i].keys.append(key) }
            } else {
                list.append(Group(app: app, detail: detail, keys: [key]))
            }
        }
        switch decision {
        case .trust: break                       // shown as baseline rules
        case .onDevice(let app): put(&onDevice, app, "signed, developer not yet trusted")
        case .review(let app, let reason): put(&review, app, reason)
        }
    }

    /// Drops keys that are no longer New (you or a later wave decided them).
    mutating func prune(_ stillNew: (String) -> Bool) {
        review = review.map { var g = $0; g.keys = g.keys.filter(stillNew); return g }.filter { !$0.keys.isEmpty }
        onDevice = onDevice.map { var g = $0; g.keys = g.keys.filter(stillNew); return g }.filter { !$0.keys.isEmpty }
    }
}

// MARK: - Baseline rules

/// "Patterns of software signed by X are ordinary": made by the learning waves, one per signer
/// (Apple, or one developer's Team ID). It keeps applying to future normal-risk patterns, always
/// through `BaselinePolicy` (never high risk, unsigned, downloaded or sensitive). Low weight: your
/// markings and learned rules win, and stories ignore it.
struct BaselineRule: Codable, Identifiable, Equatable {
    var id: String              // "apple" or "team:BQR82RBBHL"
    var name: String            // "Apple", "Slack Technologies"
    var apps: [String] = []     // apps seen with this signer (up to 8)
    var paused = false
    var created = Date()

    var signerText: String { id == "apple" ? "Signed by Apple" : "Team \(id.dropFirst(5))" }
    /// The note on patterns this rule trusted (also how they're found again).
    var note: String { "Baseline: \(name)" }
}

// MARK: - Learner

/// Learns this Mac's normal behaviour in waves after the first launch (5, 15 and 60 minutes). Each
/// wave sorts New patterns with `BaselinePolicy` and turns trusted signers into baseline rules, which
/// then keep trusting their future normal-risk patterns.
@MainActor
final class BaselineLearner: ObservableObject {
    static let waves: [TimeInterval] = [5 * 60, 15 * 60, 60 * 60]
    static let applyInterval: TimeInterval = 30

    enum Phase: Equatable { case idle, learning(wave: Int, at: Date), done }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var report: BaselineReport?
    @Published private(set) var rules: [BaselineRule] = []
    @Published private(set) var running = false

    private let store: SignatureStore
    private let classifier: PatternClassifier?
    private let defaults: UserDefaults
    private var timer: Timer?
    private var applyTimer: Timer?
    var identify: BaselinePolicy.Identify = { path in
        guard let id = SigningCache.shared.identity(path) else { return (nil, false) }
        return (id, SigningCache.shared.trusts(path, id))
    }
    var now: () -> Date = { Date() }

    init(store: SignatureStore, classifier: PatternClassifier?, defaults: UserDefaults = .standard, freshInstall: Bool) {
        self.store = store
        self.classifier = classifier
        self.defaults = defaults
        if let data = defaults.data(forKey: "baselineReport") {
            report = try? JSONDecoder().decode(BaselineReport.self, from: data)
        }
        if let data = defaults.data(forKey: "baselineRules") {
            rules = (try? JSONDecoder().decode([BaselineRule].self, from: data)) ?? []
        }
        if freshInstall, defaults.object(forKey: "baselineStartedAt") == nil {
            defaults.set(Date(), forKey: "baselineStartedAt")
            defaults.set(0, forKey: "baselineWavesDone")
        }
        updatePhase()
    }

    private var startedAt: Date? { defaults.object(forKey: "baselineStartedAt") as? Date }
    private var wavesDone: Int { defaults.integer(forKey: "baselineWavesDone") }

    /// Patterns the baseline trusts right now.
    var trustedCount: Int { store.allEntries.filter { $0.source == "baseline" }.count }

    func patternCount(_ rule: BaselineRule) -> Int {
        store.allEntries.filter { $0.source == "baseline" && $0.note == rule.note }.count
    }

    private func updatePhase() {
        guard let startedAt else { phase = (report == nil && rules.isEmpty) ? .idle : .done; return }
        if wavesDone >= Self.waves.count { phase = .done; return }
        phase = .learning(wave: wavesDone + 1, at: startedAt.addingTimeInterval(Self.waves[wavesDone]))
    }

    private func save() {
        if let report, let data = try? JSONEncoder().encode(report) { defaults.set(data, forKey: "baselineReport") }
        if let data = try? JSONEncoder().encode(rules) { defaults.set(data, forKey: "baselineRules") }
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
        guard case .learning(_, let at) = phase else { return }
        let delay = max(1, at.timeIntervalSince(now()))
        timer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.runWave(); self.schedule() }
            }
        }
    }

    private func decide(_ entries: [SignatureEntry]) async -> [(SignatureEntry, BaselineDecision)] {
        let identify = self.identify
        return await Task.detached(priority: .utility) {
            entries.map { ($0, BaselinePolicy.decide($0, identify: identify)) }
        }.value
    }

    private var newPatterns: [SignatureEntry] {
        store.allEntries.filter { $0.status == .unclassified && $0.source == nil }
    }

    private func trust(_ keys: [String], by rule: BaselineRule) {
        store.set(.safe, keys: keys, source: "baseline", note: rule.note)
    }

    /// One learning wave now (also "Build Now"): sorts New patterns and makes rules for trusted signers.
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
            case .trust(let app, let signer, let key):
                if let i = rules.firstIndex(where: { $0.id == key }) {
                    if !rules[i].apps.contains(app), rules[i].apps.count < 8 { rules[i].apps.append(app) }
                } else {
                    rules.append(BaselineRule(id: key, name: key == "apple" ? "Apple" : signer, apps: [app], created: now()))
                }
                if rules.first(where: { $0.id == key })?.paused == false { byRule[key, default: []].append(entry.id) }
            case .onDevice: onDeviceKeys.append(entry.id)
            case .review: break
            }
        }
        for (key, keys) in byRule { if let rule = rules.first(where: { $0.id == key }) { trust(keys, by: rule) } }
        if !onDeviceKeys.isEmpty { classifier?.triageOnDevice(keys: onDeviceKeys) }
        report.prune { [store] key in store.status(forKey: key) == .unclassified }
        self.report = report
        rules.sort { $0.id == "apple" ? true : $1.id == "apple" ? false : $0.name < $1.name }
        if startedAt != nil, wavesDone < Self.waves.count { defaults.set(wavesDone + 1, forKey: "baselineWavesDone") }
        save()
        updatePhase()
    }

    /// Between waves and after learning: existing, active rules trust new patterns of their signers.
    /// No new rules here (new developers wait for you or Build Now).
    func applyRules() async {
        guard !running, rules.contains(where: { !$0.paused }) else { return }
        let candidates = newPatterns
        guard !candidates.isEmpty else { return }
        var byRule: [String: [String]] = [:]
        for (entry, decision) in await decide(candidates) {
            if case .trust(_, _, let key) = decision, rules.contains(where: { $0.id == key && !$0.paused }) {
                byRule[key, default: []].append(entry.id)
            }
        }
        for (key, keys) in byRule { if let rule = rules.first(where: { $0.id == key }) { trust(keys, by: rule) } }
    }

    /// "Build Now": for existing installs, or to finish learning early.
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

    /// Paused: its patterns go back to New and it stops applying (kept, so Build Now won't recreate it).
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

    /// Every baseline rule removed and everything it trusted back to New.
    func undo() {
        let keys = store.allEntries.filter { $0.source == "baseline" }.map(\.id)
        store.set(.unclassified, keys: keys)
        rules = []
        save()
    }

    /// Trust all patterns of one app that need review (your decision).
    func trust(_ group: BaselineReport.Group) {
        store.set(.safe, keys: group.keys, source: "you", note: "Trusted from the baseline review")
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        save()
    }

    var statusText: String {
        switch phase {
        case .idle: return "Not built yet"
        case .learning(let wave, let at):
            return "Learning · wave \(wave) of \(Self.waves.count) at \(at.formatted(date: .omitted, time: .shortened))"
        case .done:
            let review = report?.reviewCount ?? 0
            return "\(rules.filter { !$0.paused }.count) rules trust \(trustedCount) patterns · \(review) need review"
        }
    }
}
