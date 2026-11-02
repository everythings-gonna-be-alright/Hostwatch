import AppKit
import Foundation
import SwiftUI

// MARK: - Policy

/// What the baseline does with one New pattern.
enum BaselineDecision: Equatable {
    case trust(app: String, signer: String)     // marked Safe automatically
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
            if path == subject { signer = id.label }
        }
        return allTrusted ? .trust(app: app, signer: signer.isEmpty ? "trusted" : signer) : .onDevice(app: app)
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
    var trusted: [Group] = []
    var onDevice: [Group] = []
    var review: [Group] = []

    var trustedCount: Int { trusted.reduce(0) { $0 + $1.keys.count } }
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
        case .trust(let app, let signer): put(&trusted, app, signer)
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

// MARK: - Learner

/// Learns this Mac's normal behaviour in waves after the first launch (5, 15 and 60 minutes):
/// each wave sorts the New patterns seen so far with `BaselinePolicy`.
@MainActor
final class BaselineLearner: ObservableObject {
    static let waves: [TimeInterval] = [5 * 60, 15 * 60, 60 * 60]

    enum Phase: Equatable { case idle, learning(wave: Int, at: Date), done }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var report: BaselineReport?
    @Published private(set) var running = false

    private let store: SignatureStore
    private let classifier: PatternClassifier?
    private let defaults: UserDefaults
    private var timer: Timer?
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
        if freshInstall, defaults.object(forKey: "baselineStartedAt") == nil {
            defaults.set(Date(), forKey: "baselineStartedAt")
            defaults.set(0, forKey: "baselineWavesDone")
        }
        updatePhase()
    }

    private var startedAt: Date? { defaults.object(forKey: "baselineStartedAt") as? Date }
    private var wavesDone: Int { defaults.integer(forKey: "baselineWavesDone") }

    private func updatePhase() {
        guard let startedAt else { phase = report == nil ? .idle : .done; return }
        if wavesDone >= Self.waves.count { phase = .done; return }
        phase = .learning(wave: wavesDone + 1, at: startedAt.addingTimeInterval(Self.waves[wavesDone]))
    }

    /// Runs waves that are due and schedules the next one.
    func schedule() {
        timer?.invalidate()
        timer = nil
        guard case .learning(_, let at) = phase else { return }
        let delay = max(1, at.timeIntervalSince(now()))
        timer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.runWave(); self.schedule() }
            }
        }
    }

    /// One wave now (also "Build Baseline Now"). Returns when patterns are sorted (the on-device
    /// part continues in the classifier).
    func runWave() async {
        guard !running else { return }
        running = true
        defer { running = false }
        let candidates = store.allEntries.filter { $0.status == .unclassified && $0.source == nil }
        let identify = self.identify
        let decisions: [(String, BaselineDecision)] = await Task.detached(priority: .utility) {
            candidates.map { ($0.id, BaselinePolicy.decide($0, identify: identify)) }
        }.value
        var report = self.report ?? BaselineReport()
        report.date = now()
        var trustKeys: [String: [String]] = [:]   // note -> keys
        var onDeviceKeys: [String] = []
        for (key, decision) in decisions {
            report.add(decision, key: key)
            switch decision {
            case .trust(_, let signer): trustKeys["Baseline: signed by \(signer)", default: []].append(key)
            case .onDevice: onDeviceKeys.append(key)
            case .review: break
            }
        }
        for (note, keys) in trustKeys { store.set(.safe, keys: keys, source: "baseline", note: note) }
        if !onDeviceKeys.isEmpty { classifier?.triageOnDevice(keys: onDeviceKeys) }
        report.prune { [store] key in store.status(forKey: key) == .unclassified }
        self.report = report
        if let data = try? JSONEncoder().encode(report) { defaults.set(data, forKey: "baselineReport") }
        if startedAt != nil, wavesDone < Self.waves.count {
            defaults.set(wavesDone + 1, forKey: "baselineWavesDone")
        }
        updatePhase()
    }

    /// "Build Baseline Now": for existing installs, or to finish learning early.
    func buildNow() async {
        if startedAt == nil { defaults.set(now(), forKey: "baselineStartedAt") }
        defaults.set(Self.waves.count - 1, forKey: "baselineWavesDone")   // this run is the last wave
        timer?.invalidate()
        await runWave()
    }

    /// Puts everything the baseline trusted back to New.
    func undo() {
        let keys = store.allEntries.filter { $0.source == "baseline" }.map(\.id)
        store.set(.unclassified, keys: keys)
        report?.trusted = []
        if let report, let data = try? JSONEncoder().encode(report) { defaults.set(data, forKey: "baselineReport") }
    }

    /// Trust all patterns of one app that need review (your decision).
    func trust(_ group: BaselineReport.Group) {
        store.set(.safe, keys: group.keys, source: "you", note: "Trusted from the baseline report")
        report?.prune { [store] key in store.status(forKey: key) == .unclassified }
        if let report, let data = try? JSONEncoder().encode(report) { defaults.set(data, forKey: "baselineReport") }
    }

    var statusText: String {
        switch phase {
        case .idle: return "Not built yet"
        case .learning(let wave, let at):
            return "Learning · wave \(wave) of \(Self.waves.count) at \(at.formatted(date: .omitted, time: .shortened))"
        case .done:
            guard let report else { return "Done" }
            return "Trusted \(report.trustedCount) patterns · \(report.reviewCount) need review"
        }
    }
}

// MARK: - Report window

struct BaselineReportView: View {
    @ObservedObject var learner: BaselineLearner
    let showPatterns: (String) -> Void

    var body: some View {
        let report = learner.report ?? BaselineReport()
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundStyle(.green)
                        .frame(width: 52, height: 52)
                        .glassEffect(.regular.tint(Color.green.opacity(0.2)), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    VStack(alignment: .leading, spacing: 4) {
                        Text("This Mac's baseline").font(.title2.weight(.semibold))
                        Text("Trusted \(report.trustedCount) patterns automatically (Apple and developers of your installed apps). "
                             + "\(report.onDeviceCount) checked on this Mac. \(report.reviewCount) need your review.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(learner.statusText).font(.caption).foregroundStyle(.secondary)
                    }
                }
                if !report.review.isEmpty {
                    section("Needs your review", symbol: "exclamationmark.triangle", tint: .orange) {
                        ForEach(report.review) { g in
                            groupRow(g, tint: .orange) {
                                Button("Show") { showPatterns(g.app) }.buttonStyle(.glass)
                                Button("Trust App") { learner.trust(g) }.buttonStyle(.glass)
                                    .help("Mark these \(g.keys.count) patterns Safe (your decision)")
                            }
                        }
                    }
                }
                if !report.trusted.isEmpty {
                    section("Trusted automatically", symbol: "checkmark.seal", tint: .green) {
                        ForEach(report.trusted.sorted { $0.keys.count > $1.keys.count }) { g in
                            groupRow(g, tint: .green) { Button("Show") { showPatterns(g.app) }.buttonStyle(.glass) }
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack {
                Text("Stories still alert on chains, whatever the baseline trusted.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Undo Baseline", role: .destructive) { learner.undo() }
                    .buttonStyle(.glass)
                    .disabled(report.trustedCount == 0)
                    .help("Put every pattern the baseline trusted back to New")
                Button { Task { await learner.buildNow() } } label: {
                    Label(learner.running ? "Sorting…" : "Build Again Now", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.glassProminent)
                .disabled(learner.running)
            }
            .controlSize(.large)
            .padding(.horizontal, 16).padding(.vertical, 10)
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .padding(.horizontal, 12).padding(.bottom, 10)
        }
        .frame(minWidth: 620, minHeight: 520)
    }

    private func section<Content: View>(_ title: String, symbol: String, tint: Color,
                                        @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol).font(.headline).foregroundStyle(tint)
            VStack(spacing: 0) { content() }
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.secondary.opacity(0.07)))
        }
    }

    private func groupRow<Actions: View>(_ g: BaselineReport.Group, tint: Color,
                                         @ViewBuilder actions: () -> Actions) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(g.app).fontWeight(.semibold)
                Text(g.detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            Text("\(g.keys.count)").font(.callout.monospacedDigit()).foregroundStyle(tint)
                .help("\(g.keys.count) patterns")
            actions().controlSize(.small)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }
}
