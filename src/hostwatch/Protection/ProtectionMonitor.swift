import Foundation

/// On an event: whether protection would stop it (Watch) or did (Endpoint Security). Questions are counted on the
/// Protection page, not marked in Events: a busy machine has many, and the list must keep exceptions visible.
enum ProtectionMark: UInt8, Sendable { case none, wouldBlock, blocked }

/// Whether the collector can enforce: its Endpoint Security client, as macOS answered it.
enum EnforcerState: Equatable, Sendable {
    case unknown, available, notEntitled, notPermitted, unsupported, failed(String)

    init(state: String, detail: String) {
        switch state {
        case "available": self = .available
        case "not_entitled": self = .notEntitled
        case "not_permitted": self = .notPermitted
        case "unsupported": self = .unsupported
        case "unknown", "": self = .unknown
        default: self = .failed(detail.isEmpty ? state : detail)
        }
    }

    var canEnforce: Bool { self == .available }

    /// For the Protection page, in plain words.
    var text: String {
        switch self {
        case .unknown: "Stopping launches and file access needs an Endpoint Security client, which this version "
            + "doesn't have yet. Watch shows what would be stopped."
        case .available: "Endpoint Security is on: Ask and Strict stop things for real."
        case .notEntitled: "Stopping needs Apple's Endpoint Security approval for Hostwatch, which is pending. "
            + "Until then Watch shows what would be stopped."
        case .notPermitted: "Endpoint Security needs Full Disk Access for the collector."
        case .unsupported: "This Mac's collector can't use Endpoint Security."
        case .failed(let why): "Endpoint Security didn't start: \(why)"
        }
    }
}

/// What protection would stop or ask about, folded by pattern: the rehearsal's findings.
struct ProtectionFinding: Codable, Identifiable, Equatable, Sendable {
    var id: String                                  // area|pattern key
    var area: ProtectionArea
    var patternKey: String
    var name: String
    var program: String
    var pattern: String
    var verdict: ProtectionVerdict
    var reason: String
    var group: String?
    var count: Int
    var firstSeen: Date
    var lastSeen: Date
    var enforced = false                            // stopped for real, not just in rehearsal
}

/// A question from the collector's Endpoint Security client: a launch or file access it holds for an answer.
struct ProtectionAsk: Identifiable, Sendable {
    var id: Int
    var event: ActivityEvent
    var area: ProtectionArea
    var reason: String
    var group: String?
    var deadline: Date
}

@MainActor
final class ProtectionMonitor: ObservableObject {
    @Published var launchMode: ProtectionMode { didSet { defaults.set(launchMode.rawValue, forKey: Keys.launch); changed() } }
    @Published var fileMode: ProtectionMode { didSet { defaults.set(fileMode.rawValue, forKey: Keys.file); changed() } }
    @Published var groups: [String: ProtectedGroupSetting] {
        didSet { defaults.set(try? JSONEncoder().encode(groups), forKey: Keys.groups); changed() }
    }
    /// The kill switch: nothing is stopped (or rehearsed) until then.
    @Published var pausedUntil: Date? { didSet { changed() } }
    @Published private(set) var enforcer: EnforcerState = .unknown
    /// Findings and counts changed (at most once a second: they change with events).
    @Published private(set) var revision = 0
    @Published private(set) var prompts: [ProtectionAsk] = []

    private(set) var findings: [String: ProtectionFinding] = [:]
    /// When rehearsal started: "Watching for 3 days".
    private(set) var since: Date
    private(set) var today: [ProtectionArea: [ProtectionVerdict: Int]] = [:]
    private var todayKey = ""

    /// The collector's configuration changed: send it.
    var onConfigChange: (() -> Void)?
    /// Answers a held launch or file access: (id, allow, seconds the collector may reuse the answer).
    var answer: ((Int, Bool, TimeInterval) -> Void)?
    /// Your answer that should stick: the pattern marked Safe (Always Allow) or Dangerous (Block).
    var markPattern: ((String, SignatureStatus) -> Void)?
    var onPromptsChange: (() -> Void)?

    private let defaults: UserDefaults
    private let fileURL: URL
    private var dirty = false
    private var publishScheduled = false
    static let findingLimit = 300

    private enum Keys {
        static let launch = "protectionLaunchMode", file = "protectionFileMode", groups = "protectionGroups"
        static let since = "protectionSince"
    }

    init(defaults: UserDefaults = .standard,
         fileURL: URL = AppPaths.support.appendingPathComponent("protection-findings.json")) {
        self.defaults = defaults
        self.fileURL = fileURL
        // Watch by default: it stops nothing, and it is how you learn what Ask would do before turning it on.
        launchMode = defaults.string(forKey: Keys.launch).flatMap(ProtectionMode.init) ?? .watch
        fileMode = defaults.string(forKey: Keys.file).flatMap(ProtectionMode.init) ?? .watch
        groups = defaults.data(forKey: Keys.groups).flatMap { try? JSONDecoder().decode([String: ProtectedGroupSetting].self, from: $0) } ?? [:]
        let started = defaults.object(forKey: Keys.since) as? Date ?? Date()
        since = started
        defaults.set(started, forKey: Keys.since)
        if let data = Vault.shared.read(fileURL), let saved = try? Self.decoder.decode([ProtectionFinding].self, from: data) {
            findings = Dictionary(saved.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        }
    }

    func mode(_ area: ProtectionArea) -> ProtectionMode { area == .launches ? launchMode : fileMode }

    func setMode(_ mode: ProtectionMode, for area: ProtectionArea) {
        if area == .launches { launchMode = mode } else { fileMode = mode }
    }

    var paused: Bool { (pausedUntil ?? .distantPast) > Date() }

    func pause(minutes: Double) { pausedUntil = Date().addingTimeInterval(minutes * 60) }
    func resume() { pausedUntil = nil }

    /// What the window's subtitle says: nil when everything is off.
    var stateWord: String? {
        if paused { return "Protection paused" }
        let modes = ProtectionArea.allCases.map(mode)
        if modes.contains(where: \.enforces) && enforcer.canEnforce { return "Protecting" }
        return modes.contains(where: { $0 != .off }) ? "Rehearsing" : nil
    }

    func enforcerStatus(_ state: String, _ detail: String) {
        let new = EnforcerState(state: state, detail: detail)
        if new != enforcer { enforcer = new }
    }

    // MARK: The live feed (Watch)

    /// One live event: marks it when protection would stop it, and counts what it would do.
    func consider(_ e: inout ActivityEvent, status: SignatureStatus) {
        guard !paused, let (area, decision) = decide(e, status: status) else { return }
        let mode = self.mode(area)
        // With Endpoint Security enforcing, what reaches the feed was allowed: the collector reports what it stopped.
        if mode.enforces && enforcer.canEnforce { return }
        guard let verdict = ProtectionPolicy.effective(decision.verdict, mode: mode), verdict != .allow else { return }
        record(area: area, event: e, decision: decision, verdict: verdict, enforced: false)
        if verdict == .block {
            e.protection = .wouldBlock
            e.protectionReason = decision.reason
        }
    }

    /// The policy's decision for an event, before the mode: nil for connections (the firewall's) and unprotected files.
    func decide(_ e: ActivityEvent, status: SignatureStatus) -> (ProtectionArea, ProtectionDecision)? {
        switch e.kind {
        case .exec:
            guard launchMode != .off else { return nil }
            return (.launches, ProtectionPolicy.decideLaunch(target: e.target, status: status, risk: e.signatureRisk,
                                                             riskReason: e.signatureReason, knownBad: e.knownBad))
        case .file:
            guard fileMode != .off, let d = ProtectionPolicy.decideFile(pattern: e.signaturePattern, status: status,
                                                                        risk: e.signatureRisk, settings: groups)
            else { return nil }
            return (.files, d)
        case .net:
            return nil
        }
    }

    private func record(area: ProtectionArea, event e: ActivityEvent, decision: ProtectionDecision,
                        verdict: ProtectionVerdict, enforced: Bool) {
        let now = Date()
        let day = now.formatted(.iso8601.year().month().day())
        if day != todayKey { todayKey = day; today = [:] }
        today[area, default: [:]][verdict, default: 0] += 1
        let id = "\(area.rawValue)|\(e.signatureKey)"
        if var f = findings[id] {
            f.count += 1
            f.lastSeen = now
            f.verdict = verdict
            f.reason = decision.reason
            f.enforced = f.enforced || enforced
            findings[id] = f
        } else {
            findings[id] = ProtectionFinding(id: id, area: area, patternKey: e.signatureKey, name: e.name,
                                             program: e.kind == .exec ? e.target : e.proc, pattern: e.signaturePattern,
                                             verdict: verdict, reason: decision.reason, group: decision.group, count: 1,
                                             firstSeen: now, lastSeen: now, enforced: enforced)
            if findings.count > Self.findingLimit, let oldest = findings.values.min(by: { $0.lastSeen < $1.lastSeen }) {
                findings[oldest.id] = nil
            }
        }
        dirty = true
        publishSoon()
    }

    /// You decided these patterns (anywhere): their findings have done their job.
    func decided(patternKeys: [String]) {
        let keys = Set(patternKeys)
        let before = findings.count
        findings = findings.filter { !keys.contains($0.value.patternKey) }
        if findings.count != before { dirty = true; publishSoon() }
    }

    func forget(_ ids: [String]) {
        for id in ids { findings[id] = nil }
        dirty = true
        publishSoon()
    }

    func count(_ area: ProtectionArea, _ verdict: ProtectionVerdict) -> Int { today[area]?[verdict] ?? 0 }

    /// Per protected-files card: what was (or would be) stopped there, in the findings kept.
    func findings(group: String) -> [ProtectionFinding] { findings.values.filter { $0.group == group } }

    private func publishSoon() {
        guard !publishScheduled else { return }
        publishScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.publishScheduled = false
                self.revision += 1
                self.save()
            }
        }
    }

    func save() {
        guard dirty, let data = try? Self.encoder.encode(Array(findings.values)) else { return }
        dirty = false
        try? Vault.shared.write(data, to: fileURL)
    }

    private func changed() {
        onConfigChange?()
        revision += 1
    }

    // MARK: The collector (Endpoint Security)

    /// What the collector needs to decide on its own: modes, and each protected card's places, expected programs and
    /// choice for everyone else. Launches it can't settle quickly come back as questions.
    func collectorConfig(home: String = NSHomeDirectory()) -> [String: Any] {
        let cards: [[String: Any]] = ProtectedGroup.all.compactMap { g in
            let s = groups[g.id] ?? ProtectedGroupSetting()
            guard s.on else { return nil }
            return ["id": g.id, "prefixes": g.prefixes(home: home), "owners": g.owners, "writesOnly": g.writesOnly,
                    "others": s.others.rawValue]
        }
        return ["launches": paused ? "off" : launchMode.rawValue, "files": paused ? "off" : fileMode.rawValue,
                "groups": cards, "hostwatch": Bundle.main.executablePath ?? ""]
    }

    /// A launch or file access the collector holds: answered at once by the policy, or asked about in a panel.
    func handleAsk(_ ask: ProtectionAsk, status: SignatureStatus) {
        guard let (area, decision) = decide(ask.event, status: status),
              let verdict = ProtectionPolicy.effective(decision.verdict, mode: mode(area)), !paused
        else { answer?(ask.id, true, 60); return }
        switch verdict {
        case .allow:
            answer?(ask.id, true, 300)
        case .block:
            answer?(ask.id, false, 60)
            record(area: area, event: ask.event, decision: decision, verdict: .block, enforced: true)
        case .ask:
            var held = ask
            held.reason = decision.reason
            held.group = decision.group
            prompts.append(held)
            onPromptsChange?()
        }
    }

    enum PromptAnswer { case block, allowOnce, alwaysAllow }

    /// Your answer in the panel. Block and Always Allow stick as pattern decisions, as in the firewall.
    func respond(_ id: Int, _ choice: PromptAnswer) {
        guard let i = prompts.firstIndex(where: { $0.id == id }) else { return }
        let ask = prompts.remove(at: i)
        onPromptsChange?()
        switch choice {
        case .block:
            answer?(id, false, 60)
            markPattern?(ask.event.signatureKey, .dangerous)
            record(area: ask.area, event: ask.event,
                   decision: .init(verdict: .block, reason: "you blocked it", group: ask.group), verdict: .block, enforced: true)
        case .allowOnce:
            answer?(id, true, 0)
        case .alwaysAllow:
            answer?(id, true, 300)
            markPattern?(ask.event.signatureKey, .safe)
        }
    }

    /// The collector gave up waiting (it decides by the mode then): the question goes.
    func expire(_ id: Int) {
        prompts.removeAll { $0.id == id }
        onPromptsChange?()
    }

    /// Something the collector stopped on its own (a reused answer, or Strict without the app).
    func collectorBlocked(_ event: ActivityEvent, area: ProtectionArea, reason: String) {
        record(area: area, event: event, decision: .init(verdict: .block, reason: reason), verdict: .block, enforced: true)
    }

    private static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .secondsSince1970; return e }()
    private static let decoder: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970; return d }()
}
