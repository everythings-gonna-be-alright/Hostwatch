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
        case .unknown: "Ask and Strict act right after a program starts or opens a protected file, a few milliseconds "
            + "late: blocked ones are stopped, questions pause the program until you answer. Only your own programs. "
            + "Endpoint Security, once Apple approves it, will stop them before they run."
        case .available: "Endpoint Security is on: Ask and Strict stop things for real."
        case .notEntitled: "Endpoint Security approval is pending, so Ask and Strict act right after a program starts "
            + "or opens a protected file, a few milliseconds late. Only your own programs."
        case .notPermitted: "Endpoint Security needs Full Disk Access for the collector."
        case .unsupported: "This Mac's collector can't use Endpoint Security."
        case .failed(let why): "Endpoint Security didn't start: \(why)"
        }
    }
}

/// What protection would stop or ask about, folded by pattern: the rehearsal's findings.
struct ProtectionFinding: Codable, Identifiable, Equatable, Sendable {
    /// How long a finding stays when it doesn't happen again: a question a week, something that would be stopped a
    /// month (it matters more). Only the list entry goes: the pattern and your decisions stay, and it comes back if
    /// it happens again.
    static func keeps(_ verdict: ProtectionVerdict) -> TimeInterval { verdict == .block ? 30 * 86_400 : 7 * 86_400 }

    func isStale(now: Date) -> Bool { now.timeIntervalSince(lastSeen) > Self.keeps(verdict) }

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
    /// Paused by Hostwatch itself (no Endpoint Security): the answer stops or resumes the process.
    var reactive = false
    /// The AI is looking at it: no question yet, a notice instead.
    var checking = false
    /// What the AI said, shown in the question when it didn't settle it.
    var aiNote: String? = nil
    /// The AI's verdict, for the question's conclusion card, and why it couldn't allow it alone.
    var aiVerdict: LocalVerdict? = nil
    var aiLimit: String? = nil
}

@MainActor
final class ProtectionMonitor: ObservableObject {
    @Published var launchMode: ProtectionMode { didSet { defaults.set(launchMode.rawValue, forKey: Keys.launch); changed() } }
    @Published var fileMode: ProtectionMode { didSet { defaults.set(fileMode.rawValue, forKey: Keys.file); changed() } }
    @Published var groups: [String: ProtectedGroupSetting] {
        didSet { defaults.set(try? JSONEncoder().encode(groups), forKey: Keys.groups); changed() }
    }
    /// Folders and files you protect yourself (Protection ▸ Protected Files and Folders).
    @Published var customPlaces: [CustomPlace] {
        didSet { defaults.set(try? JSONEncoder().encode(customPlaces), forKey: Keys.custom); changed() }
    }
    /// Rules saved by the short-lived separate list: read once, moved into places and destinations, then empty.
    @Published var accessRules: [AccessRule] {
        didSet { defaults.set(try? JSONEncoder().encode(accessRules), forKey: Keys.rules); changed() }
    }
    /// Network destinations you decided (the firewall reads them through the app).
    @Published var destinations: [Destination] {
        didSet { defaults.set(try? JSONEncoder().encode(destinations), forKey: Keys.destinations); changed() }
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
    /// Hour by hour, the last eight days: what was stopped (or would be) and asked about, for the Overview's charts.
    struct HourCount: Codable, Equatable, Sendable {
        var hour: Int                                   // hours since 1970
        var area: ProtectionArea
        var block = 0
        var ask = 0
    }
    private(set) var hourly: [HourCount] = []
    private let hourlyURL: URL
    private var todayKey = ""
    private var nextLocalAsk = 0

    /// The collector's configuration changed: send it.
    var onConfigChange: (() -> Void)?
    /// Answers a held launch or file access: (id, allow, seconds the collector may reuse the answer).
    var answer: ((Int, Bool, TimeInterval) -> Void)?
    /// Your answer that should stick: the pattern marked Safe (Always Allow) or Dangerous (Block).
    var markPattern: ((String, SignatureStatus) -> Void)?
    var onPromptsChange: (() -> Void)?

    /// Acts on programs until Endpoint Security can: stops what's blocked, pauses what's asked about.
    let engine = ReactiveEnforcer()
    private let defaults: UserDefaults
    private let fileURL: URL
    private var dirty = false
    /// When old findings were last forgotten: at launch, then at most once an hour as findings come in.
    private var lastSweep = Date.distantPast
    private var publishScheduled = false
    static let findingLimit = 300

    private enum Keys {
        static let launch = "protectionLaunchMode", file = "protectionFileMode", groups = "protectionGroups"
        static let since = "protectionSince", custom = "protectionCustomPlaces", rules = "protectionAccessRules"
        static let destinations = "protectionDestinations"
    }

    init(defaults: UserDefaults = .standard,
         fileURL: URL = AppPaths.support.appendingPathComponent("protection-findings.json")) {
        self.defaults = defaults
        self.fileURL = fileURL
        hourlyURL = fileURL.deletingLastPathComponent().appendingPathComponent(
            fileURL.deletingPathExtension().lastPathComponent + "-hourly.json")
        // Watch by default: it stops nothing, and it is how you learn what Ask would do before turning it on.
        launchMode = defaults.string(forKey: Keys.launch).flatMap(ProtectionMode.init) ?? .watch
        fileMode = defaults.string(forKey: Keys.file).flatMap(ProtectionMode.init) ?? .watch
        groups = defaults.data(forKey: Keys.groups).flatMap { try? JSONDecoder().decode([String: ProtectedGroupSetting].self, from: $0) } ?? [:]
        customPlaces = defaults.data(forKey: Keys.custom).flatMap { try? JSONDecoder().decode([CustomPlace].self, from: $0) } ?? []
        accessRules = defaults.data(forKey: Keys.rules).flatMap { try? JSONDecoder().decode([AccessRule].self, from: $0) } ?? []
        destinations = defaults.data(forKey: Keys.destinations).flatMap { try? JSONDecoder().decode([Destination].self, from: $0) } ?? []
        let started = defaults.object(forKey: Keys.since) as? Date ?? Date()
        since = started
        defaults.set(started, forKey: Keys.since)
        if let data = Vault.shared.read(fileURL), let saved = try? Self.decoder.decode([ProtectionFinding].self, from: data) {
            let now = Date()
            findings = Dictionary(saved.filter { !$0.isStale(now: now) }.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            lastSweep = now
        }
        if let data = Vault.shared.read(hourlyURL), let saved = try? JSONDecoder().decode([HourCount].self, from: data) {
            hourly = saved
        }
        if accessRules.contains(where: { $0.kind == .files }) { moveFileRulesIntoPlaces() }
        if accessRules.contains(where: { $0.kind == .network }) { moveNetworkRulesIntoDestinations() }
    }

    func mode(_ area: ProtectionArea) -> ProtectionMode { area == .launches ? launchMode : fileMode }

    func setMode(_ mode: ProtectionMode, for area: ProtectionArea) {
        if area == .launches { launchMode = mode } else { fileMode = mode }
    }

    var paused: Bool { (pausedUntil ?? .distantPast) > Date() }

    func pause(minutes: Double) { pausedUntil = Date().addingTimeInterval(minutes * 60) }
    func resume() { pausedUntil = nil }

    /// Hostwatch is quitting: every program it paused goes on (never left frozen).
    func releaseAll() {
        let hadReactive = prompts.contains(where: \.reactive)
        engine.releaseAll()
        prompts.removeAll(where: \.reactive)
        if hadReactive { onPromptsChange?() }
    }

    /// The program an event is about: what was launched, or what opened the file.
    static func subject(_ e: ActivityEvent) -> String { e.kind == .exec ? e.target : e.proc }

    /// Protection as a whole. The firewall is passed in: it counts too (Network on Ask is protecting).
    func state(network: FirewallMode) -> ProtectionState {
        ProtectionState(paused: paused, modes: ProtectionArea.allCases.map(mode), network: network)
    }

    func enforcerStatus(_ state: String, _ detail: String) {
        let new = EnforcerState(state: state, detail: detail)
        if new != enforcer { enforcer = new }
    }

    // MARK: The live feed (Watch)

    /// One live event: in Watch, marks what would be stopped and counts the rest. In Ask and Strict (without
    /// Endpoint Security) the reactive engine acts: a blocked program is stopped, a question pauses it.
    /// Asks the AI about a paused program (LiveAICheck): nil when no fast model is ready. Set by the app.
    var aiCheck: ((ActivityEvent) async -> LiveAICheck.Outcome?)?
    /// A launch question was answered (by you, the AI or the time limit): allowed or stopped. Set by the app, so the
    /// firewall's question about the same program comes after, or goes.
    var onLaunchAnswered: ((ActivityEvent, Bool) -> Void)?
    /// A program the AI let go on, for the notice. Set by the app.
    var onAIAllowed: ((ProtectionAsk, String) -> Void)?
    /// Patterns the AI let go on this session: they pass again without another check, until you decide them.
    private(set) var aiAllowed: Set<String> = []

    func consider(_ e: inout ActivityEvent, status: SignatureStatus) {
        guard !paused, let (area, decision) = decide(e, status: status) else { return }
        let mode = self.mode(area)
        // With Endpoint Security enforcing, what reaches the feed was allowed: the collector reports what it stopped.
        if mode.enforces && enforcer.canEnforce { return }
        guard let verdict = ProtectionPolicy.effective(decision.verdict, mode: mode), verdict != .allow else { return }
        guard mode.enforces else {
            record(area: area, event: e, decision: decision, verdict: verdict, enforced: false)
            if verdict == .block { e.protection = .wouldBlock; e.protectionReason = decision.reason }
            return
        }
        let path = Self.subject(e)
        switch verdict {
        case .block:
            let stopped = engine.stop(pid: e.pid, path: path)
            record(area: area, event: e, decision: decision, verdict: .block, enforced: stopped)
            e.protection = stopped ? .blocked : .wouldBlock
            e.protectionReason = stopped ? decision.reason : decision.reason + " (couldn't be stopped: not yours, or protected)"
        case .ask:
            // Let go by the AI earlier this session: it isn't paused or checked again.
            if aiAllowed.contains(e.signatureKey) { return }
            guard engine.pause(pid: e.pid, path: path) else {
                record(area: area, event: e, decision: decision, verdict: .ask, enforced: false)
                return
            }
            nextLocalAsk += 1                              // negative ids: never the collector's
            let checking = aiCheck != nil && LiveAICheck.enabled(defaults)
            prompts.append(ProtectionAsk(id: -nextLocalAsk, event: e,
                                         area: area, reason: decision.reason, group: decision.group,
                                         deadline: Date().addingTimeInterval(ReactiveEnforcer.pauseTimeout), reactive: true,
                                         checking: checking))
            onPromptsChange?()
            if checking { checkWithAI(-nextLocalAsk) }
        case .allow:
            break
        }
    }

    /// The policy's decision for an event, before the mode: nil for connections (the firewall's) and unprotected files.
    func decide(_ e: ActivityEvent, status: SignatureStatus) -> (ProtectionArea, ProtectionDecision)? {
        if Self.isOwnClaudeCall(e, own: Int(getpid())) { return nil }
        switch e.kind {
        case .exec:
            guard launchMode != .off else { return nil }
            return (.launches, ProtectionPolicy.decideLaunch(target: e.target, status: status, risk: e.signatureRisk,
                                                             riskReason: e.signatureReason, knownBad: e.knownBad))
        case .file:
            guard fileMode != .off else { return nil }
            if let d = ProtectionPolicy.decideFile(pattern: e.signaturePattern, status: status, risk: e.signatureRisk,
                                                   settings: groups, actor: e.proc) {
                return (.files, d)
            }
            return ProtectionPolicy.decideCustom(path: e.target, actor: e.proc, status: status, places: customPlaces)
                .map { (.files, $0) }
        case .net:
            return nil
        }
    }

    /// Hostwatch's own call to Claude (the AI check, Ask AI, suggestions): Claude Code started by Hostwatch itself.
    /// It runs without a question, which paused Hostwatch's own AI behind a countdown. Both must hold: Claude Code
    /// started by you or by any other program is checked as before, and so is anything else Hostwatch starts.
    nonisolated static func isOwnClaudeCall(_ e: ActivityEvent, own pid: Int) -> Bool {
        e.ppid == pid && (isClaudeInstall(e.proc) || isClaudeInstall(e.target))
    }

    /// Claude Code where its installers put it, not any program named "claude" (CodingAgent's looser test, fine for
    /// a label, is too loose to let something run unasked).
    nonisolated static func isClaudeInstall(_ path: String) -> Bool {
        if path.contains("/.local/share/claude/versions/") || path.contains("/node_modules/@anthropic-ai/claude-code/") {
            return true
        }
        return (path as NSString).lastPathComponent == "claude" && (path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/"))
    }

    private func record(area: ProtectionArea, event e: ActivityEvent, decision: ProtectionDecision,
                        verdict: ProtectionVerdict, enforced: Bool) {
        let now = Date()
        let day = now.formatted(.iso8601.year().month().day())
        if day != todayKey { todayKey = day; today = [:] }
        today[area, default: [:]][verdict, default: 0] += 1
        let hour = Int(now.timeIntervalSince1970 / 3600)
        if let i = hourly.lastIndex(where: { $0.hour == hour && $0.area == area }) {
            if verdict == .block { hourly[i].block += 1 } else { hourly[i].ask += 1 }
        } else {
            hourly.append(HourCount(hour: hour, area: area, block: verdict == .block ? 1 : 0, ask: verdict == .block ? 0 : 1))
            hourly.removeAll { $0.hour < hour - ProtectionTimeline.keepHours }
        }
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
        if now.timeIntervalSince(lastSweep) > 3600 {
            lastSweep = now
            findings = findings.filter { !$0.value.isStale(now: now) }
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

    /// File rules from the short-lived separate list become what they meant on the places: a program's Allow or Block
    /// an exception of the place that covers it (a new protected folder when none does), Block for every program a
    /// protected folder whose others are blocked. Allow for every program only overrode pattern statuses: dropped.
    func moveFileRulesIntoPlaces(home: String = NSHomeDirectory()) {
        for rule in accessRules where rule.kind == .files && rule.on {
            let path = rule.target
            guard let program = rule.program else {
                guard rule.action == .block else { continue }
                if let i = customPlaces.firstIndex(where: { $0.path == path }) { customPlaces[i].others = .block }
                else { customPlaces.append(CustomPlace(path: path, isFolder: true, others: .block)) }
                continue
            }
            func add(_ e: inout PlaceExceptions) {
                if rule.action == .allow { if !e.allowed.contains(program) { e.allowed.append(program) } }
                else if !e.blocked.contains(program) { e.blocked.append(program) }
            }
            if let i = customPlaces.indices.filter({ customPlaces[$0].covers(path) })
                .max(by: { customPlaces[$0].path.count < customPlaces[$1].path.count }) {
                add(&customPlaces[i].exceptions)
            } else if let group = ProtectedGroup.all.first(where: { g in
                g.prefixes(home: home).contains { AccessRules.covers($0, path) || AccessRules.covers(path, $0) }
            }) {
                var s = groups[group.id] ?? ProtectedGroupSetting()
                add(&s.exceptions)
                groups[group.id] = s
            } else {
                var place = CustomPlace(path: path, isFolder: true)
                add(&place.exceptions)
                customPlaces.append(place)
            }
        }
        accessRules.removeAll { $0.kind == .files }
    }

    /// Network rules from the separate list become destinations: a rule for any program the destination's choice,
    /// a rule for one program its exception.
    func moveNetworkRulesIntoDestinations() {
        for d in Destinations.from(accessRules) {
            if let i = destinations.firstIndex(where: { $0.target == d.target }) {
                destinations[i].exceptions.allowed += d.exceptions.allowed.filter { !destinations[i].exceptions.allowed.contains($0) }
                destinations[i].exceptions.blocked += d.exceptions.blocked.filter { !destinations[i].exceptions.blocked.contains($0) }
                if d.others != .firewall { destinations[i].others = d.others }
            } else {
                destinations.append(d)
            }
        }
        accessRules.removeAll { $0.kind == .network }
    }

    /// Your decision for a connection from your destinations, for the firewall: nil when you left it to the firewall.
    func networkDecision(host: String, ip: String, program: String) -> FirewallDecision? {
        Destinations.decide(destinations, host: host, ip: ip, program: program)
    }

    func forget(_ ids: [String]) {
        for id in ids { findings[id] = nil }
        dirty = true
        publishSoon()
    }

    /// Found ▸ Forget: the entries that match leave the list. Decisions and patterns are untouched.
    func forget(where match: (ProtectionFinding) -> Bool) {
        forget(findings.values.filter(match).map(\.id))
    }

    func count(_ area: ProtectionArea, _ verdict: ProtectionVerdict) -> Int { today[area]?[verdict] ?? 0 }

    /// Adds folders and files to protect (already protected paths are skipped).
    func addPlaces(_ urls: [URL]) {
        var places = customPlaces
        for url in urls {
            let path = url.standardizedFileURL.resolvingSymlinksInPath().path
            guard !places.contains(where: { $0.path == path }) else { continue }
            places.append(CustomPlace(path: path, isFolder: url.hasDirectoryPath))
        }
        customPlaces = places
    }

    func removePlace(_ id: String) {
        let group = "custom:\(id)"
        customPlaces.removeAll { $0.id == id }
        findings = findings.filter { $0.value.group != group }
        dirty = true
        publishSoon()
    }

    /// A card's or your place's name, for the question panel and the findings.
    func placeTitle(group: String) -> String? {
        ProtectedGroup.group(id: group)?.title ?? customPlaces.first { $0.groupID == group }?.name
    }

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
        if let hours = try? JSONEncoder().encode(hourly) { try? Vault.shared.write(hours, to: hourlyURL) }
    }


    private func changed() {
        if paused || !launchMode.enforces || !fileMode.enforces {
            // A question about an area that no longer enforces (or everything paused) lets its program go.
            let stale = prompts.filter { $0.reactive && (paused || !mode($0.area).enforces) }
            for ask in stale { engine.release(pid: ask.event.pid, path: Self.subject(ask.event), stop: false) }
            if !stale.isEmpty { prompts.removeAll { p in stale.contains { $0.id == p.id } }; onPromptsChange?() }
        }
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
            return ["id": g.id, "prefixes": g.prefixes(home: home), "owners": g.owners + s.exceptions.allowed,
                    "blocked": s.exceptions.blocked, "writesOnly": g.writesOnly, "others": s.others.rawValue]
        } + customPlaces.filter(\.on).map {
            ["id": $0.groupID, "prefixes": [$0.path], "owners": $0.exceptions.allowed, "blocked": $0.exceptions.blocked,
             "writesOnly": false, "others": $0.others.rawValue]
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

    /// The AI looks at a paused program, within LiveAICheck.timeLimit. Safe lets it go on this time; anything else,
    /// or no answer, turns it into your question with the AI's view in it.
    private func checkWithAI(_ id: Int) {
        guard let ask = prompts.first(where: { $0.id == id }), let check = aiCheck else { return }
        Task { @MainActor [weak self] in
            let outcome = await Self.withTimeLimit(LiveAICheck.timeLimit) { await check(ask.event) }
            guard let self, let i = self.prompts.firstIndex(where: { $0.id == id }) else { return }
            switch outcome {
            case .allow(let note)?:
                let done = self.prompts.remove(at: i)
                self.aiAllowed.insert(done.event.signatureKey)
                self.engine.release(pid: done.event.pid, path: Self.subject(done.event), stop: false)
                self.record(area: done.area, event: done.event,
                            decision: .init(verdict: .ask, reason: "allowed this time by AI: " + note, group: done.group),
                            verdict: .ask, enforced: false)
                self.onPromptsChange?()
                self.onAIAllowed?(done, note)
                if done.area == .launches { self.onLaunchAnswered?(done.event, true) }
            case .ask(let note, let verdict, let limit)?:
                self.prompts[i].checking = false
                self.prompts[i].aiNote = note
                self.prompts[i].aiVerdict = verdict
                self.prompts[i].aiLimit = limit
                self.onPromptsChange?()
            case nil:
                self.prompts[i].checking = false
                self.prompts[i].aiNote = "No fast AI model is ready (Settings ▸ AI), so you decide."
                self.onPromptsChange?()
            }
        }
    }

    /// The work's result, or nil when it takes longer than `seconds`.
    static func withTimeLimit<T: Sendable>(_ seconds: TimeInterval, _ work: @escaping @Sendable () async -> T?) async -> T? {
        await withTaskGroup(of: T?.self) { group in
            group.addTask { await work() }
            group.addTask { try? await Task.sleep(for: .seconds(seconds)); return nil }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    /// Always Block and Always Allow decide the pattern. Block Once and Allow Once decide only this time.
    enum PromptAnswer { case block, blockOnce, allowOnce, alwaysAllow }

    /// Your answer in the panel. Block and Always Allow stick as pattern decisions, as in the firewall.
    func respond(_ id: Int, _ choice: PromptAnswer) {
        guard let i = prompts.firstIndex(where: { $0.id == id }) else { return }
        let ask = prompts.remove(at: i)
        onPromptsChange?()
        if ask.reactive {
            engine.release(pid: ask.event.pid, path: Self.subject(ask.event), stop: choice == .block || choice == .blockOnce)
        }
        if ask.area == .launches { onLaunchAnswered?(ask.event, choice == .allowOnce || choice == .alwaysAllow) }
        switch choice {
        case .block:
            if !ask.reactive { answer?(id, false, 60) }
            markPattern?(ask.event.signatureKey, .dangerous)
            record(area: ask.area, event: ask.event,
                   decision: .init(verdict: .block, reason: "you blocked it", group: ask.group), verdict: .block, enforced: true)
        case .blockOnce:
            // Stopped this time, nothing decided: the next run is asked about again.
            if !ask.reactive { answer?(id, false, 0) }
            record(area: ask.area, event: ask.event,
                   decision: .init(verdict: .block, reason: "you blocked it once", group: ask.group), verdict: .block, enforced: true)
        case .allowOnce:
            if !ask.reactive { answer?(id, true, 0) }
        case .alwaysAllow:
            if !ask.reactive { answer?(id, true, 300) }
            markPattern?(ask.event.signatureKey, .safe)
        }
    }

    /// No answer in time: the collector decides by the mode, a program Hostwatch paused goes on (as Hold does).
    func expire(_ id: Int) {
        if let ask = prompts.first(where: { $0.id == id }), ask.reactive {
            engine.release(pid: ask.event.pid, path: Self.subject(ask.event), stop: false)
            record(area: ask.area, event: ask.event, decision: .init(verdict: .ask, reason: "no answer: it went on", group: ask.group),
                   verdict: .ask, enforced: false)
        }
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
