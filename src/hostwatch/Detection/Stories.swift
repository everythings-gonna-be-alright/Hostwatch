import AppKit
import Darwin
import Combine
import Foundation

// Stories: suspicious steps from one process tree (plus files it hands to other trees),
// scored together. Each step alone is often "normal"; the chain is what matters, e.g.
// Chrome writes ~/Downloads/x → xattr -d quarantine x → x runs → writes a LaunchAgent → connects out.

// MARK: - Stages

enum StoryStage: String, Codable, CaseIterable, Comparable {
    case drop, unquarantine, runFromDrop, appShell, lolbin, encodedCommand, persistence, credential, network
    case unsignedCode, swappedBinary, newDomain, beaconing, rawIP, heavyUntrusted, knownBad

    static func < (a: StoryStage, b: StoryStage) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    var weight: Int {
        switch self {
        case .drop, .lolbin, .network: return 1
        case .runFromDrop, .newDomain, .rawIP: return 2
        case .unquarantine, .appShell, .encodedCommand, .credential, .unsignedCode, .beaconing, .heavyUntrusted: return 3
        case .persistence: return 4
        case .swappedBinary: return 5
        case .knownBad: return 8
        }
    }

    /// Strong enough to make activity started from your own terminal/IDE worth a story.
    var isStrong: Bool {
        [.unquarantine, .encodedCommand, .persistence, .credential, .unsignedCode, .swappedBinary, .beaconing, .heavyUntrusted, .knownBad]
            .contains(self)
    }

    var title: String {
        switch self {
        case .drop: return "Download"
        case .unquarantine: return "Quarantine removed"
        case .runFromDrop: return "Ran downloaded/temp file"
        case .appShell: return "App spawned shell"
        case .lolbin: return "System tool"
        case .encodedCommand: return "Encoded/piped command"
        case .persistence: return "Autostart write"
        case .credential: return "Credential access"
        case .network: return "Outbound connection"
        case .unsignedCode: return "Unsigned download ran"
        case .swappedBinary: return "Binary replaced"
        case .newDomain: return "New domain"
        case .beaconing: return "Beaconing"
        case .rawIP: return "Raw-IP connection"
        case .heavyUntrusted: return "Heavy untrusted process"
        case .knownBad: return "Known malware"
        }
    }

    var symbol: String {
        switch self {
        case .drop: return "arrow.down.circle"
        case .unquarantine: return "shield.slash"
        case .runFromDrop: return "play.circle"
        case .appShell: return "terminal"
        case .lolbin: return "wrench.and.screwdriver"
        case .encodedCommand: return "curlybraces"
        case .persistence: return "arrow.clockwise.circle"
        case .credential: return "key"
        case .network: return "network"
        case .unsignedCode: return "seal"
        case .swappedBinary: return "arrow.triangle.swap"
        case .newDomain: return "globe.badge.chevron.backward"
        case .beaconing: return "dot.radiowaves.right"
        case .rawIP: return "number"
        case .heavyUntrusted: return "flame"
        case .knownBad: return "xmark.octagon"
        }
    }
}

// MARK: - Model

struct StoryStep: Codable, Identifiable {
    var id = UUID()
    var date: Date
    /// When this step's process started (exec event or kernel); tells process instances apart.
    var processStart: Date?
    var stage: StoryStage
    var note: String              // one-line explanation
    // Event snapshot, for display and Ask Claude.
    var kind: EventKind
    var time: String
    var pid: Int
    var ppid: Int
    var name: String
    var proc: String
    var target: String
    var extra: String
    var parent: String
    var host: String
    var args: String

    init(_ e: ActivityEvent, stage: StoryStage, note: String, date: Date = Date()) {
        self.date = date; self.stage = stage; self.note = note
        kind = e.kind; time = e.time; pid = e.pid; ppid = e.ppid; name = e.name; proc = e.proc
        target = e.target; extra = e.extra; parent = e.parent; host = e.host; args = e.args
    }

    var event: ActivityEvent {
        ActivityEvent(kind: kind, time: time, pid: pid, ppid: ppid, name: name, proc: proc, target: target,
                      extra: extra, parent: parent, host: host, hostSource: host.isEmpty ? "" : "dns", args: args)
    }

    var detail: String {
        switch kind {
        case .exec: return args.isEmpty ? target : args
        case .net: return "\(extra) \(host.isEmpty ? target : "\(host) [\(target)]")"
        case .file: return "\(extra) \(target)"
        }
    }
}

enum StoryOrigin: String, Codable {
    case developer   // started from a terminal/IDE: your own commands
    case app         // a GUI app (Slack, Office, a browser…)
    case background  // launchd job or unknown parent
}

struct Story: Codable, Identifiable {
    var id = UUID()
    var rootPid: Int
    var originName: String        // "Slack", "iTerm2", "launchd"
    var originPath: String
    var origin: StoryOrigin
    var steps: [StoryStep] = []
    var firstSeen = Date()
    var lastSeen = Date()
    var fired = false
    var severity: SignatureStatus = .suspicious
    var dismissed = false

    var stages: [StoryStage] { Array(Set(steps.map(\.stage))).sorted() }

    /// Distinct stages count once; a file handed from one tree to another adds a bonus.
    var score: Int {
        stages.reduce(0) { $0 + $1.weight } + (steps.contains { $0.note.hasPrefix("ran a file") } ? 1 : 0)
    }

    /// "Slack → sh → curl"
    var title: String {
        var names: [String] = []
        for s in steps where !names.contains(s.name) { names.append(s.name) }
        if !names.contains(originName) { names.insert(originName, at: 0) }
        return names.prefix(6).joined(separator: " → ")
    }

    /// Ignore key: same origin program + same set of stages.
    var signature: String { originPath + "|" + stages.map(\.rawValue).joined(separator: ",") }

    var summary: String { stages.map(\.title).joined(separator: " · ") }
}

// MARK: - Engine

@MainActor
final class StoryEngine: ObservableObject {
    /// Fired stories, newest first.
    @Published private(set) var stories: [Story] = []
    @Published private(set) var revision = 0

    private struct Proc { var ppid: Int; var path: String; var seen: Date; var start: Date? }
    private var procs: [Int: Proc] = [:]
    private var working: [UUID: Story] = [:]                 // story id -> story (fired or not)
    /// Recent steps and the story each belongs to: what new steps can link to.
    private var linkable: [(step: StoryStep, story: UUID)] = []

    // Causal-link windows (see `related`).
    static let sameProcessWindow: TimeInterval = 120
    static let processStartWindow: TimeInterval = 10 * 60
    static let lineageWindow: TimeInterval = 10 * 60
    static let scriptWindow: TimeInterval = 3 * 60
    /// Unsigned / ad-hoc programs, or ones run from Downloads or temp: every run is one story.
    static let untrustedProgramWindow: TimeInterval = 60 * 60
    /// Different programs reaching the same new domain or raw IP.
    static let destinationWindow: TimeInterval = 30 * 60
    /// Login items: the plist's writer and the program it starts, even days later (after a reboot).
    static let loginItemMemory: TimeInterval = 30 * 24 * 3600

    struct LoginItemLink: Codable {
        var plist: String
        var step: StoryStep
        var story: UUID
    }
    private var loginItems: [LoginItemLink] = []
    private var plistPrograms: [String: [String]] = [:]       // plist -> programs it starts
    /// Reads a login-item plist (tests supply their own).
    var readPlist: (String) -> Data? = { FileManager.default.contents(atPath: $0) }
    private var files: [String: (date: Date, step: StoryStep)] = [:]  // recent writes in drop zones
    private var unquarantines: [StoryStep] = []              // recent xattr -d quarantine runs
    private var ignored: Set<String>

    private let window: TimeInterval = 15 * 60
    private let fileMemory: TimeInterval = 30 * 60
    private let fileURL: URL
    private var dirty = false
    private var timer: Timer?
    /// Time of the event being processed (wall clock live, recorded time in replay).
    private var clock = Date()
    /// Off in replay: old pids from a history file may belong to other processes now.
    var liveLookups = true
    /// Off in replay: no sound, no saved stories, no ignore list.
    let persistent: Bool
    /// Who signed what: the shared cache in the app, a scratch one in tests.
    let signing: SigningCache

    init(persistent: Bool = true, signing: SigningCache = .shared) {
        self.signing = signing
        self.persistent = persistent
        let dir = AppPaths.support
        fileURL = dir.appendingPathComponent("stories.json")
        ignored = persistent ? Set(UserDefaults.standard.stringArray(forKey: "ignoredStories") ?? []) : []
        guard persistent else { return }
        load()
        loadLoginItems()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.maintain() }
        }
    }

    var activeCount: Int { stories.filter { !$0.dismissed }.count }
    /// Known-bad matches in open stories seen since `date`: what the menu bar's "known-bad matches" line counts, so
    /// dismissing or deleting those stories clears it (the matches themselves stay in the threat log).
    func openKnownBadMatches(since date: Date) -> Int {
        stories.filter { !$0.dismissed && $0.lastSeen >= date }
            .reduce(0) { $0 + $1.steps.filter { $0.stage == .knownBad }.count }
    }

    /// Undismissed stories that changed recently, for the HUD.
    func recent(within seconds: TimeInterval = 30 * 60) -> [Story] {
        stories.filter { !$0.dismissed && Date().timeIntervalSince($0.lastSeen) < seconds }
    }

    /// Every open chain, fired or not (tests and replay).
    var openChains: [Story] { Array(working.values) }

    // MARK: Ingest

    /// A story that just fired (its steps' patterns are reopened if they were decided Safe).
    var onFired: ((Story) -> Void)?

    /// Adds the event to its story; returns the stages it added (with notes), for the process hold.
    @discardableResult
    /// `extra`: stages found outside the event itself (a launched process that later runs heavy); the
    /// event was seen before, so its process isn't registered again.
    func ingest(_ e: ActivityEvent, decidedSafe: Bool, at date: Date = Date(),
                extra: [(StoryStage, String)] = []) -> [(StoryStage, String)] {
        clock = date
        if e.kind == .exec, e.pid > 0, extra.isEmpty {
            procs[e.pid] = Proc(ppid: e.ppid, path: e.target, seen: date, start: date)
            // Replay: a parent that started before the recording is still known by its path.
            if !liveLookups, e.ppid > 1, procs[e.ppid] == nil, !e.parent.isEmpty {
                procs[e.ppid] = Proc(ppid: 0, path: e.parent, seen: date, start: nil)
            }
        }
        // A pattern you marked Safe never builds a story; neither does Hostwatch's own evidence
        // gathering (codesign, spctl, lsof… started by this app).
        // (On a threat list it counts even if you marked the pattern Safe.)
        guard !decidedSafe || !e.knownBad.isEmpty || !extra.isEmpty, !Self.isOwn(e.parent), !Self.isOwn(e.proc) else { return [] }

        if e.kind == .file, e.extra.contains("w") { rememberWrite(e) }
        var found = extra.isEmpty ? stages(for: e) : extra
        guard !found.isEmpty else { return [] }
        if let q = found.first(where: { $0.0 == .unquarantine }) {
            unquarantines.append(StoryStep(e, stage: .unquarantine, note: q.1, date: clock))
            if unquarantines.count > 200 { unquarantines.removeFirst(100) }
        }
        let linked = linkedWrite(for: e)
        let linkedQuarantine = linkedUnquarantine(for: e)
        if linked != nil { found.removeAll { $0.0 == .runFromDrop } }   // the linked step says it better

        let now = clock
        let start = node(e.pid)?.start
        let candidate = found.map { StoryStep(e, stage: $0.0, note: $0.1, date: now) }

        // Steps this event is linked to: by cause (see `related`), by a file it runs, or by the login
        // item that started it.
        linkable.removeAll { now.timeIntervalSince($0.step.date) > Self.untrustedProgramWindow }
        if linkable.count > 5000 { linkable.removeFirst(linkable.count - 5000) }
        let link = LinkContext(pid: e.pid, start: start, ancestors: ancestry(of: e.pid),
                               program: Self.program(e), untrusted: isUntrustedProgram(Self.program(e)),
                               destinations: Set(candidate.compactMap(Self.rareDestination)), now: now)
        var hits = linkable.filter { related($0.step, link) }
        for extra in [linked, linkedQuarantine].compactMap({ $0 }) {
            if let owner = linkable.first(where: { $0.step.id == extra.id }) { hits.append(owner) }
        }
        hits += loginItemLinks(for: link.program, args: e.args)
        var story = resolve(hits)
        if hits.isEmpty {
            let root = rootOf(e.pid)
            story = Story(rootPid: root.pid, originName: root.originName, originPath: root.originPath, origin: root.origin)
            story.firstSeen = now
        }

        for var step in candidate {
            step.processStart = start
            // One directory walk or a burst of connections is one step, not sixty.
            let key = Self.dedupeKey(step)
            // Same tool run again (new pid each time) or same process touching the same place.
            if story.steps.contains(where: { $0.stage == step.stage && Self.dedupeKey($0) == key
                                             && ($0.pid == step.pid || step.kind == .exec) }) {
                continue
            }
            if story.steps.filter({ $0.stage == step.stage }).count >= 8 { continue }
            story.steps.append(step)
            linkable.append((step, story.id))
            if step.stage == .persistence, step.target.hasSuffix(".plist") { rememberLoginItem(step, story: story.id) }
        }
        // Running a file another tree wrote (or un-quarantined) pulls those steps into this story.
        if let linked, !story.steps.contains(where: { $0.id == linked.id }) {
            story.steps.append(linked)
            var ran = StoryStep(e, stage: .runFromDrop,
                                note: "ran a file \(linked.name) wrote \(Self.ago(linked.date, now: now))", date: now)
            ran.processStart = start
            story.steps.append(ran)
            linkable.append((ran, story.id))
        }
        if let q = linkedQuarantine, !story.steps.contains(where: { $0.id == q.id }) {
            story.steps.append(q)
        }
        guard !story.steps.isEmpty else { return found }
        story.steps.sort { $0.date < $1.date }
        if story.steps.count > 60 { story.steps.removeFirst(story.steps.count - 60) }
        story.lastSeen = now
        evaluate(&story)
        working[story.id] = story
        if let linked { found.append((.runFromDrop, "runs a file \(linked.name) just wrote")) }
        return found
    }

    // MARK: Causal links

    /// The new event, as far as linking is concerned.
    private struct LinkContext {
        var pid: Int
        var start: Date?
        var ancestors: [Int]
        var program: String
        var untrusted: Bool
        var destinations: Set<String>
        var now: Date
    }

    /// Is the new event caused by, or part of the same activity as, `step`? Only concrete links
    /// count: sharing a long-lived ancestor (an app, your terminal) does not.
    private func related(_ step: StoryStep, _ c: LinkContext) -> Bool {
        let age = c.now.timeIntervalSince(step.date)
        guard age >= -1 else { return false }
        // Evidence links, regardless of the process tree:
        // the same untrusted program (unsigned, ad-hoc, or from Downloads/temp), any run…
        if c.untrusted, Self.program(of: step) == c.program, age <= Self.untrustedProgramWindow { return true }
        // …or the same new domain / raw IP reached again, by any program.
        if !c.destinations.isEmpty, let d = Self.rareDestination(step), c.destinations.contains(d),
           age <= Self.destinationWindow { return true }
        return causal(step, age: age, pid: c.pid, start: c.start, ancestors: c.ancestors)
    }

    /// Process-tree links: same process, parent -> child, same script.
    private func causal(_ step: StoryStep, age: TimeInterval, pid: Int, start: Date?, ancestors: [Int]) -> Bool {
        // 1. Same process instance: close in time, or its own start (a dropped binary launching).
        if step.pid == pid, sameInstance(step.processStart, start) {
            if age <= Self.sameProcessWindow { return true }
            if step.kind == .exec, age <= Self.processStartWindow { return true }
            return false
        }
        // 2. Parent -> child: the step happened in an ancestor before this process was started.
        // Not for long-lived hosts (apps, terminals, agents): they start children all day, so timing
        // alone means nothing there. A real hand-off (download, then run) is linked by the file.
        if let i = ancestors.firstIndex(of: step.pid) {
            guard let start, start.timeIntervalSince(step.date) >= -2 else { return false }
            if isHost(step.pid, parent: i + 1 < ancestors.count ? ancestors[i + 1] : 0) { return false }
            return age <= Self.lineageWindow
        }
        // 3. Same script: both under the same short-lived parent (not an app or an interactive shell).
        if age <= Self.scriptWindow {
            let theirs = ancestry(of: step.pid)
            if let common = ancestors.first(where: theirs.contains), common > 1 {
                let parentOfCommon = node(common)?.ppid ?? 0
                if !isHost(common, parent: parentOfCommon) { return true }
            }
        }
        return false
    }

    /// Same process instance unless both start times are known and differ (pid reuse).
    private func sameInstance(_ a: Date?, _ b: Date?) -> Bool {
        guard let a, let b else { return true }
        return abs(a.timeIntervalSince(b)) < 1
    }

    /// Ancestor pids, parent first (stops at launchd or an unknown process).
    private func ancestry(of pid: Int) -> [Int] {
        var out: [Int] = []
        var current = pid
        for _ in 0..<16 {
            guard let p = node(current), p.ppid > 0, !out.contains(p.ppid) else { break }
            out.append(p.ppid)
            if p.ppid == 1 { break }
            current = p.ppid
        }
        return out
    }

    /// Long-lived hosts whose descendants are independent of each other: launchd, a GUI app's main
    /// binary, a session starter (login/sshd/tmux/terminal) or an interactive shell.
    private func isHost(_ pid: Int, parent: Int) -> Bool {
        guard pid > 1, let p = node(pid) else { return true }
        if p.path.contains(".app/Contents/MacOS/") || Self.isSessionStarter(p.path) { return true }
        if Self.isShell(p.path) {
            let parentPath = node(parent)?.path ?? ""
            // Interactive only under a terminal, IDE, agent or login: a shell an app (Slack…) starts
            // runs a script, and its steps belong together.
            return parentPath.isEmpty || Self.isSessionStarter(parentPath)
        }
        return false
    }

    /// The story for a set of linked steps: their stories merged (fired ones revived if they went
    /// quiet). Steps whose story is gone are carried into the result. Empty if nothing links.
    private func resolve(_ hits: [(step: StoryStep, story: UUID)]) -> Story {
        let ids = Set(hits.map(\.story))
        for id in ids where working[id] == nil {
            if let fired = stories.first(where: { $0.id == id }) { working[id] = fired }
        }
        let alive = ids.filter { working[$0] != nil }
        var story = alive.isEmpty ? Story(rootPid: 0, originName: "", originPath: "", origin: .background, steps: [])
                                  : merge(Array(alive))
        for h in hits where working[h.story] == nil && !story.steps.contains(where: { $0.id == h.step.id }) {
            story.steps.append(h.step)
        }
        if alive.isEmpty, let first = story.steps.min(by: { $0.date < $1.date }) {
            // A story rebuilt around old evidence: origin from where that evidence came from.
            let root = rootOf(first.pid)
            story.rootPid = root.pid; story.originName = root.originName
            story.originPath = root.originPath; story.origin = root.origin
            story.firstSeen = first.date
        }
        return story
    }

    // MARK: Evidence links

    static func program(_ e: ActivityEvent) -> String { e.kind == .exec ? e.target : e.proc }
    static func program(of s: StoryStep) -> String { s.kind == .exec ? s.target : s.proc }

    /// A new domain or a raw IP: rare enough that two programs reaching it are related.
    static func rareDestination(_ s: StoryStep) -> String? {
        switch s.stage {
        case .newDomain: return s.event.registrableDomain ?? (s.host.isEmpty ? nil : s.host)
        case .rawIP: return s.event.remoteHost
        default: return nil
        }
    }

    /// Unsigned or ad-hoc code, or anything run from Downloads, temp or a mounted volume.
    func isUntrustedProgram(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !SignatureBuilder.isSealedSystem(path), !Self.isOwn(path) else { return false }
        if Self.inZone(path, Self.dropZones) { return true }
        return signing.cached(path)?.untrustedCode ?? false
    }

    private func rememberLoginItem(_ step: StoryStep, story: UUID) {
        loginItems.removeAll { $0.plist == step.target || clock.timeIntervalSince($0.step.date) > Self.loginItemMemory }
        loginItems.append(LoginItemLink(plist: step.target, step: step, story: story))
        if loginItems.count > 50 { loginItems.removeFirst(loginItems.count - 50) }
        plistPrograms[step.target] = nil
        saveLoginItems()
    }

    /// Persistence steps whose plist starts this program (or runs this script).
    private func loginItemLinks(for program: String, args: String) -> [(step: StoryStep, story: UUID)] {
        guard !program.isEmpty, !loginItems.isEmpty else { return [] }
        return loginItems.filter { item in
            guard clock.timeIntervalSince(item.step.date) >= 0 else { return false }
            let programs = programs(startedBy: item.plist)
            return programs.contains(program) || programs.contains { args.contains($0) }
        }.map { ($0.step, $0.story) }
    }

    /// Program and script paths a launchd plist starts (read once it has content).
    private func programs(startedBy plist: String) -> [String] {
        if let known = plistPrograms[plist] { return known }
        guard let data = readPlist(plist), !data.isEmpty,
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return [] }
        var paths = (dict["ProgramArguments"] as? [String]) ?? []
        if let program = dict["Program"] as? String { paths.insert(program, at: 0) }
        let home = AppPaths.userHome
        let found = paths.map { $0.hasPrefix("~/") ? home + $0.dropFirst() : $0 }
            .filter { $0.hasPrefix("/") && !SignatureBuilder.isSealedSystem($0) }
        plistPrograms[plist] = found
        return found
    }

    private func saveLoginItems() {
        guard persistent, let data = try? JSONEncoder().encode(loginItems) else { return }
        UserDefaults.standard.set(data, forKey: "storyLoginItems")
    }

    private func loadLoginItems() {
        guard let data = UserDefaults.standard.data(forKey: "storyLoginItems"),
              let items = try? JSONDecoder().decode([LoginItemLink].self, from: data) else { return }
        loginItems = items.filter { Date().timeIntervalSince($0.step.date) < Self.loginItemMemory }
    }

    /// Other open stories within 30 minutes of this one: shown as "possibly related", never merged.
    func possiblyRelated(to story: Story) -> [Story] {
        stories.filter { other in
            other.id != story.id && !other.dismissed
                && other.firstSeen.timeIntervalSince(story.lastSeen) < 30 * 60
                && story.firstSeen.timeIntervalSince(other.lastSeen) < 30 * 60
        }
    }

    /// Joins linked stories into the oldest one (each step, once).
    private func merge(_ ids: [UUID]) -> Story {
        let parts = ids.compactMap { working[$0] }.sorted { $0.firstSeen < $1.firstSeen }
        guard var base = parts.first else {
            let root = Root(pid: 0, originName: "?", originPath: "", origin: .background)
            return Story(rootPid: root.pid, originName: root.originName, originPath: root.originPath, origin: root.origin)
        }
        for other in parts.dropFirst() {
            for step in other.steps where !base.steps.contains(where: { $0.id == step.id }) { base.steps.append(step) }
            base.firstSeen = min(base.firstSeen, other.firstSeen)
            base.fired = base.fired || other.fired
            working[other.id] = nil
            stories.removeAll { $0.id == other.id }
            for i in linkable.indices where linkable[i].story == other.id { linkable[i].story = base.id }
        }
        return base
    }

    private static func dedupeKey(_ s: StoryStep) -> String {
        switch s.kind {
        case .file: return (s.target as NSString).deletingLastPathComponent
        case .net: return s.host.isEmpty ? (s.target.split(separator: ":").dropLast().joined(separator: ":")) : s.host
        case .exec: return s.target
        }
    }

    /// Fires on several stages that add up, and only with a strong stage (or an app spawning a
    /// shell). Downloading+running an app, or an app reading its credentials and going online,
    /// is everyday behaviour on its own. Your own terminal/IDE needs even more.
    private func evaluate(_ story: inout Story) {
        let stages = Set(story.stages)
        // On a threat list: a story and Dangerous on its own, whoever started it.
        let knownBad = stages.contains(.knownBad)
        guard stages.count >= 2 || knownBad else { return }
        let score = story.score
        let fires = knownBad || story.origin == .developer
            ? score >= 6 && stages.contains(where: \.isStrong)
            : score >= 5 && (stages.contains(where: \.isStrong) || stages.contains(.appShell))
        guard fires, !ignored.contains(story.signature) else { return }
        let dangerous = knownBad || score >= 8
            || stages.isSuperset(of: [.persistence, .network])
            || stages.isSuperset(of: [.runFromDrop, .persistence])
            || stages.isSuperset(of: [.unquarantine, .runFromDrop])
        story.severity = dangerous ? .dangerous : .suspicious
        let wasFired = story.fired
        story.fired = true
        if let i = stories.firstIndex(where: { $0.id == story.id }) {
            stories[i] = story
            stories.sort { $0.lastSeen > $1.lastSeen }
        } else {
            stories.insert(story, at: 0)
        }
        if !wasFired, persistent { NSSound(named: "Funk")?.play() }
        if !wasFired { onFired?(story) }
        dirty = true
        revision += 1
    }

    // MARK: Stage detection

    private static let dropZones = ["/Downloads/", "/Users/Shared/", "/private/tmp/", "/tmp/", "/var/folders/",
                                    "/private/var/folders/", "/Volumes/"]
    private static let userDropZones = ["/Downloads/", "/Users/Shared/"]
    /// Tools that matter by themselves in a chain. Shells/interpreters only count when an app
    /// spawns them or their command line looks encoded/piped (they run everywhere otherwise).
    private static var riskyTools: Set<String> { SignatureBuilder.watchedTools }
    private static let keychainDump = try! NSRegularExpression(
        pattern: #"\b(find-(generic|internet)-password|dump-keychain|export)\b"#)
    private static let downloadTemp: Set<String> = ["crdownload", "download", "part", "partial", "opdownload"]
    private static let encoded: [NSRegularExpression] = [
        #"base64\s+(-d|-D|--decode)"#, #"\|\s*(ba|z|da)?sh\b"#, #"(curl|wget)[^|]*\|\s*\S"#,
        #"osascript\s+-e"#, #"\b(python3?|perl|ruby)\s+-(c|e)\b"#, #"\beval\b"#, #"-enc(odedcommand)?\b"#,
        #"[A-Za-z0-9+/]{120,}={0,2}"#,
    ].map { try! NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }

    /// Claude Code runs each command as `zsh -c 'source …/shell-snapshots/… && eval '<command>''`.
    /// Only the command inside is judged; the wrapper's own `eval` is not evidence.
    static func unwrapAgentCommand(_ args: String) -> String {
        guard args.contains("/shell-snapshots/snapshot-"),
              let eval = args.range(of: "&& eval ", options: .backwards) else { return args }
        return String(args[eval.upperBound...])
    }

    private static func inZone(_ path: String, _ zones: [String]) -> Bool {
        zones.contains { path.contains($0) || path.hasPrefix(String($0.dropLast())) }
    }

    private static func base(_ path: String) -> String { (path as NSString).lastPathComponent }

    /// This app's bundle; HOSTWATCH_OWN_BUNDLE lets replays recognise the installed app.
    private static let ownBundle = (ProcessInfo.processInfo.environment["HOSTWATCH_OWN_BUNDLE"]
                                    ?? Bundle.main.bundlePath) + "/"
    static func isOwn(_ path: String) -> Bool { !path.isEmpty && path.hasPrefix(ownBundle) }

    private func stages(for e: ActivityEvent) -> [(StoryStage, String)] {
        var out: [(StoryStage, String)] = []
        if !e.knownBad.isEmpty { out.append((.knownBad, e.knownBad)) }
        let sealedActor = SignatureBuilder.isSealedSystem(e.kind == .exec ? e.parent : e.proc)
        // Signing facts about the binary that runs (exec) or acts (file/net).
        let subject = e.kind == .exec ? e.target : e.proc
        if let why = signing.swapReason(subject) {
            out.append((.swappedBinary, "\(Self.base(subject)) \(why)"))
        } else if e.kind == .exec, let id = signing.cached(subject), id.untrustedCode,
                  id.quarantined || Self.inZone(subject, Self.dropZones) {
            out.append((.unsignedCode, "\(id.label.lowercased()) \(Self.base(subject)) ran"))
        }
        switch e.kind {
        case .exec:
            let name = Self.base(e.target).lowercased()
            if Self.inZone(e.target, Self.dropZones), !SignatureBuilder.isSealedSystem(e.target) {
                out.append((.runFromDrop, "ran \(Self.base(e.target)) from a download/temp folder"))
            }
            if name == "xattr" {
                // Only deleting (-d … quarantine) or clearing (-c, as in `xattr -cr App.app`) removes
                // quarantine; -p/-l just read it.
                let flags = e.args.split(separator: " ").filter { $0.hasPrefix("-") && !$0.hasPrefix("--") }
                    .joined()
                if flags.contains("c") || flags.contains("d") && e.args.contains("quarantine") {
                    out.append((.unquarantine, "removed quarantine: \(e.args)"))
                }
            }
            let range = NSRange(e.args.startIndex..., in: e.args)
            // `security`'s arguments are keychain data (hex tokens), not commands.
            let command = name == "security" ? "" : Self.unwrapAgentCommand(e.args)
            let commandRange = NSRange(command.startIndex..., in: command)
            if !command.isEmpty, Self.encoded.contains(where: { $0.firstMatch(in: command, range: commandRange) != nil }) {
                out.append((.encodedCommand, "suspicious command line"))
            }
            // Reading keychain secrets counts, unless a trusted, validly signed program reads its own
            // items (e.g. Claude Code reading "Claude Code-credentials").
            if name == "security", Self.keychainDump.firstMatch(in: e.args, range: range) != nil,
               !(signing.identity(e.parent).map { signing.isTrusted($0) } ?? false),
               !Self.readsOwnKeychainItem(args: e.args, parent: e.parent) {
                out.append((.credential, "read keychain secrets: \(e.args)"))
            }
            // A real GUI app (not Python.app & co. inside a framework) starting a shell/interpreter/tool.
            let parentApp = e.parent.contains(".app/Contents/MacOS/") && !e.parent.contains(".framework/")
                && !SignatureBuilder.isSealedSystem(e.parent) && !SignatureBuilder.isLolbin(e.parent)
                && !SignatureBuilder.shellHosts.contains(where: { e.parent.contains($0) })
            if parentApp, SignatureBuilder.isLolbin(e.target) {
                out.append((.appShell, "\(Self.base(e.parent)) started \(Self.base(e.target))"))
            } else if Self.riskyTools.contains(name), name != "xattr" || out.isEmpty {
                out.append((.lolbin, "ran \(name)"))
            }
        case .file:
            let writes = e.extra.contains("w")
            if writes, e.signaturePattern.hasSuffix("[persistence]") {
                out.append((.persistence, "wrote \(e.target)"))
            } else if e.signatureRisk == .high, e.signaturePattern.hasSuffix("]"), !sealedActor,
                      !(signing.identity(e.proc).map { signing.trusts(e.proc, $0) } ?? false) {
                // A trusted, validly signed program reading credential files (its own config, an
                // SDK's cache) is not theft; a swapped or modified binary is not trusted.
                out.append((.credential, "accessed \(e.target)"))
            } else if writes, !sealedActor, Self.inZone(e.target, Self.userDropZones) {
                out.append((.drop, "wrote \(Self.base(e.target))"))
            }
        case .net:
            // Inferred connections with an unknown destination ("?:?") are not evidence of anything public.
            guard !sealedActor || SignatureBuilder.isLolbin(e.proc), !e.target.hasPrefix("?") else { break }
            let host = e.remoteHost ?? e.target
            let bucket = SignatureBuilder.hostBucket(host)
            if !["loopback", "lan", "link-local", "multicast", "any", "cgnat"].contains(bucket) {
                out.append((.network, "connected to \(e.host.isEmpty ? e.target : "\(e.host):\(e.remotePort)")"))
            }
            if !e.newDomain.isEmpty {
                out.append((.newDomain, "first contact with \(e.newDomain)"))
            }
            if !e.beacon.isEmpty {
                out.append((.beaconing, "contacts \(BeaconDetector.destination(e)) \(e.beacon)"))
            }
            if e.rawIP {
                out.append((.rawIP, "raw IP \(e.target) without a DNS lookup"))
            }
        }
        return out
    }

    // MARK: Files handed between trees

    private func rememberWrite(_ e: ActivityEvent) {
        guard Self.inZone(e.target, Self.dropZones), !SignatureBuilder.isSealedSystem(e.proc) else { return }
        files[e.target] = (clock, StoryStep(e, stage: .drop, note: "\(e.name) wrote \(Self.base(e.target))", date: clock))
        if files.count > 6000 {   // trim to the newest 4000 in one pass
            let keep = files.sorted { $0.value.date > $1.value.date }.prefix(4000)
            files = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
    }

    /// An earlier `xattr -d com.apple.quarantine X` (any tree) for the file/app this exec runs.
    private func linkedUnquarantine(for e: ActivityEvent) -> StoryStep? {
        guard e.kind == .exec, Self.inZone(e.target, Self.dropZones) else { return nil }
        let anchor = e.target.components(separatedBy: ".app/").first.map { $0 + ".app" } ?? e.target
        return unquarantines.last { clock.timeIntervalSince($0.date) < fileMemory
                                    && ($0.args.contains(anchor) || $0.args.contains(e.target)) }
    }

    /// The write behind this exec (or behind a path in its arguments, e.g. xattr/chmod on it).
    private func linkedWrite(for e: ActivityEvent) -> StoryStep? {
        guard e.kind == .exec else { return nil }
        let now = clock
        if let f = files[e.target], now.timeIntervalSince(f.date) < fileMemory { return f.step }
        // Browsers write "x.crdownload"/"x.download"/"x.part" and rename it, so the final file is
        // never opened for writing: link the newest such write in the same folder (or bundle's folder).
        let folder = ((e.target.components(separatedBy: ".app/").first.map { $0 + ".app" } ?? e.target)
                      as NSString).deletingLastPathComponent
        if Self.inZone(e.target, Self.userDropZones),
           let f = files.filter({ (k, v) in now.timeIntervalSince(v.date) < fileMemory
                                  && (k as NSString).deletingLastPathComponent == folder
                                  && Self.downloadTemp.contains((k as NSString).pathExtension.lowercased()) })
                        .max(by: { $0.value.date < $1.value.date }) {
            return f.value.step
        }
        guard !e.args.isEmpty else { return nil }
        for (path, f) in files where now.timeIntervalSince(f.date) < fileMemory {
            // App bundles: the file written may be inside "X.app/…" while args name "X.app".
            let anchor = path.components(separatedBy: ".app/").first.map { $0 + ".app" } ?? path
            if e.args.contains(path) || (anchor != path && e.args.contains(anchor)) { return f.step }
        }
        return nil
    }

    // MARK: Process tree

    private struct Root { var pid: Int; var originName: String; var originPath: String; var origin: StoryOrigin }

    private func node(_ pid: Int) -> Proc? {
        if let p = procs[pid] { return p }
        guard liveLookups else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard pid > 0, proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        var buf = [CChar](repeating: 0, count: 4096)
        let n = proc_pidpath(Int32(pid), &buf, UInt32(buf.count))
        let p = Proc(ppid: Int(info.pbi_ppid), path: n > 0 ? String(cString: buf) : "", seen: Date(),
                     start: Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec)))
        procs[pid] = p
        return p
    }

    /// A program reading its own keychain item (gh reading "gh:github.com", claude reading
    /// "Claude Code-credentials") is using its own login, not stealing one. Never for browser and
    /// app "Safe Storage" keys (what stealers want), dumps, or programs in Downloads/temp folders.
    static func readsOwnKeychainItem(args: String, parent: String) -> Bool {
        // Claude Code's binary is named after its version (…/claude/versions/2.1.316).
        let program = parent.contains("/claude/versions/") ? "claude" : base(parent).lowercased()
        let temp = parent.hasPrefix("/tmp/") || parent.hasPrefix("/private/tmp/") || parent.contains("/var/folders/")
        guard program.count >= 2, !temp, !inZone(parent, userDropZones),
              !args.contains("dump-keychain"), !args.lowercased().contains("safe storage") else { return false }
        let range = NSRange(args.startIndex..., in: args)
        let names = keychainItemName.matches(in: args, range: range).compactMap { m -> String? in
            (1...3).lazy.compactMap { Range(m.range(at: $0), in: args).map { String(args[$0]) } }.first
        }
        guard !names.isEmpty else { return false }
        return names.allSatisfy { name in
            name.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).contains { $0 == program }
        }
    }

    /// The item named by `-s` (service) or `-l` (label): quoted or a bare word.
    private static let keychainItemName = try! NSRegularExpression(
        pattern: #"(?:^|\s)-[sl]\s+(?:'([^']*)'|"([^"]*)"|([^\s'"]+))"#)

    private static func isShell(_ path: String) -> Bool {
        ["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "nu", "elvish"].contains(base(path))
    }

    private static func isSessionStarter(_ path: String) -> Bool {
        ["login", "sshd", "sshd-session", "tmux", "screen", "launchd"].contains(base(path))
            || SignatureBuilder.shellHosts.contains { path.contains($0) }
    }

    /// Walks up until the parent is a long-lived host: launchd, a GUI app's main binary, or the
    /// interactive shell of a terminal. That child is the root, so each app action or each typed
    /// command forms its own tree, while an app's helpers and their children stay together.
    private func rootOf(_ pid: Int) -> Root {
        var current = pid
        var developer = false
        for _ in 0..<16 {
            guard let me = node(current) else { break }
            guard me.ppid > 1, let parent = node(me.ppid) else {
                let isApp = me.path.contains(".app/Contents/MacOS/")
                let name = isApp ? (me.path.components(separatedBy: ".app/").first.map { Self.base($0) } ?? "")
                                 : Self.base(me.path)
                return Root(pid: current, originName: name.isEmpty ? "launchd" : name, originPath: me.path,
                            origin: developer ? .developer : isApp ? .app : .background)
            }
            if Self.isSessionStarter(parent.path) { developer = developer || !parent.path.hasSuffix("launchd") }
            let parentIsApp = parent.path.contains(".app/Contents/MacOS/")
            let parentIsInteractiveShell = Self.isShell(parent.path)
                && (node(parent.ppid).map { Self.isSessionStarter($0.path) } ?? true)
            if parentIsApp || parentIsInteractiveShell || Self.isSessionStarter(parent.path) {
                let dev = developer || parentIsInteractiveShell
                    || SignatureBuilder.shellHosts.contains { parent.path.contains($0) }
                let name = parentIsApp
                    ? (parent.path.components(separatedBy: ".app/").first.map { Self.base($0) } ?? Self.base(parent.path))
                    : Self.base(parent.path)
                return Root(pid: current, originName: name, originPath: parent.path,
                            origin: dev ? .developer : parentIsApp ? .app : .background)
            }
            current = me.ppid
        }
        return Root(pid: current, originName: "?", originPath: "", origin: .background)
    }

    // MARK: Actions

    func dismiss(_ id: UUID) {
        update(id) { $0.dismissed = true }
    }

    /// Never alert again for this origin + set of stages.
    func ignoreAlways(_ id: UUID) {
        guard let s = stories.first(where: { $0.id == id }) else { return }
        ignored.insert(s.signature)
        UserDefaults.standard.set(Array(ignored), forKey: "ignoredStories")
        stories.removeAll { $0.id == id }
        working[id] = nil
        linkable.removeAll { $0.story == id }
        dirty = true; revision += 1
    }

    func delete(_ id: UUID) {
        stories.removeAll { $0.id == id }
        dirty = true; revision += 1
    }

    func clearIgnored() {
        ignored.removeAll()
        UserDefaults.standard.removeObject(forKey: "ignoredStories")
    }

    var ignoredCount: Int { ignored.count }

    private func update(_ id: UUID, _ change: (inout Story) -> Void) {
        guard let i = stories.firstIndex(where: { $0.id == id }) else { return }
        change(&stories[i])
        if working[id] != nil { change(&working[id]!) }
        dirty = true; revision += 1
    }

    // MARK: Upkeep and persistence

    private func maintain() {
        let now = Date()
        working = working.filter { now.timeIntervalSince($0.value.lastSeen) < window }
        linkable.removeAll { now.timeIntervalSince($0.step.date) > Self.untrustedProgramWindow }
        files = files.filter { now.timeIntervalSince($0.value.date) < fileMemory }
        if procs.count > 20_000 { procs = procs.filter { now.timeIntervalSince($0.value.seen) < 3600 } }
        if stories.count > 300 { stories.removeLast(stories.count - 300) }
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        stories = (try? decoder.decode([Story].self, from: data)) ?? []
    }

    func save() {
        guard dirty, persistent else { return }
        dirty = false
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(stories) { try? data.write(to: fileURL, options: .atomic) }
    }

    static func ago(_ date: Date, now: Date = Date()) -> String {
        let s = Int(now.timeIntervalSince(date))
        return s < 60 ? "\(s)s ago" : "\(s / 60) min ago"
    }

    /// Evidence for Claude: the whole chain in order.
    static func evidence(for story: Story) -> String {
        var lines = ["## Story (correlated by Hostwatch)",
                     "chain: \(story.title)",
                     "origin: \(story.originName) (\(story.origin.rawValue)) \(story.originPath)",
                     "stages: \(story.summary)",
                     "score: \(story.score), severity: \(story.severity.rawValue)", "", "steps:"]
        for s in story.steps {
            lines.append("- \(s.time) [\(s.stage.title)] \(s.name) pid \(s.pid) ← \(s.ppid): \(s.detail)  (\(s.note))")
        }
        return lines.joined(separator: "\n")
    }
}
