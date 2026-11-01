import AppKit
import Darwin
import Foundation
import SwiftUI

// Stories: suspicious steps from one process tree (plus files it hands to other trees),
// scored together. Each step alone is often "normal"; the chain is what matters, e.g.
// Chrome writes ~/Downloads/x → xattr -d quarantine x → x runs → writes a LaunchAgent → connects out.

// MARK: - Stages

enum StoryStage: String, Codable, CaseIterable, Comparable {
    case drop, unquarantine, runFromDrop, appShell, lolbin, encodedCommand, persistence, credential, network
    case unsignedCode, swappedBinary, newDomain, beaconing, rawIP

    static func < (a: StoryStage, b: StoryStage) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    var weight: Int {
        switch self {
        case .drop, .lolbin, .network: return 1
        case .runFromDrop, .newDomain, .rawIP: return 2
        case .unquarantine, .appShell, .encodedCommand, .credential, .unsignedCode, .beaconing: return 3
        case .persistence: return 4
        case .swappedBinary: return 5
        }
    }

    /// Strong enough to make activity started from your own terminal/IDE worth a story.
    var isStrong: Bool {
        [.unquarantine, .encodedCommand, .persistence, .credential, .unsignedCode, .swappedBinary, .beaconing]
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
        }
    }
}

// MARK: - Model

struct StoryStep: Codable, Identifiable {
    var id = UUID()
    var date: Date
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

    private struct Proc { var ppid: Int; var path: String; var seen: Date }
    private var procs: [Int: Proc] = [:]
    private var working: [Int: Story] = [:]                  // root pid -> story (fired or not)
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

    init(persistent: Bool = true) {
        self.persistent = persistent
        let dir = AppPaths.support
        fileURL = dir.appendingPathComponent("stories.json")
        ignored = persistent ? Set(UserDefaults.standard.stringArray(forKey: "ignoredStories") ?? []) : []
        guard persistent else { return }
        load()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.maintain() }
        }
    }

    var activeCount: Int { stories.filter { !$0.dismissed }.count }

    /// Undismissed stories that changed recently, for the HUD.
    func recent(within seconds: TimeInterval = 30 * 60) -> [Story] {
        stories.filter { !$0.dismissed && Date().timeIntervalSince($0.lastSeen) < seconds }
    }

    // MARK: Ingest

    func ingest(_ e: ActivityEvent, decidedSafe: Bool, at date: Date = Date()) {
        clock = date
        if e.kind == .exec, e.pid > 0 {
            procs[e.pid] = Proc(ppid: e.ppid, path: e.target, seen: date)
        }
        // A pattern you marked Safe never builds a story; neither does Hostwatch's own evidence
        // gathering (codesign, spctl, lsof… started by this app).
        guard !decidedSafe, !Self.isOwn(e.parent), !Self.isOwn(e.proc) else { return }

        if e.kind == .file, e.extra.contains("w") { rememberWrite(e) }
        var found = stages(for: e)
        guard !found.isEmpty else { return }
        if let q = found.first(where: { $0.0 == .unquarantine }) {
            unquarantines.append(StoryStep(e, stage: .unquarantine, note: q.1, date: clock))
            if unquarantines.count > 200 { unquarantines.removeFirst(100) }
        }
        let linked = linkedWrite(for: e)
        let linkedQuarantine = linkedUnquarantine(for: e)
        if linked != nil { found.removeAll { $0.0 == .runFromDrop } }   // the linked step says it better

        let root = rootOf(e.pid)
        var story = working[root.pid] ?? Story(rootPid: root.pid, originName: root.originName,
                                               originPath: root.originPath, origin: root.origin)
        let now = clock
        story.steps.removeAll { now.timeIntervalSince($0.date) > window }
        if story.steps.isEmpty { story.firstSeen = now; story.fired = false; story.dismissed = false }

        for (stage, note) in found {
            let step = StoryStep(e, stage: stage, note: note, date: now)
            // One directory walk or a burst of connections is one step, not sixty.
            let key = Self.dedupeKey(step)
            // Same tool run again (new pid each time) or same process touching the same place.
            if story.steps.contains(where: { $0.stage == stage && Self.dedupeKey($0) == key
                                             && ($0.pid == step.pid || step.kind == .exec) }) {
                continue
            }
            if story.steps.filter({ $0.stage == stage }).count >= 8 { continue }
            story.steps.append(step)
        }
        // Running a file another tree wrote (or un-quarantined) pulls those steps into this story.
        if let linked, !story.steps.contains(where: { $0.id == linked.id }) {
            story.steps.append(linked)
            story.steps.append(StoryStep(e, stage: .runFromDrop,
                                         note: "ran a file \(linked.name) wrote \(Self.ago(linked.date, now: now))",
                                         date: now))
        }
        if let q = linkedQuarantine, !story.steps.contains(where: { $0.id == q.id }) {
            story.steps.append(q)
        }
        guard !story.steps.isEmpty else { return }
        story.steps.sort { $0.date < $1.date }
        if story.steps.count > 60 { story.steps.removeFirst(story.steps.count - 60) }
        story.lastSeen = now
        evaluate(&story)
        working[root.pid] = story
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
        guard stages.count >= 2 else { return }
        let score = story.score
        let fires = story.origin == .developer
            ? score >= 6 && stages.contains(where: \.isStrong)
            : score >= 5 && (stages.contains(where: \.isStrong) || stages.contains(.appShell))
        guard fires, !ignored.contains(story.signature) else { return }
        let dangerous = score >= 8
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
        dirty = true
        revision += 1
    }

    // MARK: Stage detection

    private static let dropZones = ["/Downloads/", "/Users/Shared/", "/private/tmp/", "/tmp/", "/var/folders/",
                                    "/private/var/folders/", "/Volumes/"]
    private static let userDropZones = ["/Downloads/", "/Users/Shared/"]
    /// Tools that matter by themselves in a chain. Shells/interpreters only count when an app
    /// spawns them or their command line looks encoded/piped (they run everywhere otherwise).
    private static let riskyTools: Set<String> = [
        "curl", "wget", "nc", "ncat", "netcat", "socat", "osascript", "osacompile", "base64", "openssl",
        "security", "sqlite3", "launchctl", "dscl", "xattr", "spctl", "screencapture", "scp", "sftp", "ftp",
        "telnet", "ditto", "hdiutil", "pkgutil", "installer", "codesign", "chflags", "csrutil", "tccutil",
        "defaults", "profiles", "networksetup", "systemsetup", "kextload", "funzip",
    ]
    private static let keychainDump = try! NSRegularExpression(
        pattern: #"\b(find-(generic|internet)-password|dump-keychain|export)\b"#)
    private static let downloadTemp: Set<String> = ["crdownload", "download", "part", "partial", "opdownload"]
    private static let encoded: [NSRegularExpression] = [
        #"base64\s+(-d|-D|--decode)"#, #"\|\s*(ba|z|da)?sh\b"#, #"(curl|wget)[^|]*\|\s*\S"#,
        #"osascript\s+-e"#, #"\b(python3?|perl|ruby)\s+-(c|e)\b"#, #"\beval\b"#, #"-enc(odedcommand)?\b"#,
        #"[A-Za-z0-9+/]{120,}={0,2}"#,
    ].map { try! NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }

    private static func inZone(_ path: String, _ zones: [String]) -> Bool {
        zones.contains { path.contains($0) || path.hasPrefix(String($0.dropLast())) }
    }

    private static func base(_ path: String) -> String { (path as NSString).lastPathComponent }

    /// This app's bundle; HOSTWATCH_OWN_BUNDLE lets replays recognise the installed app.
    private static let ownBundle = (ProcessInfo.processInfo.environment["HOSTWATCH_OWN_BUNDLE"]
                                    ?? Bundle.main.bundlePath) + "/"
    private static func isOwn(_ path: String) -> Bool { !path.isEmpty && path.hasPrefix(ownBundle) }

    private func stages(for e: ActivityEvent) -> [(StoryStage, String)] {
        var out: [(StoryStage, String)] = []
        let sealedActor = SignatureBuilder.isSealedSystem(e.kind == .exec ? e.parent : e.proc)
        // Signing facts about the binary that runs (exec) or acts (file/net).
        let subject = e.kind == .exec ? e.target : e.proc
        if let why = SigningCache.shared.swapReason(subject) {
            out.append((.swappedBinary, "\(Self.base(subject)) \(why)"))
        } else if e.kind == .exec, let id = SigningCache.shared.cached(subject), id.untrustedCode,
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
            if !e.args.isEmpty, Self.encoded.contains(where: { $0.firstMatch(in: e.args, range: range) != nil }) {
                out.append((.encodedCommand, "suspicious command line"))
            }
            // Reading keychain secrets counts, unless a trusted, validly signed program reads its own
            // items (e.g. Claude Code reading "Claude Code-credentials").
            if name == "security", Self.keychainDump.firstMatch(in: e.args, range: range) != nil,
               !(SigningCache.shared.identity(e.parent).map { SigningCache.shared.isTrusted($0) } ?? false) {
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
            } else if e.signatureRisk == .high, e.signaturePattern.hasSuffix("]"), !sealedActor {
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
        let p = Proc(ppid: Int(info.pbi_ppid), path: n > 0 ? String(cString: buf) : "", seen: Date())
        procs[pid] = p
        return p
    }

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
        working = working.filter { $0.value.id != id }
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
        if let key = working.first(where: { $0.value.id == id })?.key { change(&working[key]!) }
        dirty = true; revision += 1
    }

    // MARK: Upkeep and persistence

    private func maintain() {
        let now = Date()
        working = working.filter { now.timeIntervalSince($0.value.lastSeen) < window }
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

// MARK: - Views

private extension SignatureStatus {
    var color: Color { Color(nsColor: nsColor) }
}

/// Stories tab: newest first, each a card with its chain of steps.
struct StoriesView: View {
    @ObservedObject var stories: StoryEngine
    let search: String
    let actions: HUDActions

    var body: some View {
        let _ = stories.revision
        let rows = filtered
        VStack(spacing: 0) {
            content(rows)
                .frame(maxWidth: .infinity, maxHeight: .infinity)   // footer stays at the window's bottom
            Divider()
            footer
        }
    }

    @ViewBuilder
    private func content(_ rows: [Story]) -> some View {
        if rows.isEmpty {
            ContentUnavailableView {
                Label(search.isEmpty ? "No Stories Yet" : "No Matching Stories",
                      systemImage: "point.3.connected.trianglepath.dotted")
            } description: {
                Text("""
                A story appears when several suspicious steps happen in one process tree within 15 minutes, \
                e.g. an app spawning a shell that downloads and runs something, or a download that removes \
                its quarantine, runs and installs a LaunchAgent. Single events stay in Events and Patterns.
                """)
            }
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(rows) { StoryCard(story: $0, stories: stories, actions: actions) }
                }
                .padding(16)
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("\(stories.activeCount) open · \(stories.stories.count) total")
            if stories.ignoredCount > 0 {
                Text("·")
                Button("Reset \(stories.ignoredCount) ignored chains") { stories.clearIgnored() }
                    .buttonStyle(.link)
            }
            Spacer()
        }
        .font(.system(size: 11))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var filtered: [Story] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let all = stories.stories.sorted { ($0.dismissed ? 1 : 0, $1.lastSeen) < ($1.dismissed ? 1 : 0, $0.lastSeen) }
        guard !q.isEmpty else { return all }
        return all.filter { s in
            s.title.lowercased().contains(q) || s.steps.contains { $0.detail.lowercased().contains(q) }
        }
    }
}

private struct StoryCard: View {
    let story: Story
    let stories: StoryEngine
    let actions: HUDActions

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                StatusPill(status: story.severity)
                Text(story.title)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 8)
                Text("\(story.origin == .developer ? "from your terminal" : story.origin == .app ? "from an app" : "background")")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text(StoryEngine.ago(story.lastSeen))
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            // Stage chips.
            HStack(spacing: 6) {
                ForEach(story.stages, id: \.self) { stage in
                    Label(stage.title, systemImage: stage.symbol)
                        .font(.system(size: 11, weight: .medium))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(story.severity.color.opacity(stage.isStrong ? 0.22 : 0.10)))
                }
                Spacer()
                Text("score \(story.score)").font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
            }
            DisclosureGroup("\(story.steps.count) steps") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(story.steps) { step in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(step.time).foregroundStyle(.secondary).frame(width: 62, alignment: .leading)
                            Image(systemName: step.stage.symbol)
                                .foregroundStyle(step.stage.isStrong ? story.severity.color : .secondary)
                                .frame(width: 16)
                            Text("\(step.name) \(step.pid)").fontWeight(.medium).frame(width: 150, alignment: .leading)
                                .lineLimit(1)
                            Text(step.detail).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                                .help(step.note)
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .contentShape(Rectangle())
                        .onTapGesture(count: 2) { actions.askAI(step.event) }
                    }
                }
                .padding(.top, 4)
            }
            .font(.system(size: 11))
            HStack(spacing: 8) {
                Button { actions.askStory(story) } label: { Label("Ask AI", systemImage: "sparkles") }
                    .buttonStyle(.glassProminent)
                if !story.dismissed {
                    Button("Dismiss") { stories.dismiss(story.id) }.buttonStyle(.glass)
                }
                Button("Always Ignore This Chain") { stories.ignoreAlways(story.id) }
                    .buttonStyle(.glass)
                    .help("Never alert again for \(story.originName) with these stages")
                Spacer()
                Button(role: .destructive) { stories.delete(story.id) } label: { Image(systemName: "trash") }
                    .buttonStyle(.glass)
                    .help("Delete this story")
            }
            .controlSize(.small)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.secondary.opacity(0.07)))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 16, bottomLeadingRadius: 16, style: .continuous)
                .fill(story.severity.color)
                .frame(width: 4)
        }
        .opacity(story.dismissed ? 0.55 : 1)
    }
}

/// Pinned alert at the top of the HUD.
struct StoryBanner: View {
    let story: Story
    let s: CGFloat

    var body: some View {
        HStack(spacing: 6 * s) {
            Image(systemName: story.severity == .dangerous ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 10 * s, weight: .bold))
                .foregroundStyle(Color(nsColor: story.severity.nsColor))
            VStack(alignment: .leading, spacing: 0) {
                Text(story.title)
                    .font(.system(size: 11 * s, weight: .semibold))
                    .foregroundStyle(HUDInk.primary)
                    .lineLimit(1).truncationMode(.middle)
                Text(story.summary)
                    .font(.system(size: 10 * s))
                    .foregroundStyle(HUDInk.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 2)
            Text(StoryEngine.ago(story.lastSeen))
                .font(.system(size: 9.5 * s).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
        }
        .padding(.horizontal, 7 * s)
        .padding(.vertical, 4 * s)
        .background(RoundedRectangle(cornerRadius: 8 * s, style: .continuous)
            .fill(Color(nsColor: story.severity.nsColor).opacity(0.35)))
    }
}

// MARK: - Replay (developer tool)

/// `Hostwatch --story-replay history.jsonl`: feeds recorded events through the story engine
/// with their recorded timestamps and prints the stories it would raise.
@MainActor
func runStoryReplay(_ path: String) -> Never {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { print("cannot read \(path)"); exit(1) }
    SigningCache.shared.live = false
    SigningCache.shared.trustInstalledAppsInMemory()
    let engine = StoryEngine(persistent: false)
    engine.liveLookups = false
    let decoder = JSONDecoder()
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let learnMinutes = Double(ProcessInfo.processInfo.environment["REPLAY_LEARN_MINUTES"] ?? "") ?? 60
    var domains: DomainRegistry?
    let beacons = BeaconDetector()
    var beaconHits: [String: String] = [:]                  // key -> label
    var rawIPs = Set<String>()
    var newDomains: [(String, String, String)] = []   // time, domain, program
    var n = 0
    for line in text.split(separator: "\n") {
        let data = Data(line.utf8)
        guard var e = try? decoder.decode(ActivityEvent.self, from: data) else { continue }
        let ts = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["ts"] as? String
        let date = ts.flatMap { iso.date(from: $0) } ?? Date()
        if domains == nil { domains = DomainRegistry(replayLearningUntil: date.addingTimeInterval(learnMinutes * 60)) }
        if e.kind == .net {
            if let d = domains?.observe(e, at: date) {
                e.newDomain = d
                if domains?.records[d]?.count == 1 { newDomains.append((e.time, d, e.name)) }
            }
            if let b = beacons.observe(e, at: date) {
                e.beacon = b
                beaconHits["\(e.name) → \(BeaconDetector.destination(e))"] = b
            }
            e.rawIP = NetSignals.isRawIP(e)
            if e.rawIP { rawIPs.insert("\(e.name) → \(e.target)") }
        }
        engine.ingest(e, decidedSafe: false, at: date)
        n += 1
    }
    print("domains: \(domains?.records.count ?? 0) seen, learning \(Int(learnMinutes)) min, "
          + "\(newDomains.count) new after learning")
    for (time, d, program) in newDomains.prefix(40) { print("   \(time) NEW DOMAIN \(d)  (\(program))") }
    print("beacons: \(beaconHits.count), raw-IP connections: \(rawIPs.count)")
    for (k, b) in beaconHits.sorted(by: { $0.key < $1.key }).prefix(20) { print("   BEACON \(k) \(b)") }
    for k in rawIPs.sorted().prefix(20) { print("   RAW IP \(k)") }
    let fired = engine.stories
    print("\(n) events -> \(fired.count) stories")
    for s in fired.reversed() {
        print("\n[\(s.severity.rawValue.uppercased())] score \(s.score)  \(s.title)   (origin \(s.origin.rawValue): \(s.originPath))")
        print("   stages: \(s.summary)")
        for st in s.steps.prefix(12) {
            print("   \(st.time) \(st.stage.rawValue.padding(toLength: 14, withPad: " ", startingAt: 0)) \(st.name): \(st.detail.prefix(110))")
        }
        if s.steps.count > 12 { print("   … \(s.steps.count - 12) more") }
    }
    exit(0)
}
