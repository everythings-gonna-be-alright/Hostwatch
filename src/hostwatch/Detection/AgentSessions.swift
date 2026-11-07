import Combine
import Darwin
import Foundation

// CodingAgent sessions: one Claude Code (or Cursor agent, Codex, Gemini CLI) process and everything its process tree
// does. An event gets its session by lineage when it arrives (a child that daemonizes and is reparented to launchd
// keeps its session), so the Events list can show one session's activity, the Patterns tab the patterns it
// produced, and the MCP server can list sessions for Claude to audit its own footprint.

/// A coding agent Hostwatch recognises by its executable.
enum CodingAgent: String, Codable, CaseIterable {
    case claude, cursor, codex, gemini

    var title: String {
        switch self {
        case .claude: "Claude Code"
        case .cursor: "Cursor agent"
        case .codex: "Codex"
        case .gemini: "Gemini CLI"
        }
    }

    var short: String {
        switch self {
        case .claude: "Claude"
        case .cursor: "Cursor"
        case .codex: "Codex"
        case .gemini: "Gemini"
        }
    }

    /// An agent's helper process (Claude Code's pty host and spare daemons): not a session of its own.
    static func isHelper(args: String) -> Bool {
        ["bg-pty-host", "bg-spare", "--bg-daemon", "--chrome-native-host", "bridge-spawn", "--daemon"].contains { args.contains($0) }
    }

    /// The project a working directory names: its folder, unless it's the home folder itself (an agent started
    /// from a daemon, not from a project).
    static func project(ofCwd cwd: String) -> String {
        cwd.isEmpty || cwd == AppPaths.userHome ? "" : (cwd as NSString).lastPathComponent
    }

    /// The agent an executable is, or nil.
    static func of(_ path: String) -> CodingAgent? {
        if path.contains("/.local/share/claude/versions/") || path.contains("/@anthropic-ai/claude-code/") { return .claude }
        if path.contains("/cursor-agent/versions/") { return .cursor }
        switch (path as NSString).lastPathComponent {
        case "claude": return .claude
        case "cursor-agent": return .cursor
        case "codex": return .codex
        case "gemini": return .gemini
        default: return nil
        }
    }
}

/// One session: the agent's process and its tree.
struct AgentSession: Identifiable, Codable, Equatable {
    var id: Int                     // the agent process's pid
    var agent: CodingAgent
    var started: Date
    var ended: Date?
    var lastSeen: Date
    /// The project: the working directory's name ("ProcessHUD"), or "" until known.
    var project = ""
    var cwd = ""
    /// Claude Code's own session id (from the guard hook), when known.
    var sessionID = ""
    /// The session's topic, as Claude Code titles it ("Pattern classifier noise reduction"), when known.
    var title = ""
    /// The first prompt (what `claude --resume` shows when there's no title yet) and the git branch, when known.
    var firstPrompt = ""
    var branch = ""
    var events = 0
    var launches = 0
    var files = 0
    var connections = 0
    /// Patterns first seen in this session.
    var newPatterns = 0
    var pids: Set<Int>
    /// Every pattern key seen in it (the Patterns tab's scope).
    var keys: Set<String> = []
    /// Domains (or hosts) its tree connected to (the Network tab's tag).
    var destinations: Set<String> = []

    var isLive: Bool { ended == nil }
    /// The topic, as `claude --resume` lists it: the title, else the first prompt, else the project.
    var topic: String {
        !title.isEmpty ? title : !firstPrompt.isEmpty ? firstPrompt : project.isEmpty ? "\(agent.short) · pid \(id)" : project
    }

    /// "Claude · ProcessHUD · Pattern classifier noise reduction".
    var name: String {
        (project.isEmpty ? "\(agent.short) · pid \(id)" : "\(agent.short) · \(project)") + (title.isEmpty && firstPrompt.isEmpty ? "" : " · \(topic)")
    }
    var duration: TimeInterval { (ended ?? lastSeen).timeIntervalSince(started) }
}

@MainActor
final class AgentSessions: ObservableObject {
    /// Live sessions, and ended ones for a while (newest first).
    @Published private(set) var sessions: [AgentSession] = []
    /// Ended sessions stay listed this long.
    static let keepEnded: TimeInterval = 30 * 60

    private var parentOf: [Int: Int] = [:]          // pid -> ppid, from process starts and process lists
    private var sessionOf: [Int: Int] = [:]         // pid -> session id (the agent's pid)
    private var index: [Int: Int] = [:]             // session id -> position in `sessions`
    private let fileURL: URL?
    private var saveScheduled = false
    /// Whether a process is alive (tests pretend).
    var isAlive: (Int) -> Bool = { pid in kill(pid_t(pid), 0) == 0 || errno == EPERM }
    /// A live process's working directory (tests pretend).
    var workingDirectory: (Int) -> String? = AgentSessions.cwd(of:)
    var now: () -> Date = { Date() }

    /// `fileURL`: where the list is saved for the MCP server (nil: not saved, e.g. tests).
    nonisolated init(fileURL: URL? = AppPaths.support.appendingPathComponent("agent-sessions.json")) {
        self.fileURL = fileURL
    }
    private var timer: Timer?

    /// Every 10 s once there is something to follow: sessions whose agent exited end.
    private func startTimerIfNeeded() {
        guard timer == nil, fileURL != nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkEnded() }
        }
    }

    func session(_ id: Int) -> AgentSession? { index[id].map { sessions[$0] } }
    func session(forPid pid: Int) -> AgentSession? { sessionOf[pid].flatMap { session($0) } }
    var live: [AgentSession] { sessions.filter(\.isLive) }

    /// Records an event; returns the session it belongs to, if any.
    @discardableResult
    func observe(_ e: ActivityEvent) -> Int? {
        let at = e.ts > 0 ? Date(timeIntervalSince1970: e.ts) : now()
        var id: Int?
        if e.kind == .exec {
            parentOf[e.pid] = e.ppid
            if let agent = CodingAgent.of(e.target), root(of: e.ppid) == nil, !CodingAgent.isHelper(args: e.args) {
                // A new agent, unless one agent runs another (a sub-agent): then it's part of the outer session.
                let cwd = workingDirectory(e.pid) ?? ""
                let s = AgentSession(id: e.pid, agent: agent, started: at, lastSeen: at,
                                     project: CodingAgent.project(ofCwd: cwd), cwd: cwd, pids: [e.pid])
                add(s)
                id = e.pid
            } else {
                id = root(of: e.ppid)
                if let id { sessionOf[e.pid] = id }
            }
        } else {
            id = root(of: e.pid)
        }
        guard let id, let i = index[id] else { return nil }
        var s = sessions[i]
        s.lastSeen = max(s.lastSeen, at)
        s.events += 1
        switch e.kind {
        case .exec: s.launches += 1; s.pids.insert(e.pid)
        case .file: s.files += 1
        case .net:
            s.connections += 1
            let host = e.host.isEmpty ? String(e.target.split(separator: ":").first ?? "") : e.host
            if let d = DomainRegistry.registrable(host) ?? (host.isEmpty ? nil : host.lowercased()) { s.destinations.insert(d) }
        }
        if !e.signatureKey.isEmpty { s.keys.insert(e.signatureKey) }
        if e.isFirst { s.newPatterns += 1 }
        sessions[i] = s
        scheduleSave()
        return id
    }

    /// The process list (once a minute, or every few seconds while Running Now is open): lineage for processes whose
    /// start Hostwatch didn't see, and agents that were already running when it started.
    func learn(_ list: [RunningProcessInfo]) {
        for p in list where parentOf[p.pid] == nil { parentOf[p.pid] = p.ppid }
        for p in list where CodingAgent.of(p.path) != nil && sessionOf[p.pid] == nil && root(of: p.ppid) == nil
                && !CodingAgent.isHelper(args: p.args) {
            let at = p.start > 0 ? Date(timeIntervalSince1970: p.start) : now()
            let cwd = workingDirectory(p.pid) ?? ""
            add(AgentSession(id: p.pid, agent: CodingAgent.of(p.path)!, started: at, lastSeen: now(),
                             project: CodingAgent.project(ofCwd: cwd), cwd: cwd, pids: [p.pid]))
        }
        checkEnded()
    }

    /// The guard hook saw a tool call: the agent's pid (found by the hook), Claude Code's session id and the
    /// working directory name the session.
    func learn(hookAgentPid pid: Int, sessionID: String, cwd: String, transcript: String = "") {
        guard pid > 0 else { return }
        if index[pid] == nil, isAlive(pid) {
            add(AgentSession(id: pid, agent: .claude, started: now(), lastSeen: now(), pids: [pid]))
        }
        guard let i = index[pid] else { return }
        var s = sessions[i]
        if !sessionID.isEmpty { s.sessionID = sessionID }
        if !cwd.isEmpty { s.cwd = cwd; s.project = CodingAgent.project(ofCwd: cwd) }
        // The title appears after a few turns: looked for again while it's missing (the file's first lines only).
        if s.title.isEmpty, !transcript.isEmpty, let facts = Self.facts(inTranscript: transcript) {
            if let t = facts.title { s.title = t }
            if s.firstPrompt.isEmpty, let p = facts.firstPrompt { s.firstPrompt = p }
            if let b = facts.branch { s.branch = b }
        }
        s.lastSeen = now()
        sessions[i] = s
        scheduleSave()
    }

    /// Every 10 s (the app's timer): sessions whose agent process is gone end; old ended ones drop off.
    func checkEnded() {
        var changed = false
        for i in sessions.indices where sessions[i].ended == nil && !isAlive(sessions[i].id) {
            sessions[i].ended = now(); changed = true
            for pid in sessions[i].pids { sessionOf[pid] = nil }
        }
        let cutoff = now().addingTimeInterval(-Self.keepEnded)
        if sessions.contains(where: { ($0.ended ?? .distantFuture) < cutoff }) {
            sessions.removeAll { ($0.ended ?? .distantFuture) < cutoff }
            changed = true
        }
        if changed { reindex(); scheduleSave() }
    }

    /// The session (if any) a destination belongs to: live ones first, then recent.
    func session(forDestination d: String) -> AgentSession? {
        sessions.first { $0.destinations.contains(d) }
    }

    /// Sessions in recorded events (Time Travel): replayed in time order, so lineage works as it did live. Ended at
    /// their last event; named from the saved list when the pid and start match, else by pid.
    nonisolated static func replay(_ events: [ActivityEvent], named: [AgentSession] = []) -> [AgentSession] {
        let engine = AgentSessions(fileURL: nil)
        return MainActor.assumeIsolated {
            engine.isAlive = { _ in true }
            engine.workingDirectory = { _ in nil }
            for e in events.sorted(by: { $0.ts < $1.ts }) { engine.observe(e) }
            return engine.sessions.map { s in
                var c = s
                c.ended = s.lastSeen
                if let known = named.first(where: { $0.id == s.id && abs($0.started.timeIntervalSince(s.started)) < 120 }) {
                    c.project = known.project; c.cwd = known.cwd; c.sessionID = known.sessionID; c.title = known.title
                    c.firstPrompt = known.firstPrompt; c.branch = known.branch
                }
                return c
            }
        }
    }

    /// The session a pid belongs to, by lineage (its ancestors' sessions count too: a process started before
    /// Hostwatch saw it is still inside the tree).
    private func root(of pid: Int) -> Int? {
        var p = pid, hops = 0
        while p > 1, hops < 64 {
            if let id = sessionOf[p], session(id)?.isLive == true { return id }
            if session(p)?.isLive == true { return p }                      // an ended one's pid may be reused
            guard let parent = parentOf[p] else { return nil }
            p = parent; hops += 1
        }
        return nil
    }

    private func add(_ s: AgentSession) {
        startTimerIfNeeded()
        sessions.insert(s, at: 0)
        sessionOf[s.id] = s.id
        reindex()
        scheduleSave()
    }

    private func reindex() {
        index = Dictionary(uniqueKeysWithValues: sessions.enumerated().map { ($1.id, $0) })
    }

    // MARK: Saving (for the MCP server)

    private func scheduleSave() {
        guard fileURL != nil, !saveScheduled else { return }
        saveScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            MainActor.assumeIsolated { self?.saveScheduled = false; self?.save() }
        }
    }

    func save() {
        guard let fileURL else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(sessions) { try? data.write(to: fileURL, options: .atomic) }
    }

    /// The saved list (the MCP server reads it while the app runs).
    nonisolated static func readSaved(from directory: URL) -> [AgentSession] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: directory.appendingPathComponent("agent-sessions.json")) else { return [] }
        return (try? decoder.decode([AgentSession].self, from: data)) ?? []
    }

    // MARK: What Claude Code knows about a session (its transcript's first lines)

    struct TranscriptFacts: Equatable { var title: String?; var firstPrompt: String?; var branch: String? }

    /// The title you gave it ("custom-title") or the one Claude Code made ("ai-title"), the first prompt and the git
    /// branch, from the transcript's first lines (what `claude --resume` lists).
    nonisolated static func facts(inTranscript path: String) -> TranscriptFacts? {
        guard let handle = FileHandle(forReadingAtPath: path), let head = try? handle.read(upToCount: 65_536) else { return nil }
        try? handle.close()
        return facts(inTranscriptHead: head)
    }

    nonisolated static func facts(inTranscriptHead head: Data) -> TranscriptFacts? {
        var out = TranscriptFacts()
        var ai: String?
        for line in head.split(separator: 0x0A) {
            guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any], let type = obj["type"] as? String
            else { continue }
            switch type {
            case "custom-title": if let t = obj["customTitle"] as? String, !t.isEmpty { out.title = t }
            case "ai-title": if let t = obj["aiTitle"] as? String, !t.isEmpty { ai = t }
            case "user":
                guard out.firstPrompt == nil, obj["isMeta"] as? Bool != true, obj["isCompactSummary"] as? Bool != true,
                      let message = obj["message"] as? [String: Any] else { continue }
                var text = message["content"] as? String
                if text == nil, let parts = message["content"] as? [[String: Any]] {
                    text = parts.compactMap { $0["type"] as? String == "text" ? $0["text"] as? String : nil }.first
                }
                if let text = text?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty, !text.hasPrefix("<") {
                    out.firstPrompt = String(text.split(separator: "\n").first ?? "").prefix(80).trimmingCharacters(in: .whitespaces)
                    if let b = obj["gitBranch"] as? String, !b.isEmpty { out.branch = b }
                }
            default: continue
            }
        }
        if out.title == nil { out.title = ai }
        return out == TranscriptFacts() ? nil : out
    }

    /// The title alone (tests and the chip).
    nonisolated static func title(inTranscriptHead head: Data) -> String? { facts(inTranscriptHead: head)?.title }

    // MARK: The working directory of a live process

    /// The process's current directory, readable for your own processes (libproc).
    nonisolated static func cwd(of pid: Int) -> String? {
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid_t(pid), PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
        return withUnsafePointer(to: &info.pvi_cdir.vip_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
    }

    /// The nearest ancestor of `pid` that is a coding agent (the hook runs this in its own process, a shell or two
    /// below the agent), or 0.
    nonisolated static func agentAncestor(of pid: Int) -> Int {
        var p = pid
        for _ in 0..<16 {
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.size
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, Int32(p)]
            guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return 0 }
            let parent = Int(info.kp_eproc.e_ppid)
            guard parent > 1 else { return 0 }
            var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            if proc_pidpath(pid_t(parent), &buffer, UInt32(buffer.count)) > 0, CodingAgent.of(String(cString: buffer)) != nil {
                return parent
            }
            p = parent
        }
        return 0
    }
}
