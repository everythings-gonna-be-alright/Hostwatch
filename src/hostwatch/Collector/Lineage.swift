import Foundation

// Who is behind a process, from kernel facts only, or nothing. source: docs/adr/0019-patterns-name-who-did-it.md
// A pattern that names who did it carries your decisions for that origin, so a wrong name would hand one origin's
// trust to another: every answer here is proven from Endpoint Security, and anything not proven is withheld.

/// One program execution, as Endpoint Security names it: the pid and its generation (a new one with every exec), so
/// a later process that reuses the pid is never mistaken for it.
struct ExecID: Hashable, Sendable {
    let pid: Int
    let generation: Int
}

/// What the collector knows about one execution, all from the kernel.
struct ExecFacts: Sendable {
    var path: String
    /// The execution it came from: the one that forked it, or the one it replaced by exec. Recorded when it was
    /// created, so a process that detaches (adopted by launchd) keeps its real parent. Nil: not known.
    var parent: ExecID?
    /// Its parent is launchd (or the kernel) from the start: the top of a chain.
    var fromLaunchd = false
    var responsible: ExecID?
    /// The code signature the kernel checked: team, signing identifier, and whether it was valid.
    var team = ""
    var signing = ""
    var validSignature = false
    /// It looks like an AI agent by its name or command line, but nothing proves which: who is withheld below it.
    var agentLike = false
}

/// Who is behind a process. `agent` and `app` are proven, `unknown` names nobody.
enum Who: Equatable, Sendable {
    case agent(String)                  // a verified AI agent above it: "Claude Code"
    case app(String)                    // no agent anywhere up to launchd: the app macOS holds responsible (its path)
    case unknown
}

/// AI agents recognised by their signature, never by name. Agents that run as scripts (Codex, Gemini CLI,
/// cursor-agent: the running program is node or bash) can't be proven and are not here.
enum VerifiedAgent {
    static let all: [(team: String, signing: String, name: String)] = [
        ("Q6L2SF6YDW", "com.anthropic.claude-code", "Claude Code"),
    ]

    static func name(_ f: ExecFacts) -> String? {
        guard f.validSignature else { return nil }
        return all.first { $0.team == f.team && $0.signing == f.signing }?.name
    }
}

/// Every execution the collector has seen, and who is behind each. Thread-safe.
final class Lineage: @unchecked Sendable {
    private let lock = NSLock()                     // guards both maps
    // A Mac runs about a thousand processes: 16,384 executions hold them and the ancestors they need many times over.
    private var facts = BoundedMap<ExecID, ExecFacts>(limit: 16_384)
    private var proven = BoundedMap<ExecID, Who>(limit: 16_384)
    /// Each pid's current execution, for events that only know the pid (connections).
    private var current = BoundedMap<Int, ExecID>(limit: 8_192)
    static let maxDepth = 64

    /// The first facts about an execution win: what it was created from never changes, and a later message's
    /// parent may be launchd after it detached.
    func learn(_ id: ExecID, _ f: ExecFacts) {
        lock.lock(); defer { lock.unlock() }
        if facts[id] == nil { facts[id] = f }
        if (current[id.pid]?.generation ?? Int.min) <= id.generation { current[id.pid] = id }
    }

    func markAgentLike(_ id: ExecID) {
        lock.lock(); defer { lock.unlock() }
        if var f = facts[id] { f.agentLike = true; facts[id] = f }
    }

    func execution(ofPid pid: Int) -> ExecID? {
        lock.lock(); defer { lock.unlock() }
        return current[pid]
    }

    func facts(_ id: ExecID) -> ExecFacts? {
        lock.lock(); defer { lock.unlock() }
        return facts[id]
    }

    /// Who is behind `id`: the nearest verified agent above it; else, when every link up to launchd is known and none
    /// only looks like an agent, the app responsible for it (not itself); else nobody.
    func who(_ id: ExecID) -> Who {
        lock.lock(); defer { lock.unlock() }
        if let known = proven[id] { return known }
        guard let start = facts[id], !start.agentLike else { return .unknown }     // it only looks like an agent itself
        let answer = walk(from: start.parent, top: start.fromLaunchd, responsible: start.responsible, own: id)
        if answer != .unknown { proven[id] = answer }    // proven answers never change: the facts they come from don't
        return answer
    }

    /// Who would be behind a program `parent` is about to launch (a launch held for your answer: it has no execution
    /// yet). The launching process is part of its chain.
    func whoForLaunch(by parent: ExecID) -> Who {
        lock.lock(); defer { lock.unlock() }
        guard let p = facts[parent] else { return .unknown }
        return walk(from: parent, top: false, responsible: p.responsible, own: nil)
    }

    /// Up from `link` to launchd. `unknown` isn't kept: a missing link may still be learned.
    private func walk(from first: ExecID?, top: Bool, responsible: ExecID?, own: ExecID?) -> Who {
        var link = first
        var reachedTop = top
        var depth = 0
        while let up = link, depth < Self.maxDepth {
            depth += 1
            if up.pid <= 1 { reachedTop = true; break }
            guard let f = facts[up] else { return .unknown }           // a link not seen: not proven
            if let name = VerifiedAgent.name(f) { return .agent(name) }
            if f.agentLike { return .unknown }                          // an agent nothing proves: withheld
            if f.fromLaunchd { reachedTop = true; break }
            link = f.parent
        }
        guard reachedTop, let r = responsible, r != own, let app = facts[r], !app.path.isEmpty else { return .unknown }
        return .app(app.path)
    }

}

/// Programs that look like an AI agent by name or command line. Only ever used to withhold who did it below them,
/// never to name one: faking it can only take attribution away.
enum AgentLookalike {
    static let markers = ["claude-code", "/.local/share/claude/", "@openai/codex", "/codex", "gemini-cli", "cursor-agent",
                          "/.cursor-server/", "aider", "/opencode"]

    static func matches(path: String, args: String) -> Bool {
        if CodingAgent.of(path) != nil { return true }
        let text = (path + " " + args).lowercased()
        return markers.contains { text.contains($0) }
    }
}

