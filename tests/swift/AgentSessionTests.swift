import Foundation
import Testing
@testable import Hostwatch

/// Agent sessions: a Claude Code process and its tree, told apart by lineage at the moment each event arrives.
@MainActor @Suite(.serialized) struct AgentSessionTracking {
    let claude = "\(home)/.local/share/claude/versions/2.1.316"
    let zsh = "/bin/zsh", git = "/usr/bin/git", curl = "/usr/bin/curl"

    final class Alive { var pids: Set<Int> = [100, 200] }
    let alive = Alive()

    func engine() -> AgentSessions {
        _ = TestEnv.ready
        let s = AgentSessions(fileURL: nil)
        let alive = alive
        s.isAlive = { alive.pids.contains($0) }
        s.workingDirectory = { pid in pid == 100 ? "\(home)/Documents/ProcessHUD" : nil }
        return s
    }

    @Test func aSessionIsTheAgentAndItsTree() throws {
        let s = engine()
        #expect(s.observe(exec(claude, pid: 100, ppid: 50, parent: "/Applications/iTerm.app/Contents/MacOS/iTerm2", args: "claude")) == 100)
        #expect(s.observe(exec(zsh, pid: 101, ppid: 100, parent: claude, args: "zsh -c 'git status'")) == 100)
        #expect(s.observe(exec(git, pid: 102, ppid: 101, parent: zsh, args: "git status")) == 100)
        #expect(s.observe(file(git, pid: 102, "r", "\(home)/Documents/ProcessHUD/.git/HEAD")) == 100)
        #expect(s.observe(net(curl, pid: 101, to: "140.82.112.3:443", host: "github.com")) == 100)
        #expect(s.observe(file("/usr/bin/vim", pid: 300, "r", "\(home)/notes.txt")) == nil)      // not in the tree
        let session = try #require(s.session(100))
        #expect(session.agent == .claude && session.project == "ProcessHUD" && session.name == "Claude · ProcessHUD")
        #expect(session.pids == [100, 101, 102] && session.events == 5)
        #expect(session.launches == 3 && session.files == 1 && session.connections == 1)
        #expect(session.keys.count == 5 && session.isLive)
        #expect(s.session(forPid: 102)?.id == 100 && s.session(forPid: 300) == nil)
    }

    /// A child reparented to launchd (it daemonized) keeps its session: lineage is decided when it is born.
    @Test func reparentedChildrenStay() {
        let s = engine()
        s.observe(exec(claude, pid: 100, ppid: 50, parent: zsh, args: "claude"))
        s.observe(exec("/usr/bin/python3", pid: 110, ppid: 100, parent: claude, args: "python3 server.py"))
        #expect(s.observe(net("/usr/bin/python3", pid: 110, to: "127.0.0.1:8000")) == 100)     // ppid is 1 by now
    }

    /// A sub-agent (Claude starting claude) is part of the outer session; a second terminal is its own.
    @Test func nestedAndParallelAgents() {
        let s = engine()
        s.observe(exec(claude, pid: 100, ppid: 50, parent: zsh, args: "claude"))
        s.observe(exec(claude, pid: 120, ppid: 100, parent: claude, args: "claude -p 'review'"))
        s.observe(exec(claude, pid: 200, ppid: 60, parent: zsh, args: "claude"))
        #expect(s.sessions.map(\.id) == [200, 100])
        #expect(s.session(forPid: 120)?.id == 100)
    }

    /// The hook names the session (Claude's own session id and the working directory), even for an agent whose
    /// start Hostwatch didn't see; the process list fills in lineage the same way.
    @Test func theHookAndTheProcessListNameSessions() {
        let s = engine()
        s.learn(hookAgentPid: 200, sessionID: "abc-123", cwd: "\(home)/Documents/git/devops")
        #expect(s.session(200)?.sessionID == "abc-123" && s.session(200)?.project == "devops")
        s.learn([RunningProcessInfo(pid: 201, ppid: 200, start: 0, uid: 501, user: "me", name: "zsh", path: zsh, args: "zsh",
                                    cpu: nil, cpuTime: 0, mem: 0, threads: 1)])
        #expect(s.observe(file(git, pid: 201, "r", "\(home)/x")) == 200)
        s.learn(hookAgentPid: 999, sessionID: "dead", cwd: "")                               // not alive: ignored
        #expect(s.session(999) == nil)
    }

    @Test func sessionsEndWhenTheAgentExits() {
        let s = engine()
        s.observe(exec(claude, pid: 100, ppid: 50, parent: zsh, args: "claude"))
        alive.pids = []
        s.checkEnded()
        #expect(s.session(100)?.isLive == false && s.live.isEmpty)
        #expect(s.observe(file(git, pid: 100, "r", "\(home)/x")) == nil)                      // a reused pid is not it
        s.now = { Date().addingTimeInterval(AgentSessions.keepEnded + 1) }
        s.checkEnded()
        #expect(s.sessions.isEmpty)
    }

    @Test func agentsAreRecognisedByExecutable() {
        #expect(CodingAgent.of(claude) == .claude)
        #expect(CodingAgent.of("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js") == .claude)
        #expect(CodingAgent.of("/usr/local/bin/codex") == .codex && CodingAgent.of("\(home)/.local/bin/cursor-agent") == .cursor)
        #expect(CodingAgent.of("/usr/bin/git") == nil && CodingAgent.of("/Applications/Claude.app/Contents/MacOS/Claude") == nil)
    }
}

/// Phase 2: sessions in history, on stories, on the Network tab; helpers are not sessions.
@MainActor @Suite(.serialized) struct AgentSessionsEverywhere {
    let claude = "\(home)/.local/share/claude/versions/2.1.316"

    @Test func helpersAreNotSessions() {
        let s = AgentSessions(fileURL: nil)
        s.isAlive = { _ in true }; s.workingDirectory = { _ in nil }
        #expect(s.observe(exec(claude, pid: 100, ppid: 50, parent: "/bin/zsh", args: "claude bg-pty-host --bg-pty-host /tmp/x.sock")) == nil)
        #expect(s.sessions.isEmpty)
    }

    @Test func replayedFromHistory() {
        var events = [exec(claude, pid: 100, ppid: 50, parent: "/bin/zsh", args: "claude"),
                      exec("/bin/zsh", pid: 101, ppid: 100, parent: claude, args: "zsh -c 'curl x'"),
                      net("/usr/bin/curl", pid: 101, to: "140.82.112.3:443", host: "api.github.com")]
        for i in events.indices { events[i].ts = 1_000 + Double(i) }
        var known = AgentSession(id: 100, agent: .claude, started: Date(timeIntervalSince1970: 1_000), lastSeen: Date(), pids: [100])
        known.project = "ProcessHUD"
        let replayed = AgentSessions.replay(events.reversed(), named: [known])          // newest first, as history lists
        #expect(replayed.count == 1 && replayed[0].pids == [100, 101] && replayed[0].ended != nil)
        #expect(replayed[0].name == "Claude · ProcessHUD" && replayed[0].destinations == ["github.com"])
        #expect(AgentSessions.replay(events, named: [])[0].name == "Claude · pid 100")
    }

    @Test func storiesCarryTheSessionName() {
        let engine = StoryEngine(persistent: false)
        var story = Story(rootPid: 1, originName: "iTerm2", originPath: "/Applications/iTerm.app/Contents/MacOS/iTerm2", origin: .background)
        story.steps = [StoryStep(exec("/usr/bin/curl", pid: 7, ppid: 6, parent: "/bin/zsh", args: "curl x"), stage: .lolbin, note: "ran curl")]
        #expect(story.title == "iTerm2 → curl")
        story.session = "Claude · ProcessHUD"
        #expect(story.title == "Claude · ProcessHUD: iTerm2 → curl")
        _ = engine
    }
}

/// The session's topic, as Claude Code titles it, and patterns grouped by session.
@MainActor @Suite struct AgentSessionNames {
    @Test func titleComesFromTheTranscript() {
        let head = Data("""
        {"type":"ai-title","aiTitle":"Pattern classifier noise reduction","sessionId":"d5"}
        {"type":"agent-name","agentName":"Pattern classifier noise reduction","sessionId":"d5"}
        {"type":"mode","mode":"normal","sessionId":"d5"}
        """.utf8)
        #expect(AgentSessions.title(inTranscriptHead: head) == "Pattern classifier noise reduction")
        let custom = Data("""
        {"type":"ai-title","aiTitle":"Something","sessionId":"d5"}
        {"type":"custom-title","customTitle":"Release 0.12","sessionId":"d5"}
        """.utf8)
        #expect(AgentSessions.title(inTranscriptHead: custom) == "Release 0.12")
        #expect(AgentSessions.title(inTranscriptHead: Data("{\"type\":\"mode\"}\nnot json\n".utf8)) == nil)
        var s = AgentSession(id: 1, agent: .claude, started: Date(), lastSeen: Date(), pids: [1])
        s.project = "ProcessHUD"; s.title = "Release 0.12"
        #expect(s.name == "Claude · ProcessHUD · Release 0.12")
    }

    @Test func patternsGroupBySession() {
        func item(_ key: String) -> PatternItem {
            let e = SignatureEntry(id: key, kind: .file, process: "/usr/bin/git", pattern: key, count: 1, firstSeen: Date(), lastSeen: Date(),
                                   status: .unclassified, exampleName: "git", examplePid: 1, exampleProc: "/usr/bin/git",
                                   exampleTarget: "", exampleExtra: "r", exampleParent: "")
            return PatternItem(entry: e, status: .unclassified, statusRank: 2, source: nil, note: nil, decidedBy: "New")
        }
        let items = ["a", "b", "c", "d"].map(item)
        let groups = [PatternItem.SessionGroup(id: 100, name: "Claude · ProcessHUD", keys: ["a", "b"], live: true),
                      PatternItem.SessionGroup(id: 200, name: "Claude · devops", keys: ["zzz"], live: false)]
        let rows = PatternItem.groupedBySession(items, sessions: groups, order: [KeyPathComparator(\.priority)])
        #expect(rows.map(\.id) == ["session:100", "session:0"])
        #expect(rows[0].entry.process == "Claude · ProcessHUD" && rows[0].children?.map(\.id) == ["a", "b"])
        #expect(rows[1].entry.process == "No AI session" && rows[1].children?.count == 2)
        let none = PatternItem.groupedBySession(items, sessions: [groups[1]], order: [])      // sessions, none listed here
        #expect(none.map(\.id) == ["session:0"] && none[0].children?.count == 4)
        #expect(PatternItem.groupedBySession(items, sessions: [], order: []).map(\.id) == ["a", "b", "c", "d"])
    }
}

/// What `claude --resume` shows, and the Events list grouped by session.
@MainActor @Suite struct AgentSessionResumeFacts {
    @Test func factsFromTheTranscript() throws {
        let head = Data("""
        {"type":"ai-title","aiTitle":"Pattern classifier noise reduction","sessionId":"d5"}
        {"type":"user","isMeta":true,"message":{"role":"user","content":"<command-name>/clear</command-name>"},"gitBranch":"main"}
        {"type":"user","message":{"role":"user","content":"Hi. I think its time to new features.\\nSecond line"},"gitBranch":"feature/x","cwd":"/x"}
        """.utf8)
        let f = try #require(AgentSessions.facts(inTranscriptHead: head))
        #expect(f.title == "Pattern classifier noise reduction" && f.branch == "feature/x")
        #expect(f.firstPrompt == "Hi. I think its time to new features.")
        var s = AgentSession(id: 1, agent: .claude, started: Date(), lastSeen: Date(), pids: [1])
        s.project = "ProcessHUD"; s.firstPrompt = "Fix the thing"
        #expect(s.topic == "Fix the thing" && s.name == "Claude · ProcessHUD · Fix the thing")
        s.title = "Fewer patterns"
        #expect(s.topic == "Fewer patterns")
    }

    @Test func eventsGroupBySession() {
        func item(_ e: ActivityEvent) -> EventItem { EventItem(event: e, status: .safe, statusRank: 3) }
        let a = item(exec("/usr/bin/git", pid: 101, ppid: 100, parent: "/bin/zsh", args: "git status"))
        let b = item(file("/usr/bin/git", pid: 101, "r", "/x"))
        let c = item(file("/usr/bin/vim", pid: 300, "r", "/y"))
        let header = EventItem.SessionHeader(id: 100, topic: "Fewer patterns", facts: "ProcessHUD · 5 min", agent: .claude, pids: [100, 101])
        let rows = EventItem.groupedBySession([a, b, c], sessions: [header])
        #expect(rows.count == 2 && rows[0].groupTitle == "Fewer patterns" && rows[0].children?.count == 2)
        #expect(rows[0].agent == .claude && rows[0].groupSubtitle == "2 events · ProcessHUD · 5 min")
        #expect(rows[1].groupTitle == "No AI session" && rows[1].children?.map(\.id) == [c.id])
        #expect(rows[0].id == EventItem.stableUUID("session:100") && EventItem.stableUUID("a") != EventItem.stableUUID("b"))
        #expect(EventItem.groupedByProcess([a, b, c]).map(\.groupTitle) == ["git", "vim"])
        #expect(EventItem.groupedBySession([c], sessions: [header]).map(\.groupTitle) == ["No AI session"])
        #expect(EventItem.groupedBySession([c], sessions: []).count == 1 && !EventItem.groupedBySession([c], sessions: [])[0].isGroup)
    }
}

/// Naming without the hook (the transcript found by working directory and start time), and Running Now groups.
@MainActor @Suite(.serialized) struct AgentSessionNaming {
    @Test func transcriptFoundByFolderAndStart() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("hw-projects-\(UUID().uuidString)")
        let folder = root.appendingPathComponent("-Users-alex-Documents-my-app")        // "/" and "." become "-"
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let old = folder.appendingPathComponent("old.jsonl"), mine = folder.appendingPathComponent("mine.jsonl")
        try Data("{\"type\":\"ai-title\",\"aiTitle\":\"Old work\"}\n".utf8).write(to: old)
        try FileManager.default.setAttributes([.creationDate: Date().addingTimeInterval(-3600)], ofItemAtPath: old.path)
        try Data("{\"type\":\"ai-title\",\"aiTitle\":\"Release 0.12\"}\n{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ship it\"},\"gitBranch\":\"main\"}\n".utf8).write(to: mine)
        let saved = AgentSessions.projectsRoot
        AgentSessions.projectsRoot = root
        defer { AgentSessions.projectsRoot = saved }
        let facts = try #require(AgentSessions.transcriptFacts(cwd: "/Users/alex/Documents/my.app", started: Date()))
        #expect(facts.title == "Release 0.12" && facts.branch == "main" && facts.firstPrompt == "ship it")
        #expect(AgentSessions.transcriptFacts(cwd: "/nowhere", started: Date()) == nil)

        let s = AgentSessions(fileURL: nil)
        s.isAlive = { _ in true }
        s.workingDirectory = { _ in "/Users/alex/Documents/my.app" }
        s.observe(exec("/Users/alex/.local/share/claude/versions/2.1.0", pid: 500, ppid: 1, parent: "/bin/zsh", args: "claude"))
        #expect(s.session(500)?.topic == "Release 0.12")                             // named with no hook at all
    }

    @Test func topicFallsBackToWhereAndWhen() {
        var s = AgentSession(id: 7, agent: .claude, started: Date(timeIntervalSince1970: 0), lastSeen: Date(), pids: [7])
        s.cwd = AppPaths.userHome
        #expect(s.topic.hasPrefix("Claude in ~, "))
        s.cwd = ""
        #expect(s.topic.hasPrefix("Claude pid 7, "))
    }

    @Test func runningNowGroups() {
        func info(_ pid: Int, _ ppid: Int, _ name: String, cpu: Double? = 1, mem: Int64 = 10) -> RunningProcessInfo {
            RunningProcessInfo(pid: pid, ppid: ppid, start: 100, uid: 501, user: "me", name: name, path: "/bin/\(name)", args: name,
                               cpu: cpu, cpuTime: 1, mem: mem, threads: 2)
        }
        let rows = RunningRow.rows([info(100, 1, "claude"), info(101, 100, "zsh"), info(102, 101, "git"), info(300, 1, "vim")])
        let header = EventItem.SessionHeader(id: 100, topic: "Release 0.12", facts: "", agent: .claude, pids: [100, 101, 102])
        let bySession = RunningRow.grouped(rows, by: .session, sessions: [header])
        #expect(bySession.map(\.name) == ["Release 0.12", "No AI session"])
        #expect(bySession[0].children?.count == 3 && bySession[0].mem == 30 && bySession[0].cpu == 3 && bySession[0].groupAgent == .claude)
        let byParent = RunningRow.grouped(rows, by: .process, sessions: [])
        #expect(byParent.map(\.name) == ["pid 1", "claude", "zsh"] && byParent[0].children?.count == 2)
        #expect(RunningRow.grouped(rows, by: .none, sessions: [header]).count == 4)
    }
}
