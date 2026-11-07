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
