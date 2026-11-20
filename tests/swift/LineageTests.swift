import Foundation
import Testing
@testable import Hostwatch

/// Who is behind a process: proven from kernel facts, or nobody. Never a guess (ADR 0019).
@Suite struct LineageProof {
    let terminal = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    let cursor = "/Applications/Cursor.app/Contents/MacOS/Cursor"
    let claudePath = NSHomeDirectory() + "/.local/share/claude/versions/2.1.329"

    func id(_ pid: Int, _ gen: Int = 1) -> ExecID { ExecID(pid: pid, generation: gen) }

    func claude(parent: ExecID, valid: Bool = true, team: String = "Q6L2SF6YDW") -> ExecFacts {
        ExecFacts(path: claudePath, parent: parent, team: team, signing: "com.anthropic.claude-code", validSignature: valid)
    }

    /// Terminal (from launchd) → zsh → [middle] → zsh → cat, Terminal responsible for all.
    func chain(_ middle: ExecFacts?) -> Lineage {
        let l = Lineage()
        l.learn(id(100), ExecFacts(path: terminal, fromLaunchd: true))
        l.learn(id(200), ExecFacts(path: "/bin/zsh", parent: id(100), responsible: id(100)))
        var below = id(200)
        if var m = middle { m.responsible = id(100); l.learn(id(300), m); below = id(300) }
        l.learn(id(400), ExecFacts(path: "/bin/zsh", parent: below, responsible: id(100)))
        l.learn(id(500), ExecFacts(path: "/bin/cat", parent: id(400), responsible: id(100)))
        return l
    }

    @Test func aVerifiedAgentAboveIsNamed() {
        #expect(chain(claude(parent: id(200))).who(id(500)) == .agent("Claude Code"))
    }

    @Test func aBinaryNamedLikeAnAgentButNotSignedByItNamesNobody() {
        // Signed by someone else, or not validly: never Claude Code. It looks like an agent, so nothing is said at all.
        for fake in [claude(parent: id(200), team: "ABCDE12345"), claude(parent: id(200), valid: false)] {
            let l = chain(fake)
            l.markAgentLike(id(300))
            #expect(l.who(id(500)) == .unknown)
        }
    }

    @Test func anUnprovableAgentWithholdsWho() {
        // Codex runs as node with a script: it looks like an agent, nothing proves it, so not "via Terminal" either.
        let l = chain(ExecFacts(path: "/opt/homebrew/bin/node", parent: id(200)))
        l.markAgentLike(id(300))
        #expect(l.who(id(500)) == .unknown)
    }

    @Test func noAgentUpToLaunchdNamesTheResponsibleApp() {
        #expect(chain(nil).who(id(500)) == .app(terminal))
    }

    @Test func aMissingLinkNamesNobody() {
        let l = Lineage()
        l.learn(id(100), ExecFacts(path: terminal, fromLaunchd: true))
        l.learn(id(500), ExecFacts(path: "/bin/cat", parent: id(400), responsible: id(100)))   // 400 never seen
        #expect(l.who(id(500)) == .unknown)
        l.learn(id(400), ExecFacts(path: "/bin/zsh", parent: id(100), responsible: id(100)))   // learned later
        #expect(l.who(id(500)) == .app(terminal))
    }

    @Test func aReusedPidIsAnotherProcess() {
        let l = chain(claude(parent: id(200)))
        // pid 300 ends and a later program reuses it: a child of the new one is not below Claude Code.
        l.learn(id(300, 2), ExecFacts(path: "/bin/zsh", parent: id(200), responsible: id(100)))
        l.learn(id(600), ExecFacts(path: "/bin/ls", parent: id(300, 2), responsible: id(100)))
        #expect(l.who(id(600)) == .app(terminal))
        #expect(l.who(id(500)) == .agent("Claude Code"))
    }

    @Test func theFirstFactsWin() {
        // Seen first from its fork, below Claude Code. A later message (after it detached) says launchd: ignored.
        let l = chain(claude(parent: id(200)))
        l.learn(id(500), ExecFacts(path: "/bin/cat", fromLaunchd: true, responsible: id(100)))
        #expect(l.who(id(500)) == .agent("Claude Code"))
    }

    @Test func anAppsOwnToolNamesTheApp() {
        let l = Lineage()
        l.learn(id(10), ExecFacts(path: cursor, fromLaunchd: true))
        l.learn(id(11), ExecFacts(path: "/opt/homebrew/bin/node", parent: id(10), responsible: id(10)))
        #expect(l.who(id(11)) == .app(cursor))
        #expect(l.who(id(10)) == .unknown)                       // responsible for itself: nothing to add
    }

    @Test func aHeldLaunchCountsItsLauncher() {
        // Claude Code's fork, about to become bash: what it launches is below Claude Code.
        let l = chain(nil)
        l.learn(id(300), claude(parent: id(200)))
        #expect(l.whoForLaunch(by: id(300)) == .agent("Claude Code"))
        #expect(l.whoForLaunch(by: id(400)) == .app(terminal))
    }
}

/// The collector turns Endpoint Security's messages into the lineage, and adds who to what it sends.
@Suite struct LineageFromMessages {
    let shell = ESShape.Process(path: "/bin/zsh", pid: 900, ppid: 800, generation: 3, responsible: 800, responsibleGeneration: 1,
                                parent: 800, parentGeneration: 1)
    let terminal = ESShape.Process(path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", pid: 800, ppid: 1,
                                   generation: 1, parent: 1, parentGeneration: 1, originalPpid: 1)

    @Test func forkAndExecBuildTheChain() {
        let agent = Agent()
        _ = agent.normalize(ESShape.fork(caller: terminal, child: shell))
        let claude = ESShape.Process(path: NSHomeDirectory() + "/.local/share/claude/versions/2.1.329", pid: 901, ppid: 900,
                                     generation: 5, responsible: 800, responsibleGeneration: 1,
                                     team: "Q6L2SF6YDW", signing: "com.anthropic.claude-code", csFlags: 0x1)
        _ = agent.normalize(ESShape.exec(caller: shell, target: claude, args: ["claude"]))
        let bash = ESShape.Process(path: "/bin/bash", pid: 902, ppid: 901, generation: 7, responsible: 800, responsibleGeneration: 1)
        _ = agent.normalize(ESShape.exec(caller: claude, target: bash, args: ["bash", "-c", "cat /tmp/x"]))
        var ev = AgentEvent([("kind", .str("file")), ("pid", .int(902))])
        agent.addWho(&ev)
        #expect(ev.string("agent") == "Claude Code" && ev.string("resp").isEmpty)
    }

    @Test func anAdoptedProcessSeenLateNamesNobody() {
        let agent = Agent()
        // First seen after it detached: launchd is its parent now, but it didn't start there.
        let orphan = ESShape.Process(path: "/bin/bash", pid: 950, ppid: 1, generation: 2, responsible: 800, responsibleGeneration: 1,
                                     parent: 1, parentGeneration: 1, originalPpid: 949)
        _ = agent.normalize(ESShape.fork(caller: terminal, child: ESShape.Process(path: "/bin/zsh", pid: 951, ppid: 800,
                                                                                  generation: 1, parent: 800, parentGeneration: 1)))
        _ = agent.normalize(ESShape.open(caller: orphan, path: "/tmp/hw-lineage", fflag: 1))
        var ev = AgentEvent([("kind", .str("file")), ("pid", .int(950))])
        agent.addWho(&ev)
        #expect(ev.string("agent").isEmpty && ev.string("resp").isEmpty)
    }
}
