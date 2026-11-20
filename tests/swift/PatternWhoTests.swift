import Foundation
import Testing
@testable import Hostwatch

/// A tool's pattern names who did it: the AI agent above it, else the app responsible for it (ADR 0019).
@MainActor @Suite struct PatternWho {
    let cursor = "/Applications/Cursor.app/Contents/MacOS/Cursor"
    let claude = "Claude Code"                              // the collector sends a verified agent by name
    let terminal = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"

    func read(_ proc: String, _ file: String, responsible: String = "", agent: String = "") -> ActivityEvent {
        ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: (proc as NSString).lastPathComponent,
                      proc: proc, target: file, extra: "r", parent: "", responsible: responsible, agent: agent)
    }

    func store(_ name: String) -> SignatureStore {
        SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("who-\(name)-\(UUID().uuidString)"))
    }

    @Test func aToolsPatternNamesTheAppOrAgent() {
        let git = NSHomeDirectory() + "/Projects/app/.git/config"
        let viaCursor = read("/opt/homebrew/bin/node", git, responsible: cursor)
        let viaClaude = read("/opt/homebrew/bin/node", git, responsible: terminal, agent: claude)
        #expect(viaCursor.signatureProcess == "/opt/homebrew/bin/node via Cursor")
        #expect(viaClaude.signatureProcess == "/opt/homebrew/bin/node via Claude Code")       // the agent, not Terminal
        #expect(viaCursor.signatureKey != viaClaude.signatureKey)
        #expect(viaCursor.signaturePattern == viaClaude.signaturePattern)                      // the pattern text is the same
        #expect(displayProcessName(viaCursor.signatureProcess) == "node via Cursor")
        #expect(SignatureBuilder.programPath(viaCursor.signatureProcess) == "/opt/homebrew/bin/node")
    }

    @Test func appsAndUnknownOriginsStayAsTheyWere() {
        let safari = read("/Applications/Safari.app/Contents/MacOS/Safari", "/tmp/x", responsible: cursor)
        #expect(!safari.signatureProcess.contains(SignatureBuilder.via))                        // an app says who it is
        let alone = read("/opt/homebrew/bin/node", "/tmp/x")
        #expect(alone.signatureProcess == "/opt/homebrew/bin/node")                              // nobody behind it
    }

    @Test func aLaunchNamesWhoIsBehindTheParent() {
        let e = ActivityEvent(kind: .exec, time: "12:00:00", pid: 11, ppid: 10, name: "cat", proc: "/bin/cat",
                              target: "/bin/cat", extra: "", parent: "/bin/zsh", args: "cat /tmp/x", agent: claude)
        #expect(e.signatureProcess == "/bin/zsh via Claude Code")
    }

    @Test func aDecisionIsCarriedOverOnce() {
        let s = store("carry")
        let file = NSHomeDirectory() + "/Projects/app/.git/config"
        let before = read("/opt/homebrew/bin/node", file)
        _ = s.observe(before)
        s.set(.safe, keys: [before.signatureKey], note: "my repo")
        let viaCursor = read("/opt/homebrew/bin/node", file, responsible: cursor)
        #expect(s.observe(viaCursor) == false)                                       // not New: it had a decision
        let carried = s.entry(viaCursor.signatureKey)
        #expect(carried?.status == .safe && carried?.source == "you" && carried?.note == "my repo")
        // From here on, each origin is decided apart.
        s.set(.suspicious, keys: [viaCursor.signatureKey])
        #expect(s.status(forKey: before.signatureKey) == .safe)
        let viaClaude = read("/opt/homebrew/bin/node", file, responsible: terminal, agent: claude)
        #expect(s.status(for: viaClaude) == .safe)                                    // not seen yet: what it was before
    }

    @Test func nothingDecidedMeansNew() {
        let s = store("new")
        let e = read("/opt/homebrew/bin/node", NSHomeDirectory() + "/Projects/app/src/a.js", responsible: cursor)
        #expect(s.observe(e) == true)
        #expect(s.status(forKey: e.signatureKey) == .unclassified)
    }

    @Test func rulesWrittenBeforeStillMatchFromAnyone() {
        var rule = LearnedRule(name: "Projects", rationale: "", kind: .file, process: "/opt/homebrew/bin/node",
                               pattern: "r ~/Projects/*", action: .safe)
        let s = store("rule")
        let e = read("/opt/homebrew/bin/node", NSHomeDirectory() + "/Projects/a", responsible: cursor)
        _ = s.observe(e)
        let entry = s.entry(e.signatureKey)!
        #expect(rule.matchesProgram(entry.process))
        rule.process = "/opt/homebrew/bin/node via Claude Code"                     // one that names who: only that
        #expect(!rule.matchesProgram(entry.process))
    }

    @Test func keysWithoutWho() {
        #expect(SignatureBuilder.keyWithoutWho("file|/bin/zsh via Cursor|r /tmp/x") == "file|/bin/zsh|r /tmp/x")
        #expect(SignatureBuilder.keyWithoutWho("file|/bin/zsh|r /tmp/x") == nil)
    }
}

/// The AI is told who did it, and that the pattern is about that.
@MainActor @Suite struct PatternWhoPrompt {
    @Test func thePromptSaysWhoDidIt() {
        let e = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "bash", proc: "/bin/bash",
                              target: "/tmp/x.sh", extra: "r", parent: "",
                              agent: "Claude Code")
        let s = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("whoprompt-\(UUID().uuidString)"))
        _ = s.observe(e)
        let prompt = TriagePrompt.pattern(s.entry(e.signatureKey)!, context: nil)
        #expect(prompt.contains("File access: bash via Claude Code opened"))
        #expect(prompt.contains("Who did it: Claude Code (this pattern covers bash only when Claude Code is behind it)"))
    }
}

/// An agent given as a path came from the build that guessed it by name: nobody is named.
@MainActor @Suite struct PatternWhoUnproven {
    @Test func aGuessedAgentNamesNobody() {
        let e = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "bash", proc: "/bin/bash",
                              target: "/tmp/x", extra: "r", parent: "",
                              responsible: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                              agent: NSHomeDirectory() + "/.local/share/claude/versions/2.1.0")
        #expect(e.signatureProcess == "/bin/bash")
    }
}
