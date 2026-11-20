import Foundation

// Who did it: a tool's or interpreter's pattern names the app or AI agent behind it ("node via Cursor reads
// ~/proj/.git/*"), so a decision about one doesn't cover the other. source: docs/adr/0019-patterns-name-who-did-it.md

extension SignatureBuilder {
    /// Between a program and who did it, in a pattern's program: "/opt/homebrew/bin/node via Cursor".
    static let via = " via "

    /// The program's path, without who did it: for every check that reads the program as a file.
    static func programPath(_ process: String) -> String {
        process.range(of: via).map { String(process[..<$0.lowerBound]) } ?? process
    }

    /// Who did it, from a pattern's program ("Cursor"), nil when it doesn't say.
    static func who(inProcess process: String) -> String? {
        process.range(of: via).map { String(process[$0.upperBound...]) }
    }

    /// Who did it, by name, as the collector proved it (`Lineage`): a verified AI agent above the process (Claude Code),
    /// else the app macOS holds responsible for it when no agent is anywhere above (Cursor, Terminal). Nil when not
    /// proven. An agent given as a path came from a build that guessed it by name: not trusted, nobody is named.
    static func who(_ e: ActivityEvent) -> String? {
        if !e.agent.isEmpty { return e.agent.contains("/") ? nil : e.agent }
        guard !e.responsible.isEmpty else { return nil }
        let name = BaselinePolicy.appName(e.responsible)
        return name.isEmpty ? nil : name
    }

    /// Whether the event's actor (exec: the parent) gets who did it: tools and interpreters, where the program alone
    /// says little about intent. An app says who it is.
    static func namesWho(_ e: ActivityEvent) -> Bool {
        let actor = e.kind == .exec ? e.parent : e.proc
        return !actor.isEmpty && ProcessOrigin.isToolLike(actor)
    }

    /// The signature with who did it in its program, when the actor is a tool and who is known.
    static func withWho(_ sig: Signature, _ e: ActivityEvent) -> Signature {
        guard namesWho(e), let who = who(e), !sig.process.contains(via) else { return sig }
        var s = sig
        s.process += via + who
        s.key = "\(e.kind.rawValue)|\(s.process)|\(s.pattern)"
        return s
    }

    /// The same pattern without who did it: where a pattern's decision is carried over from, and what your rules
    /// and combined patterns written before were about. Nil for a key that names nobody.
    static func keyWithoutWho(_ key: String) -> String? {
        let parts = key.split(separator: "|", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[1].contains(via) else { return nil }
        return "\(parts[0])|\(programPath(parts[1]))|\(parts[2])"
    }
}
