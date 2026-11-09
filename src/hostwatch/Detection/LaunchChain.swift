import Foundation

/// Who started a process, all the way up: rebuilt from what Hostwatch recorded, so it still works once every
/// process in the chain has exited (a live `ps` stops at the first one that has).
struct LaunchStep: Equatable, Sendable {
    enum Source: String, Sendable {
        case launch = "recorded launch"          // its exec event
        case list = "process list"               // the once-a-minute list around the moment
        case live = "running now"                // still alive (a pid can be reused: least sure)
    }

    var pid: Int
    var ppid: Int
    var path: String
    var args: String
    var source: Source

    var name: String { (path as NSString).lastPathComponent }
}

enum LaunchChain {
    /// The chain above `ppid`, nearest first, until launchd (pid 1) or a pid nothing knows (`broken`).
    static func build(from ppid: Int, limit: Int = 25, lookup: (Int) -> LaunchStep?) -> (steps: [LaunchStep], broken: Bool) {
        var steps: [LaunchStep] = [], pid = ppid, seen = Set<Int>()
        while pid > 1, steps.count < limit, seen.insert(pid).inserted {
            guard let step = lookup(pid) else { return (steps, true) }
            steps.append(step)
            pid = step.ppid
        }
        return (steps, false)
    }

    /// For people and for the AI: the origin first, then each step with its command line.
    static func text(_ chain: (steps: [LaunchStep], broken: Bool), session: String? = nil, earlier: [LaunchStep] = []) -> String {
        let origin = ProcessOrigin.classify(ancestors: chain.steps.map(\.path), brokenAt: chain.broken)
        var lines = ["origin: \(origin.rawValue)" + (session.map { " (AI session: \($0))" } ?? "")]
        for step in earlier {
            lines.append("  same process before: \(step.name)  \(step.args.isEmpty ? step.path : step.args)")
        }
        for step in chain.steps {
            let what = step.args.isEmpty ? step.path : step.args
            lines.append("  ← \(step.pid) \(step.name)  \(String(what.prefix(160)))  [\(step.source.rawValue)]")
        }
        lines.append(chain.broken ? "  ← (started before anything was recorded)" : "  ← 1 launchd")
        return lines.joined(separator: "\n")
    }
}

/// Everything the Launch Chain window shows: the process, its chain and where it came from.
struct LaunchChainReport: Sendable {
    var process: LaunchStep                       // the event's own process, last in the tree
    var steps: [LaunchStep]                       // parent first, as `LaunchChain.build` returns them
    var broken: Bool
    var session: String?
    var earlier: [LaunchStep] = []                // what the same pid ran before (sh exec'ing bash)

    var origin: ProcessOrigin { ProcessOrigin.classify(ancestors: steps.map(\.path), brokenAt: broken) }

    /// The step that decided the origin: the first ancestor that isn't a shell passing a command on.
    var originIndex: Int? {
        steps.firstIndex { CodingAgent.of($0.path) != nil || !ProcessOrigin.passesThrough($0.path) }
    }

    /// One sentence for people: who started it, in plain words.
    var summary: String {
        let name = originIndex.map { steps[$0].name } ?? ""
        switch origin {
        case .agent:
            let agent = originIndex.flatMap { CodingAgent.of(steps[$0].path)?.title } ?? "an AI agent"
            return "Started by \(agent)" + (session.map { " in the session “\($0)”" } ?? "")
        case .terminal: return "Started from \(name), a terminal"
        case .app: return "Started by the app \(name)"
        case .launchd: return "Started by macOS itself, as a system or login service"
        case .scheduled: return "Started on a schedule by \(name)"
        case .ssh: return "Started over a remote login (\(name))"
        case .other: return "Started by \(name)"
        case .unknown: return "Its first parent started before Hostwatch was recording"
        }
    }

    var text: String { LaunchChain.text((steps, broken), session: session, earlier: earlier) }
}
