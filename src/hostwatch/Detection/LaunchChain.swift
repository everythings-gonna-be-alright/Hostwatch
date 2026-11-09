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
