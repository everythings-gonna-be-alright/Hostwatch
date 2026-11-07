import Foundation

// MARK: - Exclusion rules (same semantics as the agent)

struct ExclusionRules {
    private struct Rule {
        let scope: String?   // nil = whole process, "proc", "net", "file"
        let pattern: String
        let isGlob: Bool
    }

    private let rules: [Rule]
    let lines: [String]

    init(text: String) {
        var rules: [Rule] = []
        var lines: [String] = []
        for raw in text.split(whereSeparator: \.isNewline) {
            var s = raw.trimmingCharacters(in: .whitespaces)
            if s.isEmpty || s.hasPrefix("#") { continue }
            lines.append(s)
            var scope: String?
            for prefix in ["proc:", "net:", "file:"] where s.lowercased().hasPrefix(prefix) {
                scope = String(prefix.dropLast())
                s = String(s.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
                break
            }
            guard !s.isEmpty else { continue }
            rules.append(Rule(scope: scope, pattern: s.lowercased(),
                              isGlob: s.contains("*") || s.contains("?")))
        }
        self.rules = rules
        self.lines = lines
    }

    func excludes(_ e: ActivityEvent) -> Bool {
        let kindScope: String = e.kind == .exec ? "proc" : e.kind.rawValue
        for rule in rules {
            let fields: [String]
            switch rule.scope {
            case nil: fields = [e.name, e.proc]
            case kindScope?: fields = rule.scope == "proc" ? [e.name, e.target] : [e.target]
            default: continue
            }
            if fields.contains(where: { match(rule, $0) }) { return true }
        }
        return false
    }

    private func match(_ rule: Rule, _ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let v = value.lowercased()
        return rule.isGlob ? fnmatch(rule.pattern, v, 0) == 0 : v.contains(rule.pattern)
    }
}

let exclusionHelp = """
One pattern per line, case-insensitive. Lines starting with # are ignored.
With * or ? it is a glob (whole value must match), otherwise a substring.
  name-or-path      hide everything from matching processes
  proc:<pattern>    hide spawns of matching executables
  net:<pattern>     hide connections to matching remote host:port
  file:<pattern>    hide opens of matching file paths
"""

let defaultExclusions = [
    "file:/dev/*",
    "file:/System/*",
    "file:/usr/lib/*",
    "file:/usr/share/*",
    "file:/Library/Preferences/*",
    "file:/private/var/db/*",
    "file:/private/var/folders/*",
    "file:*/Library/Caches/*",
    "file:*.dylib",
    "net:127.0.0.1:*",
    "net:[::1]:",
    "mdworker",
    "mds_stores",
].joined(separator: "\n") + "\n"

extension ActivityEvent {
    /// Ready-made exclusion patterns for this row: (menu title, pattern).
    var exclusionSuggestions: [(String, String)] {
        var out: [(String, String)] = [("Hide process “\(name)”", name)]
        switch kind {
        case .exec:
            out.append(("Hide spawns of \(target)", "proc:\(target)"))
        case .net:
            if !host.isEmpty, hostSource == "dns" {
                out.append(("Hide host \(host)", "net:\(host):*"))
                if let domain = registrableDomain, domain != host {
                    out.append(("Hide domain *.\(domain)", "net:*.\(domain):*"))
                }
            }
            if let host = remoteHost {
                // IPv6 hosts contain [ ], which glob treats as a class, so use substring form.
                out.append(("Hide host \(host)", host.hasPrefix("[") ? "net:\(host):" : "net:\(host):*"))
            }
            out.append(("Hide endpoint \(target)", "net:\(target)"))
        case .file:
            let folder = (target as NSString).deletingLastPathComponent
            out.append(("Hide folder \(folder)/", "file:\(folder)/*"))
            out.append(("Hide file \(target)", "file:\(target)"))
        }
        return out
    }

    var fullDetail: String {
        switch kind {
        case .exec: return args.isEmpty ? target : "\(target)  ·  \(args)"
        case .net:
            let tail = inferred ? "  · inferred (\(note))" : ""
            if target.hasPrefix("?") { return "\(extra) destination unknown\(tail)" }
            guard let label = hostLabel else { return "\(extra) \(target)\(tail)" }
            return "\(extra) \(label):\(remotePort)  [\(target)]\(tail)"
        case .file: return "\(extra.padding(toLength: 3, withPad: " ", startingAt: 0)) \(target)"
        }
    }
}
