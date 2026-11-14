import Foundation

/// Your own Allow and Block rules: a folder or file, or a network destination, for one program or any program.
/// They are your decisions, so they come before everything automatic (patterns, AI, threat lists). Pure: matched and
/// validated here, applied by ProtectionPolicy (files) and FirewallPolicy (network). source: docs/adr/0015-your-allow-and-block-rules.md
struct AccessRule: Codable, Identifiable, Equatable, Sendable {
    enum Kind: String, Codable, Sendable { case files, network }
    enum Action: String, Codable, Sendable { case allow, block }

    var id = UUID().uuidString
    var kind: Kind
    /// Files: an absolute path, a folder covering what's inside. Network: a domain (its subdomains too) or an IP.
    var target: String
    /// The program's path (an app's bundle covers everything inside it), nil for any program.
    var program: String?
    var action: Action
    var on = true

    var programName: String {
        guard let program else { return "Any program" }
        let name = (program as NSString).lastPathComponent
        return name.hasSuffix(".app") ? String(name.dropLast(4)) : name
    }

    /// "Block ssh-agent from ~/.ssh": how the rule reads in lists and reasons.
    var sentence: String {
        let who = program == nil ? "any program" : programName
        let place = kind == .files ? AccessRules.display(target) : target
        return action == .allow ? "allow \(who) \(kind == .files ? "in" : "to") \(place)"
            : "block \(who) \(kind == .files ? "from" : "to") \(place)"
    }
}

enum AccessRules {
    // MARK: Matching

    /// The rule for a file access: the most specific that covers it (one program beats any program, a deeper path a
    /// shallower one), and Block when two are equally specific.
    static func matchFile(_ rules: [AccessRule], path: String, program: String) -> AccessRule? {
        best(rules.filter { $0.on && $0.kind == .files && covers($0.target, path) && runs($0.program, program) },
             specificity: { $0.target.count })
    }

    /// The rule for a connection: a domain covers its subdomains, an IP matches itself.
    static func matchNetwork(_ rules: [AccessRule], host: String, ip: String, program: String) -> AccessRule? {
        let h = host.lowercased()
        return best(rules.filter { r in
            guard r.on, r.kind == .network, runs(r.program, program) else { return false }
            let t = r.target.lowercased()
            return t == ip || (!h.isEmpty && (h == t || h.hasSuffix("." + t)))
        }, specificity: { $0.target.count })
    }

    private static func best(_ matches: [AccessRule], specificity: (AccessRule) -> Int) -> AccessRule? {
        matches.max { a, b in
            let sa = (a.program == nil ? 0 : 1_000_000) + specificity(a), sb = (b.program == nil ? 0 : 1_000_000) + specificity(b)
            if sa != sb { return sa < sb }
            return a.action == .allow && b.action == .block            // equal: Block ranks higher, so it wins
        }
    }

    /// The path itself or anything inside it. "/var" and "/private/var" are the same place on macOS.
    static func covers(_ target: String, _ path: String) -> Bool {
        for t in variants(target) {
            for p in variants(path) where p == t || p.hasPrefix(t.hasSuffix("/") ? t : t + "/") { return true }
        }
        return false
    }

    private static func variants(_ path: String) -> [String] {
        path.hasPrefix("/private/") ? [path, String(path.dropFirst(8))] : [path, "/private" + path]
    }

    /// The program the rule names: the binary itself, or anything inside the app bundle it names.
    static func runs(_ rule: String?, _ program: String) -> Bool {
        guard let rule else { return true }
        return program == rule || program.hasPrefix(rule.hasSuffix("/") ? rule : rule + "/")
    }

    // MARK: Validation

    /// Why this rule can't be added, nil when it can. Block may be as broad as you like. Allowing any program a whole
    /// area (your home, a top folder in it, /tmp, the whole disk) or a sensitive place would open your secrets to
    /// everything, the line SignatureBuilder.isTooWide holds for patterns. Allowing one program is your call.
    static func refusal(_ rule: AccessRule, home: String = NSHomeDirectory(), sensitive: [String] = []) -> String? {
        let target = rule.target.trimmingCharacters(in: .whitespaces)
        if target.isEmpty { return rule.kind == .files ? "Choose a folder or file." : "Enter a domain or an IP address." }
        switch rule.kind {
        case .files:
            guard target.hasPrefix("/") else { return "Use a full path, starting with /." }
            guard rule.action == .allow, rule.program == nil else { return nil }
            if sensitive.contains(where: { covers(target, $0) || covers($0, target) }) {
                return "Allowing any program in a protected place (keys, keychains, passwords) isn't possible. Choose the program."
            }
            if isWholeArea(target, home: home) {
                return "Allowing any program in a whole area like this isn't possible. Choose a folder inside it, or the program."
            }
            return nil
        case .network:
            let t = target.lowercased()
            if t.contains("/") || t.contains(" ") { return "Enter a domain such as example.com, or an IP address." }
            let isIP = t.split(separator: ".").count == 4 && t.split(separator: ".").allSatisfy { Int($0) != nil } || t.contains(":")
            if !isIP && !t.contains(".") { return "Enter a whole domain such as example.com, not a top-level one like “\(t)”." }
            return nil
        }
    }

    /// Your home or one folder below it, the disk, /Users, /tmp and the like: too wide to allow to every program.
    static func isWholeArea(_ path: String, home: String) -> Bool {
        let p = path.hasSuffix("/") && path.count > 1 ? String(path.dropLast()) : path
        if ["/", "/Users", "/tmp", "/private/tmp", "/private/var", "/var", "/Applications", "/Library", "/System",
            "/Volumes", "/opt", "/usr", "/private"].contains(p) { return true }
        if p == home { return true }
        if p.hasPrefix(home + "/") { return !p.dropFirst(home.count + 1).contains("/") }
        return false
    }

    /// "~/Documents/contracts" for paths in your home.
    static func display(_ path: String, home: String = NSHomeDirectory()) -> String {
        path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }
}
