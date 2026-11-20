import Foundation

// One app's own network rules, next to the general ones. source: docs/adr/0020-firewall-rules-per-app.md

/// An app's card on the Network Firewall page: what it meets everywhere, and its own destinations.
struct AppRules: Codable, Identifiable, Equatable, Sendable {
    /// The app by path (a bundle covers every program inside it), or by name: the Network tab and blocks made before
    /// cards existed only know the name.
    var app: String
    /// Firewall decides (the general rules apply), Allow (past the general Everywhere's Block, never past a threat
    /// list or a general destination you block) or Block (every connection, your network too).
    var everywhere: DestinationChoice = .firewall
    /// Its own destinations, each Allow or Block. They win over everything but Hostwatch itself.
    var destinations: [Destination] = []

    var id: String { app }
    var byPath: Bool { app.contains("/") }
    var name: String { byPath ? PlaceExceptions.name(app) : app }

    /// Whether `program` (a path, or a name as the Network tab gives it) is this app or runs inside it. A pattern
    /// names a program with its versions collapsed and home as "~" (`SignatureBuilder.normalizeExecutable`), so a
    /// card matches that form of its path too, either way round: python's Block made from a question (the real
    /// path, cpython-3.12.13) and its blocked connection pattern (cpython-#.#.#) are one card.
    func runs(_ program: String) -> Bool {
        guard program.contains("/") else { return name == program }
        guard byPath else { return displayProcessName(program) == app }
        if AccessRules.runs(app, program) { return true }
        let pattern = SignatureBuilder.normalizeExecutable(program)
        return AccessRules.runs(SignatureBuilder.normalizeExecutable(app), pattern)
            || AccessRules.runs(SignatureBuilder.normalize(app), pattern)
            || AccessRules.runs(app, pattern)
    }

    /// The destination of its own that decides this connection: the most specific one that covers it.
    func decision(host: String, ip: String) -> FirewallDecision? {
        guard let d = destinations.filter({ $0.on && $0.others != .firewall && $0.covers(host: host, ip: ip) })
            .max(by: { $0.target.count < $1.target.count }) else { return nil }
        return d.others == .allow ? FirewallDecision(verdict: .allow, reason: "you allow \(name) to \(d.target)")
                                  : FirewallDecision(verdict: .block, reason: "you block \(name) from \(d.target)")
    }

    var ruleCount: Int { (everywhere == .firewall ? 0 : 1) + destinations.count }
}

enum AppRulesList {
    /// The card that decides for a program: the most specific one that runs it (a program's own over its bundle's).
    static func rules(for program: String, in apps: [AppRules]) -> AppRules? {
        apps.filter { $0.runs(program) }.max { $0.app.count < $1.app.count }
    }

    /// What a new card for this program is about: its outermost app bundle, so its helpers are covered, else itself.
    static func app(of program: String) -> String {
        guard program.contains("/"), let r = program.range(of: ".app/") else { return program }
        return String(program[..<r.lowerBound]) + ".app"
    }

    /// Cards from what older versions kept: apps blocked or allowed everywhere, "program name|domain" blocks and
    /// Allow Anyway exceptions, and a general destination's program chips. One card per app, in that order.
    /// The card a change about this program goes to: the one that already decides for it, else its app's.
    static func cardKey(for program: String, in apps: [AppRules]) -> String {
        rules(for: program, in: apps)?.app ?? app(of: program)
    }

    static func migrated(appBlocks: [String], everywhereAllowed: [String], domainBlocks: [String],
                         threatExceptions: [String] = [], destinations: [Destination] = [],
                         into apps: [AppRules] = []) -> [AppRules] {
        var out = apps
        func edit(_ app: String, _ change: (inout AppRules) -> Void) {
            if let i = out.firstIndex(where: { $0.app == app }) { change(&out[i]) }
            else { var r = AppRules(app: app); change(&r); out.append(r) }
        }
        func add(_ app: String, _ target: String, _ choice: DestinationChoice) {
            edit(app) { r in
                r.destinations.removeAll { $0.target == target }
                r.destinations.append(Destination(target: target, others: choice))
            }
        }
        for app in everywhereAllowed { edit(app) { $0.everywhere = .allow } }
        for app in appBlocks { edit(app) { $0.everywhere = .block } }          // on both: Block, as before
        for key in domainBlocks {
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            if parts.count == 2 { add(parts[0], parts[1], .block) }
        }
        for key in threatExceptions {
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            if parts.count == 2 { add(parts[0], parts[1], .allow) }
        }
        for d in destinations {
            for p in d.exceptions.allowed { add(p, d.target, .allow) }
            for p in d.exceptions.blocked { add(p, d.target, .block) }         // on both: Block, as before
        }
        return out
    }
}
