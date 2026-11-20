import Foundation

/// Launch and file protection: what Hostwatch would stop (Watch, on today's event feed) or stops (Ask and Strict,
/// once Endpoint Security is available). The rules mirror the firewall's, so a pattern decision means the same
/// thing for a connection, a launch and a file. source: docs/adr/0011-protection.md
enum ProtectionArea: String, CaseIterable, Codable, Sendable {
    case launches, files

    var title: String { self == .launches ? "Launches" : "Files" }
    var symbol: String { self == .launches ? "play.fill" : "doc.text.fill" }
}

enum ProtectionMode: String, CaseIterable, Codable, Sendable {
    case off, watch, ask, strict

    var short: String {
        switch self {
        case .off: "Off"
        case .watch: "Watch"
        case .ask: "Ask"
        case .strict: "Strict"
        }
    }

    var title: String {
        switch self {
        case .off: "Off"
        case .watch: "Watch: stop nothing, show what would be stopped"
        case .ask: "Ask: stop what you blocked, ask about the rest"
        case .strict: "Strict: only what's allowed runs"
        }
    }

    /// Needs the Endpoint Security client: Watch only reads the event feed.
    var enforces: Bool { self == .ask || self == .strict }
}

enum ProtectionVerdict: String, Codable, Sendable { case allow, ask, block }

struct ProtectionDecision: Equatable, Sendable {
    var verdict: ProtectionVerdict
    var reason: String
    var group: String? = nil                       // the protected-files group, for a file
}

/// A protected-files card: sensitive places grouped the way people think of them. Built on the labels
/// `SignatureBuilder` already puts on sensitive file patterns ("r ~/.ssh/*  [SSH keys]"), so the patterns,
/// stories and protection agree on what is sensitive.
struct ProtectedGroup: Identifiable, Sendable {
    let id: String
    let title: String
    let symbol: String
    let labels: Set<String>
    let expected: String                           // who may, in words, for the card
    var writesOnly = false                         // autostart places: reading them is harmless

    static let all: [ProtectedGroup] = [
        ProtectedGroup(id: "ssh", title: "SSH keys", symbol: "key.fill", labels: ["SSH keys", "SSH config"],
                       expected: "ssh, scp, sftp, git"),
        ProtectedGroup(id: "credentials", title: "Developer credentials", symbol: "lock.shield.fill",
                       labels: ["cloud credentials", "Kubernetes credentials", "registry credentials", "credentials",
                                "GitHub token", "GPG keys", "password store"],
                       expected: "their own tools: aws, gcloud, kubectl, docker, gh, gpg"),
        ProtectedGroup(id: "keychain", title: "Keychains", symbol: "lock.rectangle.stack.fill", labels: ["keychain"],
                       expected: "macOS security services (apps read through them)"),
        ProtectedGroup(id: "browser", title: "Browser passwords and cookies", symbol: "safari.fill",
                       labels: ["browser credentials", "cookies", "Safari data"], expected: "the browser itself"),
        ProtectedGroup(id: "messages", title: "Messages and Mail", symbol: "envelope.fill", labels: ["Messages", "Mail"],
                       expected: "Messages, Mail and macOS"),
        ProtectedGroup(id: "system", title: "Privacy settings and accounts", symbol: "person.badge.shield.checkmark.fill",
                       labels: ["TCC database", "local accounts", "sudoers", "PAM config"], expected: "macOS"),
        ProtectedGroup(id: "autostart", title: "Autostart locations", symbol: "arrow.clockwise.circle.fill",
                       labels: ["persistence"], expected: "installers you run, and macOS", writesOnly: true),
    ]

    static func group(forLabel label: String) -> ProtectedGroup? { all.first { $0.labels.contains(label) } }
    static func group(id: String) -> ProtectedGroup? { all.first { $0.id == id } }

    /// Where the group's files live, as absolute paths for the Endpoint Security client's path filter.
    func prefixes(home: String) -> [String] {
        func expand(_ p: String) -> String { p.hasPrefix("~") ? home + p.dropFirst() : p }
        var out = SignatureBuilder.sensitive.filter { labels.contains($0.label) }.map { expand($0.prefix) }
        if labels.contains("browser credentials") {
            out += ["~/Library/Application Support/Google/Chrome", "~/Library/Application Support/BraveSoftware",
                    "~/Library/Application Support/Microsoft Edge", "~/Library/Application Support/Arc",
                    "~/Library/Application Support/Firefox/Profiles", "~/Library/Application Support/Vivaldi"].map(expand)
        }
        if writesOnly { out += SignatureBuilder.persistence.map(expand) }
        return out
    }

    /// Programs expected here, by executable-name prefix (the collector's quick check, before asking the app).
    var owners: [String] { labels.flatMap { SignatureBuilder.owners[$0] ?? [] } }
}

/// Programs you decided for one place: always let in, or always stopped. A destination's are read into the apps'
/// cards (ADR 0020), a protected place's too (ADR 0021): kept so saved settings still read.
struct PlaceExceptions: Codable, Equatable, Sendable {
    var allowed: [String] = []
    var blocked: [String] = []

    var isEmpty: Bool { allowed.isEmpty && blocked.isEmpty }

    /// Block first: a program on both lists is stopped.
    func verdict(for program: String) -> ProtectionVerdict? {
        guard !program.isEmpty else { return nil }
        if blocked.contains(where: { AccessRules.runs($0, program) }) { return .block }
        if allowed.contains(where: { AccessRules.runs($0, program) }) { return .allow }
        return nil
    }

    static func name(_ program: String) -> String {
        let n = (program as NSString).lastPathComponent
        return n.hasSuffix(".app") ? String(n.dropLast(4)) : n
    }
}

/// A folder or file you protect yourself. Nobody is expected there but macOS's own programs: one app's own rules are
/// on its card (`AppFileRules`).
struct CustomPlace: Codable, Identifiable, Equatable, Sendable {
    var id = UUID().uuidString
    var path: String                               // absolute, standardized
    var isFolder: Bool
    var on = true
    var others: ProtectionVerdict = .ask
    var exceptions = PlaceExceptions()

    init(id: String = UUID().uuidString, path: String, isFolder: Bool, on: Bool = true, others: ProtectionVerdict = .ask,
         exceptions: PlaceExceptions = PlaceExceptions()) {
        (self.id, self.path, self.isFolder, self.on, self.others, self.exceptions) = (id, path, isFolder, on, others, exceptions)
    }

    /// Places saved before exceptions existed still read.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        path = try c.decode(String.self, forKey: .path)
        isFolder = try c.decodeIfPresent(Bool.self, forKey: .isFolder) ?? true
        on = try c.decodeIfPresent(Bool.self, forKey: .on) ?? true
        others = try c.decodeIfPresent(ProtectionVerdict.self, forKey: .others) ?? .ask
        exceptions = try c.decodeIfPresent(PlaceExceptions.self, forKey: .exceptions) ?? PlaceExceptions()
    }

    var groupID: String { "custom:\(id)" }
    var name: String { (path as NSString).lastPathComponent }

    /// The place itself or anything inside it. "/var" and "/private/var" are the same place on macOS.
    func covers(_ raw: String) -> Bool {
        let paths = [raw, raw.hasPrefix("/private/") ? String(raw.dropFirst(8)) : "/private" + raw]
        return paths.contains { $0 == path || isFolder && $0.hasPrefix(path.hasSuffix("/") ? path : path + "/") }
    }
}

/// One card's settings: on or off, and what happens to programs that aren't expected there.
struct ProtectedGroupSetting: Codable, Equatable, Sendable {
    var on = true
    var others: ProtectionVerdict = .ask
    var exceptions = PlaceExceptions()

    init(on: Bool = true, others: ProtectionVerdict = .ask, exceptions: PlaceExceptions = PlaceExceptions()) {
        (self.on, self.others, self.exceptions) = (on, others, exceptions)
    }

    /// Settings saved before exceptions existed still read.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        on = try c.decodeIfPresent(Bool.self, forKey: .on) ?? true
        others = try c.decodeIfPresent(ProtectionVerdict.self, forKey: .others) ?? .ask
        exceptions = try c.decodeIfPresent(PlaceExceptions.self, forKey: .exceptions) ?? PlaceExceptions()
    }
}

enum ProtectionPolicy {
    /// A launch, given its pattern's status and risk: the firewall's rule, with a launch's words.
    static func decideLaunch(target: String, status: SignatureStatus, risk: PatternRisk, riskReason: String,
                             knownBad: String = "", hostwatch: String = Bundle.main.executablePath ?? "") -> ProtectionDecision {
        if !hostwatch.isEmpty, target == hostwatch { return .init(verdict: .allow, reason: "Hostwatch itself") }
        if !knownBad.isEmpty { return .init(verdict: .block, reason: "on a threat list (\(knownBad))") }
        switch status {
        case .dangerous, .suspicious: return .init(verdict: .block, reason: "its pattern is marked \(status.title)")
        case .safe: return .init(verdict: .allow, reason: "its pattern is Safe")
        case .unclassified: break
        }
        switch risk {
        case .high: return .init(verdict: .block, reason: "high-risk: \(riskReason)")
        case .routine: return .init(verdict: .allow, reason: riskReason.isEmpty ? "routine" : riskReason)
        case .normal:
            // macOS's own programs pass, except the ones that run whatever they're told (shells, curl, osascript):
            // those are judged by what they run, as their patterns are.
            if SignatureBuilder.isSealedSystem(target), !SignatureBuilder.isLolbin(target) {
                return .init(verdict: .allow, reason: "macOS system program")
            }
            return .init(verdict: .ask, reason: "new launch, not decided yet")
        }
    }

    /// A file access, from its pattern: nil when the place isn't protected (or its card is off). Your decision on
    /// the pattern comes first, then the programs expected there (the pattern's risk already says so), then the
    /// card's choice for everyone else.
    static func decideFile(pattern: String, status: SignatureStatus, risk: PatternRisk,
                           settings: [String: ProtectedGroupSetting]) -> ProtectionDecision? {
        guard let label = label(of: pattern), let group = ProtectedGroup.group(forLabel: label) else { return nil }
        let setting = settings[group.id] ?? ProtectedGroupSetting()
        guard setting.on else { return nil }
        if group.writesOnly, pattern.split(separator: " ").first?.contains("w") != true { return nil }
        switch status {
        case .dangerous, .suspicious:
            return .init(verdict: .block, reason: "its pattern is marked \(status.title)", group: group.id)
        case .safe:
            return .init(verdict: .allow, reason: "its pattern is Safe", group: group.id)
        case .unclassified: break
        }
        if risk != .high { return .init(verdict: .allow, reason: "expected here", group: group.id) }
        return .init(verdict: setting.others, reason: "\(group.title): not a program expected there", group: group.id)
    }

    /// A file access in a place you protect yourself: nil when it's elsewhere (or the place is off). Your decision
    /// on the pattern first, then macOS's own programs (Finder, Spotlight, backups) pass, then the place's choice.
    static func decideCustom(path: String, actor: String, status: SignatureStatus, places: [CustomPlace],
                             hostwatch: String = Bundle.main.executablePath ?? "") -> ProtectionDecision? {
        // The deepest place that covers it: a folder inside a protected folder has its own choice.
        guard let place = places.filter({ $0.on && $0.covers(path) }).max(by: { $0.path.count < $1.path.count }) else { return nil }
        switch status {
        case .dangerous, .suspicious:
            return .init(verdict: .block, reason: "its pattern is marked \(status.title)", group: place.groupID)
        case .safe:
            return .init(verdict: .allow, reason: "its pattern is Safe", group: place.groupID)
        case .unclassified: break
        }
        if actor == hostwatch || SignatureBuilder.isSealedSystem(actor) && !SignatureBuilder.isLolbin(actor) {
            return .init(verdict: .allow, reason: "macOS system program", group: place.groupID)
        }
        return .init(verdict: place.others, reason: "\(place.name): protected by you", group: place.groupID)
    }

    /// A file access, all rules together: nil when no rule covers it. The order (ADR 0021): Hostwatch itself, the
    /// app's own places (the most specific), its Every protected place ▸ Block or Allow, then General (the built-in
    /// places, then yours). An app's place needs no protection in General.
    static func decideFileAccess(path: String, actor: String, pattern: String, status: SignatureStatus, risk: PatternRisk,
                                 writes: Bool, settings: [String: ProtectedGroupSetting], places: [CustomPlace],
                                 apps: [AppFileRules], home: String = NSHomeDirectory(),
                                 hostwatch: String = Bundle.main.executablePath ?? "") -> ProtectionDecision? {
        let general = decideFile(pattern: pattern, status: status, risk: risk, settings: settings)
            ?? decideCustom(path: path, actor: actor, status: status, places: places, hostwatch: hostwatch)
        if !hostwatch.isEmpty, actor == hostwatch { return general.map { .init(verdict: .allow, reason: "Hostwatch itself", group: $0.group) } }
        guard let app = AppFileRulesList.rules(for: actor, in: apps) else { return general }
        let group = label(of: pattern).flatMap(ProtectedGroup.group(forLabel:))?.id
        if var own = app.decision(path: path, group: group, writes: writes, home: home) {
            own.group = general?.group
            return own
        }
        guard let general else { return nil }
        switch app.everywhere {
        case .block: return .init(verdict: .block, reason: "you block \(app.name) in every protected place", group: general.group)
        case .allow: return .init(verdict: .allow, reason: "you allow \(app.name) in every protected place", group: general.group)
        case .decides: return general
        }
    }

    /// What a mode does with a decision: nil when nothing is shown or done. Strict turns a question into a block,
    /// as the firewall's Strict does.
    static func effective(_ verdict: ProtectionVerdict, mode: ProtectionMode) -> ProtectionVerdict? {
        switch mode {
        case .off: return nil
        case .watch, .ask: return verdict
        case .strict: return verdict == .ask ? .block : verdict
        }
    }

    /// The sensitive label a pattern carries: "r ~/.ssh/*  [SSH keys]" → "SSH keys". Only labelled places
    /// end in "]" (CLAUDE.md: pattern text carries meaning), and "[ordinary files]" is not sensitive.
    static func label(of pattern: String) -> String? {
        guard pattern.hasSuffix("]"), let open = pattern.range(of: "  [", options: .backwards) else { return nil }
        let label = String(pattern[open.upperBound...].dropLast())
        return label == SignatureBuilder.ordinaryFiles ? nil : label
    }
}

/// Protection as a whole, from the modes alone: the overview's header and the window's subtitle say the same.
enum ProtectionState: Equatable {
    case off, rehearsing, protecting, paused

    init(paused: Bool, modes: [ProtectionMode], network: FirewallMode) {
        if paused { self = .paused }
        else if modes.contains(where: \.enforces) || network == .ask || network == .strict { self = .protecting }
        else if modes.contains(where: { $0 != .off }) || network == .watch { self = .rehearsing }
        else { self = .off }
    }
}

extension ProtectionState {
    /// What the window's subtitle says: nil when everything is off.
    var word: String? {
        switch self {
        case .off: nil
        case .rehearsing: "Rehearsing"
        case .protecting: "Protecting"
        case .paused: "Protection paused"
        }
    }
}
