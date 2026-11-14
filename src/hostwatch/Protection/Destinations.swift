import Foundation

/// What any other program meets at a destination: no opinion (your firewall mode decides), or always allowed, or
/// always blocked.
enum DestinationChoice: String, Codable, Sendable, CaseIterable {
    case firewall, allow, block
}

/// A network destination you decided, shaped like a protected place: a domain (its subdomains too) or an IP, a choice
/// for any other program, and programs you always allow or always block there. Your decisions, so the firewall takes
/// them before threat lists and patterns. source: docs/adr/0015-your-allow-and-block-rules.md
struct Destination: Codable, Identifiable, Equatable, Sendable {
    var id = UUID().uuidString
    var target: String                         // lowercased domain or IP
    var on = true
    var others: DestinationChoice = .firewall
    var exceptions = PlaceExceptions()

    var isIP: Bool { Destinations.isIP(target) }

    /// The domain itself or a subdomain, or the very IP.
    func covers(host: String, ip: String) -> Bool {
        let h = host.lowercased()
        return target == ip || (!h.isEmpty && (h == target || h.hasSuffix("." + target)))
    }
}

enum Destinations {
    /// Your decision for a connection: the most specific destination that covers it (a longer domain over a shorter
    /// one), its program exceptions first (Block when on both), then its choice for any other program. Nil when no
    /// destination covers it, or the one that does leaves it to the firewall.
    static func decide(_ list: [Destination], host: String, ip: String, program: String) -> FirewallDecision? {
        guard let d = list.filter({ $0.on && $0.covers(host: host, ip: ip) }).max(by: { $0.target.count < $1.target.count })
        else { return nil }
        let who = PlaceExceptions.name(program)
        switch d.exceptions.verdict(for: program) {
        case .allow?: return FirewallDecision(verdict: .allow, reason: "you always allow \(who) to \(d.target)")
        case .block?: return FirewallDecision(verdict: .block, reason: "you always block \(who) to \(d.target)")
        default: break
        }
        switch d.others {
        case .firewall: return nil
        case .allow: return FirewallDecision(verdict: .allow, reason: "you allow \(d.target)")
        case .block: return FirewallDecision(verdict: .block, reason: "you block \(d.target)")
        }
    }

    /// Why this can't be a destination, nil when it can: a whole domain or an IP, not a URL or a top-level domain.
    static func refusal(_ raw: String) -> String? {
        let t = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if t.isEmpty { return "Enter a domain or an IP address." }
        if t.contains("/") || t.contains(" ") || t.contains("://") { return "Enter a domain such as example.com, or an IP address." }
        if !isIP(t) && !t.contains(".") { return "Enter a whole domain such as example.com, not a top-level one like “\(t)”." }
        return nil
    }

    static func isIP(_ t: String) -> Bool {
        t.contains(":") || (t.split(separator: ".").count == 4 && t.split(separator: ".").allSatisfy { Int($0) != nil })
    }

    /// Network rules from the short-lived separate list, as destinations: a rule for any program sets the
    /// destination's choice, a rule for one program becomes its exception.
    static func from(_ rules: [AccessRule]) -> [Destination] {
        var out: [Destination] = []
        for rule in rules where rule.kind == .network {
            let target = rule.target.lowercased()
            var d = out.first { $0.target == target } ?? Destination(target: target)
            d.on = d.on && rule.on
            if let program = rule.program {
                if rule.action == .allow { d.exceptions.allowed.append(program) } else { d.exceptions.blocked.append(program) }
            } else {
                d.others = rule.action == .allow ? .allow : .block
            }
            out.removeAll { $0.target == target }
            out.append(d)
        }
        return out
    }
}
