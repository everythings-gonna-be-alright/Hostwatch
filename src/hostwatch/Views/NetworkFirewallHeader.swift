import AppKit
import SwiftUI

/// Network Firewall, above its rules: the firewall's state and mode with five facts, then what it found over time beside
/// the destinations found most. The Overview's pattern, for connections only.
struct NetworkFirewallHeader: View {
    @ObservedObject var firewall: FirewallMonitor
    let found: [(FirewallEntry, FirewallDecision)]
    var protection: ProtectionMonitor? = nil
    var networkMap: NetworkMapStore? = nil
    let showNetwork: () -> Void
    let openFound: () -> Void
    @AppStorage("protectionChartRange") private var rangeRaw = ProtectionTimeline.Range.day.rawValue
    @StateObject private var help = ExpandState()

    private var enforcing: Bool { firewall.mode == .ask || firewall.mode == .strict }
    private var state: AreaState {
        AreaState(paused: protection?.paused ?? false, off: firewall.mode == .off, enforces: enforcing)
    }

    var body: some View {
        let range = ProtectionTimeline.Range(rawValue: rangeRaw) ?? .day
        let buckets = firewall.mode == .off ? [] : ProtectionTimeline.buckets(
            firstSeen: found.map { ($0.0.firstSeen, blocked: $0.1.verdict == .block) }, range: range)
        let top = found.sorted { ($0.0.count, $0.0.lastSeen) > ($1.0.count, $1.0.lastSeen) }.prefix(5).map { FoundConnection(entry: $0.0, decision: $0.1) }
        VStack(alignment: .leading, spacing: 18) {
            AreaHero(symbol: "network.badge.shield.half.filled", title: "Network Firewall", accent: AreaAccent.network, state: state, sentence: sentence,
                     facts: facts) {
                AreaModePicker(title: "Mode", mode: $firewall.mode, modes: FirewallMode.allCases.map { ($0, $0.short) })
                HelpLink { help.open.toggle() }
                    .popover(isPresented: $help.open, arrowEdge: .bottom) { howItDecides }
                more
            } notice: {
                if let f = firewall.fallback {
                    HStack(spacing: 8) {
                        Label("It turned itself to Watch: " + FirewallFallbackBanner.reason(f), systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        Button("Turn \(f.from.short) Back On") { firewall.mode = f.from }.buttonStyle(.glassProminent)
                    }
                }
            }
            AreaActivity(rangeRaw: $rangeRaw, buckets: buckets,
                         stopLabel: enforcing ? "blocked" : "would block", askLabel: enforcing ? "asked about" : "would ask",
                         off: firewall.mode == .off, turnOn: { firewall.mode = .watch },
                         offText: "Watch shows, by when they first appeared, the destinations that would be blocked. It blocks nothing.",
                         topTitle: "Found most",
                         topEmpty: firewall.mode == .off ? "Nothing judged while the firewall is off."
                            : "Nothing yet. Every connection seen passes.",
                         items: Array(top), footer: "Review in Found", footerCount: found.count, action: openFound) { c in
                ActivityTopRow(program: c.entry.facts.program, name: c.entry.name,
                               detail: "\(c.entry.facts.proto) \(c.entry.destination):\(c.entry.facts.port)",
                               verdict: verdict(c.decision), blocks: c.decision.verdict == .block, count: c.entry.count)
            }
        }
    }

    private var sentence: String {
        switch state {
        case .off: return "Connections aren't judged. Turn on Watch to see what the firewall would stop, without stopping anything."
        case .paused: return "Nothing is judged or blocked until protection resumes."
        case .watching: return "Nothing is blocked. Every connection is judged as Ask and Strict would."
        case .protecting:
            return firewall.mode == .strict ? "Only what's allowed connects. Anything new is blocked without asking."
                : "Blocks what you blocked. A new connection waits for your answer in a question window."
        }
    }

    private func verdict(_ d: FirewallDecision) -> String {
        if d.reason.hasPrefix("known malware") { return "Threat list" }
        if d.verdict == .block || firewall.mode == .strict { return enforcing ? "Blocks" : "Would block" }
        return enforcing ? "Asks" : "Would ask"
    }

    private var facts: [StatusFact] {
        let block = found.filter { $0.1.verdict == .block }.count
        let global = protection?.destinations.count ?? 0
        let apps = firewall.apps.count
        let network = networkMap.flatMap { m in m.profiles[m.network] }
        return [
            enforcing
                ? StatusFact(symbol: "nosign", title: "Blocked", value: firewall.blockedCount.formatted(),
                             detail: "Since Hostwatch started, \(block) destinations")
                : StatusFact(symbol: "nosign", title: "Would block", value: block.formatted(),
                             detail: block == 1 ? "1 destination" : "\(block) destinations"),
            StatusFact(symbol: "checkmark.circle", title: "Passed", value: firewall.allowedCount.formatted(),
                       detail: "Connections since Hostwatch started"),
            StatusFact(symbol: "list.bullet.rectangle", title: "Your rules", value: "\(global + apps)",
                       detail: "\(global) global, \(apps == 1 ? "1 app" : "\(apps) apps")"),
            relay,
            StatusFact(symbol: network?.trusted == false ? "cup.and.saucer" : "house", title: "This network",
                       value: network?.name ?? "Unknown",
                       detail: network.map { $0.trusted ? "Trusted" : "Not trusted: others kept away" } ?? "Not reported yet"),
        ]
    }

    /// The relay carries connections in Ask and Strict: whether it works, or that Watch doesn't need it.
    private var relay: StatusFact {
        guard enforcing else {
            return StatusFact(symbol: "arrow.triangle.branch", title: "Relay", value: "Not needed",
                              detail: "Only Ask and Strict use it")
        }
        switch firewall.relayState {
        case "on": return StatusFact(symbol: "arrow.triangle.branch", title: "Relay", value: "On", detail: "Connections pass through it")
        case "failed": return StatusFact(symbol: "arrow.triangle.branch", title: "Relay", value: "Failed",
                                         detail: firewall.relayDetail.isEmpty ? "See Help" : firewall.relayDetail)
        default: return StatusFact(symbol: "arrow.triangle.branch", title: "Relay", value: "Starting",
                                   detail: "Waiting for the collector")
        }
    }

    /// Out of the way, and said plainly: it forgets what was seen, never a rule.
    private var more: some View {
        Menu {
            Button("Show All in Network…", action: showNetwork)
            Button("Forget Seen Connections…") {
                let alert = NSAlert()
                alert.messageText = "Forget the connections seen so far?"
                alert.informativeText = "The list and its counts start again. Your rules stay as they are: blocks, "
                    + "exceptions and every Allow or Block you made."
                alert.addButton(withTitle: "Forget")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() == .alertFirstButtonReturn { firewall.clear() }
            }
            .disabled(firewall.entries.isEmpty)
        } label: { Image(systemName: "ellipsis.circle") }
        .menuStyle(.borderlessButton).fixedSize()
        .help("More: show every connection, or forget the ones seen so far")
    }

    private var howItDecides: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("How the firewall decides").font(.headline)
            Text("An app's own rules first, then the global rules, then the local network, threat lists, your patterns "
                 + "and risk. Passes: the local network, macOS itself, Hostwatch, Safe patterns and trusted developers. "
                 + "Blocks: known malware addresses, patterns marked Suspicious or Dangerous, high-risk ones (programs "
                 + "from Downloads, say). Asks about everything else that's new.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Divider()
            Text("In Ask and Strict, connections go through Hostwatch's relay: nothing is decrypted, programs running as "
                 + "root and the local network aren't covered, and if the relay fails its web check twice the firewall "
                 + "turns itself to Watch.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .padding(16)
        .frame(width: 360)
    }
}

/// A found connection with its decision, identified for the list of what was found most.
private struct FoundConnection: Identifiable {
    let entry: FirewallEntry
    let decision: FirewallDecision
    var id: String { entry.id }
}
