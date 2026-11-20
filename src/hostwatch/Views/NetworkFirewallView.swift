import AppKit
import SwiftUI

/// Protection ▸ Network Firewall, built like the Overview: the firewall's state, mode and facts, its activity beside
/// what it found most, what waits for you, then the global rules, the app rules and the networks.
struct NetworkFirewallPage: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    let showNetwork: () -> Void
    /// Protection ▸ Found, where the firewall's findings are decided.
    var openFound: () -> Void = {}
    /// Where your Allow and Block rules live (the network ones are shown here).
    var protection: ProtectionMonitor? = nil
    /// Devices, addresses and ports blocked from the network map.
    var networkMap: NetworkMapStore? = nil
    /// For a page without a network map: nothing blocked, nothing offered.
    private static let noMap = NetworkMapStore(fileURL: nil)

    var body: some View {
        let found = firewall.list(status: { signatures.status(forKey: $0) })
        GlassEffectContainer(spacing: 12) {
            VStack(alignment: .leading, spacing: 18) {
                NetworkFirewallHeader(firewall: firewall, found: found, protection: protection, networkMap: networkMap,
                                      showNetwork: showNetwork, openFound: openFound)
                if !firewall.prompts.isEmpty { waiting }
                if let protection {
                    DestinationsSection(protection: protection, map: networkMap ?? Self.noMap, bothWays: networkMap != nil,
                                        firewall: firewall, showNetwork: showNetwork)
                    AppRulesSection(firewall: firewall, signatures: signatures)
                }
                if let networkMap { NetworksSection(store: networkMap) }
            }
        }
    }

    // MARK: Waiting

    private var waiting: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Waiting for you").font(.headline)
            ForEach(firewall.prompts) { FirewallWaitingRow(prompt: $0, firewall: firewall) }
        }
        .padding(14)
        .protectionGlass(16, tint: .orange.opacity(0.18))
    }
}

/// One destination the firewall would block or ask about (or does, in Ask and Strict), with Allow and Block.
struct NetworkFindingRow: View {
    let entry: FirewallEntry
    let decision: FirewallDecision
    let mode: FirewallMode
    /// The firewall, for a domain you blocked for this app: Allow lifts that block too (it wins over the pattern).
    var firewall: FirewallMonitor? = nil
    let mark: (SignatureStatus) -> Void

    private var blockedDomain: String? { firewall?.blockedDomain(entry.facts) }

    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; f.dateTimeStyle = .named; return f
    }()

    private var verdictText: String {
        let enforcing = mode == .ask || mode == .strict
        if decision.reason.hasPrefix("known malware") { return "On a threat list" }
        if decision.verdict == .block || mode == .strict { return enforcing ? "Blocks" : "Would block" }
        return enforcing ? "Asks" : "Would ask"
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: ProcessIcons.icon(entry.facts.program)).resizable().frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(entry.name).fontWeight(.semibold)
                    Text(verdictText).font(.caption.weight(.semibold))
                        .foregroundStyle(decision.verdict == .block ? Color.red : Color.orange)
                    Text("\(entry.count)× · \(Self.relative.localizedString(for: entry.lastSeen, relativeTo: Date()))")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Text("\(entry.facts.proto) \(entry.destination):\(entry.facts.port)")
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Text(decision.reason).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !entry.facts.knownBad.isEmpty, firewall != nil {
                // A threat list outranks the pattern: only a confirmed exception lets it through.
                Button("Allow Anyway…") {
                    if ThreatException.confirm(entry) { firewall?.setThreatException(true, entry.facts) }
                }
                .help("On a threat list: \(entry.facts.knownBad)")
            } else {
                Button("Allow") {
                    // A domain you blocked for this app outranks the pattern: Safe alone changed nothing.
                    if let domain = blockedDomain { firewall?.setBlocked(false, domain: domain, program: entry.facts.program) }
                    mark(.safe)
                }
                .help(blockedDomain.map { "Unblocks \($0) for \(entry.name) and marks the pattern Safe" } ?? "Marks the pattern Safe")
            }
            Button("Block") {
                // Only this destination for this program: its pattern is often the whole web.
                if firewall?.blockDestination(entry.facts) != true { mark(.dangerous) }
            }
            .help(firewall != nil ? "Blocks \(entry.destination) for \(entry.name). Its other destinations are judged as usual"
                                  : "Marks the pattern Dangerous")
        }
        .controlSize(.small)
        .padding(.vertical, 4)
    }
}

/// Global rules: the rules for every program, shaped like protected places. A domain (its subdomains too) or an IP and what
/// every program meets there (Firewall decides, Allow or Block). One app's rules are on its card (`AppRulesSection`).
struct DestinationsSection: View {
    @ObservedObject var protection: ProtectionMonitor
    /// Devices, addresses and ports blocked both ways (the collector's own block), in the same list.
    @ObservedObject var map: NetworkMapStore
    /// False without a network map (the demo): no Block both ways.
    var bothWays = true
    /// Everywhere's card.
    @ObservedObject var firewall: FirewallMonitor
    var showNetwork: () -> Void = {}

    private var networkMap: NetworkMapStore? { bothWays ? map : nil }
    @StateObject private var adding = DestinationDraft()

    static let options: [(DestinationChoice, String)] = [(.firewall, "Firewall decides"), (.allow, "Allow"), (.block, "Block")]

    /// A card's choice: the firewall's three, or for an address, Block both ways (the collector's own block: incoming
    /// too, whatever the firewall's mode, no exceptions). The same address once had two places to be blocked.
    enum Pick: Hashable { case choice(DestinationChoice), bothWays }

    private func options(_ d: Destination) -> [(Pick, String)] {
        Self.options.map { (Pick.choice($0.0), $0.1) } + (d.isIP && networkMap != nil ? [(.bothWays, "Block both ways")] : [])
    }

    private func pick(_ d: Destination, _ binding: @escaping (@escaping (inout Destination) -> Void) -> Void) -> Binding<Pick> {
        Binding(get: {
            networkMap?.blockedAddresses.contains(d.target) == true ? .bothWays : .choice(d.others)
        }, set: { new in
            switch new {
            case .bothWays:
                guard bothWaysRefusal(d.target) == nil else { return }
                networkMap?.setBlocked(address: d.target, true)
                binding { $0.others = .block }                     // the firewall's answer too, should the block go
            case .choice(let c):
                networkMap?.setBlocked(address: d.target, false)
                binding { $0.others = c }
            }
        })
    }

    /// Why an address can't be blocked both ways, nil when it can.
    private func bothWaysRefusal(_ ip: String) -> String? {
        if ip == networkMap?.routes.gateway { return "That's the router: blocking it would cut this Mac off the network." }
        if ip.hasPrefix("127.") || ip == "::1" { return "That's this Mac itself." }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                RuleSections.heading(global: true)
                Spacer()
                Button { adding.open = true } label: { Label("Add Domain or Address…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Text("For every program. A domain (its subdomains too) or an IP address, and what programs meet there: your "
                 + "decisions, before threat lists and patterns. An app's own rules below win over these. An address or a "
                 + "device can also be blocked both ways: nothing reaches this Mac from it or goes to it, whatever the "
                 + "firewall's mode.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if adding.open { addRow }
            if networkMap == nil, protection.destinations.isEmpty, !adding.open {
                Text("None yet. Block a domain for every program, or allow one.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            EverywhereCard(firewall: firewall)
            Text("Specific destinations").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                .padding(.top, 4)
            ForEach(protection.destinations) { d in card(d) }
            if let networkMap {
                // Addresses blocked both ways from the network map, not destinations yet: the same cards, kept as
                // destinations once you change one.
                BlockedAddressCards(store: networkMap, known: Set(protection.destinations.map(\.target))) { card($0) }
                BlockedCards(store: networkMap,
                             noDestinations: protection.destinations.isEmpty && !adding.open, showNetwork: showNetwork)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .globalRulesGlass()
    }

    private var addRow: some View {
        let problem = adding.text.isEmpty ? nil : Destinations.refusal(adding.text)
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("example.com or 203.0.113.9", text: $adding.text)
                    .textFieldStyle(.roundedBorder).font(.system(size: 12, design: .monospaced))
                    .onSubmit(add)
                Button("Cancel") { adding.open = false; adding.text = "" }.controlSize(.small)
                Button("Add", action: add).buttonStyle(.glassProminent).controlSize(.small)
                    .disabled(adding.text.isEmpty || problem != nil)
            }
            if let problem { Label(problem, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
        }
    }

    private func add() {
        let target = adding.text.trimmingCharacters(in: .whitespaces).lowercased()
        guard Destinations.refusal(target) == nil else { return }
        if !protection.destinations.contains(where: { $0.target == target }) {
            protection.destinations.append(Destination(target: target))
        }
        adding.open = false
        adding.text = ""
    }

    /// The same card as a protected place: name and what it covers, on and off, then the choices and the chips.
    private func card(_ d: Destination) -> some View {
        // Kept as a destination at the first change (one shown from a both-ways block may not be one yet).
        let binding = { (change: @escaping (inout Destination) -> Void) in
            if let i = protection.destinations.firstIndex(where: { $0.id == d.id }) { change(&protection.destinations[i]) }
            else { var new = d; change(&new); protection.destinations.append(new) }
        }
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: d.isIP ? "number" : "globe").foregroundStyle(.secondary).frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text(d.target).font(.system(size: 13, weight: .medium, design: .monospaced))
                    Text(d.isIP ? "This IP address" : "And its subdomains").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("", isOn: Binding(get: { d.on }, set: { on in binding { $0.on = on } }))
                    .labelsHidden().toggleStyle(.switch).controlSize(.small)
                Button {
                    protection.destinations.removeAll { $0.id == d.id }
                    if d.isIP { networkMap?.setBlocked(address: d.target, false) }
                } label: { Image(systemName: "minus.circle") }
                    .buttonStyle(.borderless).help("Remove \(d.target)")
            }
            PlaceChoices(others: pick(d, binding), options: options(d),
                         exceptions: Binding(get: { d.exceptions }, set: { e in binding { $0.exceptions = e } }), place: d.target,
                         showsPrograms: false)
                .disabled(!d.on).opacity(d.on ? 1 : 0.5)
                .padding(.leading, 32)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }
}

/// The destination being typed (no @State macro with the command line tools).
final class DestinationDraft: ObservableObject {
    @Published var open = false
    @Published var text = ""
}

/// The Global rules' first card, always there: every destination, your network too, shaped like the others. Any program:
/// Firewall decides (the default) or Block, every program's traffic but the apps whose own card allows them everywhere.
struct EverywhereCard: View {
    @ObservedObject var firewall: FirewallMonitor

    enum Choice: Hashable { case firewall, block }

    private var others: Binding<Choice> {
        Binding(get: { firewall.everywhereBlocked ? .block : .firewall }, set: { firewall.setEverywhereBlocked($0 == .block) })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Set apart from the destinations below: a seal, a Base rule badge, and red glass while it blocks.
            HStack(spacing: 12) {
                Image(systemName: "globe.americas.fill")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background((firewall.everywhereBlocked ? Color.red : Color.blue).gradient, in: Circle())
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("Everywhere").font(.headline)
                        Text("Base rule").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Capsule().fill(Color.primary.opacity(0.10)))
                    }
                    Text("Every destination, your network too, for every program. Applies wherever no other rule decides.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            VStack(alignment: .leading, spacing: 6) {
                PlaceChoices(others: others, options: [(.firewall, "Firewall decides"), (.block, "Block")],
                             exceptions: .constant(PlaceExceptions()), place: "any destination", showsPrograms: false)
                if firewall.everywhereBlocked {
                    let allowed = firewall.apps.filter { $0.everywhere == .allow }.map(\.name)
                    Text(allowed.isEmpty ? "Every program's traffic is blocked. Allow an app everywhere in its card below."
                                         : "Every program's traffic is blocked, but \(allowed.joined(separator: ", ")).")
                        .font(.caption).foregroundStyle(.red)
                }
                if firewall.everywhereBlocked || firewall.apps.contains(where: { $0.everywhere == .block }),
                   firewall.mode == .off || firewall.mode == .watch {
                    Label(firewall.mode == .off
                          ? "The firewall is off: nothing is blocked. Ask or Strict blocks it."
                          : "Watch stops nothing: blocked connections are listed as would block. Ask or Strict blocks them.",
                          systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .padding(.leading, 46)
        }
        .padding(14)
        .protectionGlass(16, tint: firewall.everywhereBlocked ? Color.red.opacity(0.14) : nil)
    }
}
