import AppKit
import SwiftUI

/// Protection ▸ Network Firewall, built like the other Protection pages: the mode and what it does on top,
/// numbers you read at a glance, what waits for you, then what the firewall found, to decide before it enforces.
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
                modeCard
                numbers(found)
                if !firewall.prompts.isEmpty { waiting }
                FirewallRulesSection(firewall: firewall, signatures: signatures)
                if let protection {
                    DestinationsSection(protection: protection, map: networkMap ?? Self.noMap, bothWays: networkMap != nil,
                                        firewall: firewall, showNetwork: showNetwork)
                }
                if let networkMap { NetworksSection(store: networkMap) }
                findings(found)
                howItDecides
            }
        }
    }

    // MARK: Mode

    private var explanation: String {
        switch firewall.mode {
        case .off: "Connections aren't judged. Turn on Watch to see what the firewall would stop, without stopping anything."
        case .watch: "Nothing is blocked. Every connection is judged as Ask and Strict would, and listed below."
        case .ask: "Blocks what you blocked. A new connection waits for your answer in a question window."
        case .strict: "Only what's allowed connects. Anything new is blocked without asking."
        }
    }

    private var modeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                KindTile(kind: .net)
                Text("Network Firewall").font(.title3.weight(.semibold))
                Spacer()
                if firewall.mode == .ask || firewall.mode == .strict { relayStatus }
            }
            Picker("Mode", selection: $firewall.mode) {
                ForEach(FirewallMode.allCases, id: \.self) { Text($0.short).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 420, alignment: .leading)
            Text(explanation).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let f = firewall.fallback {
                HStack(spacing: 8) {
                    Label("It turned itself to Watch: " + FirewallFallbackBanner.reason(f), systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Turn \(f.from.short) Back On") { firewall.mode = f.from }.buttonStyle(.glassProminent)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(20)
    }

    @ViewBuilder private var relayStatus: some View {
        switch firewall.relayState {
        case "on": Label("Relay on", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case "failed":
            Label(firewall.relayDetail.isEmpty ? "Relay failed" : firewall.relayDetail, systemImage: "xmark.octagon.fill")
                .foregroundStyle(.red).lineLimit(1)
        default: Label("Waiting for the collector", systemImage: "hourglass").foregroundStyle(.secondary)
        }
    }

    // MARK: Numbers

    private func numbers(_ found: [(FirewallEntry, FirewallDecision)]) -> some View {
        let block = found.filter { $0.1.verdict == .block }.count, ask = found.count - block
        let enforcing = firewall.mode == .ask || firewall.mode == .strict
        return HStack(spacing: 28) {
            if enforcing { number(firewall.blockedCount, "blocked since Hostwatch started", red: firewall.blockedCount > 0) }
            number(block, enforcing ? "destinations it blocks" : "destinations it would block", red: block > 0)
            number(ask, firewall.mode == .strict ? "new ones it blocks" : "it would ask about", red: false)
            number(firewall.allowedCount, "connections passed", red: false)
            Spacer()
        }
        .opacity(firewall.mode == .off ? 0.4 : 1)
    }

    private func number(_ n: Int, _ label: String, red: Bool) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(n.formatted()).font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit()
                .foregroundStyle(red ? Color.red : Color.primary)
            Text(label).font(.caption).foregroundStyle(.secondary)
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

    // MARK: Found

    /// What the firewall found is decided in Protection ▸ Found, with launches and files: one place for everything
    /// to decide (it was listed twice, here and there). Here, how many, and the way there.
    private func findings(_ found: [(FirewallEntry, FirewallDecision)]) -> some View {
        let block = found.filter { $0.1.verdict == .block }.count
        return HStack(spacing: 10) {
            Image(systemName: found.isEmpty ? "checkmark.circle" : "exclamationmark.shield")
                .foregroundStyle(found.isEmpty ? Color.secondary : block > 0 ? Color.red : Color.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(found.isEmpty ? "Nothing to decide" : "\(found.count) connection\(found.count == 1 ? "" : "s") to decide")
                    .fontWeight(.semibold)
                Text(found.isEmpty
                     ? (firewall.mode == .off ? "Turn on Watch to see what would be blocked or asked about." : "Every connection seen passes.")
                     : "\(block) would be blocked, \(found.count - block) asked about. Allow or Block them in Found, with launches and files.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !found.isEmpty {
                Button { openFound() } label: { Label("Review in Found", systemImage: "chevron.right").labelStyle(.titleOnly) }
                    .buttonStyle(.glassProminent)
            }
            // Out of the way, and said plainly: it forgets what was seen, never a rule (those are listed above).
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
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    // MARK: How

    private var howItDecides: some View {
        Label {
            Text("Passes: the local network, macOS itself, Hostwatch, Safe patterns and trusted developers. Blocks: known "
                 + "malware addresses, patterns marked Suspicious or Dangerous, high-risk ones (programs from Downloads, "
                 + "say), and domains you blocked for an app. Asks about everything else that's new. In Ask and Strict, "
                 + "connections go through Hostwatch's relay: nothing is decrypted, programs running as root and the "
                 + "local network aren't covered, and if the relay fails its web check twice the firewall turns itself "
                 + "to Watch.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: { Image(systemName: "info.circle") }
        .font(.callout).foregroundStyle(.secondary)
        .padding(14)
        .protectionGlass(16)
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
            Button("Block") { mark(.dangerous) }
        }
        .controlSize(.small)
        .padding(.vertical, 4)
    }
}

/// Your rules, always in view: what you blocked, what you allowed despite a threat list, and what you asked to be
/// asked about again. Independent of the seen-connections list, so forgetting that never hides a rule.
struct FirewallRulesSection: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore

    /// Connection patterns marked Suspicious or Dangerous: blocked whatever the domain.
    private var blockedPatterns: [SignatureEntry] {
        signatures.allEntries.filter { $0.kind == .net && [.suspicious, .dangerous].contains(signatures.status(forKey: $0.id)) }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    var body: some View {
        let _ = signatures.revision
        let rules = firewall.rules
        let blocks = rules.filter { $0.kind == .domainBlock }, patterns = blockedPatterns
        let exceptions = rules.filter { $0.kind == .threatException }, again = rules.filter { $0.kind == .askAgain }
        VStack(alignment: .leading, spacing: 10) {
            Text("Your rules").font(.headline)
            if rules.isEmpty && patterns.isEmpty && !firewall.everywhereBlocked {
                Text("None yet. Block a domain for an app in Network, or Block a connection here, and it's listed here.")
                    .foregroundStyle(.secondary)
            }
            if !blocks.isEmpty || !patterns.isEmpty {
                group("Blocked", symbol: "nosign", tint: .red) {
                    ForEach(blocks) { r in
                        line(program: r.program, what: r.destination, detail: "every connection to this domain") {
                            Button("Unblock") { firewall.remove(r) }
                        }
                    }
                    ForEach(patterns) { e in
                        line(program: displayProcessName(e.process), what: e.pattern,
                             detail: "marked \(signatures.status(forKey: e.id).title) · \(signatures.decidedBy(e.id))") {
                            Button("Unblock") { signatures.set(.unclassified, keys: [e.id]) }
                                .help("Back to New: the firewall asks about it again")
                        }
                    }
                }
            }
            if !exceptions.isEmpty {
                group("Allowed despite a threat list", symbol: "exclamationmark.shield", tint: .orange) {
                    ForEach(exceptions) { r in
                        line(program: r.program, what: r.destination, detail: "you chose Allow Anyway") {
                            Button("Remove") { firewall.remove(r) }.help("Blocked again because of the threat list")
                        }
                    }
                }
            }
            let apps = rules.filter { $0.kind == .appBlock }
            if !apps.isEmpty || firewall.everywhereBlocked {
                group("Blocked everywhere", symbol: "globe.americas", tint: .red) {
                    if firewall.everywhereBlocked {
                        line(program: "Every program", what: "everywhere",
                             detail: "but the \(firewall.everywhereAllowed.count) you always allow") {
                            Button("Unblock") { firewall.setEverywhereBlocked(false) }.help("Back to Firewall decides")
                        }
                    }
                    ForEach(apps) { r in
                        line(program: PlaceExceptions.name(r.key), what: "everywhere", detail: "every connection, your network too") {
                            Button("Unblock") { firewall.remove(r) }.help("Its connections are judged as usual again")
                        }
                    }
                }
            }
            if !again.isEmpty {
                group("Asked about again", symbol: "questionmark.circle", tint: .secondary) {
                    ForEach(again) { r in
                        line(program: r.program, what: r.destination, detail: "you forgot your decision here") {
                            Button("Remove") { firewall.remove(r) }.help("Its pattern decides again")
                        }
                    }
                }
            }
        }
    }

    private func group<Content: View>(_ title: String, symbol: String, tint: Color, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(tint)
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(14)
    }

    private func line<Action: View>(program: String, what: String, detail: String, @ViewBuilder action: () -> Action) -> some View {
        HStack(spacing: 8) {
            Text(program).fontWeight(.semibold).lineLimit(1)
            Image(systemName: "arrow.right").font(.caption).foregroundStyle(.tertiary)
            Text(what).font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
            Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer()
            action().controlSize(.small)
        }
    }
}

/// Your destinations, shaped like protected places: a domain (its subdomains too) or an IP, what any other program
/// meets there (Firewall decides, Allow or Block), and programs you always allow or always block, as chips.
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
                Text("Your destinations").font(.headline)
                Spacer()
                Button { adding.open = true } label: { Label("Add Domain or Address…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Text("A domain (its subdomains too) or an IP address, with what any other program meets there and the programs "
                 + "you always allow or always block: your decisions, before threat lists and patterns. An address or a "
                 + "device can also be blocked both ways: nothing reaches this Mac from it or goes to it, whatever the "
                 + "firewall's mode.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if adding.open { addRow }
            if networkMap == nil, protection.destinations.isEmpty, !adding.open {
                Text("None yet. Block a domain for every program, or always allow one app to a server.")
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
        .protectionGlass(16)
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
                         exceptions: Binding(get: { d.exceptions }, set: { e in binding { $0.exceptions = e } }), place: d.target)
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

/// Your destinations' first card, always there: every destination, your network too, shaped like the others.
/// Any other program: Firewall decides (the default) or Block, every program's traffic but the ones you always allow
/// here. Always block: all of a program's traffic, whatever else you allowed (the firewall checks it first). Always
/// allow only keeps a program out of this card's Block: not past threat lists or your other destinations.
struct EverywhereCard: View {
    @ObservedObject var firewall: FirewallMonitor

    enum Choice: Hashable { case firewall, block }

    private var others: Binding<Choice> {
        Binding(get: { firewall.everywhereBlocked ? .block : .firewall }, set: { firewall.setEverywhereBlocked($0 == .block) })
    }

    /// The shared chips and Add Program, bound to the firewall's two lists.
    private var exceptions: Binding<PlaceExceptions> {
        Binding(get: { PlaceExceptions(allowed: firewall.everywhereAllowed.sorted(), blocked: firewall.appBlocks.sorted()) },
                set: { new in
                    for app in firewall.appBlocks where !new.blocked.contains(app) { firewall.setNoNetwork(false, app: app) }
                    for app in new.blocked where !firewall.appBlocks.contains(app) { firewall.setNoNetwork(true, app: app) }
                    for app in firewall.everywhereAllowed where !new.allowed.contains(app) { firewall.setAllowedEverywhere(false, app: app) }
                    for app in new.allowed where !firewall.everywhereAllowed.contains(app) { firewall.setAllowedEverywhere(true, app: app) }
                })
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
                    Text("Every destination, your network too. Applies wherever no destination below decides.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            VStack(alignment: .leading, spacing: 6) {
                PlaceChoices(others: others, options: [(.firewall, "Firewall decides"), (.block, "Block")],
                             exceptions: exceptions, place: "any destination")
                if firewall.everywhereBlocked {
                    Text("Every program's traffic is blocked, but the programs you always allow here.")
                        .font(.caption).foregroundStyle(.red)
                }
                if firewall.everywhereBlocked || !firewall.appBlocks.isEmpty, firewall.mode == .off || firewall.mode == .watch {
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
