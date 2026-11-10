import AppKit
import SwiftUI

/// Rules ▸ Protection ▸ Network Firewall, built like the other Protection pages: the mode and what it does on top,
/// numbers you read at a glance, what waits for you, then what the firewall found, to decide before it enforces.
struct NetworkFirewallPage: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    let showNetwork: () -> Void

    private static let limit = 30

    var body: some View {
        let found = firewall.list(status: { signatures.status(forKey: $0) })
        VStack(alignment: .leading, spacing: 18) {
            modeCard
            numbers(found)
            if !firewall.prompts.isEmpty { waiting }
            findings(found)
            howItDecides
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
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.quaternary.opacity(0.4)))
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
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.orange.opacity(0.1)))
    }

    // MARK: Found

    private func findings(_ found: [(FirewallEntry, FirewallDecision)]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("What the firewall found").font(.headline)
                Spacer()
                Button("Show All in Network…", action: showNetwork).buttonStyle(.link)
                Button("Clear List") { firewall.clear() }.disabled(firewall.entries.isEmpty)
                    .help("Forget the connections seen so far: your Allow and Block decisions stay")
            }
            if found.isEmpty {
                Text(firewall.mode == .off ? "Turn on Watch to see what would be blocked or asked about."
                     : "Nothing to decide: every connection seen passes.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Allow marks the program's pattern for that destination Safe. Block marks it Dangerous.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(found.prefix(Self.limit), id: \.0.id) { entry, decision in
                    NetworkFindingRow(entry: entry, decision: decision, mode: firewall.mode, firewall: firewall) { status in
                        signatures.set(status, keys: [entry.facts.patternKey],
                                       note: status == .safe ? "allowed in Protection" : "blocked in Protection")
                    }
                }
                if found.count > Self.limit {
                    Text("and \(found.count - Self.limit) more in Network").font(.caption).foregroundStyle(.tertiary)
                }
            }
        }
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
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.3)))
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
