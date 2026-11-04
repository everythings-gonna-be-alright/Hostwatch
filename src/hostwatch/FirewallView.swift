import AppKit
import SwiftUI

/// Settings ▸ Firewall: the mode, what it would do, and the list.
struct FirewallPane: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var ui: SettingsState

    var body: some View {
        let list = firewall.list(status: { signatures.status(forKey: $0) })
        let blocked = list.filter { $0.1.verdict == .block }.count
        Form {
            Section {
                Picker("Mode", selection: $firewall.mode) {
                    ForEach(FirewallMode.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.radioGroup)
                if firewall.mode == .ask || firewall.mode == .strict {
                    LabeledContent("Status") { relayStatus }
                }
            } header: {
                Text("Firewall")
            } footer: {
                Footnote(footnote)
            }
            if firewall.mode != .off {
                Section {
                    if firewall.mode == .ask || firewall.mode == .strict {
                        LabeledContent("Blocked") { Text("\(firewall.blockedCount) since Hostwatch started").monospacedDigit() }
                    }
                    LabeledContent("Would block") {
                        Text("\(blocked)").foregroundStyle(blocked > 0 ? .red : .secondary).monospacedDigit()
                    }
                    LabeledContent("Would ask about") { Text("\(list.count - blocked)").monospacedDigit() }
                    LabeledContent("Would pass") {
                        HStack(spacing: 8) {
                            Text("\(firewall.allowedCount) connections").foregroundStyle(.secondary).monospacedDigit()
                            Button("Show Connections…") { ui.showFirewallList = true }.controlSize(.small)
                        }
                    }
                } header: {
                    Text("Last 7 days")
                } footer: {
                    Footnote("Passes: the local network, macOS itself, Hostwatch, patterns that are Safe, trusted "
                             + "developers. Blocks: known malware addresses, patterns marked Suspicious or Dangerous, and "
                             + "high-risk ones (such as programs from Downloads). Asks: everything else that's new.")
                }
            }
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        .sheet(isPresented: $ui.showFirewallList) {
            FirewallListView(firewall: firewall, signatures: signatures) { ui.showFirewallList = false }
        }
    }
}

extension FirewallPane {
    var footnote: String {
        switch firewall.mode {
        case .off: return "Off: connections aren't judged."
        case .watch: return "Watch judges every connection Hostwatch sees the way Ask and Strict would, and lists what they "
            + "would block or ask about. Nothing is blocked."
        case .ask, .strict:
            return "Your programs' new connections go through Hostwatch's relay (the collector), which checks each new "
                + "program and destination. Nothing is decrypted. Not covered: programs running as root, macOS's own DNS "
                + "lookups, the local network. If the relay fails its web check twice, the firewall turns itself off."
        }
    }

    @ViewBuilder var relayStatus: some View {
        switch firewall.relayState {
        case "on": Label("On", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case "failed":
            Label(firewall.relayDetail.isEmpty ? "Failed" : firewall.relayDetail, systemImage: "xmark.octagon.fill")
                .foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
        default: Label("Waiting for the collector", systemImage: "hourglass").foregroundStyle(.secondary)
        }
    }
}

/// "Google Chrome wants to connect to x.com": Allow or Block decides the pattern; no answer blocks it this time.
struct FirewallPromptView: View {
    @ObservedObject var firewall: FirewallMonitor

    var body: some View {
        if let prompt = firewall.prompts.first {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: prompt.event.proc))
                        .resizable().frame(width: 40, height: 40)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(prompt.event.name) wants to connect to \(prompt.destination)").font(.headline)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("\(prompt.event.extra) port \(prompt.event.remotePort) · \(prompt.event.remoteHost ?? "")")
                            .font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                        Text(prompt.event.proc).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                }
                let pattern = prompt.patternKey.split(separator: "|").last.map(String.init) ?? ""
                Text("Allow or Block decides \(prompt.event.name) → \(pattern) from now on (in Patterns).")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(prompt.deadline.timeIntervalSince(context.date).rounded()))
                        Text("Blocked this time in \(left) s").font(.caption).foregroundStyle(.secondary).monospacedDigit()
                    }
                    if firewall.prompts.count > 1 {
                        Text("· \(firewall.prompts.count - 1) more waiting").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Block") { firewall.resolve(prompt.id, allow: false) }
                    Button("Allow") { firewall.resolve(prompt.id, allow: true) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(18)
            .frame(width: 500)
        }
    }
}

/// Connections the firewall would block or ask about, with Allow and Block for their pattern.
struct FirewallListView: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    let close: () -> Void

    var body: some View {
        let list = firewall.list(status: { signatures.status(forKey: $0) })
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("What the firewall would do").font(.title3.weight(.semibold))
                Text("Connections in the last 7 days it would block or ask about. Allow or Block decides the pattern "
                     + "(the program with that kind of destination), as in Patterns.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)
            Divider()
            if list.isEmpty {
                ContentUnavailableView("Nothing would be blocked", systemImage: "checkmark.shield",
                                       description: Text("Every connection seen so far would pass."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach([FirewallVerdict.block, .ask], id: \.self) { verdict in
                        let rows = list.filter { $0.1.verdict == verdict }
                        if !rows.isEmpty {
                            Section(verdict == .block ? "Would block (\(rows.count))" : "Would ask about (\(rows.count))") {
                                ForEach(rows, id: \.0.id) { entry, decision in
                                    FirewallRow(entry: entry, decision: decision, signatures: signatures)
                                }
                            }
                        }
                    }
                }
            }
            Divider()
            HStack {
                Button("Clear") { firewall.clear() }.disabled(list.isEmpty)
                Spacer()
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 720, height: 560)
    }
}

private struct FirewallRow: View {
    let entry: FirewallEntry
    let decision: FirewallDecision
    let signatures: SignatureStore

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: entry.facts.program))
                .resizable().frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(entry.name).font(.callout.weight(.semibold))
                    Text(entry.facts.proto).font(.system(size: 9, weight: .semibold))
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.18)))
                    Text("\(entry.destination):\(entry.facts.port)").font(.system(size: 12, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle)
                        .help(entry.facts.host.isEmpty ? entry.facts.ip : "\(entry.facts.host) (\(entry.facts.ip))")
                }
                Text(decision.reason.prefix(1).uppercased() + decision.reason.dropFirst())
                    .font(.caption).foregroundStyle(decision.verdict == .block ? .red : .secondary)
                Text("\(entry.count)× · last \(entry.lastSeen.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
            Spacer()
            if !entry.facts.patternKey.isEmpty, entry.facts.knownBad.isEmpty {
                let pattern = entry.facts.patternKey.split(separator: "|").last.map(String.init) ?? ""
                Button("Allow") { signatures.set(.safe, keys: [entry.facts.patternKey], note: "allowed in Firewall") }
                    .help("Mark Safe: \(entry.name) → \(pattern)")
                Button("Block") { signatures.set(.suspicious, keys: [entry.facts.patternKey], note: "blocked in Firewall") }
                    .help("Mark Suspicious: \(entry.name) → \(pattern)")
            }
        }
        .controlSize(.small)
        .padding(.vertical, 3)
    }
}
