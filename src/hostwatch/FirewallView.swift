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
            } header: {
                Text("Firewall")
            } footer: {
                Footnote("Watch judges every connection Hostwatch sees the way the firewall will, and lists what it would "
                         + "block or ask about. Nothing is blocked yet: blocking comes with the next stage (a relay in the "
                         + "collector), once Watch shows the rules fit your Mac.")
            }
            if firewall.mode != .off {
                Section {
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
