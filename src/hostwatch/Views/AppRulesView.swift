import AppKit
import SwiftUI

/// Network Firewall ▸ Apps: one card per app, under General and on the same principle. Its own Everywhere and its own
/// destinations, which win over General's (ADR 0020). Collapsed to a summary line, open to change it. A program's
/// blocked connection patterns and destinations asked about again are on its card too: there is no other list.
struct AppRulesSection: View {
    @ObservedObject var firewall: FirewallMonitor
    @ObservedObject var signatures: SignatureStore
    @StateObject private var state = AppCardsState()

    /// Per card: connection patterns marked Suspicious or Dangerous (blocked whatever the domain), newest first.
    private func blockedPatterns() -> [String: [SignatureEntry]] {
        Dictionary(grouping: signatures.allEntries
            .filter { $0.kind == .net && [.suspicious, .dangerous].contains(signatures.status(forKey: $0.id)) }
            .sorted { $0.lastSeen > $1.lastSeen }) { firewall.cardKey(for: SignatureBuilder.programPath($0.process)) }
    }

    var body: some View {
        let _ = signatures.revision
        let patterns = blockedPatterns()
        let again = Dictionary(grouping: firewall.rules) { firewall.cardKey(for: $0.program) }
        // Cards you made first, then programs known only by what you decided in questions.
        let known = Set(firewall.apps.map(\.app))
        let extra = Set(patterns.keys).union(again.keys).subtracting(known)
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }.map { AppRules(app: $0) }
        let cards = firewall.apps + extra
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                RuleSections.heading(global: false)
                Spacer()
                Button { ProgramPicker.choose(add) } label: { Label("Add App…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
                    .help("Rules for one app or command-line program")
            }
            Text("Rules for one app (an app covers every program inside it): what it meets everywhere, its own "
                 + "domains and addresses, and the connections you blocked. They win over Global rules. Always Block and "
                 + "Allow Anyway in a firewall question add the destination here.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if cards.isEmpty {
                Text("None yet. Add an app to give it its own rules.").font(.callout).foregroundStyle(.secondary)
            }
            ForEach(cards) { r in
                AppRulesCard(rules: r, patterns: patterns[r.app] ?? [], again: again[r.app] ?? [],
                             firewall: firewall, signatures: signatures, state: state)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    private func add(_ path: String) {
        firewall.addApp(path)
        state.open.insert(path)
    }
}

/// Which cards are open and what is being typed in each (no @State macro with the command line tools).
final class AppCardsState: ObservableObject {
    @Published var open: Set<String> = []
    @Published var adding: Set<String> = []
    @Published var drafts: [String: String] = [:]
}

private struct AppRulesCard: View {
    let rules: AppRules
    /// Its connection patterns you blocked, and its destinations asked about again.
    let patterns: [SignatureEntry]
    let again: [FirewallMonitor.Rule]
    @ObservedObject var firewall: FirewallMonitor
    let signatures: SignatureStore
    @ObservedObject var state: AppCardsState

    private var isOpen: Bool { state.open.contains(rules.app) }

    private static let everywhereOptions: [(DestinationChoice, String)] =
        [(.firewall, "Firewall decides"), (.allow, "Allow"), (.block, "Block")]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header
            if isOpen {
                VStack(alignment: .leading, spacing: 8) {
                    everywhere
                    ForEach(rules.destinations) { d in row(d) }
                    ForEach(patterns) { e in patternRow(e) }
                    ForEach(again) { r in againRow(r) }
                    addRow
                }
                .padding(.leading, 32)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14, tint: rules.everywhere == .block ? Color.red.opacity(0.12) : nil)
    }

    // MARK: Header

    private var header: some View {
        AppCardHeader(app: rules.app, name: rules.name, byPath: rules.byPath, open: state.open, summary: summary,
                      toggle: { if isOpen { state.open.remove(rules.app) } else { state.open.insert(rules.app) } },
                      remove: remove)
    }

    /// "Blocked everywhere · 2 destinations", when closed.
    private var summary: String {
        var parts: [String] = []
        switch rules.everywhere {
        case .allow: parts.append("Allowed everywhere")
        case .block: parts.append("Blocked everywhere")
        case .firewall: break
        }
        let blocked = rules.destinations.filter { $0.others == .block }.count + patterns.count
        let allowed = rules.destinations.count + patterns.count - blocked
        if blocked > 0 { parts.append("\(blocked) blocked") }
        if allowed > 0 { parts.append("\(allowed) allowed") }
        if !again.isEmpty { parts.append("\(again.count) asked again") }
        return parts.isEmpty ? "No rules yet: Global rules apply" : parts.joined(separator: " · ")
    }

    // MARK: Everywhere

    private var everywhere: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: "globe.americas.fill").foregroundStyle(.secondary).frame(width: 18)
                Text("Everywhere").font(.callout.weight(.medium))
                Spacer(minLength: 12)
                Picker("Everywhere", selection: Binding(get: { rules.everywhere },
                                                       set: { firewall.setEverywhere($0, app: rules.app) })) {
                    ForEach(Self.everywhereOptions, id: \.0) { Text($0.1).tag($0.0) }
                }
                .labelsHidden().fixedSize().controlSize(.small)
                .help("What \(rules.name) meets wherever none of its own destinations decides")
            }
            Text(everywhereText).font(.caption)
                .foregroundStyle(rules.everywhere == .block ? Color.red : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 26)
        }
    }

    private var everywhereText: String {
        switch rules.everywhere {
        case .firewall: return "Global rules apply, then threat lists and patterns."
        case .allow: return "Allowed, also past the global Everywhere Block. Not past a threat list or a global destination you block."
        case .block: return "Every connection is blocked, your network too, but the destinations you allow below."
        }
    }

    // MARK: Destinations

    private func row(_ d: Destination) -> some View {
        let set = { (change: @escaping (inout Destination) -> Void) in
            firewall.editApp(rules.app) { r in
                if let i = r.destinations.firstIndex(where: { $0.id == d.id }) { change(&r.destinations[i]) }
            }
        }
        return HStack(spacing: 8) {
            Image(systemName: d.isIP ? "number" : "globe").foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(d.target).font(.system(size: 12, weight: .medium, design: .monospaced))
                Text(d.isIP ? "This IP address" : "And its subdomains").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            Picker(d.target, selection: Binding(get: { d.others == .allow ? DestinationChoice.allow : .block },
                                                set: { c in set { $0.others = c } })) {
                Text("Allow").tag(DestinationChoice.allow)
                Text("Block").tag(DestinationChoice.block)
            }
            .labelsHidden().fixedSize().controlSize(.small)
            .help("What \(rules.name) meets at \(d.target)")
            Toggle("", isOn: Binding(get: { d.on }, set: { on in set { $0.on = on } }))
                .labelsHidden().toggleStyle(.switch).controlSize(.mini)
                .help(d.on ? "Turn this rule off" : "Turn this rule on")
            Button {
                firewall.editApp(rules.app) { $0.destinations.removeAll { $0.id == d.id } }
            } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove \(d.target)")
        }
        .opacity(d.on ? 1 : 0.5)
    }

    /// The card goes with everything on it: its patterns back to New, its ask-again entries removed.
    private func remove() {
        if !patterns.isEmpty { signatures.set(.unclassified, keys: patterns.map(\.id)) }
        for r in again { firewall.remove(r) }
        firewall.removeApp(rules.app)
    }

    /// A connection pattern you blocked: exact, one port and who did it, so it stays a pattern, not a destination.
    private func patternRow(_ e: SignatureEntry) -> some View {
        let who = SignatureBuilder.who(inProcess: e.process).map { " · via \($0)" } ?? ""
        return HStack(spacing: 8) {
            Image(systemName: "nosign").foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(e.pattern).font(.system(size: 12, weight: .medium, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle).help(e.pattern)
                Text("Blocked connection\(who) · marked \(signatures.status(forKey: e.id).title) by \(signatures.decidedBy(e.id))")
                    .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 12)
            Button("Unblock") { signatures.set(.unclassified, keys: [e.id]) }
                .controlSize(.small).help("Back to New: the firewall asks about it again")
        }
    }

    /// A destination whose decision you forgot: asked about again until you answer.
    private func againRow(_ r: FirewallMonitor.Rule) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "questionmark.circle").foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(r.destination).font(.system(size: 12, weight: .medium, design: .monospaced))
                Text("Asked about again: you forgot your decision here").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            Button("Remove") { firewall.remove(r) }.controlSize(.small).help("Its pattern decides again")
        }
    }

    @ViewBuilder private var addRow: some View {
        if state.adding.contains(rules.app) {
            let text = state.drafts[rules.app] ?? ""
            let problem = text.isEmpty ? nil : Destinations.refusal(text)
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    TextField("example.com or 203.0.113.9",
                              text: Binding(get: { state.drafts[rules.app] ?? "" }, set: { state.drafts[rules.app] = $0 }))
                        .textFieldStyle(.roundedBorder).font(.system(size: 12, design: .monospaced))
                        .onSubmit { add(.block) }
                    Button("Cancel") { close() }.controlSize(.small)
                    Button("Allow") { add(.allow) }.controlSize(.small)
                        .disabled(text.isEmpty || problem != nil)
                    Button("Block") { add(.block) }.buttonStyle(.glassProminent).controlSize(.small)
                        .disabled(text.isEmpty || problem != nil)
                }
                if let problem { Label(problem, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
            }
        } else {
            Button { state.adding.insert(rules.app) } label: { Label("Add Domain or Address…", systemImage: "plus") }
                .buttonStyle(.glass).controlSize(.small)
        }
    }

    private func add(_ choice: DestinationChoice) {
        let target = (state.drafts[rules.app] ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        guard Destinations.refusal(target) == nil else { return }
        firewall.editApp(rules.app) { r in
            r.destinations.removeAll { $0.target == target }
            r.destinations.append(Destination(target: target, others: choice))
        }
        close()
    }

    private func close() {
        state.adding.remove(rules.app)
        state.drafts[rules.app] = nil
    }
}

/// An app card's bar, on the firewall's and the files' pages alike: the whole bar opens and closes the card (a small
/// chevron alone was hard to hit), with the app's icon, name, and a summary closed or where it is open.
struct AppCardHeader: View {
    let app: String
    let name: String
    let byPath: Bool
    let open: Set<String>
    let summary: String
    let toggle: () -> Void
    let remove: () -> Void

    private var isOpen: Bool { open.contains(app) }

    var body: some View {
        HStack(spacing: 10) {
            Button(action: toggle) {
                HStack(spacing: 10) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 90 : 0))
                        .frame(width: 10)
                    icon
                    VStack(alignment: .leading, spacing: 2) {
                        Text(name).font(.system(size: 13, weight: .semibold))
                        Text(isOpen ? where_ : summary).font(.caption).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 8)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(isOpen ? "Hide \(name)'s rules" : "Show \(name)'s rules")
            Button(action: remove) { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove \(name) and its rules")
        }
    }

    @ViewBuilder private var icon: some View {
        if byPath {
            Image(nsImage: ProcessIcons.icon(app)).resizable().frame(width: 22, height: 22)
        } else {
            Image(systemName: "app.dashed").font(.system(size: 17)).foregroundStyle(.secondary).frame(width: 22, height: 22)
        }
    }

    /// Where the app is, or that it's known by name only.
    private var where_: String { byPath ? AccessRules.display(app) : "Every program named \(name)" }
}
