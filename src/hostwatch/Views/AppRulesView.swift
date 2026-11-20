import AppKit
import SwiftUI

/// Network Firewall ▸ Apps: one card per app, under General and on the same principle. Its own Everywhere and its own
/// destinations, which win over General's (ADR 0020). Collapsed to a summary line, open to change it.
struct AppRulesSection: View {
    @ObservedObject var firewall: FirewallMonitor
    @StateObject private var state = AppCardsState()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Apps").font(.headline)
                Spacer()
                Button { ProgramPicker.choose(add) } label: { Label("Add App…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
                    .help("Rules for one app or command-line program")
            }
            Text("Rules for one app (an app covers every program inside it): what it meets everywhere, and its own "
                 + "domains and addresses. They win over General. Always Block in a firewall question adds the "
                 + "destination here.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if firewall.apps.isEmpty {
                Text("None yet. Add an app to give it its own rules.").font(.callout).foregroundStyle(.secondary)
            }
            ForEach(firewall.apps) { r in AppRulesCard(rules: r, firewall: firewall, state: state) }
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
    @ObservedObject var firewall: FirewallMonitor
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
                    addRow
                }
                .padding(.leading, 32)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14, tint: rules.everywhere == .block ? Color.red.opacity(0.12) : nil)
    }

    // MARK: Header

    /// The whole bar opens and closes the card: a small chevron alone was hard to hit.
    private var header: some View {
        HStack(spacing: 10) {
            Button {
                if isOpen { state.open.remove(rules.app) } else { state.open.insert(rules.app) }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 90 : 0))
                        .frame(width: 10)
                    icon
                    VStack(alignment: .leading, spacing: 2) {
                        Text(rules.name).font(.system(size: 13, weight: .semibold))
                        Text(isOpen ? where_ : summary).font(.caption).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 8)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(isOpen ? "Hide \(rules.name)'s rules" : "Show \(rules.name)'s rules")
            Button { firewall.removeApp(rules.app) } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove \(rules.name) and its rules")
        }
    }

    @ViewBuilder private var icon: some View {
        if rules.byPath {
            Image(nsImage: ProcessIcons.icon(rules.app)).resizable().frame(width: 22, height: 22)
        } else {
            Image(systemName: "app.dashed").font(.system(size: 17)).foregroundStyle(.secondary).frame(width: 22, height: 22)
        }
    }

    /// Where the app is, or that it's known by name only.
    private var where_: String {
        rules.byPath ? AccessRules.display(rules.app) : "Every program named \(rules.name)"
    }

    /// "Blocked everywhere · 2 destinations", when closed.
    private var summary: String {
        var parts: [String] = []
        switch rules.everywhere {
        case .allow: parts.append("Allowed everywhere")
        case .block: parts.append("Blocked everywhere")
        case .firewall: break
        }
        let blocked = rules.destinations.filter { $0.others == .block }.count
        let allowed = rules.destinations.count - blocked
        if blocked > 0 { parts.append("\(blocked) blocked") }
        if allowed > 0 { parts.append("\(allowed) allowed") }
        return parts.isEmpty ? "No rules yet: General applies" : parts.joined(separator: " · ")
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
        case .firewall: return "General applies, then threat lists and patterns."
        case .allow: return "Allowed, also past General's Everywhere Block. Not past a threat list or a General destination you block."
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
