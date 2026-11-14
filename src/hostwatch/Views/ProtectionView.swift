import AppKit
import SwiftUI

/// The Protection rows of the Rules sidebar: Found carries a badge while something would be stopped.
struct ProtectionSidebarRows: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    /// Destinations the firewall would block (or blocks): Found counts them with launches and files.
    var networkStops: () -> Int = { 0 }

    var body: some View {
        let _ = protection.revision
        let stops = protection.findings.values.filter { $0.verdict == .block }.count + networkStops()
        Label("Overview", systemImage: "shield.lefthalf.filled").tag(RulesSegment.protectionOverview)
        Label("Protected Files and Folders", systemImage: "lock.doc").tag(RulesSegment.protectedFiles)
        if let firewall {
            FirewallSidebarRow(firewall: firewall)
        }
        Label("Found", systemImage: "exclamationmark.shield").badge(stops).tag(RulesSegment.protectionFound)
    }
}

/// The firewall's row: a badge for connections waiting for your answer (they need you now).
private struct FirewallSidebarRow: View {
    @ObservedObject var firewall: FirewallMonitor

    var body: some View {
        Label("Network Firewall", systemImage: "network.badge.shield.half.filled")
            .badge(firewall.prompts.count).tag(RulesSegment.firewall)
    }
}

/// Protection: a mode per area, the protected-files cards, and what the rehearsal found, to decide before
/// anything is stopped. source: docs/adr/0011-protection.md
struct ProtectionView: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    /// The firewall's findings, shown in Found with launches and files.
    var connections: () -> [(FirewallEntry, FirewallDecision)] = { [] }
    /// A connection's Allow or Block: through the firewall, which records a pattern the store never saw.
    var markConnection: ((FirewallEntry, SignatureStatus) -> Void)? = nil
    /// Which page of Protection: Overview, Protected Files and Folders, or Found.
    let page: RulesSegment
    /// Marks patterns: Allow (Safe) or Block (Dangerous), as everywhere else.
    let mark: ([String], SignatureStatus) -> Void
    /// Opens another page of the Rules sidebar (the overview's links).
    var go: (RulesSegment) -> Void = { _ in }

    private static let limit = 40
    /// "Show all": a long section opens in full on request (the first 40 keep the page quick).
    @StateObject private var showAll = FoundExpansion()
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; f.dateTimeStyle = .named; return f
    }()

    var body: some View {
        let _ = protection.revision
        GlassEffectContainer(spacing: 12) {
            VStack(alignment: .leading, spacing: 22) {
                switch page {
                case .protectedFiles: files
                case .protectionFound: findings
                default: ProtectionOverview(protection: protection, firewall: firewall, connections: connections, go: go)
                }
            }
        }
    }

    // MARK: Protected files

    private var files: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Protected files and folders").font(.headline)
            Text("Each place lists the programs expected there, which always pass. Choose what happens when any other "
                 + "program opens it, Ask me or Block, and add programs you always allow or always block there. Your "
                 + "choices come before patterns and AI.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(ProtectedGroup.all) { group in card(group) }
            HStack {
                Text("Your folders and files").font(.headline)
                Spacer()
                Button { addPlaces() } label: { Label("Add Folder or File…", systemImage: "plus") }
            }
            .padding(.top, 12)
            if protection.customPlaces.isEmpty {
                Text("Add a project, a folder of documents or a single file. Only macOS's own programs pass without asking.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(protection.customPlaces) { place in customRow(place) }
        }
    }

    /// A standard Open panel: folders and files, several at once.
    private func addPlaces() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Protect"
        panel.message = "Choose folders or files to protect"
        if panel.runModal() == .OK { protection.addPlaces(panel.urls) }
    }

    private func customRow(_ place: CustomPlace) -> some View {
        let hits = protection.findings(group: place.groupID).reduce(0) { $0 + $1.count }
        let binding = { (change: @escaping (inout CustomPlace) -> Void) in
            if let i = protection.customPlaces.firstIndex(where: { $0.id == place.id }) { change(&protection.customPlaces[i]) }
        }
        return VStack(alignment: .leading, spacing: 6) {
        HStack(spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: place.path)).resizable().frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(place.name).fontWeight(.medium)
                Text(place.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .help(place.path)
            }
            Spacer()
            if hits > 0 { Text("\(hits)×").foregroundStyle(.secondary).monospacedDigit().help("Found by the rehearsal") }
            Toggle("", isOn: Binding(get: { place.on }, set: { on in binding { $0.on = on } }))
                .labelsHidden().toggleStyle(.switch).controlSize(.small)
            Button { protection.removePlace(place.id) } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Stop protecting \(place.name)")
        }
            PlaceChoices(others: Binding(get: { place.others }, set: { v in binding { $0.others = v } }),
                         exceptions: Binding(get: { place.exceptions }, set: { e in binding { $0.exceptions = e } }),
                         place: place.name)
                .disabled(!place.on).opacity(place.on ? 1 : 0.5)
                .padding(.leading, 32)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }

    private func card(_ group: ProtectedGroup) -> some View {
        let setting = protection.groups[group.id] ?? ProtectedGroupSetting()
        let hits = protection.findings(group: group.id).reduce(0) { $0 + $1.count }
        let exceptions = Binding(get: { setting.exceptions }, set: { e in
            var s = protection.groups[group.id] ?? ProtectedGroupSetting(); s.exceptions = e; protection.groups[group.id] = s
        })
        return VStack(alignment: .leading, spacing: 6) {
        HStack(spacing: 10) {
            Image(systemName: group.symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.title).fontWeight(.medium)
                Text("Expected: \(group.expected)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if hits > 0 { Text("\(hits)×").foregroundStyle(.secondary).monospacedDigit().help("Found by the rehearsal") }
            Toggle("", isOn: Binding(get: { setting.on }, set: { on in
                var s = protection.groups[group.id] ?? ProtectedGroupSetting(); s.on = on; protection.groups[group.id] = s
            }))
            .labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
            PlaceChoices(others: Binding(get: { setting.others }, set: { v in
                var s = protection.groups[group.id] ?? ProtectedGroupSetting(); s.others = v; protection.groups[group.id] = s
            }), exceptions: exceptions, place: group.title)
                .disabled(!setting.on).opacity(setting.on ? 1 : 0.5)
                .padding(.leading, 32)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }

    // MARK: Findings

    private var findings: some View {
        let all = protection.findings.values.sorted {
            ($0.verdict == .block ? 0 : 1, -$0.count) < ($1.verdict == .block ? 0 : 1, -$1.count)
        }
        let network = connections()
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("What protection found").font(.headline)
                Spacer()
                if !all.isEmpty { forgetMenu(all) }
            }
            if all.isEmpty && network.isEmpty {
                Text("Nothing yet. What would be stopped or asked about appears here, so you can decide first.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Allow marks the pattern Safe. Block marks it Dangerous. Either way it leaves this list. "
                     + "Entries that don't happen again leave by themselves: a question after a week, a stop after a month.")
                    .font(.caption).foregroundStyle(.secondary)
                if !all.isEmpty {
                    Text("Launches and files").font(.subheadline.weight(.semibold)).padding(.top, 4)
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(showAll.files ? all[...] : all.prefix(Self.limit)) { f in finding(f) }
                        if all.count > Self.limit {
                            Button(showAll.files ? "Show fewer" : "Show all \(all.count)") { showAll.files.toggle() }
                                .buttonStyle(.link).font(.caption).padding(.vertical, 6)
                        }
                    }
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .protectionGlass(16)
                }
                // Connections: the firewall's findings, decided the same way.
                if !network.isEmpty {
                    HStack {
                        Text("Connections").font(.subheadline.weight(.semibold))
                        Spacer()
                        if let firewall { ConnectionsForgetMenu(firewall: firewall, found: network) }
                    }
                    .padding(.top, 8)
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(showAll.connections ? network[...] : network.prefix(Self.limit), id: \.0.id) { entry, decision in
                            NetworkFindingRow(entry: entry, decision: decision, mode: firewall?.mode ?? .watch, firewall: firewall) { status in
                                markConnection?(entry, status) ?? mark([entry.facts.patternKey], status)
                            }
                        }
                        if network.count > Self.limit {
                            Button(showAll.connections ? "Show fewer" : "Show all \(network.count)") { showAll.connections.toggle() }
                                .buttonStyle(.link).font(.caption).padding(.vertical, 6)
                        }
                    }
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .protectionGlass(16)
                }
            }
        }
    }

    /// Launches and files: clearing a long list at once (only the entries go, see ForgetMenu).
    private func forgetMenu(_ all: [ProtectionFinding]) -> some View {
        let dayAgo = Date().addingTimeInterval(-86_400)
        return ForgetMenu(questions: all.filter { $0.verdict == .ask }.count, older: all.filter { $0.lastSeen < dayAgo }.count,
                          all: all.count, forgetQuestions: { protection.forget { $0.verdict == .ask } },
                          forgetOlder: { protection.forget { $0.lastSeen < dayAgo } }, forgetAll: { protection.forget { _ in true } },
                          after: "a question after a week, a stop after a month")
    }

    private func finding(_ f: ProtectionFinding) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: ProcessIcons.icon(f.program)).resizable().frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(f.name).fontWeight(.semibold)
                    Text(f.enforced ? "Stopped" : f.verdict == .block ? "Would stop" : "Would ask")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(f.verdict == .block ? Color.red : Color.orange)
                    Text("\(f.count)× · \(Self.relative.localizedString(for: f.lastSeen, relativeTo: Date()))")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Text(f.pattern).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).help(f.pattern)
                Text(f.reason).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Allow") { mark([f.patternKey], .safe) }
            Button("Block") { mark([f.patternKey], .dangerous) }
            Button { protection.forget([f.id]) } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless).help("Remove from this list without deciding")
        }
        .controlSize(.small)
        .padding(.vertical, 4)
    }
}

extension View {
    /// The Protection pages' panel: Liquid Glass, as the Overview's cards, optionally tinted (a warning in orange).
    func protectionGlass(_ radius: CGFloat = 16, tint: Color? = nil) -> some View {
        glassEffect(tint.map { Glass.regular.tint($0) } ?? .regular, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
    }
}

/// Found ▸ Forget: clears a long list at once. Only the entries go: decisions, rules and patterns stay, and anything
/// that happens again comes back. Old entries also leave by themselves (`after` says when).
struct ForgetMenu: View {
    let questions: Int
    let older: Int
    let all: Int
    let forgetQuestions: () -> Void
    let forgetOlder: () -> Void
    let forgetAll: () -> Void
    let after: String

    var body: some View {
        Menu {
            Button("Forget Questions (\(questions))", action: forgetQuestions).disabled(questions == 0)
            Button("Forget Older Than a Day (\(older))", action: forgetOlder).disabled(older == 0)
            Divider()
            Button("Forget All (\(all))", action: forgetAll).disabled(all == 0)
        } label: {
            Label("Forget", systemImage: "eraser")
        }
        .menuStyle(.button)
        .buttonStyle(.glass)
        .controlSize(.small)
        .fixedSize()
        .help("Clear entries from this list. Decisions, rules and patterns stay. What happens again comes back. "
              + "Old entries also leave by themselves: \(after).")
    }
}

/// The firewall's findings, forgotten from the list only (FirewallMonitor.dismiss): what would be blocked or asked.
struct ConnectionsForgetMenu: View {
    @ObservedObject var firewall: FirewallMonitor
    let found: [(FirewallEntry, FirewallDecision)]

    var body: some View {
        let dayAgo = Date().addingTimeInterval(-86_400)
        let questions = found.filter { $0.1.verdict == .ask }.map(\.0.id)
        let older = found.filter { $0.0.lastSeen < dayAgo }.map(\.0.id)
        ForgetMenu(questions: questions.count, older: older.count, all: found.count,
                   forgetQuestions: { firewall.dismiss(questions) }, forgetOlder: { firewall.dismiss(older) },
                   forgetAll: { firewall.dismiss(found.map(\.0.id)) },
                   after: "a connection not seen for a week")
    }
}

/// Which Found sections are open in full (no @State macro with the command line tools).
final class FoundExpansion: ObservableObject {
    @Published var files = false
    @Published var connections = false
}

/// A place's choices, as a sentence: what any other program meets (Ask me or Block), and the programs you always
/// allow or always block there, added with visible buttons and shown as chips. "Others: Ask" said none of this.
struct PlaceChoices: View {
    @Binding var others: ProtectionVerdict
    @Binding var exceptions: PlaceExceptions
    let place: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text("Any other program").font(.callout).foregroundStyle(.secondary)
                Picker("Any other program", selection: $others) {
                    Text("Ask me").tag(ProtectionVerdict.ask)
                    Text("Block").tag(ProtectionVerdict.block)
                }
                .labelsHidden().fixedSize().controlSize(.small)
                .help("What happens when a program not expected in \(place), and not in your list below, opens it")
                Spacer(minLength: 12)
                Button("Allow a Program…") { choose { if !exceptions.allowed.contains($0) { exceptions.allowed.append($0) } } }
                    .help("Always let a program into \(place), without asking")
                Button("Block a Program…") { choose { if !exceptions.blocked.contains($0) { exceptions.blocked.append($0) } } }
                    .help("Always stop a program in \(place)")
            }
            .buttonStyle(.link)
            .controlSize(.small)
            ExceptionChips(exceptions: $exceptions)
        }
    }

    private func choose(_ add: (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.message = "Choose an app, or a command-line program. An app covers every program inside it."
        if panel.runModal() == .OK, let url = panel.url { add(url.standardizedFileURL.path) }
    }
}

/// A place's exceptions as small chips: green always allowed, red always blocked, each removable.
struct ExceptionChips: View {
    @Binding var exceptions: PlaceExceptions

    var body: some View {
        if !exceptions.isEmpty {
            HStack(spacing: 6) {
                ForEach(exceptions.allowed, id: \.self) { p in chip(p, allowed: true) }
                ForEach(exceptions.blocked, id: \.self) { p in chip(p, allowed: false) }
            }
        }
    }

    private func chip(_ program: String, allowed: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: allowed ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(allowed ? Color.green : Color.red)
            Text(PlaceExceptions.name(program)).lineLimit(1)
            Button {
                if allowed { exceptions.allowed.removeAll { $0 == program } } else { exceptions.blocked.removeAll { $0 == program } }
            } label: { Image(systemName: "xmark").font(.system(size: 9, weight: .bold)) }
                .buttonStyle(.plain).foregroundStyle(.secondary)
                .help("Remove: \(allowed ? "no longer always allowed" : "no longer always blocked")")
        }
        .font(.caption)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(Capsule().fill(Color.primary.opacity(0.07)))
        .help("\(allowed ? "Always allowed" : "Always blocked") here: \(program)")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(PlaceExceptions.name(program)), \(allowed ? "always allowed" : "always blocked")")
    }
}
