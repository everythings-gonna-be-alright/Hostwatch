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

/// Rules ▸ Protection: a mode per area, the protected-files cards, and what the rehearsal found, to decide before
/// anything is stopped. source: docs/adr/0011-protection.md
struct ProtectionView: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    /// The firewall's findings, shown in Found with launches and files.
    var connections: () -> [(FirewallEntry, FirewallDecision)] = { [] }
    /// Which page of Rules ▸ Protection: Overview, Protected Files and Folders, or Found.
    let page: RulesSegment
    /// Marks patterns: Allow (Safe) or Block (Dangerous), as everywhere else.
    let mark: ([String], SignatureStatus) -> Void
    /// Opens another page of the Rules sidebar (the overview's links).
    var go: (RulesSegment) -> Void = { _ in }

    private static let limit = 40
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; f.dateTimeStyle = .named; return f
    }()

    var body: some View {
        let _ = protection.revision
        VStack(alignment: .leading, spacing: 22) {
            switch page {
            case .protectedFiles: files
            case .protectionFound: findings
            default: ProtectionOverview(protection: protection, firewall: firewall, connections: connections, go: go)
            }
        }
    }

    // MARK: Protected files

    private var files: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Protected files and folders").font(.headline)
            Text("Programs that aren't expected in these places are asked about, or blocked. Allow one by marking its "
                 + "pattern Safe, here or in Patterns.")
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
        return HStack(spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: place.path)).resizable().frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(place.name).fontWeight(.medium)
                Text(place.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .help(place.path)
            }
            Spacer()
            if hits > 0 { Text("\(hits)×").foregroundStyle(.secondary).monospacedDigit().help("Found by the rehearsal") }
            Picker("Others", selection: Binding(get: { place.others }, set: { v in binding { $0.others = v } })) {
                Text("Others: Ask").tag(ProtectionVerdict.ask)
                Text("Others: Block").tag(ProtectionVerdict.block)
            }
            .labelsHidden().fixedSize().disabled(!place.on)
            Toggle("", isOn: Binding(get: { place.on }, set: { on in binding { $0.on = on } }))
                .labelsHidden().toggleStyle(.switch).controlSize(.small)
            Button { protection.removePlace(place.id) } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Stop protecting \(place.name)")
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.quaternary.opacity(0.35)))
    }

    private func card(_ group: ProtectedGroup) -> some View {
        let setting = protection.groups[group.id] ?? ProtectedGroupSetting()
        let hits = protection.findings(group: group.id).reduce(0) { $0 + $1.count }
        return HStack(spacing: 10) {
            Image(systemName: group.symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.title).fontWeight(.medium)
                Text("Expected: \(group.expected)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if hits > 0 { Text("\(hits)×").foregroundStyle(.secondary).monospacedDigit().help("Found by the rehearsal") }
            Picker("Others", selection: Binding(get: { setting.others }, set: { v in
                var s = setting; s.others = v; protection.groups[group.id] = s
            })) {
                Text("Others: Ask").tag(ProtectionVerdict.ask)
                Text("Others: Block").tag(ProtectionVerdict.block)
            }
            .labelsHidden().fixedSize().disabled(!setting.on)
            Toggle("", isOn: Binding(get: { setting.on }, set: { on in
                var s = setting; s.on = on; protection.groups[group.id] = s
            }))
            .labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.quaternary.opacity(0.35)))
    }

    // MARK: Findings

    private var findings: some View {
        let all = protection.findings.values.sorted {
            ($0.verdict == .block ? 0 : 1, -$0.count) < ($1.verdict == .block ? 0 : 1, -$1.count)
        }
        let network = connections()
        return VStack(alignment: .leading, spacing: 8) {
            Text("What protection found").font(.headline)
            if all.isEmpty && network.isEmpty {
                Text("Nothing yet. What would be stopped or asked about appears here, so you can decide first.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Allow marks the pattern Safe. Block marks it Dangerous. Either way it leaves this list.")
                    .font(.caption).foregroundStyle(.secondary)
                if !all.isEmpty {
                    Text("Launches and files").font(.subheadline.weight(.semibold)).padding(.top, 4)
                    ForEach(all.prefix(Self.limit)) { f in finding(f) }
                    if all.count > Self.limit {
                        Text("and \(all.count - Self.limit) more").font(.caption).foregroundStyle(.tertiary)
                    }
                }
                // Connections: the firewall's findings, decided the same way.
                if !network.isEmpty {
                    Text("Connections").font(.subheadline.weight(.semibold)).padding(.top, 8)
                    ForEach(network.prefix(Self.limit), id: \.0.id) { entry, decision in
                        NetworkFindingRow(entry: entry, decision: decision, mode: firewall?.mode ?? .watch) { status in
                            mark([entry.facts.patternKey], status)
                        }
                    }
                    if network.count > Self.limit {
                        Text("and \(network.count - Self.limit) more on the Network Firewall page").font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
        }
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
