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

    static let placeOptions: [(ProtectionVerdict, String)] = [(.ask, "Ask me"), (.block, "Block")]

    var body: some View {
        let _ = protection.revision
        GlassEffectContainer(spacing: 12) {
            VStack(alignment: .leading, spacing: 22) {
                switch page {
                case .protectedFiles: files
                case .protectionFound:
                    FoundPage(protection: protection, firewall: firewall, connections: connections,
                              markConnection: markConnection, mark: mark)
                default: ProtectionOverview(protection: protection, firewall: firewall, connections: connections, go: go)
                }
            }
        }
    }

    // MARK: Protected files

    private var files: some View {
        VStack(alignment: .leading, spacing: 18) {
            ProtectedFilesHeader(protection: protection, go: go)
            general
            AppFileRulesSection(protection: protection)
        }
    }

    /// Global rules: the places protected for every program, each with the programs expected there and what any other
    /// program meets. One app's own rules are on its card under App rules.
    private var general: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                RuleSections.heading(global: true)
                Spacer()
                Button { addPlaces() } label: { Label("Add Folder or File…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Text("For every program. Each place lists the programs expected there, which always pass. Choose what happens "
                 + "when any other program opens it, Ask me or Block. An app's own rules below win over these.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach(ProtectedGroup.all) { group in card(group) }
            Text("Your folders and files").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary).padding(.top, 8)
            if protection.customPlaces.isEmpty {
                Text("Add a project, a folder of documents or a single file. Only macOS's own programs pass without asking.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(protection.customPlaces) { place in customRow(place) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .globalRulesGlass()
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
                         options: Self.placeOptions, exceptions: .constant(PlaceExceptions()), place: place.name,
                         showsPrograms: false, othersLabel: "Any other program")
                .disabled(!place.on).opacity(place.on ? 1 : 0.5)
                .padding(.leading, 32)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }

    private func card(_ group: ProtectedGroup) -> some View {
        let setting = protection.groups[group.id] ?? ProtectedGroupSetting()
        let hits = protection.findings(group: group.id).reduce(0) { $0 + $1.count }
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
            }), options: Self.placeOptions, exceptions: .constant(PlaceExceptions()), place: group.title,
                showsPrograms: false, othersLabel: "Any other program")
                .disabled(!setting.on).opacity(setting.on ? 1 : 0.5)
                .padding(.leading, 32)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }
}

extension View {
    /// The Protection pages' panel: Liquid Glass, as the Overview's cards, optionally tinted (a warning in orange).
    func protectionGlass(_ radius: CGFloat = 16, tint: Color? = nil) -> some View {
        glassEffect(tint.map { Glass.regular.tint($0) } ?? .regular, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
    }
}

/// Global rules wear a light blue: they apply to every program, a scope, not a status (DESIGN.md ▸ Glass). Blue is the
/// one colour no status uses, fixed rather than the accent, which can be graphite.
enum RuleSections {
    static let global = Color.blue

    /// "Global rules" with its globe, or "App rules": the two sections' headings on the files and firewall pages.
    static func heading(global: Bool) -> some View {
        Label {
            Text(global ? "Global rules" : "App rules").font(.headline)
        } icon: {
            Image(systemName: global ? "globe" : "app.badge.checkmark")
                .foregroundStyle(global ? Self.global : Color.secondary)
        }
    }
}

extension View {
    /// The Global rules section's panel: glass with the scope's light blue.
    func globalRulesGlass() -> some View { protectionGlass(16, tint: RuleSections.global.opacity(0.06)) }
}

/// A place's choices, as a sentence: what any other program meets (Ask me or Block), and the programs you always
/// allow or always block there, added with visible buttons and shown as chips. "Others: Ask" said none of this.
struct PlaceChoices<Choice: Hashable>: View {
    @Binding var others: Choice
    /// The choices for any other program, in order: Ask me and Block for a place, Firewall decides, Allow and Block
    /// for a destination. One component, so folders and destinations read the same.
    let options: [(Choice, String)]
    @Binding var exceptions: PlaceExceptions
    let place: String
    /// False on the Global rules cards: what one app meets lives on that app's own card.
    var showsPrograms = true
    /// Who the choice is for, when not the default ("Every program" without programs).
    var othersLabel: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(othersLabel ?? (showsPrograms ? "Any other program" : "Every program")).font(.callout).foregroundStyle(.secondary)
                Picker("Any other program", selection: $others) {
                    ForEach(options.indices, id: \.self) { i in Text(options[i].1).tag(options[i].0) }
                }
                .labelsHidden().fixedSize().controlSize(.small)
                .help("What happens when a program not in your list below uses \(place)")
                Spacer(minLength: 12)
                if showsPrograms { addProgram }
            }
            if showsPrograms { ExceptionChips(exceptions: $exceptions) }
        }
    }

    private var addProgram: some View {
        // One labelled button, styled like the page's other buttons: an action, not a link (HIG). Blue link text on
        // every card was noise, and a bare + was easy to miss.
        Menu {
            Button("Always Allow a Program…") { ProgramPicker.choose { if !exceptions.allowed.contains($0) { exceptions.allowed.append($0) } } }
            Button("Always Block a Program…") { ProgramPicker.choose { if !exceptions.blocked.contains($0) { exceptions.blocked.append($0) } } }
        } label: {
            Label("Add Program", systemImage: "plus")
        }
        .menuStyle(.button)
        .buttonStyle(.glass)
        .controlSize(.small)
        .fixedSize()
        .help("Always allow, or always block, a program here")
    }
}

/// Choose an app or a command-line program, from /Applications.
@MainActor enum ProgramPicker {
    static func choose(_ add: (String) -> Void) {
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
