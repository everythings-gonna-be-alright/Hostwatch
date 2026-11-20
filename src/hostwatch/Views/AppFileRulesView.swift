import AppKit
import SwiftUI

/// Protected Files and Folders ▸ Apps: one card per app, under General and on the same principle as the firewall's.
/// Its own Every protected place and its own places, which win over General's (ADR 0021).
struct AppFileRulesSection: View {
    @ObservedObject var protection: ProtectionMonitor
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
            Text("Rules for one app (an app covers every program inside it): what it meets in every protected place, and "
                 + "its own places, built-in or any folder or file. They win over General. A place here needs no "
                 + "protection in General.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if protection.appFiles.isEmpty {
                Text("None yet. Add an app to give it its own rules.").font(.callout).foregroundStyle(.secondary)
            }
            ForEach(protection.appFiles) { r in AppFileRulesCard(rules: r, protection: protection, state: state) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    private func add(_ path: String) {
        protection.addAppFiles(path)
        state.open.insert(path)
    }
}

private struct AppFileRulesCard: View {
    let rules: AppFileRules
    @ObservedObject var protection: ProtectionMonitor
    @ObservedObject var state: AppCardsState

    private static let everywhereOptions: [(AppPlaceChoice, String)] =
        [(.decides, "Protection decides"), (.allow, "Allow"), (.block, "Block")]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            AppCardHeader(app: rules.app, name: rules.name, byPath: true, open: state.open, summary: summary,
                          toggle: { if state.open.contains(rules.app) { state.open.remove(rules.app) } else { state.open.insert(rules.app) } },
                          remove: { protection.removeAppFiles(rules.app) })
            if state.open.contains(rules.app) {
                VStack(alignment: .leading, spacing: 8) {
                    everywhere
                    ForEach(rules.places) { p in row(p) }
                    addMenu
                }
                .padding(.leading, 32)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14, tint: rules.everywhere == .block ? Color.red.opacity(0.12) : nil)
    }

    /// "Blocked in every protected place · 2 allowed", when closed.
    private var summary: String {
        var parts: [String] = []
        switch rules.everywhere {
        case .allow: parts.append("Allowed in every protected place")
        case .block: parts.append("Blocked in every protected place")
        case .decides: break
        }
        let blocked = rules.places.filter { $0.verdict == .block }.count
        let allowed = rules.places.count - blocked
        if blocked > 0 { parts.append("\(blocked) blocked") }
        if allowed > 0 { parts.append("\(allowed) allowed") }
        return parts.isEmpty ? "No rules yet: General applies" : parts.joined(separator: " · ")
    }

    // MARK: Every protected place

    private var everywhere: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: "lock.doc.fill").foregroundStyle(.secondary).frame(width: 18)
                Text("Every protected place").font(.callout.weight(.medium))
                Spacer(minLength: 12)
                Picker("Every protected place", selection: Binding(get: { rules.everywhere },
                                                                   set: { c in protection.editAppFiles(rules.app) { $0.everywhere = c } })) {
                    ForEach(Self.everywhereOptions, id: \.0) { Text($0.1).tag($0.0) }
                }
                .labelsHidden().fixedSize().controlSize(.small)
                .help("What \(rules.name) meets in General's places wherever none of its own places decides")
            }
            Text(everywhereText).font(.caption)
                .foregroundStyle(rules.everywhere == .block ? Color.red : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 26)
        }
    }

    private var everywhereText: String {
        switch rules.everywhere {
        case .decides: "General applies: the programs expected there pass, then patterns and each place's choice."
        case .allow: "Allowed in every place General protects, before patterns and each place's choice."
        case .block: "Blocked from every place General protects, even where it's expected, but the places you allow below."
        }
    }

    // MARK: Places

    private func row(_ p: AppPlace) -> some View {
        let set = { (change: @escaping (inout AppPlace) -> Void) in
            protection.editAppFiles(rules.app) { r in
                if let i = r.places.firstIndex(where: { $0.id == p.id }) { change(&r.places[i]) }
            }
        }
        return HStack(spacing: 8) {
            if let g = p.group {
                Image(systemName: g.symbol).foregroundStyle(.secondary).frame(width: 18)
            } else {
                Image(nsImage: NSWorkspace.shared.icon(forFile: p.place)).resizable().frame(width: 18, height: 18)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(p.title).font(.system(size: 12, weight: .medium))
                Text(subtitle(p)).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .help(p.path ?? "")
            }
            Spacer(minLength: 12)
            Picker(p.title, selection: Binding(get: { p.verdict == .allow ? ProtectionVerdict.allow : .block },
                                               set: { v in set { $0.verdict = v } })) {
                Text("Allow").tag(ProtectionVerdict.allow)
                Text("Block").tag(ProtectionVerdict.block)
            }
            .labelsHidden().fixedSize().controlSize(.small)
            .help("What \(rules.name) meets in \(p.title)")
            Toggle("", isOn: Binding(get: { p.on }, set: { on in set { $0.on = on } }))
                .labelsHidden().toggleStyle(.switch).controlSize(.mini)
                .help(p.on ? "Turn this rule off" : "Turn this rule on")
            Button {
                protection.editAppFiles(rules.app) { $0.places.removeAll { $0.id == p.id } }
            } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove \(p.title)")
        }
        .opacity(p.on ? 1 : 0.5)
    }

    private func subtitle(_ p: AppPlace) -> String {
        if let g = p.group { return g.writesOnly ? "Built-in place, changes only" : "Built-in place" }
        let path = AccessRules.display(p.place)
        return p.isFolder ? path + " and everything inside" : path
    }

    /// Allow or Block, then which place: a built-in one, or a folder or file chosen in an Open panel.
    private var addMenu: some View {
        Menu {
            Menu("Allow In") { places(.allow) }
            Menu("Block From") { places(.block) }
        } label: {
            Label("Add Place", systemImage: "plus")
        }
        .menuStyle(.button)
        .buttonStyle(.glass)
        .controlSize(.small)
        .fixedSize()
        .help("Allow or block \(rules.name) in one place")
    }

    @ViewBuilder private func places(_ verdict: ProtectionVerdict) -> some View {
        ForEach(ProtectedGroup.all) { g in
            Button(g.title) { add(AppPlace.group(g.id), isFolder: true, verdict) }
        }
        Divider()
        Button("Folder or File…") {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = true
            panel.allowsMultipleSelection = true
            panel.prompt = verdict == .allow ? "Allow" : "Block"
            panel.message = "Choose folders or files to \(verdict == .allow ? "allow" : "block") \(rules.name) in"
            guard panel.runModal() == .OK else { return }
            for url in panel.urls {
                add(url.standardizedFileURL.resolvingSymlinksInPath().path, isFolder: url.hasDirectoryPath, verdict)
            }
        }
    }

    private func add(_ place: String, isFolder: Bool, _ verdict: ProtectionVerdict) {
        protection.editAppFiles(rules.app) { r in
            r.places.removeAll { $0.place == place }
            r.places.append(AppPlace(place: place, isFolder: isFolder, verdict: verdict))
        }
    }
}
