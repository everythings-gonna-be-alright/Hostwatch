import AppKit
import SwiftUI

/// Protection ▸ Packages: malicious packages in your projects' lockfiles, the lists they are checked against, and the
/// folders you added. source: docs/adr/0024-package-guard.md
struct PackagesPage: View {
    @ObservedObject var packages: PackageGuard

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            AreaHero(symbol: "shippingbox.fill", title: "Packages", accent: AreaAccent.found,
                     state: AreaState(paused: false, off: !packages.enabled, enforces: false),
                     sentence: sentence, facts: facts) {
                Toggle("Check packages", isOn: $packages.enabled).toggleStyle(.switch).controlSize(.small).labelsHidden()
                    .help("Check your projects for known malicious packages")
                Button { packages.scanNow() } label: { Label("Check Now", systemImage: "arrow.clockwise") }
                    .buttonStyle(.glass).controlSize(.small).disabled(!packages.enabled || !packages.busy.isEmpty)
            } notice: {
                if !packages.busy.isEmpty {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(packages.busy + "…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if !packages.lastError.isEmpty {
                    Label(packages.lastError, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.secondary)
                }
            }
            findings
            lists
            folders
        }
    }

    private var sentence: String {
        guard packages.enabled else { return "Your projects aren't checked for malicious packages." }
        if packages.lists.isEmpty { return "Your projects are checked once the lists for their languages are downloaded." }
        return packages.findings.isEmpty
            ? "No known malicious package in your projects. They are checked again when a lockfile changes or a list grows."
            : "Malicious packages are installed in your projects. Remove or upgrade them, then change any keys this Mac holds."
    }

    private var facts: [StatusFact] {
        let records = packages.lists.values.reduce(0) { $0 + $1.count }
        let updated = packages.lists.values.map(\.updated).max()
        return [
            StatusFact(symbol: "exclamationmark.octagon", title: "Found", value: "\(packages.findings.count)",
                       detail: packages.findings.isEmpty ? "None installed" : "In \(Set(packages.findings.map(\.project)).count) projects"),
            StatusFact(symbol: "folder", title: "Projects", value: "\(packages.projectCount)", detail: "Found by Spotlight and your folders"),
            StatusFact(symbol: "list.bullet.rectangle", title: "Known malicious", value: records.formatted(),
                       detail: updated.map { "Updated \($0.formatted(.relative(presentation: .named)))" } ?? "Not downloaded yet"),
        ]
    }

    // MARK: Found

    private var findings: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Found").font(.headline)
            if packages.findings.isEmpty {
                Text("Nothing found. A package version on the list shows here, and as a story, as soon as it is in a lockfile.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(packages.findings) { f in row(f) }
        }
    }

    private func row(_ f: PackageFinding) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "shippingbox").foregroundStyle(.red).frame(width: 22)
                .accessibilityLabel("Malicious package")
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(f.package.label).font(.body.monospaced()).fontWeight(.medium)
                    Text(f.package.ecosystem.title).font(.caption).foregroundStyle(.secondary)
                }
                Text("In \(f.project), found \(f.found.formatted(.relative(presentation: .named)))")
                    .font(.caption).foregroundStyle(.secondary)
                Text(f.lockfile).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).help(f.lockfile)
            }
            Spacer()
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: f.lockfile)]) }
                .controlSize(.small)
            if let url = f.advisory {
                Button("Advisory") { NSWorkspace.shared.open(url) }.controlSize(.small)
                    .help("What OSV.dev knows about \(f.malwareID)")
            }
            Button("Dismiss") { packages.dismiss(f) }.controlSize(.small)
                .help("Hide it. The same package in this lockfile isn't reported again.")
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .protectionGlass(14)
    }

    // MARK: Lists and folders

    private var lists: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Lists").font(.headline)
            Text("From OSV.dev, fed by the OpenSSF malicious-packages project. A list is downloaded only for the languages "
                 + "your projects use, then updated daily with what changed. Nothing about your projects leaves this Mac.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ForEach(PackageEcosystem.allCases, id: \.self) { eco in
                if let s = packages.lists[eco.osv] {
                    HStack {
                        Text(eco.title)
                        Spacer()
                        Text("\(s.count.formatted()) packages").monospacedDigit().foregroundStyle(.secondary)
                        Text(s.updated.formatted(.relative(presentation: .named))).foregroundStyle(.secondary)
                            .frame(minWidth: 90, alignment: .trailing)
                    }
                    .font(.callout)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(14)
    }

    private var folders: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Your folders").font(.headline)
                Spacer()
                Button { addFolder() } label: { Label("Add Folder…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Text("Spotlight finds most projects. Add folders it doesn't index, such as an external disk.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(packages.folders, id: \.self) { path in
                HStack {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable().frame(width: 18, height: 18)
                    Text(path).lineLimit(1).truncationMode(.middle).help(path)
                    Spacer()
                    Button { packages.removeFolder(path) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless).help("Stop checking \((path as NSString).lastPathComponent)")
                        .accessibilityLabel("Remove \((path as NSString).lastPathComponent)")
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(14)
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Check"
        panel.message = "Choose folders with projects to check"
        if panel.runModal() == .OK { for url in panel.urls { packages.addFolder(url.path) } }
    }
}

/// The Packages row of the Protection sidebar, with a badge while something is found.
struct PackagesSidebarRow: View {
    @ObservedObject var packages: PackageGuard

    var body: some View {
        Label("Packages", systemImage: "shippingbox").badge(packages.findings.count).tag(RulesSegment.packages)
    }
}

struct PackagesRailButton: View {
    @ObservedObject var packages: PackageGuard
    let page: RulesSegment
    let open: (RulesSegment) -> Void

    var body: some View {
        RailButton(symbol: "shippingbox", title: "Packages", badge: packages.findings.count, selected: page == .packages) {
            open(.packages)
        }
    }
}
