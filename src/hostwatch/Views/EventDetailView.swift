import AppKit
import SwiftUI

/// Events ▸ double-click: the event in a panel under the list, as Running Now shows a process. It follows the
/// selection, so the arrow keys walk through events with their details. Ask AI and the launch chain are buttons here
/// rather than the double-click itself: a new window for every look was heavy.
struct EventDetailPanel: View {
    let event: ActivityEvent
    @ObservedObject var signatures: SignatureStore
    let actions: HUDActions
    let close: () -> Void
    @StateObject private var chain = ChainState()

    private var status: SignatureStatus { signatures.status(for: event) }
    private var path: String { event.kind == .exec ? event.target : event.proc }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    facts
                    subject
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                if let report = chain.report {
                    LaunchChainStrip(report: report).frame(width: 340)
                }
            }
            buttons
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .task(id: event.id) {
            // A short pause first: arrowing through rows shouldn't rebuild a chain for every row passed.
            chain.report = nil
            try? await Task.sleep(for: .milliseconds(250))
            if !Task.isCancelled { chain.report = actions.launchChain(event) }
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: ProcessIcons.icon(path)).resizable().frame(width: 36, height: 36)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(event.name).font(.title3.weight(.semibold))
                    StatusPill(status: status)
                    if event.protection != .none {
                        Label(event.protection == .blocked ? "Stopped" : "Would be stopped", systemImage: "nosign")
                            .font(.caption.weight(.semibold)).foregroundStyle(.red)
                            .help(event.protectionReason)
                    }
                }
                Text(path.isEmpty ? "Path unknown" : path)
                    .font(.callout).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Button(action: close) { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.plain).foregroundStyle(.secondary).help("Close details")
                .keyboardShortcut(.cancelAction)
        }
    }

    private var facts: some View {
        let key = event.signatureKey
        let decided = signatures.decidedBy(key)
        return Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 4) {
            GridRow {
                fact("Kind", event.kind == .exec ? "Launch" : event.kind == .net ? "Connection" : "File access")
                fact("Time", event.ts > 0 ? event.dayTime + String(event.time.dropFirst(8)) : event.time)
                fact("PID", String(event.pid))
                fact("Parent", event.parent.isEmpty ? String(event.ppid)
                     : "\((event.parent as NSString).lastPathComponent) (\(event.ppid))")
            }
            GridRow {
                fact("Signed by", SigningCache.shared.cached(path)?.label ?? "–")
                fact("Decided by", decided.isEmpty ? "Nobody yet" : decided)
                fact("Risk", event.signatureReason.isEmpty ? "\(event.signatureRisk)".capitalized : event.signatureReason)
                    .gridCellColumns(2)
            }
        }
    }

    /// What the event is about, in its kind's terms, with the pattern it's decided by.
    private var subject: some View {
        VStack(alignment: .leading, spacing: 6) {
            switch event.kind {
            case .exec:
                block(event.args.isEmpty ? event.target : event.args)
            case .net:
                let host = event.host.isEmpty ? (event.remoteHost ?? "?") : event.host
                block("\(event.extra) \(host):\(event.remotePort)" + (event.host.isEmpty ? "" : "  [\(event.remoteHost ?? "")]"))
                let signals = [event.newDomain.isEmpty ? nil : "first contact with \(event.newDomain)",
                               event.beacon.isEmpty ? nil : "beacon: \(event.beacon)",
                               event.rawIP ? "raw IP on an unusual port" : nil,
                               event.knownBad.isEmpty ? nil : event.knownBad].compactMap { $0 }
                if !signals.isEmpty { Text(signals.joined(separator: " · ")).font(.caption).foregroundStyle(.orange) }
            case .file:
                block("\(FileModeIcon.title(event.extra)) \(event.target)")
            }
            HStack(spacing: 6) {
                Text("Pattern").font(.caption).foregroundStyle(.secondary)
                Text(event.signaturePattern).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(event.signaturePattern)
            }
        }
    }

    private var buttons: some View {
        HStack(spacing: 8) {
            Button { actions.askAI(event) } label: { Label("Ask AI…", systemImage: "sparkles") }
                .buttonStyle(.glassProminent)
            Button { actions.showLaunchChain(event) } label: { Label("Launch Chain…", systemImage: "point.3.connected.trianglepath.dotted") }
            Button { actions.watch(event) } label: { Label("Watch Closely…", systemImage: "eye") }
            Button { NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") } label: {
                Label("Reveal in Finder", systemImage: "folder")
            }
            .disabled(path.isEmpty)
            Spacer()
            Menu {
                ForEach([SignatureStatus.safe, .suspicious, .dangerous, .unclassified], id: \.self) { s in
                    Button(s == .unclassified ? "New (Undecided)" : s.title) {
                        signatures.set(s, keys: [event.signatureKey], note: "marked in Events")
                    }
                }
            } label: { Label("Mark", systemImage: "checkmark.shield") }
            .fixedSize()
        }
        .controlSize(.small)
    }

    private func block(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11, design: .monospaced))
            .textSelection(.enabled)
            .lineLimit(3)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
    }

    private func fact(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit()).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                .help(value)
        }
    }
}

/// The launch chain, built a moment after the selection settles (no @State macro with the command line tools).
private final class ChainState: ObservableObject {
    @Published var report: LaunchChainReport?
}
