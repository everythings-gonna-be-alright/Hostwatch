import AppKit
import SwiftUI

struct StatusPill: View {
    let status: SignatureStatus

    var body: some View {
        // Color carries meaning in the icon, tint and hairline; the label stays in the primary
        // text color so it reads in light and dark mode (colored text on its own tint did not).
        let tint = Color(nsColor: status.nsColor)
        Label {
            Text(status == .unclassified ? "New" : status.title).foregroundStyle(.primary)
        } icon: {
            Image(systemName: status.symbol).foregroundStyle(tint)
        }
        .font(.system(size: 11, weight: .semibold))
        .labelStyle(.titleAndIcon)
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .background(Capsule().fill(tint.opacity(0.16)))
        .overlay(Capsule().strokeBorder(tint.opacity(0.45), lineWidth: 0.5))
        .lineLimit(1)
        .fixedSize()
    }
}

/// "12 dangerous · 3 suspicious · 80 new · 900 safe"
struct PatternTally: View {
    @ObservedObject var signatures: SignatureStore

    var body: some View {
        let _ = signatures.revision
        HStack(spacing: 10) {
            ForEach([SignatureStatus.dangerous, .suspicious, .unclassified, .safe], id: \.self) { status in
                let n = signatures.count(status)
                Label("\(n)", systemImage: status.symbol)
                    .foregroundStyle(n > 0 ? Color(nsColor: status.nsColor) : .secondary)
                    .help("\(n) \(status == .unclassified ? "unclassified" : status.rawValue) patterns")
            }
        }
        .font(.system(size: 11, weight: .medium))
    }
}

struct PatternsView: View {
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    let actions: HUDActions
    @Binding var filter: SignatureFilter

    var body: some View {
        let _ = signatures.revision
        let rows = signatures.patternItems(filter: filter)
        VStack(spacing: 0) {
            toolbar(count: rows.count)
            Divider()
            Table(rows, selection: $signatures.selection, sortOrder: $signatures.patternOrder) {
                TableColumn("Status", value: \.priority) { item in
                    HStack(spacing: 4) {
                        StatusPill(status: item.status)
                        if item.entry.risk == .high {
                            Image(systemName: "flame.fill").foregroundStyle(.red).help("High-risk pattern")
                        }
                    }
                }
                .width(min: 88, ideal: 108, max: 140)
                TableColumn("Kind", value: \.kind) { item in
                    Image(systemName: item.entry.kind.symbol)
                        .foregroundStyle(item.entry.kind.color)
                        .help(item.entry.kind.title)
                }
                .width(min: 20, ideal: 24, max: 32)
                TableColumn("Process", value: \.processName) { item in
                    Text(displayProcessName(item.entry.process)).fontWeight(.semibold).help(item.entry.process)
                }
                .width(min: 90, ideal: 170)
                TableColumn("Pattern", value: \.pattern) { item in
                    Text(item.pattern).truncationMode(.middle).help(item.pattern)
                }
                .width(min: 160, ideal: 360)
                TableColumn("Signer", value: \.signer) { item in
                    let id = SigningCache.shared.cached(SignatureStore.subjectPath(item.entry))
                    HStack(spacing: 4) {
                        if let id, id.untrustedCode || id.valid == false {
                            Image(systemName: "exclamationmark.shield").foregroundStyle(.orange)
                        } else if let id, SigningCache.shared.isTrusted(id) {
                            Image(systemName: "checkmark.seal").foregroundStyle(.green)
                        }
                        Text(item.signer)
                    }
                    .help(id.map { "\($0.label) · Team \($0.teamID ?? "none")"
                        + (SigningCache.shared.isTrusted($0) ? " · trusted" : "") } ?? "not inspected yet")
                }
                .width(min: 70, ideal: 130, max: 220)
                TableColumn("Reason", value: \.reason) { item in
                    Text(item.reason).foregroundStyle(.secondary).help(item.reason)
                }
                .width(min: 80, ideal: 220)
                TableColumn("Count", value: \.count) { item in
                    Text("\(item.count)×").monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(min: 50, ideal: 70, max: 100)
                TableColumn("First Seen", value: \.firstSeen) { item in
                    Text(Self.relative.localizedString(for: item.firstSeen, relativeTo: Date()))
                        .foregroundStyle(.secondary).help(item.firstSeen.formatted())
                }
                .width(min: 70, ideal: 90, max: 130)
                TableColumn("Last Seen", value: \.lastSeen) { item in
                    Text(Self.relative.localizedString(for: item.lastSeen, relativeTo: Date()))
                        .foregroundStyle(.secondary).help(item.lastSeen.formatted())
                }
                .width(min: 70, ideal: 90, max: 130)
            }
            .font(.system(size: 12, design: .monospaced))
            // Double-click (primaryAction) asks Claude; right-click acts on the selection.
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first, let entry = signatures.entry(id) { menu(for: entry) }
            } primaryAction: { ids in
                if let id = ids.first, let entry = signatures.entry(id) { actions.askAI(entry.exampleEvent) }
            }
            Divider()
            HStack {
                Text(classifier.lastMessage.isEmpty
                     ? "Patterns are fingerprints: the same process doing the same kind of thing is one pattern."
                     : classifier.lastMessage)
                    .lineLimit(1)
                Spacer()
                PatternTally(signatures: signatures)
                Text("·")
                Text("\(signatures.selection.count) selected · \(rows.count) shown")
                    .monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    private func toolbar(count: Int) -> some View {
        HStack(spacing: 10) {
            ShowFilterPicker(filter: $filter)
            Menu("Mark Selected") {
                ForEach(SignatureStatus.allCases, id: \.self) { status in
                    Button(status == .unclassified ? "Unclassified" : status.title) {
                        signatures.set(status, keys: Array(signatures.selection))
                    }
                }
                Divider()
                Button("Delete Selected Patterns") { signatures.delete(keys: Array(signatures.selection)) }
            }
            .disabled(signatures.selection.isEmpty)
            .fixedSize()
            Spacer()
            Toggle("Auto-classify new", isOn: $classifier.autoClassify)
                .toggleStyle(.switch)
                .controlSize(.small)
                .help("Every 90 s, triage up to 40 new patterns (seen for over a minute): on-device first, then Claude.")
            if classifier.running {
                ProgressView().controlSize(.small)
                Button("Cancel") { classifier.cancel() }
                    .buttonStyle(.glass)
            } else {
                Button { classifier.classifyNow() } label: {
                    Label("Classify New", systemImage: "sparkles")
                }
                .buttonStyle(.glassProminent)
                    .disabled(signatures.count(.unclassified) == 0)
                    .help("Triage up to \(classifier.batchSize) new patterns: on-device model first (private), "
                          + "then Claude for what it can't settle. Configure in Detection ▸ AI Triage.")
            }
            Button("Trust Baseline…") { confirmBaseline() }
                .buttonStyle(.glass)
                .help("Mark every unclassified pattern as safe: \"this is how my Mac normally behaves\".")
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    /// Trust (or stop trusting) the developer who signed this pattern's binary; re-scores patterns.
    @ViewBuilder
    private func trustMenu(for entry: SignatureEntry) -> some View {
        let cache = SigningCache.shared
        if let id = cache.cached(SignatureStore.subjectPath(entry)), id.signed, !id.adhoc, !id.apple,
           let team = id.teamID {
            let name = id.organization ?? team
            if cache.trustedTeams.contains(team) {
                Button("Stop Trusting Developer “\(name)” (\(team))") {
                    cache.setTrusted(team, false); signatures.reassess()
                }
            } else {
                Button("Trust Developer “\(name)” (\(team))") {
                    cache.setTrusted(team, true); signatures.reassess()
                }
            }
            Divider()
        }
    }

    @ViewBuilder
    private func menu(for entry: SignatureEntry) -> some View {
        // Act on the whole selection when right-clicking inside it.
        let keys = signatures.selection.contains(entry.id) ? Array(signatures.selection) : [entry.id]
        Button("Ask Claude About This Pattern…") { actions.askAI(entry.exampleEvent) }
        Divider()
        trustMenu(for: entry)
        ForEach(SignatureStatus.allCases, id: \.self) { status in
            Button("Mark \(keys.count > 1 ? "\(keys.count) Patterns" : "Pattern") \(status.title)") {
                signatures.set(status, keys: keys)
            }
        }
        Menu("Mark All \(entry.kind.title) From \((entry.process as NSString).lastPathComponent)") {
            ForEach(SignatureStatus.allCases, id: \.self) { status in
                Button(status == .unclassified ? "Clear Rule" : status.title) {
                    signatures.setProcessRule(status, kind: entry.kind, process: entry.process)
                }
            }
        }
        Divider()
        Button("Copy Pattern") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("\(entry.process) → \(entry.pattern)", forType: .string)
        }
        Button("Delete Pattern") { signatures.delete(keys: keys) }
    }

    private func confirmBaseline() {
        let alert = NSAlert()
        alert.messageText = "Trust all \(signatures.count(.unclassified)) unclassified patterns?"
        alert.informativeText = """
        They will be marked Safe and hidden by "Hide Safe". Only do this when you believe the Mac \
        is clean, because anything already running becomes part of the trusted baseline. You can undo \
        it per pattern later.
        """
        alert.addButton(withTitle: "Trust as Baseline")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { _ = signatures.trustBaseline() }
    }
}
