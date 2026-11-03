import AppKit
import SwiftUI

extension Color {
    /// Claude's warm clay accent, for anything Claude decided or suggested.
    static let claude = Color(red: 0.85, green: 0.47, blue: 0.34)
}

/// "Decided By": regular text with a small mark for who decided (Claude, on-device AI, you, a rule…).
struct DeciderLabel: View {
    let text: String

    private var mark: (symbol: String, color: Color)? {
        if text.contains("Claude") { return ("asterisk", .claude) }
        if text.hasPrefix("AI suggests") { return ("sparkle", .secondary) }
        if text.hasPrefix("AI") { return ("apple.intelligence", .secondary) }
        if text.hasPrefix("You") { return ("person.fill", .secondary) }
        if text.hasPrefix("Rule") { return ("checklist", .secondary) }
        if text.hasPrefix("Baseline") { return ("checkmark.shield", .secondary) }
        if text.hasPrefix("Automatic") { return ("gearshape", .secondary) }
        return nil
    }

    var body: some View {
        HStack(spacing: 4) {
            if let mark {
                Image(systemName: mark.symbol)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(mark.color)
                    .frame(width: 12)
            }
            Text(text).foregroundStyle(text == "New" ? .secondary : .primary).lineLimit(1)
        }
        .help(text)
    }
}

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
                .width(min: 64, ideal: 84, max: 140)
                TableColumn("Decided By", value: \.decidedBy) { item in
                    DeciderLabel(text: item.decidedBy)
                }
                .width(min: 56, ideal: 96, max: 220)
                TableColumn("Kind", value: \.kind) { item in
                    Image(systemName: item.entry.kind.symbol)
                        .foregroundStyle(item.entry.kind.color)
                        .help(item.entry.kind.title)
                }
                .width(min: 20, ideal: 24, max: 32)
                TableColumn("Process", value: \.processName) { item in
                    Text(displayProcessName(item.entry.process)).fontWeight(.semibold).help(item.entry.process)
                }
                .width(min: 60, ideal: 110)
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
                .width(min: 60, ideal: 140)
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
            // Double-click (primaryAction) asks AI; right-click acts on the selection.
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
            if let scope = signatures.scope {
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill").foregroundStyle(.tint)
                    Text("\(scope.title) · \(scope.keys.count) pattern\(scope.keys.count == 1 ? "" : "s")").lineLimit(1)
                    Button { signatures.scope = nil } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .help("Show all patterns")
                }
                .font(.system(size: 12, weight: .medium))
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(Capsule().fill(Color.accentColor.opacity(0.14)))
                .fixedSize()
            } else {
                ShowFilterPicker(filter: $filter, signatures: signatures)
            }
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
            Button { actions.openBaseline() } label: { Label("Needs You…", systemImage: "checklist") }
                .buttonStyle(.glass)
                .help("Rules ▸ Needs You: decide New patterns, with AI suggestions")
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
        Button("Ask AI About This Pattern…") { actions.askAI(entry.exampleEvent) }
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
                .disabled(status == .safe && !SignatureStore.canTrustWholeProcess(entry.process))
            }
        }
        Divider()
        Button("Copy Pattern") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("\(entry.process) → \(entry.pattern)", forType: .string)
        }
        Button("Delete Pattern") { signatures.delete(keys: keys) }
    }
}
