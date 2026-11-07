import AppKit
import SwiftUI

/// The inspector beside the Patterns table: the selected pattern in full, in plain words and as text, with
/// everything the columns truncate, and the decisions you can make about it. Several selected: what you can do
/// with all of them. Nothing selected: what the inspector is for.
struct PatternInspector: View {
    @ObservedObject var signatures: SignatureStore
    let actions: HUDActions

    private var keys: [String] { signatures.keys(forSelection: signatures.selection) }

    var body: some View {
        let _ = signatures.revision
        let keys = keys
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if keys.count == 1, let entry = signatures.entry(keys[0]) {
                    PatternDetails(entry: entry, signatures: signatures, actions: actions)
                } else if keys.count > 1 {
                    Text("\(keys.count) patterns selected").font(.headline)
                    Text("Mark them all at once, or combine them into one shared pattern from the Mark Selected menu.")
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    MarkButtons { signatures.set($0, keys: keys) }
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Image(systemName: "sidebar.trailing").font(.system(size: 28)).foregroundStyle(.tertiary)
                        Text("Select a pattern").font(.headline)
                        Text("Its full text, what it means in plain words, who decided it and why, and the example "
                             + "it was last seen in. Double-click a row to ask the AI about it.")
                            .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct PatternDetails: View {
    let entry: SignatureEntry
    @ObservedObject var signatures: SignatureStore
    let actions: HUDActions

    private static let absolute: Date.FormatStyle = .dateTime.day().month(.abbreviated).hour().minute()

    var body: some View {
        let status = signatures.status(forKey: entry.id)
        let identity = SigningCache.shared.cached(SignatureStore.subjectPath(entry))
        // What it is, in words.
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: entry.kind.symbol).foregroundStyle(entry.kind.color)
                Text(displayProcessName(entry.process)).font(.headline)
                Spacer()
                StatusPill(status: status)
                if entry.risk == .high { Image(systemName: "flame.fill").foregroundStyle(.red).help("High-risk pattern") }
            }
            Text(RuleText.does(kind: entry.kind, pattern: entry.pattern))
                .font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
        }

        // The pattern itself, whole, selectable.
        section("Pattern") {
            Text(entry.pattern)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Text(entry.process)
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if signatures.isCombined(entry.id) {
                Label("A combined pattern: others were merged into it", systemImage: "arrow.triangle.merge")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }

        // Who decided, and why.
        section("Decision") {
            row("Decided by", signatures.decidedBy(entry.id))
            if let note = entry.note, !note.isEmpty { row("Why", note.replacingOccurrences(of: "⚠︎ ", with: "")) }
            if let reopened = entry.reopened { row("Reopened", reopened) }
            if let s = entry.suggestion {
                row("AI suggests", "\(s.status.title) (\(s.source))" + (s.note.map { ": \($0)" } ?? ""))
            }
            row("Risk", entry.risk == .high ? "high" : entry.risk == .routine ? "routine" : "normal")
            MarkButtons(current: status) { signatures.set($0, keys: [entry.id]) }
        }

        // When and how often.
        section("Seen") {
            row("Count", "\(entry.count.formatted())×")
            row("First", entry.firstSeen.formatted(Self.absolute))
            row("Last", entry.lastSeen.formatted(Self.absolute))
            row("Last example", exampleText)
        }

        // The binary.
        section("Program") {
            if let identity {
                HStack(spacing: 4) {
                    if identity.untrustedCode || identity.valid == false {
                        Image(systemName: "exclamationmark.shield").foregroundStyle(.orange)
                    } else if SigningCache.shared.isTrusted(identity) {
                        Image(systemName: "checkmark.seal").foregroundStyle(.green)
                    }
                    Text(identity.label)
                    if let team = identity.teamID { Text("· \(team)").foregroundStyle(.secondary) }
                }
                .font(.system(size: 12))
                if identity.quarantined { row("Note", "downloaded (quarantined)") }
                if identity.valid == false { row("Note", "signature does not match the binary") }
            } else {
                Text("Signature not inspected yet").font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }

        HStack(spacing: 8) {
            Button { actions.askAI(entry.exampleEvent) } label: { Label("Ask AI…", systemImage: "sparkles") }
                .buttonStyle(.glass)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(entry.process) → \(entry.pattern)", forType: .string)
            } label: { Label("Copy", systemImage: "doc.on.doc") }
                .buttonStyle(.glass)
        }
        .controlSize(.small)
    }

    private var exampleText: String {
        switch entry.kind {
        case .exec: "\(entry.exampleName) (pid \(entry.examplePid)) started \(entry.exampleTarget)"
        case .net: "\(entry.exampleName) (pid \(entry.examplePid)) → \(entry.exampleHost.map { "\($0) " } ?? "")\(entry.exampleTarget)"
        case .file: "\(entry.exampleName) (pid \(entry.examplePid)) \(entry.exampleExtra) \(entry.exampleTarget)"
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary).kerning(0.4)
            content()
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label).foregroundStyle(.secondary).frame(width: 84, alignment: .trailing)
            Text(value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 12))
    }
}

/// Safe / Suspicious / Dangerous, the current one shown as chosen.
private struct MarkButtons: View {
    var current: SignatureStatus? = nil
    let mark: (SignatureStatus) -> Void

    var body: some View {
        HStack(spacing: 6) {
            ForEach([SignatureStatus.safe, .suspicious, .dangerous], id: \.self) { status in
                Button { mark(status) } label: {
                    Label(status.title, systemImage: status.symbol)
                }
                .buttonStyle(.glass)
                .tint(current == status ? Color(nsColor: status.nsColor) : nil)
            }
            if current != nil, current != .unclassified {
                Button("Undo") { mark(.unclassified) }.buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("Back to New")
            }
        }
        .controlSize(.small)
        .padding(.top, 2)
    }
}
