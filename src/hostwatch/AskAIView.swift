import AppKit
import SwiftUI

/// The Ask AI window: what happened (in words and labelled rows), the AI verdict, and the raw
/// evidence the AI gets (collapsed, editable). The ask bar stays at the bottom.
struct AskAIView: View {
    @ObservedObject var analysis: AIAnalysis

    private var event: ActivityEvent { analysis.event }

    /// Off only for rendering previews (scroll views don't render offscreen).
    var scrollable = true

    var body: some View {
        Group {
            if scrollable { ScrollView { content } } else { content }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { AIAskBar(analysis: analysis) }
        .frame(minWidth: 640, minHeight: 620)
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            AIVerdictCard(analysis: analysis)
            switch event.kind {
            case .exec: processCard(title: "Process", symbol: "gearshape.2")
            case .net: connectionCard; processCard(title: "Process", symbol: "gearshape.2")
            case .file: fileCard; processCard(title: "Process", symbol: "gearshape.2")
            }
            lineageCard
            activityCard
            AIEvidenceSection(analysis: analysis)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: event.kind.symbol)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(event.kind.color)
                .frame(width: 52, height: 52)
                .glassEffect(.regular.tint(event.kind.color.opacity(0.25)), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(event.name).font(.title2.weight(.semibold)).lineLimit(1)
                    Text("PID \(event.pid)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    Spacer(minLength: 8)
                    Text(event.time).font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
                Text(summary).font(.body).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                chips
            }
        }
    }

    /// One sentence about what happened, in words.
    private var summary: String {
        switch event.kind {
        case .exec:
            let parent = (event.parent as NSString).lastPathComponent
            return parent.isEmpty ? "Started a new process." : "Started by \(parent)."
        case .net:
            if event.inferred && (event.target.hasPrefix("?") || event.target.isEmpty) {
                return "Made a \(event.extra) connection that closed before its destination could be seen."
            }
            let port = event.target.split(separator: ":").last.map(String.init) ?? "?"
            let place = event.host.isEmpty ? (event.remoteHost ?? event.target) : event.host
            return "Connected to \(place) on port \(port) over \(event.extra)\(event.inferred ? " (inferred)" : "")."
        case .file:
            let name = (event.target as NSString).lastPathComponent
            return "Opened \(name) for \(access.lowercased())."
        }
    }

    private var access: String {
        switch event.extra {
        case "w": return "Writing"
        case "rw": return "Reading and writing"
        default: return "Reading"
        }
    }

    private var chips: some View {
        FlowLayout(spacing: 6) {
            if let status = analysis.patternStatus { StatusPill(status: status) }
            if analysis.patternRisk == .high { Chip(text: "High risk", symbol: "flame.fill", color: .orange) }
            if event.isFirst { Chip(text: "First time", symbol: "sparkle", color: .yellow) }
            if let id = analysis.facts?.signing { signingChip(id) }
            if event.inferred { Chip(text: "Inferred", symbol: "questionmark.circle", color: .secondary) }
            if !event.newDomain.isEmpty { Chip(text: "New domain", symbol: "globe.badge.chevron.backward", color: .purple) }
            if !event.beacon.isEmpty { Chip(text: "Beacon \(event.beacon)", symbol: "dot.radiowaves.right", color: .red) }
            if event.rawIP { Chip(text: "Raw IP", symbol: "number", color: .orange) }
        }
    }

    private func signingChip(_ id: CodeIdentity) -> some View {
        let bad = id.untrustedCode || id.valid == false || id.missing
        return Chip(text: id.label, symbol: bad ? "exclamationmark.shield" : (id.apple ? "apple.logo" : "checkmark.seal"),
                    color: bad ? .orange : (analysis.facts?.trusted == true ? .green : .secondary))
    }

    // MARK: Detail cards

    private var connectionCard: some View {
        Card(title: "Connection", symbol: "network") {
            if event.inferred && (event.target.hasPrefix("?") || event.target.isEmpty) {
                Row("Destination") {
                    Text("Unknown").foregroundStyle(.secondary)
                        .help("The connection closed before Hostwatch could read it; only its traffic was counted.")
                }
            } else {
                Row("Destination") { Text(event.host.isEmpty ? "No hostname" : event.host).textSelection(.enabled) }
                Row("Address") { Mono(event.target) }
                if !event.host.isEmpty {
                    Row("Name from") {
                        Text(event.hostSource == "dns" ? "DNS lookup by this Mac" : "Reverse DNS (may be the provider's name)")
                    }
                }
            }
            Row("Protocol") { Text(event.extra.isEmpty ? "?" : event.extra) }
            if let traffic {
                Row("Traffic") {
                    Label("\(traffic.in) in · \(traffic.out) out", systemImage: "arrow.up.arrow.down")
                }
            }
            if !event.newDomain.isEmpty { Row("New domain") { Text(event.newDomain) } }
            if !event.beacon.isEmpty { Row("Beaconing") { Text("connects \(event.beacon)").foregroundStyle(.red) } }
        }
    }

    /// "53314 B in / 41084 B out" from an inferred connection's note, in readable sizes.
    private var traffic: (in: String, out: String)? {
        let numbers = event.note.matches(of: #/(\d+) B (in|out)/#)
        guard numbers.count == 2, let i = Int64(numbers[0].1), let o = Int64(numbers[1].1) else { return nil }
        let f = { (b: Int64) in ByteCountFormatter.string(fromByteCount: b, countStyle: .file) }
        return (f(i), f(o))
    }

    private var fileCard: some View {
        Card(title: "File", symbol: "doc") {
            Row("Path") { PathValue(path: event.target) }
            Row("Access") {
                Label(access, systemImage: event.extra.contains("w") ? "square.and.pencil" : "eye")
                    .foregroundStyle(event.extra.contains("w") ? .orange : .primary)
            }
            if let f = analysis.facts {
                if !f.fileExists {
                    Row("Now") { Text("No longer exists").foregroundStyle(.secondary) }
                } else {
                    if let size = f.fileSize {
                        Row("Size") { Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file)) }
                    }
                    if let modified = f.fileModified { Row("Modified") { Text(modified.formatted(date: .abbreviated, time: .standard)) } }
                    Row("Quarantine") {
                        Text(f.fileQuarantined ? "Downloaded (quarantined)" : "None")
                            .foregroundStyle(f.fileQuarantined ? .orange : .secondary)
                    }
                }
            }
        }
    }

    private func processCard(title: String, symbol: String) -> some View {
        Card(title: title, symbol: symbol) {
            Row("Name") { Text("\(event.name)  ·  PID \(event.pid)  ·  parent \(event.ppid)").textSelection(.enabled) }
            let exe = analysis.facts?.executable ?? (event.kind == .exec ? event.target : event.proc)
            if !exe.isEmpty { Row("Executable") { PathValue(path: exe) } }
            if let id = analysis.facts?.signing {
                Row("Signed by") {
                    HStack(spacing: 6) {
                        signingChip(id)
                        if let team = id.teamID { Text("Team \(team)").font(.caption).foregroundStyle(.secondary) }
                        if analysis.facts?.trusted == true { Text("trusted").font(.caption).foregroundStyle(.green) }
                    }
                }
            }
            if let f = analysis.facts {
                Row("Running") {
                    Text(f.running ? "Yes · \(f.user) · since \(f.started)" : "No longer running")
                        .foregroundStyle(f.running ? .primary : .secondary)
                }
                if !f.commandLine.isEmpty {
                    Row("Command") {
                        Mono(f.commandLine, lines: 4)
                    }
                }
            } else {
                Row("Details") { ProgressView().controlSize(.small) }
            }
        }
    }

    @ViewBuilder
    private var lineageCard: some View {
        if let lineage = analysis.facts?.lineage, !lineage.isEmpty {
            Card(title: "Started by", symbol: "arrow.triangle.branch") {
                FlowLayout(spacing: 6) {
                    ForEach(lineage) { step in
                        Crumb(name: step.name, pid: step.pid).help(step.path)
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                    }
                    Crumb(name: event.name, pid: event.pid, current: true)
                }
            }
        }
    }

    @ViewBuilder
    private var activityCard: some View {
        let related = analysis.relatedEvents
        if !related.isEmpty {
            Card(title: "Recent activity of this process", symbol: "clock") {
                ForEach(Array(related.prefix(8).enumerated()), id: \.offset) { _, e in
                    HStack(spacing: 8) {
                        Text(e.time).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Image(systemName: e.kind.symbol).foregroundStyle(e.kind.color).frame(width: 16)
                        Text(e.fullDetail).font(.system(size: 11, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    }
                }
                if related.count > 8 {
                    Text("\(related.count - 8) more in the evidence below").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

}

// MARK: - Shared AI pieces (event and domain windows)

/// The AI verdict: a hint before asking, then verdict, confidence, AI risk score and the answer.
struct AIVerdictCard: View {
    @ObservedObject var analysis: AIAnalysis
    

    var body: some View { card }

    @ViewBuilder
    private var card: some View {
        if analysis.answer.isEmpty && analysis.state != .asking && !isFailed {
            HStack(spacing: 10) {
                Image(systemName: "sparkles").foregroundStyle(.secondary)
                Text(analysis.state == .gathering ? "Collecting evidence…"
                     : "No verdict yet. Ask \(analysis.engine == .onDevice ? "the on-device model" : "Claude") (⌘↩) whether this is safe.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Color.secondary.opacity(0.25), style: StrokeStyle(lineWidth: 1, dash: [4, 4])))
        } else {
            let verdict = analysis.verdict ?? .unknown
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Image(systemName: verdictSymbol(verdict)).font(.title2).foregroundStyle(verdict.color)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(analysis.state == .asking && analysis.verdict == nil ? "Analysing…" : verdict.rawValue.capitalized)
                            .font(.title3.weight(.semibold))
                            .foregroundStyle(analysis.verdict == nil ? Color.primary : verdict.color)
                        HStack(spacing: 8) {
                            if let confidence {
                                Text("Confidence: \(confidence)").font(.caption).foregroundStyle(.secondary)
                            }
                            if let risk = analysis.aiRisk {
                                Text("AI risk \(risk)/100").font(.caption.weight(.semibold)).foregroundStyle(RiskScale.color(risk))
                            }
                        }
                    }
                    Spacer()
                    if analysis.state == .asking { ProgressView().controlSize(.small) }
                    Text(analysis.engine == .onDevice ? "On-device" : "Claude")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if case .failed(let message) = analysis.state {
                    Text(message).foregroundStyle(.red).textSelection(.enabled)
                } else if !answerBody.isEmpty {
                    Text(rendered(answerBody))
                        .font(.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(16)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(verdict.color.opacity(analysis.verdict == nil ? 0.05 : 0.10)))
            .overlay(alignment: .leading) {
                UnevenRoundedRectangle(topLeadingRadius: 16, bottomLeadingRadius: 16, style: .continuous)
                    .fill(analysis.verdict == nil ? Color.secondary.opacity(0.4) : verdict.color)
                    .frame(width: 4)
            }
        }
    }

    private var isFailed: Bool { if case .failed = analysis.state { return true }; return false }

    private func verdictSymbol(_ v: Verdict) -> String {
        switch v {
        case .safe: return "checkmark.shield.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .dangerous: return "xmark.octagon.fill"
        case .unknown: return "sparkles"
        }
    }

    /// "CONFIDENCE: high" from the answer.
    private var confidence: String? {
        analysis.answer.split(separator: "\n").first { $0.uppercased().hasPrefix("CONFIDENCE:") }
            .map { $0.dropFirst("CONFIDENCE:".count).trimmingCharacters(in: .whitespaces).lowercased() }
    }

    /// The answer without the VERDICT/CONFIDENCE lines (shown as the badge above).
    private var answerBody: String {
        analysis.answer.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { let u = $0.uppercased(); return !u.hasPrefix("VERDICT:") && !u.hasPrefix("CONFIDENCE:") && !u.hasPrefix("RISK:") }
            .joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func rendered(_ markdown: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: markdown, options: options)) ?? AttributedString(markdown)
    }

}

/// The evidence the AI gets: collapsed, editable, re-collectable.
struct AIEvidenceSection: View {
    @ObservedObject var analysis: AIAnalysis
    

    var body: some View {
        DisclosureGroup(isExpanded: $analysis.showEvidence) {
            VStack(alignment: .leading, spacing: 8) {
                Text(analysis.engine == .onDevice
                     ? "Analysed on this Mac by Apple's on-device model; nothing is sent anywhere."
                     : "Sent to Claude when you ask. Edit anything first; obvious secrets are masked automatically.")
                    .font(.caption).foregroundStyle(.secondary)
                TextEditor(text: $analysis.context)
                    .font(.system(size: 11, design: .monospaced))
                    .autocorrectionDisabled()
                    .frame(minHeight: 200, idealHeight: 260)
                    .scrollContentBackground(.hidden)
                    .padding(6)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.secondary.opacity(0.08)))
                    .disabled(analysis.state == .gathering || analysis.state == .asking)
            }
            .padding(.top, 6)
        } label: {
            HStack {
                Label("Evidence for the AI", systemImage: "doc.text.magnifyingglass").font(.headline)
                Text("\(analysis.context.split(separator: "\n").count) lines").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button { analysis.gather() } label: { Label("Re-collect", systemImage: "arrow.clockwise") }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .disabled(analysis.state == .gathering || analysis.state == .asking)
            }
        }
    }

}

/// The glass bar at the bottom: engine, local files, status, Copy Answer, Ask.
struct AIAskBar: View {
    @ObservedObject var analysis: AIAnalysis
    

    var body: some View {
        HStack(spacing: 10) {
            Picker("Engine", selection: $analysis.engine) {
                Text("Claude").tag(AIEngine.claude)
                Text("On-device").tag(AIEngine.onDevice)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("Claude: strongest analysis, evidence is sent to Anthropic. On-device: Apple's private model, "
                  + "smaller, evidence shortened to fit; nothing leaves the Mac.")
            .disabled(analysis.state == .asking)
            if analysis.engine == .claude {
                Toggle("Read local files", isOn: $analysis.allowFileTools)
                    .help("Off: Claude only sees the evidence. On: it may read files on this Mac, read-only.")
                    .disabled(analysis.state == .asking)
            }
            Text(statusText).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(analysis.answer, forType: .string)
            } label: { Label("Copy Answer", systemImage: "doc.on.doc") }
                .buttonStyle(.glass)
                .disabled(analysis.answer.isEmpty)
            if analysis.state == .asking {
                Button("Cancel") { analysis.cancel() }.buttonStyle(.glass)
            } else {
                Button { analysis.ask() } label: {
                    Label(analysis.answer.isEmpty ? (analysis.engine == .onDevice ? "Ask On-Device" : "Ask Claude") : "Ask Again",
                          systemImage: "sparkles")
                }
                .keyboardShortcut(.return, modifiers: .command)
                .buttonStyle(.glassProminent)
                .disabled(analysis.state == .gathering)
            }
        }
        .controlSize(.large)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .padding(.horizontal, 12)
        .padding(.bottom, 10)
    }

    private var statusText: String {
        switch analysis.state {
        case .gathering: return "Collecting evidence…"
        case .ready: return analysis.answer.isEmpty ? "⌘↩ to ask" : analysis.footer
        case .asking: return analysis.engine == .onDevice ? "Analysing on this Mac…" : "Claude is analysing…"
        case .done: return analysis.footer
        case .failed: return "Failed"
        }
    }
}

/// 0-100 risk: colour and word.
enum RiskScale {
    static func color(_ score: Int) -> Color {
        switch score {
        case ..<25: return .green
        case ..<50: return .yellow
        case ..<75: return .orange
        default: return .red
        }
    }

    static func word(_ score: Int) -> String {
        switch score {
        case ..<25: return "Low"
        case ..<50: return "Medium"
        case ..<75: return "High"
        default: return "Critical"
        }
    }
}

// MARK: - Building blocks

/// A titled group of labelled rows (the macOS inspector look).
struct Card<Content: View>: View {
    let title: String
    let symbol: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: symbol).font(.headline)
            VStack(alignment: .leading, spacing: 8) { content }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.secondary.opacity(0.07)))
    }
}

/// "Label    value", the label column aligned.
struct Row<Value: View>: View {
    let label: String
    @ViewBuilder let value: Value

    init(_ label: String, @ViewBuilder value: () -> Value) {
        self.label = label
        self.value = value()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label).foregroundStyle(.secondary).frame(width: 96, alignment: .trailing)
            value.frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.callout)
    }
}

/// Monospaced, selectable text (paths, addresses, command lines).
struct Mono: View {
    let text: String
    var lines = 1

    init(_ text: String, lines: Int = 1) { self.text = text; self.lines = lines }

    var body: some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .lineLimit(lines)
            .truncationMode(.middle)
            .textSelection(.enabled)
            .help(text)
    }
}

/// A path with Reveal in Finder and Copy.
struct PathValue: View {
    let path: String

    var body: some View {
        HStack(spacing: 6) {
            Mono(path)
            Spacer(minLength: 4)
            Button { NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(.borderless)
            .help("Reveal in Finder")
            .disabled(!FileManager.default.fileExists(atPath: path))
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(path, forType: .string)
            } label: { Image(systemName: "doc.on.doc") }
            .buttonStyle(.borderless)
            .help("Copy path")
        }
    }
}

struct Chip: View {
    let text: String
    let symbol: String
    let color: Color

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.caption.weight(.medium))
            .lineLimit(1)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .foregroundStyle(color)
            .background(Capsule().fill(color.opacity(0.14)))
    }
}

private struct Crumb: View {
    let name: String
    let pid: Int
    var current = false

    var body: some View {
        HStack(spacing: 4) {
            Text(name).fontWeight(current ? .semibold : .regular)
            Text("\(pid)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
        .font(.callout)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(current ? Color.accentColor.opacity(0.18) : Color.secondary.opacity(0.12)))
    }
}

/// Lays children out left to right, wrapping to new lines (chips, the process chain).
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(width: proposal.width ?? .infinity, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrange(width: bounds.width, subviews: subviews)
        for (subview, point) in zip(subviews, result.points) {
            subview.place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> (size: CGSize, points: [CGPoint]) {
        var points: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, lineHeight: CGFloat = 0, maxX: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                x = 0
                y += lineHeight + spacing
                lineHeight = 0
            }
            points.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
            maxX = max(maxX, x - spacing)
        }
        return (CGSize(width: maxX, height: y + lineHeight), points)
    }
}
