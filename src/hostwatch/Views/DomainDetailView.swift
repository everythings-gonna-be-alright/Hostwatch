import AppKit
import SwiftUI

struct DomainDetailView: View {
    @ObservedObject var details: DomainDetails
    @ObservedObject var analysis: AIAnalysis
    @ObservedObject var domains: DomainRegistry
    let markKnown: (Bool) -> Void
    let showInTimeline: (Date) -> Void
    var scrollable = true

    /// Live (Mark Known updates it), falling back to the snapshot.
    private var record: DomainRecord { let _ = domains.revision; return domains.records[details.record.domain] ?? details.record }

    var body: some View {
        Group {
            if scrollable { ScrollView { content } } else { content }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { AIAskBar(analysis: analysis) }
        .frame(minWidth: 640, minHeight: 600)
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            riskCard
            AIVerdictCard(analysis: analysis)
            domainCard
            programsCard
            connectionsCard
            AIEvidenceSection(analysis: analysis)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "globe")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(EventKind.net.color)
                .frame(width: 52, height: 52)
                .glassEffect(.regular.tint(EventKind.net.color.opacity(0.25)), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(record.domain).font(.title2.weight(.semibold)).lineLimit(1).textSelection(.enabled)
                    Spacer(minLength: 8)
                    Button(record.known ? "Known" : "Mark Known") { markKnown(!record.known) }
                        .buttonStyle(.glass)
                        .controlSize(.small)
                        .help(record.known ? "Marked known: click to undo" : "You know this domain: it never counts as new")
                }
                Text(summary).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                FlowLayout(spacing: 6) {
                    if record.known { Chip(text: "Known", symbol: "checkmark.circle", color: .green) }
                    else if record.baseline { Chip(text: "Usual", symbol: "house", color: .secondary) }
                    else { Chip(text: "New", symbol: "sparkle", color: .purple) }
                    if details.connections.contains(where: { !$0.beacon.isEmpty }) {
                        Chip(text: "Beaconing", symbol: "dot.radiowaves.right", color: .red)
                    }
                    if details.signers.values.contains(where: \.bad) {
                        Chip(text: "Untrusted program", symbol: "exclamationmark.shield", color: .orange)
                    }
                    Chip(text: "\(record.count) connection\(record.count == 1 ? "" : "s")", symbol: "arrow.left.arrow.right", color: .secondary)
                }
            }
        }
    }

    private var summary: String {
        let programs = record.programs.prefix(3).joined(separator: ", ")
        let first = record.firstSeen.formatted(date: .abbreviated, time: .shortened)
        return "Reached by \(programs.isEmpty ? "unknown programs" : programs)\(record.programs.count > 3 ? " and others" : ""). First seen \(first)."
    }

    // MARK: Risk

    private var riskCard: some View {
        HStack(alignment: .top, spacing: 16) {
            ZStack {
                Circle().stroke(Color.secondary.opacity(0.2), lineWidth: 7)
                Circle().trim(from: 0, to: CGFloat(details.risk.score) / 100)
                    .stroke(RiskScale.color(details.risk.score), style: StrokeStyle(lineWidth: 7, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                VStack(spacing: 0) {
                    Text("\(details.risk.score)").font(.title2.weight(.bold).monospacedDigit())
                    Text(RiskScale.word(details.risk.score)).font(.caption2).foregroundStyle(.secondary)
                }
            }
            .frame(width: 72, height: 72)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Local risk \(details.risk.score) of 100")
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text("Risk score").font(.headline)
                    Text("from what this Mac saw").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if let ai = analysis.aiRisk {
                        Label("AI \(ai)/100", systemImage: "sparkles").font(.caption.weight(.semibold))
                            .foregroundStyle(RiskScale.color(ai))
                    }
                }
                ForEach(details.risk.reasons) { r in
                    HStack(spacing: 6) {
                        Text(r.points > 0 ? "+\(r.points)" : "\(r.points)")
                            .font(.caption.monospacedDigit().weight(.semibold))
                            .foregroundStyle(r.points > 0 ? Color.orange : Color.green)
                            .frame(width: 30, alignment: .trailing)
                        Text(r.text).font(.callout)
                    }
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(RiskScale.color(details.risk.score).opacity(0.08)))
    }

    // MARK: Cards

    private var domainCard: some View {
        Card(title: "Domain", symbol: "globe") {
            Row("Hostnames") { Text(record.hosts.joined(separator: ", ")).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
            Row("Addresses") {
                Text(details.addresses.isEmpty ? "Looking up…" : details.addresses.prefix(6).joined(separator: ", "))
                    .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    .foregroundStyle(details.addresses.isEmpty ? .secondary : .primary)
            }
            Row("First seen") { Text(record.firstSeen.formatted(date: .abbreviated, time: .standard)) }
            Row("Last seen") { Text(record.lastSeen.formatted(date: .abbreviated, time: .standard)) }
            Row("Connections") {
                HStack {
                    Text("\(record.count)")
                    Spacer()
                    Button { showInTimeline(record.firstSeen) } label: { Label("First contact in Time Travel", systemImage: "clock.arrow.circlepath") }
                        .buttonStyle(.borderless)
                }
            }
        }
    }

    @ViewBuilder
    private var programsCard: some View {
        let paths = Array(Set(details.connections.map(\.proc)).filter { !$0.isEmpty }).sorted()
        Card(title: "Programs", symbol: "app.badge") {
            if paths.isEmpty {
                ForEach(record.programs, id: \.self) { name in Row("Program") { Text(name) } }
                if record.programs.isEmpty { Text("No program recorded").foregroundStyle(.secondary) }
            } else {
                ForEach(paths, id: \.self) { path in
                    Row(BaselinePolicy.appName(path)) {
                        VStack(alignment: .leading, spacing: 4) {
                            PathValue(path: path)
                            if let s = details.signers[path] {
                                Chip(text: s.label + (s.trusted ? " · trusted" : ""),
                                     symbol: s.bad ? "exclamationmark.shield" : "checkmark.seal",
                                     color: s.bad ? .orange : (s.trusted ? .green : .secondary))
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var connectionsCard: some View {
        if !details.connections.isEmpty {
            Card(title: "Recent connections", symbol: "clock") {
                ForEach(Array(details.connections.prefix(10).enumerated()), id: \.offset) { _, e in
                    HStack(spacing: 8) {
                        Text(e.clockTime).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Text(e.name).fontWeight(.medium).lineLimit(1).frame(width: 140, alignment: .leading)
                        Text(e.host.isEmpty ? e.target : "\(e.host) [\(e.target)]")
                            .font(.system(size: 11, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                        if !e.beacon.isEmpty { Image(systemName: "dot.radiowaves.right").foregroundStyle(.red).help("beacon \(e.beacon)") }
                    }
                }
                if details.connections.count > 10 {
                    Text("\(details.connections.count - 10) more in the evidence below").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}
