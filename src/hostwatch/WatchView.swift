import AppKit
import SwiftUI

/// One Watch Closely session in the app: asks the collector to record, receives the profile as it grows, and
/// (once recording ends) explains it with Claude or the on-device model.
@MainActor
final class WatchSession: ObservableObject, Identifiable {
    enum State: Equatable { case starting, recording, done(String), failed(String) }

    let id = UUID().uuidString
    let pid: Int
    let name: String
    let path: String
    @Published private(set) var state: State = .starting
    @Published private(set) var profile: BehaviorProfile?
    @Published private(set) var analysis: AIAnalysis?
    @Published var seconds: Double

    /// Sends {"watch": …} to the collector (wired by the app); false when the collector isn't connected.
    var send: ([String: Any]) -> Bool = { _ in false }

    init(pid: Int, name: String, path: String, seconds: Double = 60) {
        self.pid = pid; self.name = name; self.path = path; self.seconds = seconds
    }

    var isRecording: Bool { state == .starting || state == .recording }

    func start() {
        profile = nil
        analysis = nil
        state = .starting
        if !send(["id": id, "pid": pid, "seconds": seconds]) {
            state = .failed("The collector isn't running. Start it (Activity ▸ Start Collector), then watch again.")
        }
    }

    func stop() { _ = send(["id": id, "stop": true]) }

    /// A message from the collector for this session.
    func receive(_ m: WatchMessage) {
        guard m.id == id else { return }
        if let p = m.profile { profile = p }
        switch m.state {
        case "recording": state = .recording
        case "done":
            state = .done(m.detail)
            prepareAnalysis()
        default: state = .failed(m.detail.isEmpty ? "Recording failed." : m.detail)
        }
    }

    /// The AI's evidence: the final profile, the signature and the parent chain.
    func prepareAnalysis() {
        guard let profile, analysis == nil else { return }
        let path = self.path, pid = self.pid
        let subject = ActivityEvent(kind: .exec, time: "", pid: pid, ppid: profile.processes.first?.ppid ?? 0, name: name,
                                    proc: path, target: path, extra: "", parent: "")
        analysis = AIAnalysis(subject: subject, instructions: WatchAdvice.instructions) {
            let id = SigningCache.shared.identity(path)
            let signer = id.map { "\($0.label)\($0.teamID.map { " (Team \($0))" } ?? "")" } ?? ""
            return profile.evidence(signer: signer, parentChain: WatchSession.parentChain(pid))
        }
    }

    /// "zsh (812) ← Terminal (640) ← launchd (1)", while they're running.
    nonisolated static func parentChain(_ pid: Int) -> String {
        var chain: [String] = []
        var p = ProcessList.parent(pid)
        while p > 0, chain.count < 6 {
            chain.append("\(Agent.base(ProcessList.path(p)).isEmpty ? "?" : Agent.base(ProcessList.path(p))) (\(p))")
            if p == 1 { break }
            p = ProcessList.parent(p)
        }
        return chain.joined(separator: " ← ")
    }
}

/// The Watch Closely window: what the process did, in plain words, with highlights first; then Claude's or the
/// on-device model's explanation.
struct WatchView: View {
    @ObservedObject var session: WatchSession
    /// Off only for rendering previews (scroll views don't render offscreen).
    var scrollable = true

    var body: some View {
        Group {
            if scrollable { ScrollView { content } } else { content }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let analysis = session.analysis { AIAskBar(analysis: analysis) }
        }
        .frame(minWidth: 680, minHeight: 640)
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            if case .failed(let message) = session.state {
                Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            if let analysis = session.analysis {
                AIVerdictCard(analysis: analysis)
            } else if session.isRecording {
                placeholder
            }
            if let p = session.profile {
                highlights(p)
                summary(p)
                details(p)
            }
            if let analysis = session.analysis { AIEvidenceSection(analysis: analysis) }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: session.path))
                .resizable().frame(width: 52, height: 52)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(session.name).font(.title2.weight(.semibold)).lineLimit(1)
                    Text("PID \(session.pid)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    Spacer(minLength: 8)
                    controls
                }
                Mono(session.path)
                status
            }
        }
    }

    @ViewBuilder private var controls: some View {
        if session.isRecording {
            Button { session.stop() } label: { Label("Stop", systemImage: "stop.fill") }
                .buttonStyle(.glass)
                .help("Stop recording now and analyse what was recorded")
        } else {
            Menu {
                ForEach([30.0, 60, 120, 300], id: \.self) { s in
                    Button(Self.duration(s)) { session.seconds = s; session.start() }
                }
            } label: {
                Label("Watch Again", systemImage: "record.circle")
            }
            .menuStyle(.button)
            .buttonStyle(.glass)
            .fixedSize()
        }
    }

    @ViewBuilder private var status: some View {
        switch session.state {
        case .starting:
            Label("Starting…", systemImage: "hourglass").font(.callout).foregroundStyle(.secondary)
        case .recording:
            let done = session.profile?.seconds ?? 0
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Image(systemName: "record.circle").foregroundStyle(.red).symbolEffect(.pulse)
                    Text("Recording · \(Int(done)) of \(Int(session.seconds)) s · \(session.profile?.events ?? 0) events")
                        .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
                ProgressView(value: min(done, session.seconds), total: session.seconds).frame(maxWidth: 320)
            }
        case .done(let why):
            Label("Recorded \(Int(session.profile?.seconds ?? 0)) s\(why.isEmpty ? "" : ", ended: \(why)")",
                  systemImage: "checkmark.circle").font(.callout).foregroundStyle(.secondary)
        case .failed:
            EmptyView()
        }
    }

    private var placeholder: some View {
        HStack(spacing: 10) {
            Image(systemName: "sparkles").foregroundStyle(.secondary)
            Text("When recording ends, Claude or the on-device model can explain what \(session.name) did. "
                 + "Stop now to analyse what's recorded so far.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .strokeBorder(Color.secondary.opacity(0.25), style: StrokeStyle(lineWidth: 1, dash: [4, 4])))
    }

    // MARK: What stands out

    private func highlights(_ p: BehaviorProfile) -> some View {
        let list = p.highlights()
        return Card(title: "What stands out", symbol: "exclamationmark.bubble") {
            if list.isEmpty {
                Text(p.events == 0 ? "Nothing recorded yet." : "Nothing unusual so far.").foregroundStyle(.secondary)
            }
            ForEach(list) { h in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: Self.symbol(h.level)).foregroundStyle(Self.color(h.level)).frame(width: 16)
                    Text(h.text).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
                .font(.callout)
            }
        }
    }

    private func summary(_ p: BehaviorProfile) -> some View {
        let written = p.files.values.filter { $0.ops.contains { ["write", "create", "read/write", "truncate"].contains($0) } }.count
        let deleted = p.files.values.filter { $0.ops.contains("delete") }.count
        return FlowLayout(spacing: 8) {
            Chip(text: "\(p.processes.count) process\(p.processes.count == 1 ? "" : "es")", symbol: "gearshape.2", color: .blue)
            Chip(text: "\(p.files.count) file\(p.files.count == 1 ? "" : "s") · \(written) changed · \(deleted) deleted", symbol: "doc", color: .teal)
            Chip(text: "\(p.network.count) destination\(p.network.count == 1 ? "" : "s")", symbol: "network", color: .green)
            if !p.targets.isEmpty { Chip(text: "\(p.targets.count) other process\(p.targets.count == 1 ? "" : "es")", symbol: "arrow.triangle.branch", color: .orange) }
            if !p.ipc.isEmpty { Chip(text: "\(p.ipc.count) service\(p.ipc.count == 1 ? "" : "s")", symbol: "point.3.connected.trianglepath.dotted", color: .purple) }
            Chip(text: "\(p.events) events", symbol: "waveform.path.ecg", color: .secondary)
        }
    }

    // MARK: Details

    @ViewBuilder private func details(_ p: BehaviorProfile) -> some View {
        if p.processes.count > 1 || !(p.processes.first?.args.isEmpty ?? true) {
            Card(title: "Processes", symbol: "gearshape.2") {
                ForEach(Array(Self.ordered(p.processes).enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(String(repeating: "   ", count: item.depth) + (item.depth > 0 ? "↳ " : ""))
                            .font(.system(size: 12, design: .monospaced)).foregroundStyle(.tertiary)
                        Text(Agent.base(item.proc.path).isEmpty ? "?" : Agent.base(item.proc.path)).fontWeight(.semibold)
                        Text("\(item.proc.pid)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        if item.proc.exited { Text("exited").font(.caption).foregroundStyle(.tertiary) }
                        Mono(item.proc.args)
                    }
                    .font(.callout)
                }
            }
        }
        if !p.network.isEmpty {
            Card(title: "Network (\(p.network.count))", symbol: "network") {
                ForEach(p.network.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.prefix(60), id: \.key) { key, n in
                    HStack { Mono(key); Spacer(); if n > 1 { Text("×\(n)").foregroundStyle(.secondary).monospacedDigit() } }
                }
            }
        }
        list("Other processes it acted on", "arrow.triangle.branch",
             p.targets.map { ("\($0.action) \(Agent.base($0.path).isEmpty ? "process" : Agent.base($0.path)) (\($0.pid))", $0.count) })
        list("Persistence", "arrow.clockwise.circle", Self.pairs(p.persistence))
        list("Privileges", "person.badge.key", Self.pairs(p.privileges))
        list("System", "cpu", Self.pairs(p.system))
        list("Services it talked to", "point.3.connected.trianglepath.dotted", Self.pairs(p.ipc))
        if !p.files.isEmpty {
            Card(title: "Files (\(p.files.count)\(p.filesDropped > 0 ? " + \(p.filesDropped) more" : ""))", symbol: "doc.on.doc") {
                ForEach(FileGroup.groups(p.files).prefix(40)) { group in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(group.files.prefix(100), id: \.path) { f in
                                HStack(alignment: .firstTextBaseline, spacing: 6) {
                                    Text(f.name).font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                        .help(f.path)
                                    ForEach(f.use.ops, id: \.self) { op in
                                        Text(op).font(.caption2.weight(.semibold))
                                            .padding(.horizontal, 5).padding(.vertical, 1)
                                            .foregroundStyle(Self.opColor(op))
                                            .background(Capsule().fill(Self.opColor(op).opacity(0.14)))
                                    }
                                    if !f.use.detail.isEmpty { Text(f.use.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                                }
                            }
                            if group.files.count > 100 { Text("… \(group.files.count - 100) more").font(.caption).foregroundStyle(.secondary) }
                        }
                        .padding(.leading, 4)
                    } label: {
                        HStack(spacing: 6) {
                            Mono(group.folder + "/")
                            Text(group.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
            }
        }
        if !p.counts.isEmpty {
            Card(title: "System events", symbol: "waveform.path.ecg") {
                FlowLayout(spacing: 6) {
                    ForEach(p.counts.sorted { $0.value > $1.value }, id: \.key) { key, n in
                        Text("\(key) \(n)").font(.caption.monospacedDigit())
                            .padding(.horizontal, 7).padding(.vertical, 2)
                            .background(Capsule().fill(Color.secondary.opacity(0.12)))
                    }
                }
                if p.execMemory > 0 {
                    Text("Memory made executable \(p.execMemory) time\(p.execMemory == 1 ? "" : "s").").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private func list(_ title: String, _ symbol: String, _ items: [(String, Int)]) -> some View {
        if !items.isEmpty {
            Card(title: title, symbol: symbol) {
                ForEach(items.prefix(60), id: \.0) { text, n in
                    HStack(alignment: .firstTextBaseline) {
                        Text(text.prefix(1).uppercased() + text.dropFirst()).font(.callout).textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        if n > 1 { Text("×\(n)").foregroundStyle(.secondary).monospacedDigit() }
                    }
                }
            }
        }
    }

    // MARK: Helpers

    static func pairs(_ d: [String: Int]) -> [(String, Int)] {
        d.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    /// Processes as a tree: each after its parent, indented.
    static func ordered(_ procs: [BehaviorProfile.Proc]) -> [(proc: BehaviorProfile.Proc, depth: Int)] {
        var out: [(BehaviorProfile.Proc, Int)] = []
        var placed = Set<Int>()
        func walk(_ p: BehaviorProfile.Proc, _ depth: Int) {
            guard !placed.contains(p.pid) else { return }
            placed.insert(p.pid)
            out.append((p, depth))
            for c in procs where c.ppid == p.pid && c.pid != p.pid { walk(c, depth + 1) }
        }
        if let root = procs.first { walk(root, 0) }
        for p in procs where !placed.contains(p.pid) { walk(p, 0) }
        return out
    }

    static func duration(_ s: Double) -> String { s < 60 ? "\(Int(s)) Seconds" : s == 60 ? "1 Minute" : "\(Int(s / 60)) Minutes" }

    static func symbol(_ l: BehaviorHighlight.Level) -> String {
        switch l {
        case .risky: return "exclamationmark.octagon.fill"
        case .notable: return "exclamationmark.triangle.fill"
        case .info: return "info.circle"
        }
    }

    static func color(_ l: BehaviorHighlight.Level) -> Color {
        switch l {
        case .risky: return .red
        case .notable: return .orange
        case .info: return .secondary
        }
    }

    static func opColor(_ op: String) -> Color {
        switch op {
        case "read", "loaded as code": return .secondary
        case "delete", "quarantine removed", "made executable": return .red
        case "rename", "renamed here", "truncate": return .orange
        default: return .blue
        }
    }
}
