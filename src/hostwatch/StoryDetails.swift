import AppKit
import SwiftUI

/// The story window (double-click a story): the whole chain, event by event, on a vertical timeline,
/// indented by process lineage. *Suspicious steps* shows what made it a story; *All activity* adds
/// everything else those processes did in that time (from history), dimmed, so the chain reads in context.
@MainActor
final class StoryDetails: ObservableObject {
    let story: Story
    @Published var showAll = false
    @Published private(set) var context: [ActivityEvent] = []
    @Published private(set) var loading = false
    @Published private(set) var loaded = false
    private let historyDirectory: URL
    private let live: [ActivityEvent]

    init(story: Story, historyDirectory: URL, live: [ActivityEvent]) {
        self.story = story
        self.historyDirectory = historyDirectory
        self.live = live
    }

    /// Processes in the chain.
    var pids: Set<Int> { Set(story.steps.map(\.pid)) }

    /// pid → parent pid, from the steps and the context's launches.
    var parents: [Int: Int] {
        // Launches say who the parent is; other events' ppid may be missing (1) or stale.
        var map: [Int: Int] = [:]
        for s in story.steps where s.kind == .exec && s.ppid > 0 { map[s.pid] = s.ppid }
        for e in context where e.kind == .exec && e.ppid > 0 && map[e.pid] == nil { map[e.pid] = e.ppid }
        for s in story.steps where s.ppid > 1 && map[s.pid] == nil { map[s.pid] = s.ppid }
        return map
    }

    /// How many of the chain's processes are above this one (for indenting), at most 5.
    func depth(_ pid: Int) -> Int {
        let parents = self.parents, inChain = pids
        var d = 0, current = pid, seen: Set<Int> = [pid]
        while let p = parents[current], inChain.contains(p), !seen.contains(p), d < 5 {
            d += 1; seen.insert(p); current = p
        }
        return d
    }

    enum Item: Identifiable {
        case step(StoryStep)
        case event(ActivityEvent)

        var id: String {
            switch self {
            case .step(let s): return "s" + s.id.uuidString
            case .event(let e): return "e" + e.id.uuidString
            }
        }
        var time: String {
            switch self { case .step(let s): return s.time; case .event(let e): return e.time }
        }
        var pid: Int {
            switch self { case .step(let s): return s.pid; case .event(let e): return e.pid }
        }
    }

    /// The timeline: steps only, or steps merged with the processes' other events (oldest first).
    var items: [Item] {
        let steps = story.steps.map(Item.step)
        guard showAll else { return steps }
        let stepKeys = Set(story.steps.map { "\($0.time)|\($0.pid)|\($0.kind.rawValue)|\($0.target)" })
        let others = context.filter { !stepKeys.contains("\($0.time)|\($0.pid)|\($0.kind.rawValue)|\($0.target)") }
            .map(Item.event)
        // Stable merge by clock time (steps first within the same second).
        return (steps.enumerated().map { (0, $0.offset, $0.element) } + others.enumerated().map { (1, $0.offset, $0.element) })
            .sorted { ($0.2.time, $0.0, $0.1) < ($1.2.time, $1.0, $1.1) }
            .map(\.2)
    }

    /// Everything the chain's processes did from a little before the story to a little after it.
    func loadContext() {
        guard !loaded, !loading else { return }
        loading = true
        let pids = self.pids, dir = historyDirectory
        let from = story.firstSeen.addingTimeInterval(-60), to = story.lastSeen.addingTimeInterval(120)
        let first = story.steps.map(\.time).min() ?? "", last = story.steps.map(\.time).max() ?? ""
        let live = self.live
        Task {
            let fromHistory = await Task.detached(priority: .userInitiated) { () -> [ActivityEvent] in
                let archive = HistoryArchive(directory: dir)
                let (events, _) = archive.events(archive.segments(), from: from, to: to, maxBytes: 30_000_000)
                return events.filter { pids.contains($0.pid) }.reversed()
            }.value
            // History may be off: fall back to what's still in memory, around the story's clock times.
            let events = !fromHistory.isEmpty ? fromHistory
                : live.filter { pids.contains($0.pid) && $0.time >= first && $0.time <= last }.reversed()
            self.context = Array(events.prefix(2_000))
            self.loading = false
            self.loaded = true
        }
    }

    /// Process lineage for the tree card: each process once, in order of appearance.
    var processes: [(pid: Int, name: String, path: String)] {
        var seen = Set<Int>(), out: [(Int, String, String)] = []
        for s in story.steps where !seen.contains(s.pid) {
            seen.insert(s.pid)
            out.append((s.pid, s.name, s.kind == .exec ? s.target : s.proc))
        }
        return out
    }
}

// MARK: - Sentences

enum StoryText {
    static func base(_ path: String) -> String { (path as NSString).lastPathComponent }

    static func short(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    static func mode(_ m: String) -> String {
        m.contains("r") && m.contains("w") ? "read and wrote" : m.contains("w") ? "wrote" : "read"
    }

    /// "zsh started curl", "curl connected to evil.example:443", "python3 read ~/.ssh/id_ed25519".
    static func sentence(kind: EventKind, name: String, parent: String, target: String, extra: String, host: String) -> String {
        switch kind {
        case .exec: return "\(parent.isEmpty ? "?" : base(parent)) started \(base(target))"
        case .net:
            let port = target.split(separator: ":").last.map(String.init) ?? ""
            return "\(name) connected to \(host.isEmpty ? target : "\(host):\(port)")"
        case .file: return "\(name) \(mode(extra)) \(short(target))"
        }
    }

    static func origin(_ story: Story) -> String {
        switch story.origin {
        case .developer: return "Started from your terminal or IDE (\(story.originName))"
        case .app: return "Started by the app \(story.originName)"
        case .background: return "Started in the background (\(story.originName))"
        }
    }

    static func duration(_ story: Story) -> String {
        let s = Int(story.lastSeen.timeIntervalSince(story.firstSeen))
        return s < 60 ? "\(max(s, 1)) s" : s < 3600 ? "\(s / 60) min" : "\(s / 3600) h \(s % 3600 / 60) min"
    }
}

// MARK: - View

struct StoryDetailView: View {
    @ObservedObject var details: StoryDetails
    let actions: HUDActions
    let dismiss: () -> Void
    let ignore: () -> Void

    /// Off only for rendering previews (scroll views don't render offscreen).
    var scrollable = true

    private var story: Story { details.story }

    var body: some View {
        Group {
            if scrollable { ScrollView { page } } else { page }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { bottomBar }
        .frame(minWidth: 680, minHeight: 560)
    }

    private var page: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            timeline
            processCard
        }
        .padding(20)
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: story.severity == .dangerous ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(story.severity.color)
                VStack(alignment: .leading, spacing: 3) {
                    Text(story.title).font(.title2.weight(.semibold)).lineLimit(2).textSelection(.enabled)
                    Text("\(StoryText.origin(story)) · \(story.steps.count) suspicious step\(story.steps.count == 1 ? "" : "s") "
                         + "in \(StoryText.duration(story)) · \(story.firstSeen.formatted(date: .abbreviated, time: .standard))")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                VStack(spacing: 0) {
                    Text("\(story.score)").font(.system(size: 26, weight: .semibold).monospacedDigit())
                        .foregroundStyle(story.severity.color)
                    Text("score").font(.caption).foregroundStyle(.secondary)
                }
                .help("Each distinct stage adds its weight; persistence, credentials and swapped binaries weigh most")
            }
            FlowLayout(spacing: 6) {
                StatusPill(status: story.severity)
                ForEach(story.stages, id: \.self) { stage in
                    Chip(text: stage.title, symbol: stage.symbol,
                         color: stage.isStrong ? story.severity.color : .secondary)
                }
                if story.dismissed { Chip(text: "Dismissed", symbol: "eye.slash", color: .secondary) }
            }
        }
    }

    // MARK: Timeline

    private var timeline: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("The chain, event by event", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
                Spacer()
                Picker("", selection: Binding(get: { details.showAll }, set: { on in
                    details.showAll = on
                    if on { details.loadContext() }
                })) {
                    Text("Suspicious steps").tag(false)
                    Text(details.loaded ? "All activity (\(details.context.count))" : "All activity").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .help("All activity: everything these processes did around the story (from history), dimmed")
            }
            if details.showAll && details.loading {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Reading history…").foregroundStyle(.secondary) }
                    .font(.callout)
            }
            VStack(alignment: .leading, spacing: 0) {
                let items = details.items
                ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                    TimelineRow(item: item, depth: details.depth(item.pid), severity: story.severity,
                                first: i == 0, last: i == items.count - 1, actions: actions)
                }
            }
            Text("Indented by process: a child runs below its parent. Double-click a step to ask AI about it.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.secondary.opacity(0.07)))
    }

    // MARK: Processes

    private var processCard: some View {
        Card(title: "Processes in this chain", symbol: "arrow.triangle.branch") {
            ForEach(details.processes, id: \.pid) { p in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(String(repeating: "    ", count: details.depth(p.pid)) + (details.depth(p.pid) > 0 ? "└ " : ""))
                        .font(.system(.callout, design: .monospaced)).foregroundStyle(.tertiary)
                    Text(p.name).fontWeight(.semibold)
                    Text("\(p.pid)").monospacedDigit().foregroundStyle(.secondary)
                    Text(StoryText.short(p.path)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    Spacer(minLength: 0)
                    if let id = SigningCache.shared.cached(p.path) {
                        Text(id.label).font(.caption)
                            .foregroundStyle(id.untrustedCode || id.valid == false ? Color.orange : Color.secondary)
                    }
                }
                .font(.callout)
            }
        }
    }

    // MARK: Actions

    private var bottomBar: some View {
        HStack(spacing: 8) {
            Button { actions.askStory(story) } label: { Label("Ask AI About This Story", systemImage: "sparkles") }
                .buttonStyle(.glassProminent)
            Button { actions.showInTimeline(story.firstSeen) } label: { Label("Show in Timeline", systemImage: "clock.arrow.circlepath") }
                .buttonStyle(.glass)
            Spacer()
            if !story.dismissed { Button("Dismiss", action: dismiss).buttonStyle(.glass) }
            Button("Always Ignore This Chain", action: ignore).buttonStyle(.glass)
                .help("Never alert again for \(story.originName) with these stages")
        }
        .controlSize(.regular)
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }
}

/// One event on the vertical timeline: time, a dot on the line (stage icon for suspicious steps),
/// a sentence, and the detail (command line, address, path) with why it counts.
private struct TimelineRow: View {
    let item: StoryDetails.Item
    let depth: Int
    let severity: SignatureStatus
    let first: Bool
    let last: Bool
    let actions: HUDActions

    private var isStep: Bool { if case .step = item { return true } else { return false } }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(item.time).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                .frame(width: 58, alignment: .trailing).padding(.top, 3)
            // The line, with a dot (or the stage icon) for this event.
            ZStack(alignment: .top) {
                Rectangle().fill(Color.secondary.opacity(0.25)).frame(width: 2)
                    .padding(.top, first ? 12 : 0).padding(.bottom, last ? nil : 0)
                    .frame(maxHeight: last ? 12 : .infinity, alignment: .top)
                marker.padding(.top, 2)
            }
            .frame(width: 24)
            .frame(maxHeight: .infinity, alignment: .top)
            content
                .padding(.leading, CGFloat(depth) * 18)
                .padding(.bottom, isStep ? 12 : 6)
            Spacer(minLength: 0)
        }
        .fixedSize(horizontal: false, vertical: true)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { actions.askAI(event) }
        .contextMenu {
            Button("Ask AI About This Event…") { actions.askAI(event) }
            if case .step(let s) = item { Button("Show in Timeline") { actions.showInTimeline(s.date) } }
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(item.time)  \(sentence)  \(detail)", forType: .string)
            }
        }
    }

    private var event: ActivityEvent {
        switch item { case .step(let s): return s.event; case .event(let e): return e }
    }

    @ViewBuilder private var marker: some View {
        switch item {
        case .step(let s):
            Image(systemName: s.stage.symbol)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 22, height: 22)
                .background(Circle().fill(s.stage.isStrong ? severity.color : Color.secondary))
        case .event:
            Circle().fill(Color.secondary.opacity(0.5)).frame(width: 7, height: 7).padding(.top, 5)
        }
    }

    private var sentence: String {
        let e = event
        return StoryText.sentence(kind: e.kind, name: e.name, parent: e.parent, target: e.target, extra: e.extra, host: e.host)
    }

    private var detail: String {
        let e = event
        switch e.kind {
        case .exec: return e.args.isEmpty ? StoryText.short(e.target) : e.args
        case .net: return "\(e.extra) \(e.target)"
        case .file: return ""      // the path is already in the sentence
        }
    }

    @ViewBuilder private var content: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if case .step(let s) = item {
                    Text(s.stage.title.uppercased())
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(s.stage.isStrong ? severity.color : .secondary)
                }
                Text(sentence).fontWeight(isStep ? .semibold : .regular)
                Text("pid \(event.pid)").font(.caption).foregroundStyle(.tertiary).monospacedDigit()
            }
            .font(.callout)
            if !detail.isEmpty {
                Text(detail)
                    .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                    .lineLimit(isStep ? 4 : 1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            if case .step(let s) = item, !s.note.isEmpty {
                Label(s.note, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
            }
        }
        .opacity(isStep ? 1 : 0.7)
    }
}
