import AppKit
import SwiftUI

/// One row of Events ▸ Running Now.
struct RunningRow: Identifiable, Equatable {
    let info: RunningProcessInfo
    let parentName: String
    /// A group row (by parent process or by AI session): the processes under it, and the agent's maker.
    var children: [RunningRow]? = nil
    var groupAgent: CodingAgent? = nil
    var isGroup: Bool { children != nil }
    var id: String { isGroup ? "g:\(info.name)" : "\(info.pid)-\(info.start)" }

    var pid: Int { info.pid }
    var name: String { info.name }
    var started: Date? { info.start > 0 ? Date(timeIntervalSince1970: info.start) : nil }

    // Sort values (computed once, compared as numbers or plain strings).
    let sortName: String
    let sortUser: String
    let sortParent: String
    var cpu: Double { info.cpu ?? -1 }
    var cpuTime: Double { info.cpuTime }
    var mem: Int64 { info.mem }
    var threads: Int { info.threads }
    var written: Int64 { info.written ?? -1 }
    var writeRate: Double { info.writeRate ?? -1 }
    var start: Double { info.start }

    init(info: RunningProcessInfo, parentName: String) {
        self.info = info
        self.parentName = parentName
        sortName = info.name.lowercased()
        sortUser = info.user.lowercased()
        sortParent = parentName.lowercased()
    }

    func matches(_ q: String) -> Bool {
        q.isEmpty || sortName.contains(q) || info.path.lowercased().contains(q) || info.args.lowercased().contains(q)
            || sortUser == q || String(info.pid) == q
    }

    static func rows(_ list: [RunningProcessInfo]) -> [RunningRow] {
        let names = Dictionary(list.map { ($0.pid, $0.name) }, uniquingKeysWith: { a, _ in a })
        return list.map { RunningRow(info: $0, parentName: names[$0.ppid] ?? ($0.ppid == 0 ? "kernel" : "")) }
    }

    /// Grouped: one row per parent process (its children under it), or per AI session (its tree under it, the
    /// rest under "No AI session"). A group's numbers are its members' added up.
    static func grouped(_ rows: [RunningRow], by grouping: EventGrouping, sessions: [EventItem.SessionHeader]) -> [RunningRow] {
        switch grouping {
        case .none: return rows
        case .process:
            var order: [String] = [], byParent: [String: [RunningRow]] = [:]
            for r in rows {
                let key = r.parentName.isEmpty ? "pid \(r.info.ppid)" : r.parentName
                if byParent[key] == nil { order.append(key) }
                byParent[key, default: []].append(r)
            }
            return order.map { group(byParent[$0]!, title: $0, agent: nil) }
        case .session:
            var rest = rows, out: [RunningRow] = []
            for s in sessions {
                let mine = rest.filter { s.pids.contains($0.pid) }
                guard !mine.isEmpty else { continue }
                rest.removeAll { s.pids.contains($0.pid) }
                out.append(group(mine, title: s.topic, agent: s.agent))
            }
            if !rest.isEmpty, !sessions.isEmpty { out.append(group(rest, title: "No AI session", agent: nil)) }
            return out.isEmpty ? rows : out
        }
    }

    private static func group(_ list: [RunningRow], title: String, agent: CodingAgent?) -> RunningRow {
        let cpus = list.compactMap(\.info.cpu), writes = list.compactMap(\.info.written), rates = list.compactMap(\.info.writeRate)
        let info = RunningProcessInfo(
            pid: 0, ppid: 0, start: list.map(\.info.start).filter { $0 > 0 }.min() ?? 0, uid: list.map(\.info.uid).min() ?? 0,
            user: Set(list.map(\.info.user)).count == 1 ? list[0].info.user : "", name: title, path: "", args: "",
            cpu: cpus.isEmpty ? nil : cpus.reduce(0, +), cpuTime: list.reduce(0) { $0 + $1.info.cpuTime },
            mem: list.reduce(0) { $0 + $1.info.mem }, threads: list.reduce(0) { $0 + $1.info.threads },
            written: writes.isEmpty ? nil : writes.reduce(0, +), writeRate: rates.isEmpty ? nil : rates.reduce(0, +))
        var g = RunningRow(info: info, parentName: "")
        g.children = list
        g.groupAgent = agent
        return g
    }
}

/// Every running process, refreshed every 3 s from the collector while the list is open.
@MainActor
final class RunningProcesses: ObservableObject {
    @Published var showing = false { didSet { showing ? start() : stop() } }
    @Published private(set) var rows: [RunningRow] = []
    @Published private(set) var updated: Date?
    /// The Mac's used memory when the list arrived (footprints summed would show 40 GB on an 18 GB Mac).
    @Published private(set) var memoryUsed: Int64 = 0
    let memoryTotal = Int64(ProcessInfo.processInfo.physicalMemory)
    @Published private(set) var unavailable = false        // the collector isn't connected
    @Published var selection: RunningRow.ID?
    /// The selected process's information below the list: opened by double-click (or Show Info), then it follows
    /// the selection until closed. The way to its launch in the timeline is only offered there.
    @Published var showInfo = false
    @Published var sortOrder: [KeyPathComparator<RunningRow>] = [KeyPathComparator(\RunningRow.cpu, order: .reverse)]
    /// When Hostwatch's recorded history begins: a process started before can't be shown at its launch.
    @Published private(set) var recordingStart: Date?
    /// Time Travel: the moment shown (nil: live). The list is then a recorded one and live lists are ignored.
    @Published private(set) var moment: Date?
    /// Time Travel: when the list shown was recorded (the moment is rebuilt from it and the next one).
    @Published private(set) var recordedAt: Date?
    var isRecorded: Bool { moment != nil }

    var request: () -> Bool = { false }
    var historyDirectory: URL?
    static let interval: TimeInterval = 3

    private var timer: Timer?

    var selected: RunningRow? { selection.flatMap { id in rows.first { $0.id == id } } }

    private func start() {
        guard timer == nil else { return }
        ask()
        // A second list soon after the first, so CPU % shows without waiting a whole interval.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in
            guard let self, self.showing else { return }
            self.ask()
        }
        timer = Timer.scheduledTimer(withTimeInterval: Self.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.ask() }
        }
        if let dir = historyDirectory {
            Task { [weak self] in
                let first = await Task.detached(priority: .utility) { HistoryArchive(directory: dir).segments().first?.start }.value
                self?.recordingStart = first
            }
        }
    }

    private func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func ask() {
        guard moment == nil else { return }
        unavailable = !request()
    }

    /// Each process's bytes written in the previous list, for the write rate.
    private var lastWritten: [String: (bytes: Int64, at: Date)] = [:]

    func receive(_ list: [RunningProcessInfo], at now: Date = Date()) {
        guard showing, moment == nil else { return }
        var list = list
        var seen: [String: (bytes: Int64, at: Date)] = [:]
        for i in list.indices {
            guard let w = list[i].written else { continue }
            let key = "\(list[i].pid)-\(list[i].start)"
            if let prev = lastWritten[key], now.timeIntervalSince(prev.at) > 0.5 {
                list[i].writeRate = Double(max(0, w - prev.bytes)) / now.timeIntervalSince(prev.at)
            }
            seen[key] = (w, now)
        }
        lastWritten = seen
        rows = RunningRow.rows(list)
        updated = now
        memoryUsed = Int64(SystemSampler.memoryUsedBytes())
        unavailable = false
    }

    /// Time Travel: the list recorded at or just before `at` (nil: nothing recorded near it).
    func showRecorded(_ snapshot: ProcessHistory.Snapshot?, at: Date) {
        guard showing else { return }
        moment = at
        rows = snapshot.map { RunningRow.rows($0.processes) } ?? []
        updated = snapshot?.at
        recordedAt = snapshot?.recordedAt
        unavailable = false
    }

    /// Back from Time Travel: the next live list replaces the recorded one.
    func showLive() {
        guard moment != nil else { return }
        moment = nil
        rows = []
        updated = nil
        if showing { ask() }
    }

    /// Whether the launch is inside the recorded history.
    func launchRecorded(_ row: RunningRow) -> Bool {
        guard let started = row.started else { return false }
        guard let recordingStart else { return true }
        return started >= recordingStart.addingTimeInterval(-1)
    }
}

// MARK: - Formatting

enum RunningFormat {
    static func duration(_ seconds: TimeInterval) -> String {
        let s = Int(max(0, seconds))
        switch s {
        case ..<60: return "\(s) s"
        case ..<3600: return "\(s / 60) min"
        case ..<86_400: return "\(s / 3600) h \(s % 3600 / 60) min"
        default: return "\(s / 86_400) d \(s % 86_400 / 3600) h"
        }
    }

    /// CPU time as h:mm:ss (like Activity Monitor), with hundredths under a minute.
    static func cpuTime(_ seconds: Double) -> String {
        if seconds < 60 { return String(format: "%.2f s", seconds) }
        let s = Int(seconds)
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
            : String(format: "%d:%02d", s / 60, s % 60)
    }

    static func bytes(_ n: Int64) -> String { ByteCountFormatter.string(fromByteCount: n, countStyle: .memory) }

    static func cpu(_ v: Double?) -> String { v.map { String(format: "%.1f", $0) } ?? "–" }
}

@MainActor
enum ProcessIcons {
    private static var cache: [String: NSImage] = [:]

    /// The app's icon for anything inside an .app bundle, else the file's.
    static func icon(_ path: String) -> NSImage {
        if let hit = cache[path] { return hit }
        var file = path
        if let r = path.range(of: ".app/") { file = String(path[..<r.lowerBound]) + ".app" }
        let image = file.isEmpty ? NSWorkspace.shared.icon(for: .unixExecutable) : NSWorkspace.shared.icon(forFile: file)
        if cache.count > 2000 { cache.removeAll() }
        cache[path] = image
        return image
    }
}

// MARK: - View

struct RunningProcessesView: View {
    @ObservedObject var running: RunningProcesses
    @ObservedObject var signatures: SignatureStore
    let search: String
    /// This session's events: launches recorded in them are marked and can be asked about.
    let history: [ActivityEvent]
    let showSpawn: (RunningRow) -> Void
    let actions: HUDActions
    var grouping = EventGrouping.none
    var sessions: [EventItem.SessionHeader] = []

    var body: some View {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let rows = RunningRow.grouped(running.rows.filter { $0.matches(q) }.sorted(using: running.sortOrder),
                                      by: grouping, sessions: sessions)
        let launches = Dictionary(grouping: history.lazy.filter { $0.kind == .exec }, by: \.pid)
        let launchEvent = { (pid: Int, start: Double) in launches[pid].flatMap { TimeTravel.launch(in: $0, pid: pid, start: start) } }
        VStack(spacing: 0) {
            if running.rows.isEmpty {
                // Fills the space like the table would: otherwise the window's column shrinks to the
                // placeholder's height and floats in the middle.
                placeholder.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                table(rows, launchEvent)
                Divider()
                if running.showInfo, let row = running.selected {
                    detail(row, launchEvent).transition(.move(edge: .bottom).combined(with: .opacity))
                } else {
                    footer(rows)
                }
            }
        }
        .animation(.smooth(duration: 0.2), value: running.showInfo)
    }

    @ViewBuilder private var placeholder: some View {
        if running.isRecorded {
            ContentUnavailableView("No Process List Here", systemImage: "clock.badge.questionmark",
                                   description: Text("Hostwatch records the running processes once a minute while the collector runs and history is on. Nothing was recorded in the 3 minutes before this moment."))
        } else if running.unavailable {
            ContentUnavailableView("Collector Off", systemImage: "bolt.horizontal.circle",
                                   description: Text("Running processes come from the collector. Start it to see them."))
        } else {
            ProgressView("Reading running processes…").frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func table(_ rows: [RunningRow], _ launchEvent: @escaping (Int, Double) -> ActivityEvent?) -> some View {
        let now = running.updated ?? Date()
        return Table(rows, children: \.children, selection: $running.selection, sortOrder: $running.sortOrder) {
            TableColumn("Process", value: \.sortName) { row in
                HStack(spacing: 6) {
                    if row.isGroup {
                        if let agent = row.groupAgent { AgentBadge(agent: agent) }
                        else { Image(systemName: "rectangle.3.group").foregroundStyle(.secondary).frame(width: 16) }
                    } else {
                        Image(nsImage: ProcessIcons.icon(row.info.path)).resizable().frame(width: 16, height: 16)
                    }
                    Text(row.name).fontWeight(.semibold).lineLimit(1)
                    if !row.isGroup, launchEvent(row.pid, row.start) != nil {
                        Image(systemName: "sparkle").font(.system(size: 9)).foregroundStyle(.yellow)
                            .help("Started while Hostwatch was watching: its launch is in the timeline")
                    }
                }
                .help(row.info.path)
            }
            .width(min: 120, ideal: 190)
            TableColumn("PID", value: \.pid) { row in
                Text(row.isGroup ? "\(row.children!.count)×" : String(row.pid)).foregroundStyle(.secondary).monospacedDigit()
                    .help(row.isGroup ? "\(row.children!.count) processes in this group" : "")
            }
            .width(min: 40, ideal: 54, max: 70)
            TableColumn("User", value: \.sortUser) { row in
                Text(row.info.user).foregroundStyle(row.info.uid == 0 ? .orange : .secondary).lineLimit(1)
            }
            .width(min: 50, ideal: 80, max: 120)
            TableColumn("% CPU", value: \.cpu) { row in
                Text(RunningFormat.cpu(row.info.cpu)).monospacedDigit()
                    .foregroundStyle((row.info.cpu ?? 0) >= 50 ? Color.orange : .primary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 48, ideal: 58, max: 70)
            TableColumn("CPU Time", value: \.cpuTime) { row in
                Text(RunningFormat.cpuTime(row.cpuTime)).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 60, ideal: 76, max: 96)
            TableColumn("Memory", value: \.mem) { row in
                Text(RunningFormat.bytes(row.mem)).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 60, ideal: 76, max: 96)
            TableColumn("Threads", value: \.threads) { row in
                Text(String(row.threads)).foregroundStyle(.secondary).monospacedDigit()
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 44, ideal: 54, max: 64)
            TableColumn("Writing", value: \.writeRate) { row in
                let rate = row.info.writeRate
                Text(rate.map { $0 >= 1 ? Rate.text($0) : "0" } ?? "–").monospacedDigit()
                    .foregroundStyle((rate ?? 0) >= 1_000_000 ? Color.orange : (rate ?? 0) >= 1 ? .primary : .secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .help(row.info.written.map { "Writing to disk now: bytes per second over the last refresh (or the minute "
                        + "around the Time Travel moment). \(RunningFormat.bytes($0)) written since it started." }
                        ?? "Not known for this moment: disk writes are recorded from version 0.10 on")
            }
            .width(min: 64, ideal: 84, max: 100)
            TableColumn("Running For", value: \.start) { row in
                Text(row.started.map { RunningFormat.duration(now.timeIntervalSince($0)) } ?? "–")
                    .foregroundStyle(.secondary).monospacedDigit()
                    .help(row.started.map { "Started \($0.formatted(date: .abbreviated, time: .standard))" } ?? "")
            }
            .width(min: 70, ideal: 90, max: 110)
            TableColumn("Parent", value: \.sortParent) { row in
                if !row.isGroup {
                    Text(row.parentName.isEmpty ? String(row.info.ppid) : "\(row.parentName) (\(row.info.ppid))")
                        .foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .width(min: 80, ideal: 140)
        }
        .font(.system(size: 12))
        .contextMenu(forSelectionType: RunningRow.ID.self) { ids in
            if let id = ids.first, let row = running.rows.first(where: { $0.id == id }) { menu(row, launchEvent(row.pid, row.start)) }
            else if let id = ids.first, let group = rows.first(where: { $0.id == id }), group.isGroup {
                Text("\(group.name): \(group.children!.count) processes")
            }
        } primaryAction: { ids in
            guard let id = ids.first else { return }
            running.selection = id
            running.showInfo = true
        }
    }

    @ViewBuilder private func menu(_ row: RunningRow, _ launch: ActivityEvent?) -> some View {
        Button("Show Info") { running.selection = row.id; running.showInfo = true }
        Button("Watch \(row.name) Closely…") { actions.watch(Self.event(for: row)) }
        if let e = launch {
            Button("Ask AI: Is This Dangerous?…") { actions.askAI(e) }
        }
        Divider()
        Button("Reveal in Finder") { NSWorkspace.shared.selectFile(row.info.path, inFileViewerRootedAtPath: "") }
            .disabled(row.info.path.isEmpty)
        Button("Copy Command Line") { copy(row.info.args.isEmpty ? row.info.path : row.info.args) }
        Button("Copy Path") { copy(row.info.path) }.disabled(row.info.path.isEmpty)
        Button("Copy PID") { copy(String(row.pid)) }
    }

    private func footer(_ grouped: [RunningRow]) -> some View {
        let rows = grouped.flatMap { $0.children ?? [$0] }
        let cpu = rows.reduce(0) { $0 + ($1.info.cpu ?? 0) }
        return HStack(spacing: 12) {
            Text("\(rows.count) processes").monospacedDigit()
            Text("CPU \(String(format: "%.0f", cpu))%").monospacedDigit()
            Text("Memory \(RunningFormat.bytes(running.memoryUsed)) of \(RunningFormat.bytes(running.memoryTotal)) used")
                .monospacedDigit()
                .help("Used memory as Activity Monitor counts it: app, wired and compressed. Each row shows the process's own footprint, which includes memory shared with others, so the rows don't add up to this.")
            Spacer()
            Text("Double-click a process for its information")
                .foregroundStyle(.tertiary)
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 14).padding(.vertical, 7)
    }

    // MARK: Detail

    private func detail(_ row: RunningRow, _ launchEvent: (Int, Double) -> ActivityEvent?) -> some View {
        let info = row.info
        let now = running.updated ?? Date()
        let launch = launchEvent(row.pid, row.start)
        let recorded = running.launchRecorded(row)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(nsImage: ProcessIcons.icon(info.path)).resizable().frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(info.name).font(.title3.weight(.semibold))
                        if let launch { StatusPill(status: signatures.status(for: launch)) }
                    }
                    Text(info.path.isEmpty ? "Path unknown" : info.path)
                        .font(.callout).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                }
                Spacer()
                Button { running.showInfo = false } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Close details")
            }
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 4) {
                GridRow {
                    fact("PID", String(info.pid))
                    fact("Parent", row.parentName.isEmpty ? String(info.ppid) : "\(row.parentName) (\(info.ppid))")
                    fact("User", info.user.isEmpty ? "–" : info.user)
                    fact("Threads", String(info.threads))
                }
                GridRow {
                    fact("Started", row.started.map { $0.formatted(date: .abbreviated, time: .standard) } ?? "–")
                    fact("Running for", row.started.map { RunningFormat.duration(now.timeIntervalSince($0)) } ?? "–")
                    fact(running.isRecorded ? "CPU then" : "CPU now", info.cpu.map { String(format: "%.1f%%", $0) } ?? "–")
                    fact("CPU time", RunningFormat.cpuTime(info.cpuTime))
                }
                GridRow {
                    fact("Memory", RunningFormat.bytes(info.mem))
                    fact("Disk written", info.written.map(RunningFormat.bytes) ?? "–")
                    fact(running.isRecorded ? "Writing then" : "Writing now", info.writeRate.map(Rate.text) ?? "–")
                    fact("CPU share", row.started.map { start in
                        let alive = now.timeIntervalSince(start)
                        return alive > 0 ? String(format: "%.1f%% average", 100 * info.cpuTime / alive) : "–"
                    } ?? "–")
                }
            }
            if !info.args.isEmpty {
                Text(info.args)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
            }
            HStack(spacing: 8) {
                Button { showSpawn(row) } label: { Label("Show Spawn in Timeline", systemImage: "clock.arrow.circlepath") }
                    .buttonStyle(.glassProminent)
                    .disabled(!recorded)
                    .help(recorded ? "Open Time Travel at the moment it started, with its launch selected"
                          : "It started before Hostwatch began recording\(running.recordingStart.map { " (\($0.formatted(date: .abbreviated, time: .shortened)))" } ?? "")")
                Button { actions.watch(Self.event(for: row)) } label: { Label("Watch Closely…", systemImage: "eye") }
                if let launch {
                    Button { actions.askAI(launch) } label: { Label("Ask AI…", systemImage: "sparkles") }
                }
                Button { NSWorkspace.shared.selectFile(info.path, inFileViewerRootedAtPath: "") } label: {
                    Label("Reveal in Finder", systemImage: "folder")
                }
                .disabled(info.path.isEmpty)
                Spacer()
                if !recorded {
                    Text("Started before recording began").font(.callout).foregroundStyle(.secondary)
                }
            }
            .controlSize(.small)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    private func fact(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit()).textSelection(.enabled).lineLimit(1)
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// A launch event standing in for a running process (Watch Closely takes an event).
    static func event(for row: RunningRow) -> ActivityEvent {
        let time = (row.started ?? Date()).formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))
        var e = ActivityEvent(kind: .exec, time: time, pid: row.pid, ppid: row.info.ppid, name: row.name,
                              proc: row.info.path, target: row.info.path, extra: "", parent: row.parentName, args: row.info.args)
        e.pstart = row.info.start
        return e
    }
}
