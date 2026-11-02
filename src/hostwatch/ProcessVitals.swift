import Darwin
import Foundation
import SwiftUI

/// One process above the collector's floor (≥ 5% CPU or ≥ 300 MB), every 5 s.
struct ProcessVitalSample: Codable, Sendable, Equatable {
    var pid: Int
    var start: Double             // s since 1970 (0: unknown)
    var name: String
    var path: String
    var cpu: Double               // % of one core over the last 5 s
    var mem: Int64                // physical footprint
    var cpu_total: Double?        // CPU seconds used since it started
}

/// Processes Hostwatch saw start that are still running and using a lot of CPU or memory ("heavy"),
/// so they stand out among the events. Sustained use counts, not spikes: CPU averaged over 30 s, or a
/// memory footprint above the limit. Only processes launched while Hostwatch was watching (not apps
/// that were already running, which would be "heavy" all day).
@MainActor
final class ProcessVitals: ObservableObject {
    struct Launch: Equatable {
        var pid: Int
        var start: Double
        var name: String
        var path: String
        var parent: String
        var seen: Date
        var event: ActivityEvent

        static func == (a: Launch, b: Launch) -> Bool { a.pid == b.pid && a.start == b.start && a.seen == b.seen }
    }

    struct Tracked {
        var launch: Launch
        var samples: [(date: Date, cpu: Double, mem: Int64)] = []
        var peakCPU = 0.0
        var peakMem: Int64 = 0
        var cpuTotal = 0.0
        var heavySince: Date?         // heavy now, since
        var wasHeavy = false
        var ended: Date?
        var reportedUntrusted = false

        var cpuNow: Double { samples.last?.cpu ?? 0 }
        var memNow: Int64 { samples.last?.mem ?? 0 }
    }

    enum Badge: Equatable {
        case heavy(cpu: Double, mem: Int64, running: TimeInterval, cpuHeavy: Bool, memHeavy: Bool)
        case ended(peakCPU: Double, peakMem: Int64, ago: TimeInterval)
    }

    static let window: TimeInterval = 30
    static let keepEnded: TimeInterval = 10 * 60
    static let maxLaunches = 20_000

    @Published private(set) var revision = 0
    private(set) var launches: [Int: Launch] = [:]
    private(set) var tracked: [Int: Tracked] = [:]

    var enabled: Bool { defaults.object(forKey: "heavyHighlight") as? Bool ?? true }
    /// % of one core, averaged over `window`.
    var cpuLimit: Double { let v = defaults.double(forKey: "heavyCPUPercent"); return v > 0 ? v : 50 }
    var memLimit: Int64 { let v = defaults.double(forKey: "heavyMemoryGB"); return Int64((v > 0 ? v : 1) * 1_000_000_000) }

    var now: () -> Date = { Date() }
    var isAlive: (Int) -> Bool = { pid in kill(pid_t(pid), 0) == 0 || errno == EPERM }
    /// Called once per process that turns heavy while being unsigned, ad-hoc, quarantined or from a
    /// download/temp folder (the cryptominer pattern).
    var onHeavyUntrusted: ((Launch, Tracked) -> Void)?
    var isUntrusted: (String) -> Bool = { path in
        if SignatureBuilder.isDropZone(SignatureBuilder.normalize(path)) { return true }
        guard let id = SigningCache.shared.cached(path) else { return false }
        return id.untrustedCode || id.quarantined || id.valid == false
    }
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    // MARK: Input

    /// A launch the app saw (live or restored from history).
    func noteLaunch(_ e: ActivityEvent) {
        guard e.kind == .exec, e.pid > 0 else { return }
        launches[e.pid] = Launch(pid: e.pid, start: e.pstart, name: e.name, path: e.target, parent: e.parent,
                                 seen: now(), event: e)
        if launches.count > Self.maxLaunches {
            for (pid, _) in launches.sorted(by: { $0.value.seen < $1.value.seen }).prefix(launches.count - Self.maxLaunches + 1000)
                where tracked[pid] == nil {
                launches[pid] = nil
            }
        }
    }

    nonisolated static func sameProcess(_ a: Double, _ b: Double) -> Bool { a == 0 || b == 0 || abs(a - b) < 1.5 }

    /// The collector's list (every 5 s): follow the ones we saw start.
    func receive(_ samples: [ProcessVitalSample]) {
        let t = now()
        let hadTracked = !tracked.isEmpty
        var reported = Set<Int>()
        for s in samples {
            guard let launch = launches[s.pid], Self.sameProcess(launch.start, s.start) else { continue }
            reported.insert(s.pid)
            var tr = tracked[s.pid].flatMap { $0.launch == launch ? $0 : nil } ?? Tracked(launch: launch)
            tr.samples.append((t, s.cpu, s.mem))
            tr.peakCPU = max(tr.peakCPU, s.cpu)
            tr.peakMem = max(tr.peakMem, s.mem)
            tr.cpuTotal = s.cpu_total ?? tr.cpuTotal
            tracked[s.pid] = tr
        }
        for (pid, var tr) in tracked where !reported.contains(pid) && tr.ended == nil {
            if isAlive(pid) {
                tr.samples.append((t, 0, tr.memNow))          // still running, below the floor now
            } else {
                tr.ended = t
            }
            tracked[pid] = tr
        }
        for (pid, var tr) in tracked {
            tr.samples.removeAll { t.timeIntervalSince($0.date) > 2 * Self.window }
            let heavy = tr.ended == nil && isHeavy(tr, at: t)
            if heavy {
                if tr.heavySince == nil { tr.heavySince = t }
                tr.wasHeavy = true
                if !tr.reportedUntrusted, isUntrusted(tr.launch.path) {
                    tr.reportedUntrusted = true
                    onHeavyUntrusted?(tr.launch, tr)
                }
            } else {
                tr.heavySince = nil
            }
            let stale = tr.ended.map { t.timeIntervalSince($0) > (tr.wasHeavy ? Self.keepEnded : 0) }
                ?? (!tr.wasHeavy && tr.samples.allSatisfy { $0.cpu == 0 })
            tracked[pid] = stale ? nil : tr
        }
        if hadTracked || !tracked.isEmpty { revision &+= 1 }    // nothing followed: no redraw
    }

    // MARK: Questions

    func cpuAverage(_ tr: Tracked, at t: Date) -> Double {
        let recent = tr.samples.filter { t.timeIntervalSince($0.date) <= Self.window }
        return recent.isEmpty ? 0 : recent.map(\.cpu).reduce(0, +) / Double(recent.count)
    }

    /// Sustained: CPU averaged over 30 s (at least 25 s of samples), or memory above the limit.
    func isHeavy(_ tr: Tracked, at t: Date) -> Bool {
        guard enabled else { return false }
        let recent = tr.samples.filter { t.timeIntervalSince($0.date) <= Self.window }
        let span = (recent.last?.date).flatMap { last in recent.first.map { last.timeIntervalSince($0.date) } } ?? 0
        let cpuHeavy = span >= Self.window - 5 && cpuAverage(tr, at: t) >= cpuLimit
        return cpuHeavy || tr.memNow >= memLimit
    }

    /// Heavy right now, busiest first (for the strip above the events).
    var heavyNow: [Tracked] {
        let t = now()
        return tracked.values.filter { $0.heavySince != nil && $0.ended == nil }
            .sorted { cpuAverage($0, at: t) > cpuAverage($1, at: t) }
    }

    /// The badge for an event's row: on the launch of a process that is (or recently was) heavy.
    func badge(for e: ActivityEvent) -> Badge? {
        guard enabled, e.kind == .exec, let tr = tracked[e.pid], Self.sameProcess(tr.launch.start, e.pstart),
              tr.launch.start != 0 || e.pstart != 0 || tr.launch.event.id == e.id else { return nil }
        let t = now()
        if let ended = tr.ended {
            return tr.wasHeavy ? .ended(peakCPU: tr.peakCPU, peakMem: tr.peakMem, ago: t.timeIntervalSince(ended)) : nil
        }
        guard tr.heavySince != nil else { return nil }
        let avg = cpuAverage(tr, at: t)
        return .heavy(cpu: avg, mem: tr.memNow, running: running(tr, at: t),
                      cpuHeavy: avg >= cpuLimit, memHeavy: tr.memNow >= memLimit)
    }

    /// pids heavy now (for the HUD and the "only these" filter).
    var heavyPids: Set<Int> { Set(heavyNow.map(\.launch.pid)) }

    func running(_ tr: Tracked, at t: Date) -> TimeInterval {
        tr.launch.start > 0 ? t.timeIntervalSince1970 - tr.launch.start : t.timeIntervalSince(tr.launch.seen)
    }

    // MARK: Text

    static func memory(_ bytes: Int64) -> String {
        bytes >= 1_000_000_000 ? String(format: "%.1f GB", Double(bytes) / 1e9) : "\(bytes / 1_000_000) MB"
    }

    static func duration(_ s: TimeInterval) -> String {
        let s = max(0, Int(s))
        return s < 60 ? "\(s) s" : s < 3600 ? "\(s / 60) min" : "\(s / 3600) h \(s % 3600 / 60) min"
    }
}

// MARK: - One shape for live and Time Travel

/// A heavy process at one moment: what the strip and the badges show, live or at the playhead. Recorded in
/// the metrics history every 5 s (usually 0–3 entries), so Time Travel shows exactly what live showed.
struct HeavyProcess: Codable, Sendable, Equatable, Identifiable {
    var pid: Int
    var start: Double            // s since 1970 (0: unknown)
    var name: String
    var path: String
    var parent: String
    var cpu: Double              // % of one core, averaged over 30 s
    var mem: Int64
    var cpuHeavy: Bool
    var memHeavy: Bool
    var untrusted: Bool

    var id: String { "\(pid)-\(start)" }

    /// A launch event for Ask AI when the real one isn't at hand (Time Travel).
    var launchEvent: ActivityEvent {
        var e = ActivityEvent(kind: .exec, time: "", pid: pid, ppid: 0, name: name, proc: path, target: path,
                              extra: "", parent: parent)
        e.pstart = start
        return e
    }
}

extension ProcessVitals {
    /// Heavy right now, in the shape the views and the history use.
    var snapshot: [HeavyProcess] {
        let t = now()
        return heavyNow.map { tr in
            let cpu = cpuAverage(tr, at: t)
            return HeavyProcess(pid: tr.launch.pid, start: tr.launch.start, name: tr.launch.name, path: tr.launch.path,
                                parent: tr.launch.parent, cpu: (cpu * 10).rounded() / 10, mem: tr.memNow,
                                cpuHeavy: cpu >= cpuLimit, memHeavy: tr.memNow >= memLimit, untrusted: isUntrusted(tr.launch.path))
        }
    }

    /// The live context for the Events list.
    var liveContext: HeavyContext {
        HeavyContext(entries: snapshot, at: now(), live: true,
                     events: { [weak self] pid in self?.tracked[pid]?.launch.event },
                     ended: { [weak self] e in
                         if case .ended? = self?.badge(for: e) { return self?.badge(for: e) }
                         return nil
                     })
    }
}

/// What the strip and the badges show: live, or at the Time Travel playhead.
struct HeavyContext {
    var entries: [HeavyProcess]
    var at: Date
    var live: Bool
    /// The launch event for a pid, when known (for Ask AI).
    var events: (Int) -> ActivityEvent? = { _ in nil }
    /// Live only: "ended · peak" for heavy processes that exited in the last 10 minutes.
    var ended: (ActivityEvent) -> ProcessVitals.Badge? = { _ in nil }

    static let empty = HeavyContext(entries: [], at: Date(), live: true)

    func entry(for e: ActivityEvent) -> HeavyProcess? {
        guard e.kind == .exec else { return nil }
        return entries.first { $0.pid == e.pid && ProcessVitals.sameProcess($0.start, e.pstart) }
    }

    func badge(for e: ActivityEvent) -> ProcessVitals.Badge? {
        if let h = entry(for: e) {
            return .heavy(cpu: h.cpu, mem: h.mem, running: running(h), cpuHeavy: h.cpuHeavy, memHeavy: h.memHeavy)
        }
        return live ? ended(e) : nil
    }

    func running(_ h: HeavyProcess) -> TimeInterval { h.start > 0 ? at.timeIntervalSince1970 - h.start : 0 }

    var pids: Set<Int> { Set(entries.map(\.pid)) }
}

// MARK: - Views

/// A tag on the launch row: "🔥 380% · 2.1 GB · 12 min" while heavy, "ended · peak 240%" after (tinted,
/// like a Finder tag, not a solid pill).
struct VitalBadgeView: View {
    let badge: ProcessVitals.Badge
    var compact = false

    var body: some View {
        switch badge {
        case .heavy(let cpu, let mem, let running, let cpuHeavy, _):
            Label {
                Text(compact ? (cpuHeavy ? "\(Int(cpu))%" : ProcessVitals.memory(mem))
                     : [cpuHeavy ? "\(Int(cpu))% CPU" : nil, ProcessVitals.memory(mem),
                        running > 0 ? ProcessVitals.duration(running) : nil].compactMap { $0 }.joined(separator: " · "))
                    .monospacedDigit()
            } icon: {
                Image(systemName: cpuHeavy ? "flame.fill" : "memorychip.fill").symbolRenderingMode(.hierarchical)
            }
            .labelStyle(.titleAndIcon)
            .font(.system(size: compact ? 10 : 11, weight: .medium))
            .foregroundStyle(Color.orange)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(Color.orange.opacity(0.14)))
            .overlay(Capsule().strokeBorder(Color.orange.opacity(0.35), lineWidth: 0.5))
            .accessibilityLabel("Running heavy: \(Int(cpu)) percent CPU, \(ProcessVitals.memory(mem)) memory")
            .help("Still running and using a lot: \(Int(cpu))% of one CPU core on average over 30 s, "
                  + "\(ProcessVitals.memory(mem)) of memory" + (running > 0 ? ", running for \(ProcessVitals.duration(running))" : ""))
        case .ended(let peakCPU, let peakMem, let ago):
            Label {
                Text(compact ? "ended" : "Ended \(ProcessVitals.duration(ago)) ago · peak \(Int(peakCPU))% · \(ProcessVitals.memory(peakMem))")
                    .monospacedDigit()
            } icon: {
                Image(systemName: "checkmark.circle")
            }
            .labelStyle(.titleAndIcon)
            .font(.system(size: compact ? 10 : 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(Color.secondary.opacity(0.10)))
        }
    }
}

/// Collapsed or expanded, shared by live and Time Travel.
final class HeavyStripState: ObservableObject {
    @Published var collapsed = false
}

/// Above the events: processes started while watching that run heavy, live or at the playhead. A tinted
/// banner with one row per process (app icon, CPU gauge, memory, running time) and a ⋯ menu.
struct HeavyStrip: View {
    let context: HeavyContext
    @ObservedObject var state: HeavyStripState
    let onlyThese: Bool
    let toggleOnlyThese: () -> Void
    let actions: HUDActions

    var body: some View {
        let heavy = context.entries.sorted { $0.cpu > $1.cpu }
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "flame.fill")
                    .font(.system(size: 16))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text(context.live ? "Still running heavy" : "Running heavy at \(context.at.formatted(date: .omitted, time: .standard))")
                        .font(.headline)
                    Text("\(heavy.count) process\(heavy.count == 1 ? "" : "es") started while Hostwatch was watching")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                if state.collapsed {
                    // One line: the busiest names, so collapsing never hides that something is there.
                    Text(heavy.prefix(3).map { "\($0.name) \($0.cpuHeavy ? "\(Int($0.cpu))%" : ProcessVitals.memory($0.mem))" }
                        .joined(separator: "  ·  "))
                        .font(.callout.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 8)
                Toggle(isOn: Binding(get: { onlyThese }, set: { _ in toggleOnlyThese() })) {
                    Label("Only These", systemImage: "line.3.horizontal.decrease")
                }
                .toggleStyle(.button)
                .buttonStyle(.glass)
                .help(onlyThese ? "Show all events again" : "Show only these processes' events")
                Button {
                    withAnimation(.snappy) { state.collapsed.toggle() }
                } label: {
                    Image(systemName: "chevron.down").rotationEffect(.degrees(state.collapsed ? -90 : 0))
                }
                .buttonStyle(.glass)
                .help(state.collapsed ? "Show details" : "Collapse")
            }
            .controlSize(.small)
            if !state.collapsed {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                    ForEach(heavy.prefix(5)) { h in HeavyRow(h: h, context: context, actions: actions) }
                }
                if heavy.count > 5 {
                    Text("and \(heavy.count - 5) more").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(14)
        // Content, not a control: a tinted grouped background (Liquid Glass is for the control layer).
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.orange.opacity(0.07)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.orange.opacity(0.22), lineWidth: 0.5))
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

private struct HeavyRow: View {
    let h: HeavyProcess
    let context: HeavyContext
    let actions: HUDActions

    private var event: ActivityEvent { context.events(h.pid) ?? h.launchEvent }

    var body: some View {
        GridRow(alignment: .center) {
            HStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: h.path))
                    .resizable().frame(width: 20, height: 20)
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 6) {
                        Text(h.name).font(.body.weight(.semibold))
                        if h.untrusted {
                            Text("Untrusted").font(.caption2.weight(.semibold)).foregroundStyle(.red)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Color.red.opacity(0.12)))
                                .help("Unsigned, ad-hoc, quarantined or from a download/temp folder")
                        }
                    }
                    Text("pid " + String(h.pid) + (h.parent.isEmpty ? "" : " · from " + (h.parent as NSString).lastPathComponent))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            // One full core is a quarter of the gauge: 400% fills it.
            Gauge(value: min(h.cpu, 400), in: 0...400) { EmptyView() }
                .gaugeStyle(.accessoryLinearCapacity)
                .tint(h.cpuHeavy ? Color.orange : Color.secondary)
                .frame(width: 90)
                .help("\(Int(h.cpu))% of one CPU core (400% fills the bar)")
            Text("\(Int(h.cpu))%").font(.callout.monospacedDigit()).foregroundStyle(h.cpuHeavy ? .primary : .secondary)
                .gridColumnAlignment(.trailing)
            Label(ProcessVitals.memory(h.mem), systemImage: "memorychip")
                .font(.callout.monospacedDigit()).foregroundStyle(h.memHeavy ? .primary : .secondary)
            Text(context.running(h) > 0 ? ProcessVitals.duration(context.running(h)) : "")
                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Button { actions.askAI(event) } label: { Image(systemName: "sparkles") }
                    .buttonStyle(.borderless)
                    .help("Ask AI about \(h.name)")
                Menu {
                    Button("Ask AI About \(h.name)…") { actions.askAI(event) }
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: h.path)]) }
                    Button("Copy Path") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(h.path, forType: .string)
                    }
                } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.button).buttonStyle(.borderless).menuIndicator(.hidden).fixedSize()
            }
            .gridColumnAlignment(.trailing)
        }
    }
}
