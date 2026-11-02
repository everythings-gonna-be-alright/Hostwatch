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

    static func sameProcess(_ a: Double, _ b: Double) -> Bool { a == 0 || b == 0 || abs(a - b) < 1.5 }

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

// MARK: - Views

/// "🔥 380% · 2.1 GB · 12 min" on the launch row of a heavy process; grey "ended · peak 380%" after.
struct VitalBadgeView: View {
    let badge: ProcessVitals.Badge
    var compact = false

    var body: some View {
        switch badge {
        case .heavy(let cpu, let mem, let running, let cpuHeavy, let memHeavy):
            HStack(spacing: 4) {
                Image(systemName: cpuHeavy ? "flame.fill" : "memorychip.fill")
                Text(compact ? (cpuHeavy ? "\(Int(cpu))%" : ProcessVitals.memory(mem))
                             : "\(Int(cpu))% CPU · \(ProcessVitals.memory(mem)) · \(ProcessVitals.duration(running))")
                    .monospacedDigit()
            }
            .font(.system(size: compact ? 10 : 11, weight: .semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Capsule().fill(cpuHeavy || memHeavy ? Color.orange : Color.secondary))
            .help("Still running and using a lot: \(Int(cpu))% of one CPU core on average over 30 s, "
                  + "\(ProcessVitals.memory(mem)) of memory, running for \(ProcessVitals.duration(running))")
        case .ended(let peakCPU, let peakMem, let ago):
            HStack(spacing: 4) {
                Image(systemName: "checkmark.circle")
                Text(compact ? "ended" : "ended \(ProcessVitals.duration(ago)) ago · peak \(Int(peakCPU))% · \(ProcessVitals.memory(peakMem))")
                    .monospacedDigit()
            }
            .font(.system(size: compact ? 10 : 11, weight: .medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Capsule().strokeBorder(Color.secondary.opacity(0.4)))
        }
    }
}

/// Above the events: the processes you (or something) started that are still running heavy.
struct HeavyStrip: View {
    @ObservedObject var vitals: ProcessVitals
    let onlyThese: Bool
    let toggleOnlyThese: () -> Void
    let actions: HUDActions

    var body: some View {
        let _ = vitals.revision
        let heavy = vitals.heavyNow
        if !heavy.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "flame.fill").foregroundStyle(.orange)
                    Text("\(heavy.count) process\(heavy.count == 1 ? "" : "es") started while watching \(heavy.count == 1 ? "is" : "are") still running heavy")
                        .font(.system(size: 12, weight: .semibold))
                    Spacer()
                    Button(onlyThese ? "Show All Events" : "Show Only These", action: toggleOnlyThese)
                        .buttonStyle(.glass).controlSize(.small)
                }
                ForEach(heavy.prefix(4), id: \.launch.pid) { tr in
                    HeavyRow(tr: tr, vitals: vitals, actions: actions)
                }
                if heavy.count > 4 {
                    Text("and \(heavy.count - 4) more").font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.orange.opacity(0.08))
        }
    }
}

private struct HeavyRow: View {
    let tr: ProcessVitals.Tracked
    let vitals: ProcessVitals
    let actions: HUDActions

    var body: some View {
        let t = vitals.now()
        let cpu = vitals.cpuAverage(tr, at: t)
        HStack(spacing: 10) {
            Text(tr.launch.name).font(.system(size: 12, weight: .semibold)).frame(minWidth: 90, alignment: .leading)
            Text("pid " + String(tr.launch.pid)).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
            // CPU bar: one full core = a quarter of the bar, so 400% fills it.
            GeometryReader { g in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.secondary.opacity(0.15))
                    Capsule().fill(Color.orange).frame(width: g.size.width * min(1, cpu / 400))
                }
            }
            .frame(width: 80, height: 6)
            Text("\(Int(cpu))% CPU · \(ProcessVitals.memory(tr.memNow)) · \(ProcessVitals.duration(vitals.running(tr, at: t)))")
                .font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
            if vitals.isUntrusted(tr.launch.path) {
                Text("untrusted program").font(.system(size: 10, weight: .semibold)).foregroundStyle(.red)
            }
            Spacer()
            Button("Ask AI") { actions.askAI(tr.launch.event) }.buttonStyle(.glass).controlSize(.mini)
            Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: tr.launch.path)]) } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(.glass).controlSize(.mini).help("Reveal \(tr.launch.path) in Finder")
        }
        .help("Started by \((tr.launch.parent as NSString).lastPathComponent): \(tr.launch.event.args.isEmpty ? tr.launch.path : tr.launch.event.args)")
    }
}
