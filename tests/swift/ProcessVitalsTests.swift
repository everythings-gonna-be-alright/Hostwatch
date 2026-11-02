import AppKit
import Foundation
import SwiftUI
import Testing
@testable import Hostwatch

/// Heavy processes: launched while watching, still running, using a lot of CPU or memory, sustained.
@MainActor @Suite struct HeavyProcesses {
    var clock = Date(timeIntervalSince1970: 1_800_000_000)

    func make() -> (ProcessVitals, UserDefaults) {
        let d = scratchDefaults("hw-vitals")
        let v = ProcessVitals(defaults: d)
        v.isUntrusted = { $0.contains("/Downloads/") }
        return (v, d)
    }

    func launch(_ pid: Int, _ path: String, start: Double) -> ActivityEvent {
        var e = exec(path, pid: pid, ppid: 1, parent: "/bin/zsh", args: (path as NSString).lastPathComponent)
        e.pstart = start
        return e
    }

    func sample(_ pid: Int, start: Double, cpu: Double, mem: Int64 = 100_000_000) -> ProcessVitalSample {
        ProcessVitalSample(pid: pid, start: start, name: "x", path: "/x", cpu: cpu, mem: mem, cpu_total: 10)
    }

    /// Feeds `count` samples 5 s apart.
    func feed(_ v: ProcessVitals, _ samples: [ProcessVitalSample], count: Int, from t0: Date) -> Date {
        var t = t0
        for _ in 0..<count {
            v.now = { t }
            v.receive(samples)
            t = t.addingTimeInterval(5)
        }
        return t
    }

    @Test func sustainedCPUIsHeavyButASpikeIsNot() {
        let (v, _) = make()
        v.isAlive = { _ in true }
        let e = launch(4411, "/usr/local/bin/worker", start: 1_799_999_000)
        v.now = { clock }
        v.noteLaunch(e)
        _ = feed(v, [sample(4411, start: 1_799_999_000, cpu: 380)], count: 2, from: clock)
        #expect(v.badge(for: e) == nil)                                          // 5 s of data: a spike
        _ = feed(v, [sample(4411, start: 1_799_999_000, cpu: 380)], count: 5, from: clock.addingTimeInterval(10))
        guard case .heavy(let cpu, _, let running, true, false)? = v.badge(for: e) else {
            Issue.record("not heavy: \(String(describing: v.badge(for: e)))"); return
        }
        #expect(cpu >= 300 && running > 900)
        #expect(v.heavyPids == [4411])
    }

    @Test func memoryCountsAtOnce() {
        let (v, _) = make()
        v.isAlive = { _ in true }
        let e = launch(9120, "/opt/homebrew/bin/node", start: 1_799_000_000)
        v.now = { clock }
        v.noteLaunch(e)
        _ = feed(v, [sample(9120, start: 1_799_000_000, cpu: 6, mem: 2_100_000_000)], count: 1, from: clock)
        guard case .heavy(_, let mem, _, false, true)? = v.badge(for: e) else { Issue.record("not heavy"); return }
        #expect(mem == 2_100_000_000)
    }

    @Test func endedShowsPeakThenGoesAway() {
        let (v, _) = make()
        var alive = true
        v.isAlive = { _ in alive }
        let e = launch(500, "/usr/bin/clang", start: 1_799_999_900)
        v.now = { clock }
        v.noteLaunch(e)
        var t = feed(v, [sample(500, start: 1_799_999_900, cpu: 240)], count: 8, from: clock)
        alive = false
        t = feed(v, [], count: 1, from: t)
        guard case .ended(let peak, _, _)? = v.badge(for: e) else { Issue.record("not ended"); return }
        #expect(peak == 240 && v.heavyNow.isEmpty)
        _ = feed(v, [], count: 1, from: t.addingTimeInterval(ProcessVitals.keepEnded + 5))
        #expect(v.badge(for: e) == nil)
    }

    @Test func onlyProcessesLaunchedWhileWatchingAndNotAReusedPid() {
        let (v, _) = make()
        v.isAlive = { _ in true }
        _ = feed(v, [sample(77, start: 1_700_000_000, cpu: 400)], count: 8, from: clock)  // never saw it start
        #expect(v.tracked.isEmpty)
        let e = launch(88, "/usr/local/bin/tool", start: 1_799_999_000)
        v.noteLaunch(e)
        _ = feed(v, [sample(88, start: 1_799_000_000, cpu: 400)], count: 8, from: clock)  // pid 88, other process
        #expect(v.badge(for: e) == nil)
    }

    @Test func heavyUntrustedReportsOnceAndBuildsAStory() {
        let (v, _) = make()
        v.isAlive = { _ in true }
        let stories = StoryEngine(persistent: false)
        var reports = 0
        var stages: [StoryStage] = []
        let miner = launch(4411, "\(home)/Downloads/xmrig", start: 1_799_999_000)
        v.onHeavyUntrusted = { launch, tracked in
            reports += 1
            stages += stories.ingest(launch.event, decidedSafe: false,
                                     extra: [(StoryStage.heavyUntrusted, "keeps running heavy")]).map(\.0)
        }
        v.now = { clock }
        v.noteLaunch(miner)
        _ = feed(v, [sample(4411, start: 1_799_999_000, cpu: 390)], count: 12, from: clock)
        #expect(reports == 1)
        #expect(stages == [.heavyUntrusted])          // a step in its story (alone, 3 points: not an alert yet)
    }

    @Test func thresholdsComeFromSettings() {
        let (v, d) = make()
        v.isAlive = { _ in true }
        d.set(200.0, forKey: "heavyCPUPercent")
        let e = launch(31, "/usr/local/bin/busy", start: 1_799_999_000)
        v.now = { clock }
        v.noteLaunch(e)
        _ = feed(v, [sample(31, start: 1_799_999_000, cpu: 120)], count: 8, from: clock)
        #expect(v.badge(for: e) == nil)                                           // below 2 cores
        d.set(false, forKey: "heavyHighlight")
        #expect(v.badge(for: e) == nil)
    }
}

/// The collector's side: every process above the floor, and the start time on launches.
@Suite struct CollectorVitals {
    @Test func vitalsListsProcessesAboveTheFloor() {
        let a = ProcessInstance(pid: 1, start: 1), b = ProcessInstance(pid: 2, start: 2), c = ProcessInstance(pid: 3, start: 3)
        let before: [ProcessInstance: ProcessUsage] = [
            a: ProcessUsage(cpuNanos: 0, footprint: 10, read: 0, written: 0),
            b: ProcessUsage(cpuNanos: 0, footprint: 500_000_000, read: 0, written: 0),
            c: ProcessUsage(cpuNanos: 0, footprint: 10, read: 0, written: 0),
        ]
        let after: [ProcessInstance: ProcessUsage] = [
            a: ProcessUsage(cpuNanos: 4e9, footprint: 10, read: 0, written: 0),            // 80% over 5 s
            b: ProcessUsage(cpuNanos: 0, footprint: 500_000_000, read: 0, written: 0),       // big memory
            c: ProcessUsage(cpuNanos: 0.1e9, footprint: 10, read: 0, written: 0),          // 2%: below
        ]
        let rows = TopSampler.vitals(before: before, after: after, seconds: 5)
        #expect(rows.map(\.pid) == [1, 2])
        #expect(abs(rows[0].cpu - 80) < 0.01 && rows[0].cpuSeconds == 4)
    }

    @Test func startTimeOfARealProcess() throws {
        let start = try #require(ProcessList.realStart(Int(getpid())))
        let age = Date().timeIntervalSince1970 - start
        #expect(age >= 0 && age < 3600)                                      // this test run started just now
        #expect(ProcessList.realStart(99_999_999) == nil)
    }
}

/// Live and Time Travel share one shape (`HeavyProcess`), recorded with each metrics sample.
@MainActor @Suite struct HeavyInTimeTravel {
    static let xmrig = HeavyProcess(pid: 4411, start: 1_799_999_000, name: "xmrig", path: "\(home)/Downloads/xmrig",
                                    parent: "/bin/zsh", cpu: 380, mem: 2_100_000_000, cpuHeavy: true, memHeavy: true, untrusted: true)

    @Test func recordedWithTheMetricsSample() throws {
        var sample = MetricSample(t: 1_800_000_000, cpu: 40, mem: 0.5, pressure: 1, netIn: 0, netOut: 0)
        sample.heavy = [Self.xmrig]
        let data = try JSONEncoder().encode(sample)
        #expect(String(decoding: data, as: UTF8.self).contains("\"h\":[{"))
        #expect(try JSONDecoder().decode(MetricSample.self, from: data).heavy == [Self.xmrig])
    }

    @Test func badgesAtThePlayheadMatchTheExactProcess() {
        let context = HeavyContext(entries: [Self.xmrig], at: Date(timeIntervalSince1970: 1_800_000_000), live: false)
        var launch = exec("\(home)/Downloads/xmrig", pid: 4411, ppid: 1, parent: "/bin/zsh")
        launch.pstart = 1_799_999_000
        guard case .heavy(380, 2_100_000_000, 1000, true, true)? = context.badge(for: launch) else {
            Issue.record("no badge: \(String(describing: context.badge(for: launch)))"); return
        }
        launch.pstart = 1_700_000_000                                              // same pid, another process
        #expect(context.badge(for: launch) == nil)
    }
}

/// HOSTWATCH_RENDER=<dir> writes heavy-strip.png there (to look at the layout).
@MainActor @Suite struct HeavyStripRender {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil))
    func render() throws {
        let t = Date(timeIntervalSince1970: 1_800_000_000)
        let node = HeavyProcess(pid: 9120, start: 1_799_997_540, name: "node", path: "/opt/homebrew/bin/node", parent: "/bin/zsh",
                                cpu: 12, mem: 1_400_000_000, cpuHeavy: false, memHeavy: true, untrusted: false)
        let context = HeavyContext(entries: [HeavyInTimeTravel.xmrig, node], at: t, live: true)
        let actions = HUDActions(openFullScreen: {}, openExclusions: {}, toggleCollector: {}, quit: {}, askAI: { _ in })
        var e1 = exec("\(home)/Downloads/xmrig", pid: 4411, ppid: 1, parent: "/bin/zsh", args: "./xmrig -o pool:443")
        e1.pstart = 1_799_999_000
        var e2 = exec("/opt/homebrew/bin/node", pid: 9120, ppid: 1, parent: "/bin/zsh", args: "node server.js")
        e2.pstart = 1_799_997_540
        let collapsed = HeavyStripState(); collapsed.collapsed = true
        let view = VStack(alignment: .leading, spacing: 8) {
            HeavyStrip(context: context, state: HeavyStripState(), onlyThese: false, toggleOnlyThese: {}, actions: actions)
            HeavyStrip(context: HeavyContext(entries: [HeavyInTimeTravel.xmrig], at: t, live: false), state: collapsed,
                       onlyThese: true, toggleOnlyThese: {}, actions: actions)
            ForEach([e1, e2], id: \.pid) { e in
                HStack(spacing: 8) {
                    Text("12:01:07").foregroundStyle(.secondary)
                    Image(systemName: "flame.fill").foregroundStyle(.orange)
                    Text(e.name).fontWeight(.semibold).frame(width: 70, alignment: .leading)
                    if let b = context.badge(for: e) { VitalBadgeView(badge: b) }
                    Text(e.args).foregroundStyle(.secondary)
                }
                .font(.system(size: 12, design: .monospaced))
                .padding(.horizontal, 16)
            }
            VitalBadgeView(badge: .ended(peakCPU: 240, peakMem: 900_000_000, ago: 95)).padding(.horizontal, 16)
        }
        .padding(.bottom, 10)
        .frame(width: 900)
        .background(Color(nsColor: .windowBackgroundColor))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.nsImage)
        let tiff = try #require(image.tiffRepresentation)
        let png = try #require(NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]))
        try png.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("heavy-strip.png"))
    }
}

/// HUD backgrounds: four distinct looks; the two near-identical old ones map onto the new set.
@Suite struct HUDBackgrounds {
    @Test func oldChoicesCarryOver() {
        #expect(OverlayBackground(stored: "blur") == .glass)
        #expect(OverlayBackground(stored: "dark") == .solid)
        #expect(OverlayBackground(stored: "transparent") == .transparent)
        #expect(OverlayBackground.allCases.map(\.title) == ["Glass", "Clear Glass", "Solid", "None"])
    }

    @Test func contrastGoesFromPureGlassToNearlyOpaque() {
        #expect(HUDSurface.floor(0) == 0)
        #expect(abs(HUDSurface.floor(0.45) - 0.62) < 0.001)        // the default look is unchanged
        #expect(abs(HUDSurface.floor(1) - 0.95) < 0.001)
        #expect(HUDSurface.floor(0.2) < HUDSurface.floor(0.3))
    }

    @Test func transparencyFadesTheBackgroundButNeverHidesIt() {
        #expect(HUDSurface.layerOpacity(0) == 1)
        #expect(abs(HUDSurface.layerOpacity(1) - 0.1) < 0.001)
        #expect(HUDSurface.layerOpacity(0.5) > HUDSurface.layerOpacity(0.8))
    }
}
