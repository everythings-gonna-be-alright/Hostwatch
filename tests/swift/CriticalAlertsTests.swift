import Foundation
import Testing
@testable import Hostwatch

/// Critical notifications: only when protection really stopped, once per outage, gone when it is back.
@MainActor @Suite struct CriticalAlertsRules {
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    @Test func theCollectorGetsHalfAMinuteAtLaunchThenNone() {
        var clock = OutageClock(launch: t0)
        #expect(clock.update(down: true, now: t0 + 25) == .none)            // a service still coming up
        #expect(clock.update(down: true, now: t0 + 31) == .alert)
        #expect(clock.update(down: true, now: t0 + 200) == .none)           // once per outage
        #expect(clock.update(down: false, now: t0 + 210) == .recovered)
        #expect(clock.update(down: true, now: t0 + 220) == .alert)          // stopped while connected: at once
        #expect(clock.update(down: false, now: t0 + 222) == .recovered)     // launchd started it again
    }

    @Test func noCollectorWantedMeansNoAlert() {
        var clock = OutageClock(launch: t0)
        #expect(clock.update(down: false, now: t0 + 100) == .none)          // stopped by you: not "down"
    }

    @Test func theAlertsGoThroughDeliveryAndRespectTheSwitch() {
        let alerts = CriticalAlerts(defaults: scratchDefaults("hw-crit-alerts"))
        var posted: [CriticalProblem] = [], removed: [CriticalProblem] = []
        alerts.post = { p, _, body in posted.append(p); #expect(!body.contains(";")) }
        alerts.remove = { removed.append($0) }
        alerts.filterStopped(why: "")
        alerts.filterRunning()
        #expect(posted == [.filterStopped] && removed.isEmpty)              // a recovery keeps the notice
        #expect(alerts.active.isEmpty)
        alerts.filterStopped(why: "")
        alerts.filterRunning()
        #expect(alerts.active.isEmpty)
        alerts.enabled = false                                               // off: nothing posts
        alerts.filterStopped(why: "")
        #expect(posted == [.filterStopped, .filterStopped])
        #expect(alerts.active == [.filterStopped])                           // the menu bar's dot still shows it
        alerts.check(down: false, now: Date())
        #expect(alerts.active == [.filterStopped])                           // the collector being fine doesn't clear it
        alerts.filterRunning()
        #expect(alerts.active.isEmpty)
    }

    @Test func theFilterCountsOnlyWhenItStopsByItself() {
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-crit"),
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("crit-\(UUID()).json"))
        var stopped: [String] = []
        fw.onFilterStopped = { stopped.append($0) }
        fw.mode = .ask
        fw.relayStatus("on", "")
        fw.relayStatus("off", "")                                            // gone while asking
        fw.relayStatus("on", "")
        fw.mode = .watch                                                     // you chose Watch: the relay goes off
        fw.relayStatus("off", "")
        #expect(stopped == [""])
        fw.mode = .strict
        fw.relayStatus("failed", "pf refused the rules")
        #expect(stopped == ["", "pf refused the rules"])
    }
}
