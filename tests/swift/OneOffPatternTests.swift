import Foundation
import Testing
@testable import Hostwatch

/// A command typed once: recorded (detection works the first time), hidden from the Patterns tab unless asked,
/// and forgotten a week later unless it happens again or someone decided it.
@MainActor @Suite(.serialized) struct OneOffPatterns {
    func store() -> SignatureStore {
        _ = TestEnv.ready
        let s = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("hw-oneoff-\(UUID().uuidString)"))
        s.showSeenOnce = false
        return s
    }

    /// Records the event and backdates its pattern; returns its key.
    @discardableResult
    func seen(_ s: SignatureStore, _ e: ActivityEvent, daysAgo: Double = 8, times: Int = 1) -> String {
        _ = s.observe(e)
        let key = e.signatureKey
        if var entry = s.entry(key) {
            entry.count = times
            entry.lastSeen = Date().addingTimeInterval(-daysAgo * 86_400)
            entry.firstSeen = entry.lastSeen
            s.restore(entry)
        }
        return key
    }

    func shell(_ cmd: String) -> ActivityEvent {
        event(.exec, pid: 50, ppid: 40, name: "curl", proc: "/bin/zsh", target: "/usr/bin/curl", parent: "/bin/zsh", args: cmd)
    }

    @Test func aWeekOldOneOffIsForgotten() throws {
        let s = store()
        defer { s.showSeenOnce = false }
        let once = seen(s, net("/usr/bin/curl", pid: 50, to: "142.250.1.1:443", host: "google.us"))
        let twice = seen(s, net("/usr/bin/curl", pid: 51, to: "93.184.216.34:443", host: "example.com"), times: 2)
        let fresh = seen(s, net("/usr/bin/curl", pid: 52, to: "151.101.1.69:443", host: "pypi.org"), daysAgo: 2)
        let decided = seen(s, net("/usr/bin/curl", pid: 53, to: "140.82.112.3:443", host: "github.com"))
        s.set(.safe, keys: [decided], note: "allowed in Firewall")
        let story = seen(s, net("/usr/bin/curl", pid: 54, to: "185.199.108.133:443", host: "githubusercontent.com"))
        s.inUse = { [story] }
        let a = try #require(s.entry(once)), b = try #require(s.entry(twice))
        #expect(s.isOneOff(a) && !s.isOneOff(b))

        s.tidy()
        #expect(s.entry(once) == nil)                                 // seen once, a week ago, undecided
        #expect(s.entry(twice) != nil)                                // happened again
        #expect(s.entry(fresh) != nil)                                // not a week yet
        #expect(s.entry(decided) != nil)                              // your decision stays
        #expect(s.entry(story) != nil)                                // an open story uses it
        #expect(s.tidySummary.contains("1 one-off"))

        _ = s.observe(net("/usr/bin/curl", pid: 60, to: "142.250.1.1:443", host: "google.us"))
        #expect(s.entry(once)?.status == .unclassified)               // it happens again: simply new again
    }

    /// Seen once and Safe only because it's routine: hidden and forgotten too. Your decision: always shown, kept.
    @Test func automaticSafeOneOffsAreHiddenButYoursShow() throws {
        let s = store()
        defer { s.showSeenOnce = false }
        let logd = "/usr/libexec/logd"
        let routine = seen(s, file(logd, pid: 1, "r", "/Library/Application Support/Apple/logs/one.log"))
        let mine = seen(s, net("/usr/bin/curl", pid: 50, to: "142.250.1.1:443", host: "google.us"))
        s.set(.safe, keys: [mine], note: "allowed in Firewall")
        let r = try #require(s.entry(routine)), m = try #require(s.entry(mine))
        #expect(r.source == "auto" && s.isOneOff(r) && s.isForgettableOneOff(r))
        #expect(!s.isOneOff(m))
        s.tidy()
        #expect(s.entry(routine) == nil && s.entry(mine) != nil)
    }

    @Test func riskyOneOffsStay() {
        let s = store()
        let risky = seen(s, net("\(home)/Downloads/x/updater", pid: 70, to: "203.0.113.9:8443"))
        #expect(s.entry(risky)?.risk == .high)
        s.tidy()
        #expect(s.entry(risky) != nil)
    }

    @Test func patternsTabHidesOneOffsUnlessAsked() {
        let s = store()
        defer { s.showSeenOnce = false }
        let once = seen(s, shell("curl https://google.us"), daysAgo: 0)
        let twice = seen(s, shell("curl https://example.com"), daysAgo: 0, times: 3)
        var keys = Set(s.patternItems(filter: .all).map(\.id))
        #expect(!keys.contains(once) && keys.contains(twice))
        #expect(s.oneOffCount(filter: .all) >= 1)
        s.search = "google.us"                                        // search finds it anyway
        #expect(s.patternItems(filter: .all).map(\.id).contains(once))
        s.search = ""
        s.showSeenOnce = true
        keys = Set(s.patternItems(filter: .all).map(\.id))
        #expect(keys.contains(once) && keys.contains(twice))
    }
}
