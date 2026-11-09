import Foundation
import Testing
@testable import Hostwatch

/// Firewall rules and Watch mode: what passes, what's asked about, what's blocked.
@MainActor @Suite struct FirewallRules {
    func facts(_ program: String, ip: String, port: String = "443", host: String = "", risk: PatternRisk = .normal,
               reason: String = "", knownBad: String = "") -> FirewallFacts {
        FirewallFacts(program: program, proto: "TCP", ip: ip, port: port, host: host, risk: risk, riskReason: reason,
                      knownBad: knownBad, patternKey: "net|\(program)|TCP internet:443")
    }
    let app = "/Applications/Tool.app/Contents/MacOS/Tool"

    @Test func decisions() {
        func v(_ f: FirewallFacts, _ s: SignatureStatus = .unclassified) -> FirewallVerdict {
            FirewallPolicy.decide(f, status: s, hostwatch: "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch").verdict
        }
        #expect(v(facts(app, ip: "192.168.1.20")) == .allow)                               // local network
        #expect(v(facts(app, ip: "127.0.0.1")) == .allow)
        #expect(v(facts("/Applications/Hostwatch.app/Contents/MacOS/Hostwatch", ip: "1.2.3.4")) == .allow)
        #expect(v(facts(app, ip: "1.2.3.4"), .safe) == .allow)
        #expect(v(facts(app, ip: "1.2.3.4", knownBad: "ThreatFox: AsyncRAT"), .safe) == .block)   // even if Safe
        #expect(v(facts(app, ip: "1.2.3.4"), .suspicious) == .block)
        #expect(v(facts(app, ip: "1.2.3.4"), .dangerous) == .block)
        #expect(v(facts(app, ip: "1.2.3.4", risk: .high, reason: "network from a temp/download location")) == .block)
        #expect(v(facts(app, ip: "1.2.3.4", risk: .routine, reason: "trusted signer: Apple")) == .allow)
        #expect(v(facts("/usr/libexec/trustd", ip: "17.1.2.3")) == .allow)                 // macOS itself
        #expect(v(facts("/usr/bin/curl", ip: "1.2.3.4")) == .ask)                          // a tool: not "macOS itself"
        #expect(v(facts(app, ip: "1.2.3.4")) == .ask)                                     // new
    }

    @Test func unknownDestinationsAreLeftOut() throws {
        let line = #"{"kind":"net","time":"05:55:24","pid":49216,"ppid":49214,"name":"curl","proc":"/usr/bin/curl","target":"?:?","extra":"TCP","inferred":true,"note":"closed"}"#
        let inferred = try JSONDecoder().decode(ActivityEvent.self, from: Data(line.utf8))
        #expect(FirewallMonitor.facts(inferred) == nil)       // the firewall always knows where a connection goes
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fw"), fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("fwu-\(UUID()).json"))
        fw.mode = .watch
        #expect(fw.observe(inferred, status: .suspicious) == nil && fw.entries.isEmpty)
    }

    @Test func watchListsWhatWouldntPassAndJudgesAgain() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-fw-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fw"), fileURL: dir.appendingPathComponent("fw.json"))
        let e = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 5, to: "93.184.216.34:443", host: "example.com")
        #expect(fw.observe(e, status: .unclassified) == nil)                              // off: nothing
        fw.mode = .watch
        #expect(fw.observe(e, status: .unclassified)?.verdict == .ask)
        fw.observe(e, status: .unclassified)
        fw.observe(net("/usr/libexec/trustd", pid: 6, to: "17.1.2.3:443"), status: .unclassified)
        #expect(fw.entries.count == 1 && fw.entries.values.first?.count == 2 && fw.allowedCount == 1)
        #expect(fw.list(status: { _ in .unclassified }).first?.1.verdict == .ask)
        #expect(fw.list(status: { _ in .safe }).isEmpty)                                 // you allowed it since
        #expect(fw.list(status: { _ in .suspicious }).first?.1.verdict == .block)
        fw.save()
        let again = FirewallMonitor(defaults: scratchDefaults("hw-fw"), fileURL: dir.appendingPathComponent("fw.json"))
        #expect(again.entries.keys == fw.entries.keys && again.entries.values.first?.count == 2 && again.allowedCount == 1)
    }
}

/// Network ▸ Block for an App: one domain stopped for one program, whatever the program's pattern says.
@MainActor @Suite struct FirewallDomainBlocks {
    let app = "/Applications/Tool.app/Contents/MacOS/Tool"
    func facts(_ program: String, host: String, ip: String = "93.184.216.34") -> FirewallFacts {
        FirewallFacts(program: program, proto: "TCP", ip: ip, port: "443", host: host, risk: .normal, riskReason: "",
                      knownBad: "", patternKey: "net|\(program)|TCP internet:443")
    }

    @Test func yourBlockWinsOverASafePatternButNotTheLocalNetwork() {
        let hw = "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch"
        let blocked = FirewallPolicy.decide(facts(app, host: "api.example.com"), status: .safe, blockedDomain: "example.com", hostwatch: hw)
        #expect(blocked.verdict == .block && blocked.reason.contains("example.com"))
        // The app's one web pattern stays Safe: nothing else of it is stopped.
        #expect(FirewallPolicy.decide(facts(app, host: "other.org"), status: .safe, hostwatch: hw).verdict == .allow)
        #expect(FirewallPolicy.decide(facts(app, host: "nas.local", ip: "192.168.1.5"), status: .safe,
                                      blockedDomain: "nas.local", hostwatch: hw).verdict == .allow)
    }

    @Test func aBlockCoversTheDomainsHostsForThatAppOnly() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-fwd-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fwd"), fileURL: dir.appendingPathComponent("fw.json"))
        fw.setBlocked(true, domain: "example.com", program: "Tool")      // as the Network tab names the app
        #expect(fw.blockedDomain(facts(app, host: "api.example.com")) == "example.com")
        #expect(fw.blockedDomain(facts(app, host: "example.com")) == "example.com")
        #expect(fw.blockedDomain(facts(app, host: "example.org")) == nil)
        #expect(fw.blockedDomain(facts("/usr/bin/curl", host: "api.example.com")) == nil)
        #expect(fw.blockedDomain(facts(app, host: "")) == nil)                            // an address alone
        let again = FirewallMonitor(defaults: scratchDefaults("hw-fwd"), fileURL: dir.appendingPathComponent("fw.json"))
        #expect(again.isBlocked(domain: "example.com", program: app))                       // kept, path or name alike
        again.setBlocked(false, domain: "example.com", program: "Tool")
        #expect(again.blockedDomain(facts(app, host: "api.example.com")) == nil)
    }
}

/// Network ▸ Forget promises the destination is asked about again. A trusted app's web pattern is routine, which on
/// its own passes without asking, so forgetting a Block must not turn it into a silent Allow.
@MainActor @Suite struct FirewallForgetAsksAgain {
    @Test func aForgottenBlockIsAskedAboutAgainUntilYouDecide() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-fwf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fwf"), fileURL: dir.appendingPathComponent("fw.json"))
        fw.mode = .ask
        // macOS's own trustd: undecided, it passes without asking (as a trusted app's routine pattern does).
        let app = "/usr/libexec/trustd"
        let e = net(app, pid: 7, to: "93.184.216.34:443", host: "api.example.com")
        let store = SignatureStore(directory: dir)
        store.observe(e)
        #expect(fw.observe(e, status: store.status(for: e)) == nil || fw.entries.isEmpty)   // passes, not listed
        store.set(.suspicious, keys: [e.signatureKey], note: "blocked in Network")
        #expect(fw.observe(e, status: store.status(for: e))?.verdict == .block)
        let id = try #require(fw.entries.keys.first)

        _ = fw.forget([id], signatures: store)
        #expect(store.status(for: e) == .unclassified)
        // Today this passes silently: routine and undecided means Allow.
        #expect(fw.observe(e, status: store.status(for: e))?.verdict == .ask)
        // Another destination of the same program is not affected.
        let other = net(app, pid: 7, to: "1.2.3.4:443", host: "other.org")
        #expect(fw.observe(other, status: store.status(for: other))?.verdict == .allow)

        // A rule or the AI marking it Safe doesn't answer for you…
        #expect(FirewallPolicy.decide(FirewallMonitor.facts(e)!, status: .safe, askAgain: true).verdict == .ask)
        // …your own decision does, wherever you make it.
        store.onYouDecided = { fw.decided(patternKeys: $0) }
        store.set(.safe, keys: [e.signatureKey])
        #expect(!fw.asksAgain(FirewallMonitor.facts(e)!))
        #expect(fw.observe(e, status: store.status(for: e))?.verdict == .allow)
        let again = FirewallMonitor(defaults: scratchDefaults("hw-fwf"), fileURL: dir.appendingPathComponent("fw.json"))
        #expect(again.askAgain.isEmpty)
    }
}

/// When the relay fails, the firewall falls back to Watch and says so until you pick a mode again.
@MainActor @Suite struct FirewallFallbackWarning {
    @Test func failingRelayFallsBackAndWarnsUntilYouChoose() {
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fw-fallback"),
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("fwf-\(UUID()).json"))
        fw.mode = .ask
        fw.relayStatus("on", "")
        #expect(fw.fallback == nil)
        fw.relayStatus("failed", "The web check through the relay failed twice, so the firewall turned itself off.")
        #expect(fw.mode == .watch)
        #expect(fw.fallback?.from == .ask && fw.fallback?.why.contains("failed twice") == true)
        #expect(FirewallFallbackBanner.reason(fw.fallback!).hasPrefix("Ask stopped blocking: "))
        fw.mode = .ask                                         // "Turn Ask Back On", or any mode you pick
        #expect(fw.fallback == nil)
        fw.mode = .watch
        fw.relayStatus("failed", "x")                          // already in Watch: nothing turned off, no warning
        #expect(fw.fallback == nil)
    }
}
