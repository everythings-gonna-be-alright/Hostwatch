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
