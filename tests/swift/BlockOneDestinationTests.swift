import Foundation
import Testing
@testable import Hostwatch

/// Always Block on a firewall question blocks that destination for that program, never the program's whole web
/// pattern (`TCP internet:443`), and Unblock is in effect at once.
@MainActor @Suite struct BlockOneDestination {
    func monitor() -> FirewallMonitor {
        _ = TestEnv.ready
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fwd"),
                                 fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("fwd-\(UUID()).json"))
        fw.mode = .ask
        return fw
    }
    let tool = "/opt/homebrew/bin/kubescape"

    @Test func alwaysBlockBlocksOnlyThatDomain() throws {
        let fw = monitor()
        var marked: [SignatureStatus] = [], answers: [(String, Bool)] = [], flushed = 0
        fw.markPattern = { marked.append($1) }
        fw.answer = { key, pass, _ in answers.append((key, pass)) }
        fw.flushAnswers = { flushed += 1 }
        let bad = net(tool, pid: 7, to: "93.184.216.34:443", host: "api.tracker.example")
        let good = net(tool, pid: 7, to: "140.82.112.3:443", host: "api.github.com")
        #expect(bad.signatureKey.hasSuffix("TCP internet:443") && bad.signatureKey == good.signatureKey)   // one pattern for the web
        fw.handleAsk(key: "k1", event: bad)
        fw.handleAsk(key: "k2", event: good)
        let prompt = try #require(fw.prompts.first { $0.key == "k1" })
        fw.resolve(prompt.id, allow: false)

        #expect(marked.isEmpty)                                                // the pattern stays undecided
        #expect(fw.isBlocked(domain: "tracker.example", program: tool) && flushed == 1)
        #expect(answers.map(\.0) == ["k1"] && answers[0].1 == false)
        #expect(fw.prompts.map(\.key) == ["k2"])                               // github is still asked about
        let decide = { (e: ActivityEvent) in
            let f = try #require(FirewallMonitor.facts(e))
            return FirewallPolicy.decide(f, status: .unclassified, app: fw.appRules(for: f.program)).verdict
        }
        #expect(try decide(bad) == .block && decide(good) == .ask)
    }

    @Test func anAddressWithoutANameIsBlockedByAddress() throws {
        let fw = monitor()
        let bare = net(tool, pid: 7, to: "198.18.0.7:443")
        fw.handleAsk(key: "k", event: bare)
        fw.resolve(try #require(fw.prompts.first).id, allow: false)
        let f = try #require(FirewallMonitor.facts(bare))
        #expect(fw.blockedDomain(f) == "198.18.0.7")
        #expect(fw.apps.first?.destinations.map(\.target) == ["198.18.0.7"])
    }

    @Test func clearingAConnectionPatternFlushesAtOnce() throws {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("fwd-sig-\(UUID())"))
        let e = net(tool, pid: 7, to: "93.184.216.34:443", host: "api.tracker.example")
        _ = store.observe(e)
        var cleared: [[String]] = []
        store.onStatusSet = { cleared.append($0) }
        store.set(.suspicious, keys: [e.signatureKey], note: "blocked in Firewall")
        store.set(.unclassified, keys: [e.signatureKey])                       // Unblock in Your rules
        #expect(cleared == [[e.signatureKey], [e.signatureKey]])
    }
}
