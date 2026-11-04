import AppKit
import SwiftUI
import Testing
@testable import Hostwatch

/// The Network tab: the firewall (mode, waiting connections, what's blocked or asked about) next to the domains.
@MainActor @Suite(.serialized) struct NetworkTab {
    func firewall() -> (FirewallMonitor, SignatureStore) {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-net-\(UUID().uuidString)")
        let store = SignatureStore(directory: dir)
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-net"), fileURL: dir.appendingPathComponent("fw.json"))
        fw.answer = { _, _, _ in }
        fw.mode = .ask
        for (proc, to, host) in [("/Users/someone/Downloads/updater", "203.0.113.9:8443", "cdn.example.net"),
                                 ("/opt/tools/bin/syncd", "93.184.216.34:443", "api.example.com"),
                                 ("/usr/local/bin/fetcher", "198.18.0.7:80", "")] {
            _ = fw.observe(net(proc, pid: 9, to: to, host: host), status: .unclassified)
        }
        fw.handleAsk(key: "k", event: net("/usr/bin/curl", pid: 7, to: "93.184.216.34:443", host: "example.com"))
        return (fw, store)
    }

    @Test func remembersTheFilter() {
        let defaults = UserDefaults.standard
        let saved = defaults.string(forKey: "networkFilter")
        defer { if let saved { defaults.set(saved, forKey: "networkFilter") } else { defaults.removeObject(forKey: "networkFilter") } }
        NetworkViewState().filter = .attention
        #expect(NetworkViewState().filter == .attention)
        NetworkViewState().filter = .all
        #expect(NetworkViewState().filter == .all)
    }

    /// One row per destination: a domain's firewall connections go under it, an address without a name gets its
    /// own row, and the row shows the most urgent thing the firewall does there.
    @Test func domainsAndFirewallMergeIntoOneTimeline() throws {
        let (fw, store) = firewall()
        let now = Date()
        let records = [DomainRecord(domain: "example.com", firstSeen: now.addingTimeInterval(-60), lastSeen: now.addingTimeInterval(-30),
                                    count: 4, programs: ["syncd"], hosts: ["api.example.com"], baseline: false),
                       DomainRecord(domain: "quiet.org", firstSeen: now.addingTimeInterval(-9000), lastSeen: now.addingTimeInterval(-8000),
                                    count: 1, programs: ["Safari"], hosts: ["www.quiet.org"], baseline: true)]
        let entries = fw.list(status: { store.status(forKey: $0) })
        let rows = NetworkRow.build(records: records, isNew: { !$0.baseline }, entries: entries, byYou: { _ in false },
                                    waiting: Set(fw.prompts.map(\.patternKey)), firewallOn: true)
        let example = try #require(rows.first { $0.destination == "example.com" })
        #expect(example.isNew && example.status == "New" && example.firewall == .undecided)
        #expect(example.children?.map(\.destination) == ["syncd"] && example.children?.first?.detail == "TCP api.example.com:443")
        let quiet = try #require(rows.first { $0.destination == "quiet.org" })
        #expect(quiet.firewall == .passes && quiet.children == nil && quiet.status == "Baseline")
        #expect(rows.contains { $0.destination == "example.net" && $0.record == nil })        // cdn.example.net, not in the inventory
        #expect(rows.contains { $0.destination == "198.18.0.7" && $0.statusRank == 4 })      // an address without a name

        let off = NetworkRow.build(records: records, isNew: { _ in false }, entries: entries, byYou: { _ in false },
                                   waiting: [], firewallOn: false)
        #expect(off.allSatisfy { $0.firewall == .off })
        let mine = NetworkRow.build(records: records, isNew: { _ in false }, entries: entries, byYou: { _ in true },
                                    waiting: [], firewallOn: true)
        #expect(mine.first { $0.destination == "example.com" }?.firewall == .undecided)      // byYou only matters for blocks
    }

    @Test func answeringInTheListAnswersTheQuestion() throws {
        let (fw, _) = firewall()
        var answered: [(String, Bool)] = []
        fw.answer = { key, pass, _ in answered.append((key, pass)) }
        let id = try #require(fw.prompts.first?.id)
        fw.resolve(id, allow: false)
        #expect(fw.prompts.isEmpty && answered.count == 1 && answered[0] == ("k", false))
    }

    @Test func modesHaveShortNames() {
        #expect(FirewallMode.allCases.map(\.short) == ["Off", "Watch", "Ask", "Strict"])
    }

    /// HOSTWATCH_RENDER=<dir> writes network.png and settings-firewall.png there.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil)) func render() throws {
        let (fw, store) = firewall()
        let domains = DomainRegistry(replayLearningUntil: Date().addingTimeInterval(-1))
        let t = Date()
        for (i, h) in ["api.example.com", "www.apple.com", "cdn.example.net", "docs.swift.org"].enumerated() {
            domains.observe(net("/opt/tools/bin/syncd", pid: 9, to: "93.184.216.\(i):443", host: h), at: t.addingTimeInterval(Double(i) * 30))
        }
        let state = NetworkViewState()
        state.filter = .all
        state.selection = ["d:example.com"]
        try write(NetworkView(domains: domains, firewall: fw, signatures: store, state: state, search: ""), "network", 1100, 460)
        try write(FirewallPane(firewall: fw, signatures: store).frame(width: 560), "settings-firewall", 560, 520)
    }

    func write<V: View>(_ view: V, _ name: String, _ w: CGFloat, _ h: CGFloat) throws {
        let host = NSHostingView(rootView: view.frame(width: w, height: h).background(Color(nsColor: .windowBackgroundColor)))
        host.frame = NSRect(x: 0, y: 0, width: w, height: h)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.4))
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("\(name).png"))
    }
}
