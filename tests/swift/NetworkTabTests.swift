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

    @Test func remembersWhichSectionIsShown() {
        let defaults = UserDefaults.standard
        let saved = defaults.string(forKey: "networkSection")
        defer { if let saved { defaults.set(saved, forKey: "networkSection") } else { defaults.removeObject(forKey: "networkSection") } }
        DomainsViewState().section = .domains
        #expect(DomainsViewState().section == .domains)
        DomainsViewState().section = .firewall
        #expect(DomainsViewState().section == .firewall)
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

    /// HOSTWATCH_RENDER=<dir> writes network-firewall.png there.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil)) func render() throws {
        let (fw, store) = firewall()
        let view = FirewallTabView(firewall: fw, signatures: store, search: "")
            .frame(width: 1000, height: 520).background(Color(nsColor: .windowBackgroundColor))
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(x: 0, y: 0, width: 1000, height: 520)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("network-firewall.png"))
    }
}
