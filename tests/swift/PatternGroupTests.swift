import AppKit
import Foundation
import SwiftUI
import Testing
@testable import Hostwatch

/// Patterns grouped by program: one row per program with its patterns under it.
@MainActor @Suite(.serialized) struct PatternGroups {
    func store() -> SignatureStore {
        _ = TestEnv.ready
        let s = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("hw-group-\(UUID().uuidString)"))
        s.showSeenOnce = true
        return s
    }

    func fill(_ s: SignatureStore) -> (curl: [String], tool: String) {
        var curl: [String] = []
        for (i, host) in ["google.us", "example.com", "pypi.org"].enumerated() {
            let e = net("/usr/bin/curl", pid: 50 + i, to: "142.250.1.\(i):443", host: host)
            _ = s.observe(e); _ = s.observe(e)
            curl.append(e.signatureKey)
        }
        s.set(.dangerous, keys: [curl[1]])
        s.set(.safe, keys: [curl[2]])
        let tool = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 70, to: "45.1.2.3:443")
        _ = s.observe(tool); _ = s.observe(tool)
        return (curl, tool.signatureKey)
    }

    @Test func oneRowPerProgramWithTheMostSeriousStatus() throws {
        let s = store()
        defer { s.showSeenOnce = false }
        let (curl, tool) = fill(s)
        let items = s.patternItems(filter: .all)
        let rows = PatternItem.grouped(items, order: [KeyPathComparator(\.lastSeen, order: .reverse)])
        let group = try #require(rows.first { $0.id == "group:curl" })
        #expect(group.children?.count == 3 && Set(group.children!.map(\.id)) == Set(curl))
        #expect(group.status == .dangerous)                                   // the most serious of its patterns
        #expect(group.newCount == 1 && group.pattern == "3 patterns · 1 New")
        #expect(group.count == 6 && group.kinds == [.net])
        #expect(rows.contains { $0.id == tool && !$0.isGroup })              // a single pattern stays a plain row
    }

    @Test func aProgramRowStandsForItsPatterns() {
        let s = store()
        defer { s.showSeenOnce = false }
        let (curl, tool) = fill(s)
        #expect(s.keys(forSelection: ["group:curl"]) == curl.sorted())
        #expect(Set(s.keys(forSelection: ["group:curl", tool])) == Set(curl + [tool]))
        s.set(.suspicious, keys: s.keys(forSelection: ["group:curl"]))
        #expect(curl.allSatisfy { s.status(forKey: $0) == .suspicious })
    }

    /// HOSTWATCH_RENDER=<dir> writes patterns-grouped.png there.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil)) func render() throws {
        let s = store()
        defer { s.showSeenOnce = false }
        _ = fill(s)
        s.groupByProcess = true
        let classifier = PatternClassifier(store: s)
        let view = PatternsView(signatures: s, classifier: classifier,
                                actions: HUDActions(openFullScreen: {}, openExclusions: {}, toggleCollector: {}, quit: {}, askAI: { _ in }),
                                filter: .constant(.all))
            .frame(width: 1200, height: 300).background(Color(nsColor: .windowBackgroundColor))
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(x: 0, y: 0, width: 1200, height: 300)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.4))
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("patterns-grouped.png"))
    }
}
