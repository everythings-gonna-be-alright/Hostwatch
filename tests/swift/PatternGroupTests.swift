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

/// The Patterns list is built off the main thread from a copy of the store; it must say exactly what the store says.
@MainActor @Suite(.serialized) struct PatternListBuilding {
    func store() -> SignatureStore {
        _ = TestEnv.ready
        let s = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("hw-list-\(UUID().uuidString)"))
        s.showSeenOnce = true
        for (i, host) in ["google.us", "example.com", "pypi.org", "github.com"].enumerated() {
            let e = net("/usr/bin/curl", pid: 50 + i, to: "142.250.1.\(i):443", host: host)
            _ = s.observe(e); _ = s.observe(e)
        }
        let tool = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 70, to: "45.1.2.3:443")
        _ = s.observe(tool); _ = s.observe(tool)
        let keys = s.allEntries.map(\.id).sorted()
        s.set(.dangerous, keys: [keys[0]])
        s.set(.safe, keys: [keys[1]], note: "allowed in Firewall")
        return s
    }

    @Test func backgroundRowsMatchTheStore() {
        let s = store()
        defer { s.showSeenOnce = false }
        let (items, counts) = s.patternInput(filter: .all).compute()
        #expect(items.count == s.allEntries.count)
        for item in items {
            #expect(item.status == s.status(forKey: item.id))
            #expect(item.decidedBy == s.decidedBy(item.id))
            #expect(item.note == s.note(forKey: item.id).note && item.source == s.note(forKey: item.id).source)
        }
        for status in SignatureStatus.allCases { #expect((counts.byStatus[status] ?? 0) == s.count(status)) }
        let important = s.allEntries.filter {
            SignatureFilter.important.admits(s.status(forKey: $0.id), risk: $0.risk, reviewed: s.reviewedByYou($0.id))
        }.count
        #expect(counts.important == important && important >= 1)
    }

    @Test func fastSortingAgreesWithTheTablesComparator() {
        let s = store()
        defer { s.showSeenOnce = false }
        let items = s.patternInput(filter: .all).compute().items
        for order in [KeyPathComparator(\PatternItem.count, order: .reverse), KeyPathComparator(\PatternItem.priority),
                      KeyPathComparator(\PatternItem.lastSeen, order: .reverse)] {
            let fast = PatternItem.sorted(items, by: [order]).map { $0[keyPath: order.keyPath] as! AnyHashable }
            let slow = items.sorted(using: [order]).map { $0[keyPath: order.keyPath] as! AnyHashable }
            #expect(fast == slow)
        }
    }

    @Test func theModelPublishesRowsAndCounts() async throws {
        let s = store()
        defer { s.showSeenOnce = false }
        let model = PatternListModel()
        model.build(s, filter: .all, wait: true)
        #expect(model.shown == 5 && model.counts.byStatus[.dangerous] == s.count(.dangerous))
        let important = s.patternItems(filter: .important).count
        s.groupByProcess = true
        model.build(s, filter: .important)                              // in the background
        for _ in 0..<50 where model.shown != important { try await Task.sleep(nanoseconds: 20_000_000) }
        #expect(model.shown == important && important < 5)
    }
}
