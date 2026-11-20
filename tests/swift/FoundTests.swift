import Foundation
import Testing
@testable import Hostwatch

/// Found: one list of launches, files and connections, grouped by program, filtered, and quick to act on.
@MainActor @Suite struct FoundList {
    func finding(_ program: String, _ pattern: String, area: ProtectionArea = .files, block: Bool = false,
                 count: Int = 1, seen: Date = Date()) -> FoundItem {
        FoundItem(finding: ProtectionFinding(id: "\(area.rawValue)|\(program)|\(pattern)", area: area, patternKey: pattern,
                                             name: (program as NSString).lastPathComponent, program: program, pattern: pattern,
                                             verdict: block ? .block : .ask, reason: "r", group: nil, count: count,
                                             firstSeen: seen, lastSeen: seen))
    }

    @Test func groupedByProgramStopsFirst() {
        let items = [finding("/usr/bin/curl", "a", count: 9), finding("/usr/bin/curl", "b", block: true),
                     finding("/opt/x", "c", count: 50)]
        let groups = FoundGroup.make(items, sort: .often)
        #expect(groups.map(\.name) == ["curl", "x"])                  // a program that would be stopped comes first
        #expect(groups[0].items.map(\.what) == ["b", "a"] && groups[0].stops == 1 && groups[0].total == 10)
        #expect(FoundGroup.make(items, sort: .name).map(\.name) == ["curl", "x"])
    }

    @Test func filtersAndSearch() {
        let s = FoundState()
        let items = [finding("/usr/bin/curl", "r ~/.ssh/*", block: true), finding("/bin/zsh", "exec /tmp/x", area: .launches)]
        s.area = .launches
        #expect(s.filter(items).map(\.programName) == ["zsh"])
        s.area = .all; s.kind = .stops
        #expect(s.filter(items).map(\.programName) == ["curl"])
        s.kind = .everything; s.search = "SSH"
        #expect(s.filter(items).map(\.programName) == ["curl"])
    }

    @Test func forgettingIsOnScreenAtOnce() {
        let suite = "found-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
        let before = m.revision
        m.forget(["nothing"])
        #expect(m.revision == before + 1)                            // not after the next batch, a second later
    }

    @Test func programsKeepTheirPlaceWhileYouDecide() {
        let s = FoundState()
        var items = [finding("/usr/bin/curl", "a", count: 9), finding("/usr/bin/curl", "b", count: 8),
                     finding("/opt/x", "c", count: 12), finding("/opt/y", "d", count: 1)]
        #expect(s.arrange(FoundGroup.make(items, sort: .often)).map(\.name) == ["curl", "x", "y"])
        // Forgetting curl's biggest entry would sort it below x: it stays first, and its other entry keeps its place.
        items.removeAll { $0.what == "a" }
        items.append(finding("/opt/z", "e", block: true))          // new, and it would be stopped: after the others
        let kept = s.arrange(FoundGroup.make(items, sort: .often))
        #expect(kept.map(\.name) == ["curl", "x", "y", "z"])
        // A new sort orders everything afresh.
        s.sort = .name
        #expect(s.arrange(FoundGroup.make(items, sort: .name)).map(\.name) == ["curl", "x", "y", "z"])
        s.sort = .often
        #expect(s.arrange(FoundGroup.make(items, sort: .often)).first?.name == "z")
    }
}
