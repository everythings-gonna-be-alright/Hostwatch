import Foundation
import Testing
@testable import Hostwatch

/// A helper the collector starts is, for an instant, its copy: named Hostwatch, holding the collector's sockets (the
/// firewall relay's connections to other apps' destinations). Those are never reported as someone's connections.
@Suite struct OwnSocketsInHelpers {
    @Test func aChildOfTheCollectorIsOurs() {
        let agent = Agent()
        agent.rememberPid(70_001, path: "/sbin/pfctl", ppid: agent.selfPid)
        agent.rememberPid(70_002, path: "/usr/bin/curl", ppid: 70_003)
        #expect(agent.isOursOrStarting(70_001))
        #expect(!agent.isOursOrStarting(70_002))
    }

    @Test func itsByteCountsAreLeftOut() {
        let agent = Agent()
        agent.rememberPid(70_011, path: "/sbin/pfctl", ppid: agent.selfPid)
        agent.rememberPid(70_012, path: "/usr/bin/curl", ppid: 1)
        let report = agent.trafficReport([(pid: 70_011, name: "Hostwatch", remote: "104.18.19.125", sent: 900, received: 100),
                                          (pid: 70_012, name: "curl", remote: "104.18.19.125", sent: 10, received: 10)])
        #expect(report.map(\.name) == ["curl"])
    }
}

/// What was stored from those sockets before is dropped at launch, unless someone decided it.
@MainActor @Suite struct OwnSocketsCleanup {
    func copy(_ remote: String) -> ActivityEvent {
        ActivityEvent(kind: .net, time: "12:00:00", pid: 25_927, ppid: 22_788, name: "Hostwatch", proc: "/sbin/pfctl",
                      target: remote, extra: "TCP", parent: "", host: "cursor.sh", hostSource: "dns")
    }

    @Test func patternsFromThemAreDropped() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ownsockets-\(UUID().uuidString)")
        let store = SignatureStore(directory: dir)
        let stray = copy("104.18.19.125:443"), decided = copy("192.168.1.19:57501")
        _ = store.observe(stray); _ = store.observe(decided)
        store.set(.suspicious, keys: [decided.signatureKey])
        store.save(sync: true)
        let reopened = SignatureStore(directory: dir)
        #expect(reopened.entry(stray.signatureKey) == nil)
        #expect(reopened.entry(decided.signatureKey)?.status == .suspicious)     // yours stays
    }

    @Test func mapEntriesFromThemAreDropped() {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("ownmap-\(UUID().uuidString).json")
        let store = NetworkMapStore(fileURL: file)
        store.observeOutgoing(copy("104.18.19.125:443"), blocked: false)
        let curl = ActivityEvent(kind: .net, time: "12:00:00", pid: 501, ppid: 1, name: "curl", proc: "/usr/bin/curl",
                                 target: "93.184.216.34:443", extra: "TCP", parent: "", host: "www.example.com", hostSource: "dns")
        store.observeOutgoing(curl, blocked: false)
        store.save()
        let reopened = NetworkMapStore(fileURL: file)
        #expect(reopened.outgoing.values.map(\.program) == ["curl"])
    }
}

/// pfctl is started with its three standard files and nothing else of the collector's.
@Suite struct HelpersGetNoSockets {
    @Test func outputErrorsAndStatusApart() {
        let r = Spawned.runCapturing("/bin/sh", ["-c", "read line; echo \"got $line\"; echo oops >&2; exit 3"], input: "rules\n")
        #expect(r.status == 3 && r.out == "got rules\n" && r.err == "oops\n")
    }

    @Test func aSocketTheCollectorHoldsIsNotInherited() {
        let s = socket(AF_INET, SOCK_STREAM, 0)                  // not close-on-exec, like a relay connection
        let fd = dup2(s, 50)                                      // far from what the shell itself opens
        close(s)
        #expect(fd == 50)
        defer { close(fd) }
        let open = Spawned.runCapturing("/bin/sh", ["-c", "for f in /dev/fd/*; do echo ${f##*/}; done"]).out
            .split(separator: "\n").compactMap { Int($0) }
        #expect(!open.contains(Int(fd)))
        #expect(open.allSatisfy { $0 <= 3 })                    // 0, 1, 2 and the shell's own directory listing
    }
}
