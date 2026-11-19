import Foundation
import Testing
@testable import Hostwatch

/// Protection with Endpoint Security, without the kernel: what the collector settles alone, and how every held
/// launch or open is answered exactly once.
@Suite(.serialized) struct AgentGuardHolds {
    let home = "/Users/me"
    var config: HoldConfig {
        HoldConfig(launches: true, files: true, places: [
            HoldPlace(id: "ssh", prefixes: ["/Users/me/.ssh"], owners: ["ssh", "git"]),
            HoldPlace(id: "browsers", prefixes: ["/Users/me/Library/Application Support/Google/Chrome"],
                      names: ["Cookies", "Login Data"]),
            HoldPlace(id: "autostart", prefixes: ["/Users/me/Library/LaunchAgents"], writesOnly: true),
            HoldPlace(id: "mine", prefixes: ["/Users/me/Documents/contracts"], blocked: ["/opt/homebrew/bin/rclone"]),
        ], hostwatch: "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch")
    }

    func exec(_ path: String, args: String = "", uid: uid_t = 501, pid: Int = 900) -> HoldRequest {
        HoldRequest(what: .exec, path: path, pid: pid, ppid: 800, parent: "/opt/homebrew/bin/fish", args: args, uid: uid, seconds: 30)
    }

    func open(_ program: String, _ file: String, mode: String = "r", uid: uid_t = 501) -> HoldRequest {
        HoldRequest(what: .open, path: program, pid: 901, ppid: 800, file: file, mode: mode, uid: uid, seconds: 30)
    }

    func local(_ r: HoldRequest, ours: Set<Int> = []) -> (allow: Bool, reason: String)? {
        config.local(r, userUID: 501, ours: { ours.contains($0) })
    }

    @Test func launchesTheAppMustDecideGoToIt() {
        #expect(local(exec("/usr/bin/curl", args: "curl test.ua")) == nil)          // runs whatever it's told
        #expect(local(exec("/opt/homebrew/bin/rclone")) == nil)                     // not macOS's own
        #expect(local(exec("/usr/bin/ditto")) == nil)                                 // copies anything: asked
        #expect(local(exec("/usr/bin/sw_vers"))?.allow == true)                       // macOS's own program
        #expect(local(exec("/opt/homebrew/bin/rclone", uid: 0))?.allow == true)      // not your process
        #expect(local(exec("/opt/homebrew/bin/rclone", pid: 77), ours: [77])?.allow == true)   // Hostwatch's own
        #expect(local(exec(config.hostwatch))?.allow == true)
        var off = config; off.launches = false
        #expect(off.local(exec("/usr/bin/curl"), userUID: 501, ours: { _ in false })?.allow == true)
    }

    @Test func opensOnlyInProtectedPlacesAndByWhoIsNotExpected() {
        #expect(local(open("/usr/bin/python3", "/Users/me/.ssh/id_ed25519")) == nil)
        #expect(local(open("/usr/bin/cat", "/Users/me/.ssh/id_ed25519"))?.allow == true)            // as the app's risk says
        #expect(local(open("/usr/bin/ssh", "/Users/me/.ssh/id_ed25519"))?.allow == true)            // expected there
        #expect(local(open("/usr/bin/ssh-agent", "/Users/me/.ssh/id_ed25519"))?.allow == true)      // by name prefix
        #expect(local(open("/usr/bin/python3", "/Users/me/.sshfoo/x"))?.allow == true)                   // not inside
        #expect(local(open("/usr/bin/python3", "/Users/me/notes.txt"))?.allow == true)
        let chrome = "/Users/me/Library/Application Support/Google/Chrome/Default/"
        #expect(local(open("/usr/bin/python3", chrome + "Cookies")) == nil)                          // a credential store
        #expect(local(open("/usr/bin/python3", chrome + "History"))?.allow == true)                  // the rest of a profile
        #expect(local(open("/usr/bin/python3", "/Users/me/Library/LaunchAgents/x.plist"))?.allow == true)   // reading
        #expect(local(open("/usr/bin/python3", "/Users/me/Library/LaunchAgents/x.plist", mode: "w")) == nil)
        let blocked = local(open("/opt/homebrew/bin/rclone", "/Users/me/Documents/contracts/a.pdf"))
        #expect(blocked?.allow == false && blocked?.reason.isEmpty == false)
        #expect(local(open("/System/Applications/Mail.app/Contents/MacOS/Mail", "/Users/me/.ssh/known_hosts"))?.allow == true)
    }

    @Test func configReadsTheAppsShape() {
        let c = HoldConfig(["launches": "ask", "files": "watch", "hostwatch": "/H",
                            "groups": [["id": "ssh", "prefixes": ["/Users/me/.ssh"], "owners": ["ssh"], "writesOnly": false]]])
        #expect(c.launches && !c.files && c.places.count == 1 && c.prefixes.isEmpty)
        #expect(HoldConfig(["files": "strict", "groups": [["id": "a", "prefixes": ["/x"]]]]).prefixes == ["/x"])
    }

    // MARK: Answers

    final class Rig: @unchecked Sendable {
        let g = AgentGuard()
        let client: AgentClient
        let lock = NSLock()
        var lines: [[String: Any]] = []
        var results: [String: [Bool]] = [:]

        init(config: [String: Any] = ["launches": "ask", "files": "ask", "groups": []]) {
            var fds: [Int32] = [0, 0]
            socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
            client = AgentClient(fd: fds[0])
            client.uid = 501
            g.quick = 60                                             // the timers are driven by hand
            g.send = { [unowned self] _, ev in
                let obj = (try? JSONSerialization.jsonObject(with: ev.jsonLine())) as? [String: Any] ?? [:]
                self.lock.lock(); self.lines.append(obj); self.lock.unlock()
            }
            g.configure(config, from: client)
        }

        func hold(_ name: String, _ r: HoldRequest) {
            g.request(r) { [unowned self] allow in self.lock.lock(); self.results[name, default: []].append(allow); self.lock.unlock() }
        }
        func kinds() -> [String] { lock.lock(); defer { lock.unlock() }; return lines.compactMap { $0["kind"] as? String } }
        func lastID() -> Int { lock.lock(); defer { lock.unlock() }; return lines.last(where: { $0["kind"] as? String == "guard_ask" })?["id"] as? Int ?? 0 }
    }

    @Test func theAppsAnswerIsGivenOnceAndReusedExactly() {
        let rig = Rig()
        let curl = exec("/usr/bin/curl", args: "curl test.ua")
        rig.hold("a", curl)
        #expect(rig.kinds().last == "guard_ask" && rig.results["a"] == nil)
        rig.g.answer(["id": rig.lastID(), "allow": false, "ttl": 60])
        rig.g.answer(["id": rig.lastID(), "allow": true, "ttl": 60])                 // a second answer changes nothing
        #expect(rig.results["a"] == [false])
        rig.hold("b", curl)                                                            // the same launch again
        #expect(rig.results["b"] == [false] && rig.kinds().last == "guard_block")
        rig.hold("c", exec("/usr/bin/curl", args: "curl ukr.net"))                      // another one is asked about
        #expect(rig.results["c"] == nil && rig.kinds().last == "guard_ask")
        rig.g.answer(["id": rig.lastID(), "allow": true, "ttl": 0])                     // once: not reused
        rig.hold("d", exec("/usr/bin/curl", args: "curl ukr.net"))
        #expect(rig.results["c"] == [true] && rig.results["d"] == nil)
    }

    @Test func silenceLetsItGoAndYourQuestionBlocksAtTheDeadline() {
        let rig = Rig()
        rig.hold("quiet", exec("/usr/bin/curl", args: "curl a"))
        let quiet = rig.lastID()
        rig.g.quiet(quiet)                                                             // no quick answer: it goes on
        #expect(rig.results["quiet"] == [true] && rig.kinds().last == "guard_late")
        rig.g.expire(quiet)
        #expect(rig.results["quiet"] == [true])                                         // never answered twice

        rig.hold("asked", exec("/usr/bin/curl", args: "curl b"))
        let asked = rig.lastID()
        rig.g.wait(["id": asked])                                                      // you're being asked
        rig.g.quiet(asked)
        #expect(rig.results["asked"] == nil)
        rig.g.expire(asked)                                                            // macOS's deadline
        #expect(rig.results["asked"] == [false] && rig.kinds().last == "guard_block")
        #expect(rig.g.pendingCount == 0)
    }

    @Test func withoutTheAppEverythingGoesOn() {
        let rig = Rig()
        rig.hold("held", exec("/usr/bin/curl", args: "curl c"))
        rig.g.clientGone(rig.client)
        #expect(rig.results["held"] == [true] && rig.g.pendingCount == 0 && !rig.g.isDeciding)
        rig.hold("after", exec("/usr/bin/curl", args: "curl d"))
        #expect(rig.results["after"] == [true])
    }
}
