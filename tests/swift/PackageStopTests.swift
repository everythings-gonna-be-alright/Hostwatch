import Foundation
import Testing
@testable import Hostwatch

/// ADR 0024, layer 3: install scripts and named installs recognised, the compact lists, the collector's stop, the
/// Claude Code guard's check and Strict's quarantine.
@MainActor @Suite(.serialized) struct PackageStopTests {
    func ref(_ e: PackageEcosystem, _ n: String, _ v: String) -> PackageRef { PackageRef(ecosystem: e, name: n, version: v) }
    func names(_ args: String) -> [String] {
        InstallContext.namedInstalls(args.split(separator: " ").map(String.init)).map { $0.package.label.trimmingCharacters(in: .whitespaces) }
    }

    // MARK: What a launch installs

    @Test func installScriptsCarryTheirPackage() {
        let npm = InstallContext.script(path: "/bin/sh", args: ["sh", "-c", "node install.js"], cwd: "",
                                        env: ["npm_lifecycle_event": "postinstall", "npm_package_name": "evil", "npm_package_version": "1.0.2"])
        #expect(npm == InstallTarget(package: ref(.npm, "evil", "1.0.2"), how: .script, detail: "postinstall"))
        // Your own `npm run build` has the package in its environment too, but it isn't an install.
        #expect(InstallContext.script(path: "/bin/sh", args: [], cwd: "",
                                      env: ["npm_lifecycle_event": "build", "npm_package_name": "shop"]) == nil)
        let cargo = InstallContext.script(path: "/p/target/debug/build/evil-1a2b/build-script-build", args: [], cwd: "",
                                          env: ["CARGO_PKG_NAME": "evil", "CARGO_PKG_VERSION": "0.1.0"])
        #expect(cargo?.package == ref(.crates, "evil", "0.1.0"))
        // `cargo run` of your own crate has CARGO_PKG_NAME too: only a build script counts.
        #expect(InstallContext.script(path: "/p/target/debug/shop", args: [], cwd: "", env: ["CARGO_PKG_NAME": "shop"]) == nil)
        let pip = InstallContext.script(path: "/usr/bin/python3", args: ["python3", "/x/_in_process.py", "build_wheel"],
                                        cwd: "/tmp/pip-install-1/evil_abc", env: [:]) { path in
            path == "/tmp/pip-install-1/evil_abc/PKG-INFO" ? "Metadata-Version: 2.1\nName: Evil-Pkg\nVersion: 2.0\n\nbody" : nil
        }
        #expect(pip?.package == ref(.pypi, "Evil-Pkg", "2.0"))
        let gem = InstallContext.script(path: "/usr/bin/ruby", args: ["ruby", "extconf.rb"],
                                        cwd: "/Users/me/.gem/ruby/3.3.0/gems/evil-gem-1.2.3/ext/evil", env: [:])
        #expect(gem?.package == ref(.rubygems, "evil-gem", "1.2.3"))
    }

    @Test func namedInstallsAreReadFromTheCommandLine() {
        #expect(names("npm install a b@1.2.3 -D --registry https://r.example") == ["a", "b 1.2.3"])
        #expect(names("npm i @scope/x@^1.0 @scope/y@2.0.0") == ["@scope/x", "@scope/y 2.0.0"])
        #expect(names("node /opt/homebrew/lib/node_modules/npm/bin/npm-cli.js install y") == ["y"])
        #expect(names("python3 -m pip install -r requirements.txt foo==1.0 bar[extra]>=2 ./local") == ["foo 1.0", "bar"])
        #expect(names("pip3.12 install Evil") == ["Evil"])
        #expect(names("uv pip install x") == ["x"])
        #expect(names("npx cowsay hello world") == ["cowsay"])          // only the package, not its arguments
        #expect(names("pnpm dlx create-thing my-app") == ["create-thing"])
        #expect(names("pipx run black --check .") == ["black"])
        #expect(names("cargo add serde@1.0.1") == ["serde 1.0.1"])
        #expect(names("go get github.com/a/b@v1.2.3") == ["github.com/a/b v1.2.3"])
        #expect(names("gem install rails") == ["rails"])
        for none in ["npm run build", "npm install", "yarn", "go build ./...", "go run main.go", "npm test",
                     "pip install -e .", "npm install github:user/repo", "ls -la", "node server.js install x"] {
            #expect(names(none).isEmpty, "\(none)")
        }
        #expect(InstallContext.namedInstalls(["npx", "x"]).first?.how == .run)
        #expect(InstallContext.namedInstalls(["npm", "install", "x"]).first?.how == .install)
    }

    // MARK: The compact lists

    func lists() -> ListedPackages {
        var l = ListedPackages()
        l.add(index: Data("evil\tMAL-1\t*\nchalk\tMAL-2\t=5.6.1\nfsevents\tMAL-3\t>1.0.0<1.2.11\nOrchestrator\tMAL-4\t*\n".utf8), ecosystem: .npm)
        l.add(index: Data("evil-pkg\tMAL-9\t*\n".utf8), ecosystem: .pypi)
        return l
    }

    @Test func compactListsFindWhatTheIndexLists() {
        let l = lists()
        #expect(l.record(for: ref(.npm, "evil", "")) != nil)                // every version: even an unknown one
        #expect(l.record(for: ref(.npm, "chalk", "5.6.1"))?.id == "MAL-2")
        #expect(l.record(for: ref(.npm, "chalk", "5.6.2")) == nil)
        #expect(l.record(for: ref(.npm, "chalk", "")) == nil)              // a version list needs the version
        #expect(l.record(for: ref(.npm, "fsevents", "1.1.2"))?.id == "MAL-3")
        #expect(l.record(for: ref(.npm, "orchestrator", "1.0.0")) == nil)  // npm names keep their case
        #expect(l.record(for: ref(.pypi, "Evil_Pkg", "1.0")) != nil)       // PyPI's don't
        #expect(l.record(for: ref(.npm, "left-pad", "1.0.0")) == nil)
        // Across the socket and back, the same lists.
        let wire = try! JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: l.payload)) as! [String: Any]
        #expect(ListedPackages(payload: wire) == l)
    }

    // MARK: The collector

    final class Rig: @unchecked Sendable {
        let g = AgentGuard()
        let lock = NSLock()
        var lines: [[String: Any]] = []
        var results: [Bool] = []

        init(launches: String, enforce: Bool, lists: ListedPackages) {
            var fds: [Int32] = [0, 0]
            socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
            let client = AgentClient(fd: fds[0])
            client.uid = 501
            g.quick = 60
            g.send = { [unowned self] _, ev in
                let obj = (try? JSONSerialization.jsonObject(with: ev.jsonLine())) as? [String: Any] ?? [:]
                self.lock.lock(); self.lines.append(obj); self.lock.unlock()
            }
            g.configure(["launches": launches, "files": "off", "groups": []], from: client)
            g.packages.configure(["enforce": enforce, "lists": lists.payload])
        }

        func hold(_ path: String, _ installs: [InstallTarget]) {
            var r = HoldRequest(what: .exec, path: path, pid: 900, ppid: 899, parent: "/bin/zsh", args: "", uid: 501, seconds: 10)
            r.installs = installs
            g.request(r) { [unowned self] allow in self.lock.lock(); self.results.append(allow); self.lock.unlock() }
        }
    }

    @Test func theCollectorStopsListedInstallsAlone() {
        let rig = Rig(launches: "off", enforce: true, lists: lists())
        #expect(rig.g.packages.isEnforcing)
        rig.hold("/bin/sh", [InstallTarget(package: ref(.npm, "evil", "1.0.0"), how: .script, detail: "postinstall")])
        #expect(rig.results == [false])
        let line = rig.lines.last { $0["kind"] as? String == "guard_package" } ?? [:]
        #expect(line["kind"] as? String == "guard_package" && line["package"] as? String == "evil"
                && line["detail"] as? String == "postinstall")
        // Not listed, launches not guarded: it goes on with nothing asked.
        rig.hold("/bin/sh", [InstallTarget(package: ref(.npm, "chalk", "5.6.2"), how: .script, detail: "postinstall")])
        rig.hold("/usr/bin/curl", [])
        #expect(rig.results == [false, true, true])
        #expect(rig.lines.filter { $0["kind"] as? String != "guard_status" }.count == 1)
    }

    @Test func watchModeStopsNothing() {
        let rig = Rig(launches: "off", enforce: false, lists: lists())
        #expect(!rig.g.packages.isEnforcing)
        rig.hold("/bin/sh", [InstallTarget(package: ref(.npm, "evil", "1.0.0"), how: .script, detail: "postinstall")])
        #expect(rig.results == [true])
    }

    // MARK: The Claude Code guard

    @Test func claudeIsStoppedFromInstallingAListedPackage() {
        let l = lists()
        var g = CommandGuard(home: "/Users/me")
        g.listedPackage = { l.record(for: $0).map { $0.id.isEmpty ? "MAL-1" : $0.id } }
        let bad = g.assess(tool: "Bash", input: ["command": "cd app && npm install evil"], cwd: "/Users/me/app")
        #expect(bad.level == .deny && bad.reasons.first?.contains("installs evil") == true)
        #expect(g.assess(tool: "Bash", input: ["command": "npx evil"], cwd: "/Users/me").reasons.first?.contains("runs evil") == true)
        #expect(g.assess(tool: "Bash", input: ["command": "npm install chalk@5.6.1"], cwd: "/Users/me").level == .deny)
        #expect(g.assess(tool: "Bash", input: ["command": "npm install chalk@5.6.2 left-pad"], cwd: "/Users/me").level == .ok)
    }

    // MARK: The app

    func guardIn(_ dir: URL) -> PackageGuard {
        let defaults = UserDefaults(suiteName: "hw-stop-\(UUID().uuidString)")!
        return PackageGuard(directory: dir, defaults: defaults)
    }

    func scratch() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-stop-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func stopsAreRecordedOncePerInstall() {
        let g = guardIn(scratch())
        let line: [String: Any] = ["kind": "guard_package", "ecosystem": "npm", "package": "evil", "version": "1.0.0",
                                   "how": "script", "detail": "postinstall", "malware": "MAL-1", "path": "/bin/sh"]
        let stop = g.stopped(line)
        #expect(stop?.sentence == "Stopped the postinstall script of evil 1.0.0" && stop?.malwareID == "MAL-1")
        #expect(g.stopped(line) == nil && g.stops.count == 1)              // the same script again a moment later
        #expect(g.stopped(["ecosystem": "nope", "package": "x"]) == nil)
        let install = PackageStop(package: ref(.npm, "evil", ""), malwareID: "", how: "install", detail: "npm install",
                                  program: "", args: "", date: Date())
        #expect(install.sentence == "Stopped npm install of evil")
    }

    @Test func modeComesFromTheOldSwitch() {
        let defaults = UserDefaults(suiteName: "hw-stop-\(UUID().uuidString)")!
        defaults.set(false, forKey: "packageGuardEnabled")
        #expect(PackageGuard(directory: scratch(), defaults: defaults).mode == .off)
        #expect(guardIn(scratch()).mode == .ask)
    }

    @Test func strictQuarantinesTheMatchingFolderAndRestoresIt() throws {
        let project = scratch()
        let fm = FileManager.default
        func pkg(_ path: String, _ name: String, _ version: String) throws {
            let dir = project.appendingPathComponent(path)
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data(#"{"name":"\#(name)","version":"\#(version)"}"#.utf8).write(to: dir.appendingPathComponent("package.json"))
        }
        try pkg("node_modules/evil", "evil", "1.0.0")
        try pkg("node_modules/web/node_modules/evil", "evil", "1.0.0")
        try pkg("node_modules/@s/ui/node_modules/evil", "evil", "2.0.0")      // another version: stays
        let lockfile = project.appendingPathComponent("package-lock.json").path
        let f = PackageFinding(package: ref(.npm, "evil", "1.0.0"), malwareID: "MAL-1", lockfile: lockfile, found: Date())
        #expect(Set(PackageGuard.installedFolders(f).map { $0.replacingOccurrences(of: project.path + "/", with: "") })
                == ["node_modules/evil", "node_modules/web/node_modules/evil"])

        let g = guardIn(scratch())
        g.quarantine(f)
        #expect(g.quarantined.count == 2 && !fm.fileExists(atPath: project.appendingPathComponent("node_modules/evil").path))
        #expect(fm.fileExists(atPath: project.appendingPathComponent("node_modules/@s/ui/node_modules/evil").path))
        let top = try #require(g.quarantined.first { $0.original.hasSuffix("/node_modules/evil") && !$0.original.contains("web") })
        g.restore(top)
        #expect(fm.fileExists(atPath: project.appendingPathComponent("node_modules/evil/package.json").path) && g.quarantined.count == 1)
        g.deleteQuarantined(g.quarantined[0])
        #expect(g.quarantined.isEmpty)
    }
}
