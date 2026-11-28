import Foundation
import Testing
@testable import Hostwatch

/// ADR 0024, layer 4: install scripts contained, lookalike names, the age check.
@MainActor @Suite(.serialized) struct PackageContainTests {
    func ref(_ e: PackageEcosystem, _ n: String, _ v: String = "") -> PackageRef { PackageRef(ecosystem: e, name: n, version: v) }
    let home = "/Users/me"

    // MARK: Pure rules

    @Test func containedOpensAndLaunches() {
        let read = InstallContainment.readPaths(home: home), write = InstallContainment.writePaths(home: home)
        #expect(InstallContainment.open("/Users/me/.ssh/id_ed25519", mode: "r", read: read, write: write) == .read)
        #expect(InstallContainment.open("/Users/me/.npmrc", mode: "r", read: read, write: write) == .read)
        #expect(InstallContainment.open("/Users/me/.zshrc", mode: "r", read: read, write: write) == nil)     // shells read it
        #expect(InstallContainment.open("/Users/me/.zshrc", mode: "w", read: read, write: write) == .write)
        #expect(InstallContainment.open("/Users/me/Library/LaunchAgents/x.plist", mode: "rw", read: read, write: write) == .write)
        #expect(InstallContainment.open("/Users/me/.sshd", mode: "r", read: read, write: write) == nil)       // not a prefix trick
        #expect(InstallContainment.open("/Users/me/app/node_modules/x/index.js", mode: "w", read: read, write: write) == nil)
        #expect(InstallContainment.open("/Users/me/Library/Application Support/Google/Chrome/Default/Login Data",
                                        mode: "r", read: read, write: write) == .read)
        #expect(InstallContainment.blockedLaunch(path: "/usr/local/bin/node", args: ["node", "/Users/me/.local/bin/claude", "-p"])?.name == "claude")
        #expect(InstallContainment.blockedLaunch(path: "/opt/homebrew/bin/trufflehog", args: ["trufflehog", "filesystem"]) != nil)
        #expect(InstallContainment.blockedLaunch(path: "/usr/bin/make", args: ["make"]) == nil)
    }

    @Test func registriesAndBuildHostsOnly() {
        #expect(InstallContainment.hostAllowed("registry.npmjs.org"))
        #expect(InstallContainment.hostAllowed("objects.githubusercontent.com"))
        #expect(InstallContainment.hostAllowed("127.0.0.1"))
        #expect(!InstallContainment.hostAllowed("api.github.com"))       // where nx's script published what it stole
        #expect(!InstallContainment.hostAllowed("webhook.site"))
        #expect(!InstallContainment.hostAllowed("evilregistry.npmjs.org.attacker.io"))
        #expect(!InstallContainment.hostAllowed(""))
        let mine = InstallContainment.configuredRegistries(
            npmrc: "registry=https://npm.corp.example/\n@team:registry=https://pkgs.corp.example/npm/\n//npm.corp.example/:_authToken=x",
            pipConf: "[global]\nindex-url = https://pypi.corp.example/simple\n")
        #expect(mine == ["npm.corp.example", "pkgs.corp.example", "pypi.corp.example"])
        #expect(InstallContainment.hostAllowed("npm.corp.example", extra: mine))
    }

    @Test func lookalikeNames() {
        let known = Set(PackageNames.builtIn[.npm]!)
        #expect(PackageNames.lookalike("reactt", .npm, known: known) == "react")
        #expect(PackageNames.lookalike("expresss", .npm, known: known) == "express")
        #expect(PackageNames.lookalike("lodahs", .npm, known: known) == "lodash")            // neighbours swapped
        #expect(PackageNames.lookalike("reactdom", .npm, known: known) == "react-dom")
        #expect(PackageNames.lookalike("react", .npm, known: known) == nil)                  // the real one
        #expect(PackageNames.lookalike("left-pad", .npm, known: known) == nil)
        #expect(PackageNames.lookalike("ms", .npm, known: known) == nil)                     // too short to judge
        let py = Set(PackageNames.builtIn[.pypi]!.map(PackageEcosystem.pypi.normalize))
        #expect(PackageNames.lookalike("reqeusts", .pypi, known: py) == "requests")
        #expect(PackageNames.lookalike("Requests", .pypi, known: py) == nil)
    }

    @Test func registryAnswersGiveTheFirstPublish() {
        let npm = Data(#"{"time":{"created":"2026-11-25T10:00:00.000Z","modified":"2026-11-26T10:00:00.000Z"}}"#.utf8)
        let first = PackageAge.firstPublished(json: npm, .npm)
        #expect(first != nil && PackageAge.isNew(first!, now: first!.addingTimeInterval(3 * 86_400)))
        #expect(!PackageAge.isNew(first!, now: first!.addingTimeInterval(30 * 86_400)))
        let pypi = Data(#"{"releases":{"1.0":[{"upload_time_iso_8601":"2020-01-02T00:00:00.123Z"}],"0.1":[{"upload_time_iso_8601":"2019-05-01T00:00:00Z"}]}}"#.utf8)
        #expect(PackageAge.firstPublished(json: pypi, .pypi)?.formatted(.iso8601.year()) == "2019")
        #expect(PackageAge.firstPublished(json: Data(#"{"crate":{"created_at":"2024-03-01T00:00:00Z"}}"#.utf8), .crates) != nil)
        #expect(PackageAge.url(ref(.npm, "@corp/internal")) == nil)          // scoped names stay on this Mac
        #expect(PackageAge.url(ref(.go, "github.com/a/b")) == nil)
    }

    // MARK: The collector

    final class Rig: @unchecked Sendable {
        let g = AgentGuard()
        let lock = NSLock()
        var lines: [[String: Any]] = []
        var results: [String: Bool] = [:]

        init(mode: String, firewallHosts: [String] = []) {
            var fds: [Int32] = [0, 0]
            socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
            let client = AgentClient(fd: fds[0])
            client.uid = 501
            g.quick = 60
            g.send = { [unowned self] _, ev in
                let obj = (try? JSONSerialization.jsonObject(with: ev.jsonLine())) as? [String: Any] ?? [:]
                self.lock.lock(); self.lines.append(obj); self.lock.unlock()
            }
            g.configure(["launches": "off", "files": "off", "groups": []], from: client)
            g.packages.configure(["mode": mode, "contain": ["read": InstallContainment.readPaths(home: "/Users/me"),
                                                            "write": InstallContainment.writePaths(home: "/Users/me"), "hosts": firewallHosts],
                                  "known": ["npm": PackageNames.builtIn[.npm]!]])
        }

        func exec(_ name: String, pid: Int, ppid: Int, path: String, argv: [String] = [], installs: [InstallTarget] = []) {
            var r = HoldRequest(what: .exec, path: path, pid: pid, ppid: ppid, parent: "", args: argv.joined(separator: " "), uid: 501, seconds: 10)
            r.installs = installs; r.argv = argv
            g.request(r) { [unowned self] allow in self.lock.lock(); self.results[name] = allow; self.lock.unlock() }
        }
        func open(_ name: String, pid: Int, file: String, mode: String = "r") {
            let r = HoldRequest(what: .open, path: "/usr/local/bin/node", pid: pid, ppid: 1, file: file, mode: mode, uid: 501, seconds: 10)
            g.request(r) { [unowned self] allow in self.lock.lock(); self.results[name] = allow; self.lock.unlock() }
        }
        func contained() -> [[String: Any]] { lines.filter { $0["kind"] as? String == "guard_contain" } }
    }

    let postinstall = InstallTarget(package: PackageRef(ecosystem: .npm, name: "nice-lib", version: "2.0.0"), how: .script, detail: "postinstall")

    @Test func scriptsAndTheirChildrenAreContained() {
        let rig = Rig(mode: "ask")
        rig.exec("npm", pid: 100, ppid: 50, path: "/usr/local/bin/node", argv: ["node", "npm", "install"])
        rig.exec("script", pid: 101, ppid: 100, path: "/bin/sh", argv: ["sh", "-c", "node setup.js"], installs: [postinstall])
        rig.exec("child", pid: 102, ppid: 101, path: "/usr/local/bin/node", argv: ["node", "setup.js"])
        rig.g.packages.forked(parent: 102, child: 103)
        #expect(rig.g.packages.contained(100) == nil)                  // the package manager itself isn't
        #expect(rig.g.packages.contained(103)?.target.package.name == "nice-lib")
        rig.open("npmrc-by-npm", pid: 100, file: "/Users/me/.npmrc")
        rig.open("ssh-by-child", pid: 102, file: "/Users/me/.ssh/id_rsa")
        rig.open("rc-by-fork", pid: 103, file: "/Users/me/.zshrc", mode: "w")
        rig.open("project-file", pid: 102, file: "/Users/me/app/build/out.js", mode: "w")
        rig.exec("ai", pid: 104, ppid: 102, path: "/usr/local/bin/node", argv: ["node", "/opt/homebrew/bin/claude", "-p", "find secrets"])
        #expect(rig.results["npmrc-by-npm"] == true && rig.results["project-file"] == true)
        #expect(rig.results["ssh-by-child"] == false && rig.results["rc-by-fork"] == false && rig.results["ai"] == false)
        #expect(Set(rig.contained().compactMap { $0["tried"] as? String }) == ["read", "write", "launch"])
        #expect(rig.contained().allSatisfy { $0["package"] as? String == "nice-lib" && $0["enforced"] as? Bool == true })
        // The script ended and its pid went to something else: no longer contained.
        rig.g.packages.exited(102)
        rig.exec("reused", pid: 101, ppid: 1, path: "/usr/bin/ssh")
        #expect(rig.g.packages.contained(101) == nil && rig.g.packages.contained(102) == nil)
    }

    @Test func watchRecordsAndStopsNothing() {
        let rig = Rig(mode: "watch")
        rig.exec("script", pid: 201, ppid: 200, path: "/bin/sh", installs: [postinstall])
        rig.open("ssh", pid: 201, file: "/Users/me/.ssh/config")
        #expect(rig.results["ssh"] == true && rig.contained().first?["enforced"] as? Bool == false)
        rig.open("ssh-again", pid: 201, file: "/Users/me/.ssh/config")
        #expect(rig.contained().count == 1)                             // once a minute, not on every open
    }

    @Test func runnersPassChildrenAreContained() {
        let rig = Rig(mode: "ask")
        let npx = InstallTarget(package: PackageRef(ecosystem: .npm, name: "create-thing", version: ""), how: .run, detail: "npx")
        rig.exec("npx", pid: 300, ppid: 1, path: "/usr/local/bin/node", argv: ["node", "npx", "create-thing"], installs: [npx])
        rig.open("npx-login", pid: 300, file: "/Users/me/.npmrc")
        rig.exec("bin", pid: 301, ppid: 300, path: "/usr/local/bin/node", argv: ["node", "create-thing"])
        rig.open("bin-ssh", pid: 301, file: "/Users/me/.ssh/id_rsa")
        #expect(rig.results["npx-login"] == true && rig.results["bin-ssh"] == false)
        #expect(rig.lines.contains { $0["kind"] as? String == "guard_install" && $0["package"] as? String == "create-thing" })
    }

    @Test func connectionsLeaveOnlyForRegistries() {
        let rig = Rig(mode: "ask", firewallHosts: ["npm.corp.example"])
        rig.exec("script", pid: 401, ppid: 400, path: "/bin/sh", installs: [postinstall])
        #expect(rig.g.packageConnect(pid: 401, program: "/usr/local/bin/node", host: "registry.npmjs.org") == nil)
        #expect(rig.g.packageConnect(pid: 401, program: "/usr/local/bin/node", host: "npm.corp.example") == nil)
        #expect(rig.g.packageConnect(pid: 401, program: "/usr/local/bin/node", host: "webhook.site")?.enforced == true)
        #expect(rig.g.packageConnect(pid: 400, program: "/usr/local/bin/node", host: "webhook.site") == nil)   // not contained
    }

    @Test func strictRefusesLookalikesAskOnlyTells() {
        let typo = InstallTarget(package: PackageRef(ecosystem: .npm, name: "expresss", version: ""), how: .install, detail: "npm install")
        let ask = Rig(mode: "ask")
        ask.exec("i", pid: 500, ppid: 1, path: "/usr/local/bin/node", installs: [typo])
        #expect(ask.results["i"] == true && ask.contained().first?["tried"] as? String == "lookalike")
        let strict = Rig(mode: "strict")
        strict.exec("i", pid: 500, ppid: 1, path: "/usr/local/bin/node", installs: [typo])
        #expect(strict.results["i"] == false)
    }

    // MARK: The app

    @Test func containedLinesReadAsSentences() {
        let g = PackageGuard(directory: FileManager.default.temporaryDirectory.appendingPathComponent("hw-contain-\(UUID().uuidString)"),
                             defaults: UserDefaults(suiteName: "hw-contain-\(UUID().uuidString)")!)
        let line: [String: Any] = ["ecosystem": "npm", "package": "nice-lib", "version": "2.0.0", "how": "script",
                                   "detail": "postinstall", "tried": "read", "target": NSHomeDirectory() + "/.ssh/id_rsa", "enforced": true]
        #expect(g.contained(line)?.sentence == "The postinstall script of nice-lib 2.0.0 tried to read ~/.ssh/id_rsa. Stopped.")
        #expect(g.contained(line) == nil)                                // the same try again within the hour
        var watched = line; watched["tried"] = "connect"; watched["target"] = "webhook.site"; watched["enforced"] = false
        #expect(g.contained(watched)?.sentence == "The postinstall script of nice-lib 2.0.0 tried to connect to webhook.site. Let through (Watch).")
        let config = g.collectorConfig(home: "/Users/me")
        #expect(config["mode"] as? String == "ask" && ((config["known"] as? [String: [String]])?["npm"]?.contains("react") ?? false))
        #expect(((config["contain"] as? [String: Any])?["read"] as? [String])?.contains("/Users/me/.ssh") ?? false)
    }

    @Test func claudeIsAskedAboutLookalikes() {
        var g = CommandGuard(home: "/Users/me")
        let known = Set(PackageNames.builtIn[.npm]!)
        g.lookalikePackage = { PackageNames.lookalike($0.name, $0.ecosystem, known: known) }
        let v = g.assess(tool: "Bash", input: ["command": "npm install reactt"], cwd: "/Users/me")
        #expect(v.level == .ask && v.reasons.first?.contains("looks like react") == true)
        #expect(g.assess(tool: "Bash", input: ["command": "npm install react"], cwd: "/Users/me").level == .ok)
        #expect(CommandGuard.namedInstalls(in: "cd x && FOO=1 npm i a b; pip install c") .map(\.name) == ["a", "b", "c"])
    }
}
