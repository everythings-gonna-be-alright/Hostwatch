import Foundation
import Testing
@testable import Hostwatch

/// ADR 0024, layers 1 and 2: the malicious-package list and the lockfile scan.
@MainActor @Suite(.serialized) struct PackageGuardTests {
    func ref(_ e: PackageEcosystem, _ n: String, _ v: String) -> PackageRef { PackageRef(ecosystem: e, name: n, version: v) }

    func scratch() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-packages-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func osv(_ id: String, _ name: String, eco: String = "npm", versions: [String]? = nil, events: [[String: String]]? = nil,
             withdrawn: Bool = false) -> Data {
        var affected: [String: Any] = ["package": ["name": name, "ecosystem": eco]]
        if let versions { affected["versions"] = versions }
        if let events { affected["ranges"] = [["type": "SEMVER", "events": events]] }
        var obj: [String: Any] = ["id": id, "modified": "2026-11-28T01:00:00Z", "affected": [affected]]
        if withdrawn { obj["withdrawn"] = "2026-11-28T02:00:00Z" }
        return try! JSONSerialization.data(withJSONObject: obj)
    }

    // MARK: The list

    @Test func recordsBecomeIndexLines() {
        let all = MalwareIndex.lines(fromOSV: osv("MAL-1", "evil", events: [["introduced": "0"]]), ecosystem: .npm)
        #expect(all?.lines == ["evil\tMAL-1\t*"])
        let some = MalwareIndex.lines(fromOSV: osv("MAL-2", "chalk", versions: ["5.6.1"]), ecosystem: .npm)
        #expect(some?.lines == ["chalk\tMAL-2\t=5.6.1"])
        let range = MalwareIndex.lines(fromOSV: osv("MAL-3", "fsevents", events: [["introduced": "1.0.0"], ["fixed": "1.2.11"]]), ecosystem: .npm)
        #expect(range?.lines == ["fsevents\tMAL-3\t>1.0.0<1.2.11"])
        #expect(MalwareIndex.lines(fromOSV: osv("MAL-4", "x", versions: ["1"], withdrawn: true), ecosystem: .npm)?.lines == [])
        #expect(MalwareIndex.lines(fromOSV: osv("GHSA-1", "x", versions: ["1"]), ecosystem: .npm) == nil)
    }

    @Test func matchesExactVersionsAndRanges() {
        let index = Data("""
        chalk\tMAL-2\t=5.6.1
        fsevents\tMAL-3\t>1.0.0<1.2.11
        Orchestrator\tMAL-5\t*
        request-s\tMAL-6\t*

        """.utf8)
        let npm: Set<PackageRef> = [ref(.npm, "chalk", "5.6.1"), ref(.npm, "chalk", "5.6.0"), ref(.npm, "fsevents", "1.1.2"),
                                    ref(.npm, "fsevents", "1.2.11"), ref(.npm, "orchestrator", "0.3.8")]
        let found = MalwareIndex.matches(in: index, ecosystem: .npm, wanted: npm)
        #expect(Set(found.keys) == [ref(.npm, "chalk", "5.6.1"), ref(.npm, "fsevents", "1.1.2")])
        // PyPI ignores case and treats -, _ and . alike (the index read as PyPI's here).
        let py = MalwareIndex.matches(in: index, ecosystem: .pypi, wanted: [ref(.pypi, "Request_S", "1.0")])
        #expect(py.count == 1)
        #expect(PackageEcosystem.pypi.normalize("Request_S.x") == "request-s-x")
    }

    @Test func versionOrder() {
        #expect(PackageVersion.compare("1.2.10", "1.2.9") > 0)
        #expect(PackageVersion.compare("1.0.0-beta", "1.0.0") < 0)
        #expect(PackageVersion.compare("v1.2.0", "1.2") == 0)
        #expect(PackageVersion.compare("2.0rc1", "2.0") < 0)
        let r = MalwareRecord(id: "M", ranges: [.init(introduced: "1.0.0", lastAffected: "1.2.0")])
        #expect(r.covers("1.2.0") && r.covers("1.0.0") && !r.covers("1.2.1") && !r.covers("0.9"))
        #expect(MalwareRecord(id: "M", spec: r.spec) == r)
    }

    @Test func updatesReplaceAndWithdrawRecords() {
        let index = Data("a\tMAL-1\t*\nb\tMAL-2\t=1.0\n".utf8)
        let merged = MalwareIndex.merged(index, replacing: ["MAL-2", "MAL-1"], with: ["b\tMAL-2\t=1.0,1.1"])
        #expect(String(decoding: merged, as: UTF8.self) == "b\tMAL-2\t=1.0,1.1\n")
        #expect(MalwareIndex.count(merged) == 1)
    }

    @Test func readsOSVExportZip() throws {
        let dir = scratch()
        try osv("MAL-1", "evil", events: [["introduced": "0"]]).write(to: dir.appendingPathComponent("MAL-1.json"))
        try osv("MAL-2", "chalk", versions: ["5.6.1"]).write(to: dir.appendingPathComponent("MAL-2.json"))
        try Data(#"{"id":"GHSA-x","affected":[]}"#.utf8).write(to: dir.appendingPathComponent("GHSA-x.json"))
        let zip = dir.appendingPathComponent("all.zip")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        p.currentDirectoryURL = dir
        p.arguments = ["-q", "all.zip", "MAL-1.json", "MAL-2.json", "GHSA-x.json"]
        try p.run(); p.waitUntilExit()
        let built = try PackageGuard.buildIndex(zip: zip, .npm)
        #expect(built.count == 2)
        #expect(String(decoding: built.index, as: UTF8.self).contains("chalk\tMAL-2\t=5.6.1"))
        #expect(throws: ZipReader.ZipError.self) { try ZipReader(data: Data("not a zip".utf8)) }
    }

    // MARK: Lockfiles

    @Test func npmFamily() {
        let lock = #"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/chalk":{"version":"5.6.1"},"node_modules/a/node_modules/@s/b":{"version":"1.0.0"},"node_modules/mine":{"link":true}}}"#
        #expect(Set(Lockfiles.parse(fileName: "package-lock.json", text: lock)) == [ref(.npm, "chalk", "5.6.1"), ref(.npm, "@s/b", "1.0.0")])
        let v1 = #"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#
        #expect(Set(Lockfiles.parse(fileName: "package-lock.json", text: v1)) == [ref(.npm, "a", "1.0.0"), ref(.npm, "b", "2.0.0")])
        let pnpm = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\npackages:\n  '@s/b@1.0.0':\n    resolution: {}\n  chalk@5.6.1:\n    resolution: {}\nsnapshots:\n  /old/1.2.3_peer:\n    x: y\n  /v6@2.0.0(react@18.0.0):\n    x: y\n"
        #expect(Set(Lockfiles.parse(fileName: "pnpm-lock.yaml", text: pnpm))
                == [ref(.npm, "@s/b", "1.0.0"), ref(.npm, "chalk", "5.6.1"), ref(.npm, "old", "1.2.3"), ref(.npm, "v6", "2.0.0")])
        let yarn = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.2.0\"\n  dependencies:\n    x \"^1\"\n\nlodash@^4:\n  version \"4.17.21\"\n"
        #expect(Set(Lockfiles.parse(fileName: "yarn.lock", text: yarn)) == [ref(.npm, "@babel/core", "7.2.0"), ref(.npm, "lodash", "4.17.21")])
        let berry = "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n"
        #expect(Lockfiles.parse(fileName: "yarn.lock", text: berry) == [ref(.npm, "lodash", "4.17.21")])
        let bun = #"{ "packages": { "chalk": ["chalk@5.6.1", "", {}, "sha"], "@s/b": ["@s/b@1.0.0", "", {}], "app": ["app@workspace:."], } }"#
        #expect(Set(Lockfiles.parse(fileName: "bun.lock", text: bun)) == [ref(.npm, "chalk", "5.6.1"), ref(.npm, "@s/b", "1.0.0")])
    }

    @Test func pythonFamily() {
        let req = "requests==2.31.0\nDjango[argon2] == 4.2 ; python_version > '3'\n# c==1\n-e .\nflask>=2\n"
        #expect(Set(Lockfiles.parse(fileName: "requirements-dev.txt", text: req)) == [ref(.pypi, "requests", "2.31.0"), ref(.pypi, "Django", "4.2")])
        let uv = "version = 1\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"idna\" },\n]\n"
        #expect(Lockfiles.parse(fileName: "uv.lock", text: uv) == [ref(.pypi, "requests", "2.31.0")])
        let pipfile = #"{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#
        #expect(Set(Lockfiles.parse(fileName: "Pipfile.lock", text: pipfile)) == [ref(.pypi, "requests", "2.31.0"), ref(.pypi, "pytest", "8.0.0")])
        #expect(Lockfiles.distInfo("python_dateutil-2.9.0.post0.dist-info") == ref(.pypi, "python_dateutil", "2.9.0.post0"))
        #expect(Lockfiles.distInfo("requests") == nil)
    }

    @Test func otherEcosystems() {
        let cargo = "[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        #expect(Lockfiles.parse(fileName: "Cargo.lock", text: cargo) == [ref(.crates, "serde", "1.0.0")])
        let sum = "github.com/a/b v1.2.3 h1:x=\ngithub.com/a/b v1.2.3/go.mod h1:y=\n"
        #expect(Lockfiles.parse(fileName: "go.sum", text: sum) == [ref(.go, "github.com/a/b", "v1.2.3")])
        let gems = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.5-arm64-darwin)\n      racc (~> 1.4)\n    rake (13.0.6)\n\nPLATFORMS\n  arm64-darwin\n"
        #expect(Set(Lockfiles.parse(fileName: "Gemfile.lock", text: gems)) == [ref(.rubygems, "nokogiri", "1.15.5"), ref(.rubygems, "rake", "13.0.6")])
        let composer = #"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0"}]}"#
        #expect(Lockfiles.parse(fileName: "composer.lock", text: composer).count == 2)
        let nuget = #"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"},"Mine":{"type":"Project"}}}}"#
        #expect(Lockfiles.parse(fileName: "packages.lock.json", text: nuget) == [ref(.nuget, "Newtonsoft.Json", "13.0.3")])
        #expect(Lockfiles.parse(fileName: "package-lock.json", text: "{broken").isEmpty)
    }

    @Test func projectLockfilesOnly() {
        #expect(PackageScan.isProjectLockfile("/Users/a/code/shop/package-lock.json"))
        #expect(PackageScan.isProjectLockfile("/Users/a/code/shop/node_modules/.package-lock.json"))
        #expect(!PackageScan.isProjectLockfile("/Users/a/code/shop/node_modules/x/package-lock.json"))
        #expect(!PackageScan.isProjectLockfile("/Users/a/Library/Caches/x/yarn.lock"))
        #expect(!PackageScan.isProjectLockfile("/Users/a/code/shop/README.md"))
        #expect(PackageScan.projectName("/Users/a/code/shop/node_modules/.package-lock.json") == "shop")
        #expect(PackageScan.projectName("/Users/a/code/api/.venv/pyvenv.cfg") == "api")
    }

    // MARK: The scan

    @Test func scanFindsOnceAndForgetsWhatWasFixed() async throws {
        _ = TestEnv.ready
        let dir = scratch()
        let defaults = UserDefaults(suiteName: "hw-packages-\(UUID().uuidString)")!
        let g = PackageGuard(directory: dir, defaults: defaults)
        try Vault.shared.write(Data("chalk\tMAL-2\t=5.6.1\n".utf8), to: dir.appendingPathComponent("npm.idx"))
        let project = dir.appendingPathComponent("shop")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        let lock = project.appendingPathComponent("package-lock.json")
        try Data(#"{"packages":{"node_modules/chalk":{"version":"5.6.1"},"node_modules/ok":{"version":"1.0.0"}}}"#.utf8).write(to: lock)
        var raised: [PackageFinding] = []
        g.onFinding = { raised.append($0) }
        g.seed([lock.path])
        await g.scan(all: false)
        #expect(raised.map(\.package) == [ref(.npm, "chalk", "5.6.1")] && raised.first?.malwareID == "MAL-2")
        #expect(raised.first?.project == "shop")
        await g.scan(all: true)
        #expect(raised.count == 1 && g.findings.count == 1)      // found again, not raised again
        // Upgraded: the finding goes, and a later change is checked without a list update.
        try Data(#"{"packages":{"node_modules/chalk":{"version":"5.6.2"}}}"#.utf8).write(to: lock)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(60)], ofItemAtPath: lock.path)
        await g.scan(all: false)
        #expect(g.findings.isEmpty)
        g.save()
        #expect(PackageGuard(directory: dir, defaults: defaults).lockfiles[lock.path] != nil)
    }

    @Test func dismissedStaysDismissed() async throws {
        _ = TestEnv.ready
        let dir = scratch()
        let g = PackageGuard(directory: dir, defaults: UserDefaults(suiteName: "hw-packages-\(UUID().uuidString)")!)
        try Vault.shared.write(Data("evil\tMAL-1\t*\n".utf8), to: dir.appendingPathComponent("PyPI.idx"))
        let req = dir.appendingPathComponent("requirements.txt")
        try Data("Evil==1.0\n".utf8).write(to: req)
        g.seed([req.path])
        await g.scan(all: true)
        let f = try #require(g.findings.first)
        g.dismiss(f)
        await g.scan(all: true)
        #expect(g.findings.isEmpty)
    }
}
