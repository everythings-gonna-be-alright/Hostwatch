import Foundation

// Which launches install a package (ADR 0024, layer 3): a package's install script, or a package manager told to
// install a name. Pure: the collector calls it inside the launch hold, the Claude Code guard on a command's words.

/// A package a launch is about to install or run, and how.
struct InstallTarget: Equatable, Sendable {
    enum How: String, Sendable { case script, install, run }
    var package: PackageRef
    var how: How
    var detail = ""             // the script's event (postinstall) or the manager's verb (npm install)
}

enum InstallContext {
    /// The environment variables a script hold reads: everything else is skipped without being copied.
    static let envNames: Set<String> = ["npm_package_name", "npm_package_version", "npm_lifecycle_event",
                                        "CARGO_PKG_NAME", "CARGO_PKG_VERSION"]
    /// npm's scripts that run during an install (`prepare` too: it runs for git dependencies).
    static let installEvents: Set<String> = ["preinstall", "install", "postinstall", "prepare"]

    /// What a launch installs: its install script's package, else the packages named on its command line.
    static func targets(path: String, args: [String], env: [String: String], cwd: String,
                        read: (String) -> String? = { _ in nil }) -> [InstallTarget] {
        if let s = script(path: path, args: args, cwd: cwd, env: env, read: read) { return [s] }
        return namedInstalls(args)
    }

    // MARK: Install scripts

    /// npm, pnpm, yarn and bun run each script with the package in the environment. Cargo runs a crate's build
    /// script from `…/build/<crate>-<hash>/build-script-build` with the crate in the environment. pip runs a build
    /// backend inside the unpacked source, where `PKG-INFO` names it. RubyGems runs `extconf.rb` inside the gem.
    static func script(path: String, args: [String], cwd: String, env: [String: String],
                       read: (String) -> String? = { _ in nil }) -> InstallTarget? {
        if let event = env["npm_lifecycle_event"], installEvents.contains(event),
           let name = env["npm_package_name"], !name.isEmpty {
            return InstallTarget(package: PackageRef(ecosystem: .npm, name: name, version: env["npm_package_version"] ?? ""),
                                 how: .script, detail: event)
        }
        let base = (path as NSString).lastPathComponent
        if base.hasPrefix("build-script-"), let name = env["CARGO_PKG_NAME"], !name.isEmpty {
            return InstallTarget(package: PackageRef(ecosystem: .crates, name: name, version: env["CARGO_PKG_VERSION"] ?? ""),
                                 how: .script, detail: "build script")
        }
        let words = args.map { ($0 as NSString).lastPathComponent }
        if !cwd.isEmpty, words.contains(where: { $0 == "_in_process.py" || $0 == "setup.py" }),
           let info = read((cwd as NSString).appendingPathComponent("PKG-INFO")), let ref = pkgInfo(info) {
            return InstallTarget(package: ref, how: .script, detail: "build")
        }
        if words.contains("extconf.rb"), let ref = gemFolder(cwd) ?? args.lazy.compactMap(gemFolder).first {
            return InstallTarget(package: ref, how: .script, detail: "extconf.rb")
        }
        return nil
    }

    /// `Name:` and `Version:` from a source distribution's PKG-INFO.
    static func pkgInfo(_ text: String) -> PackageRef? {
        var name = "", version = ""
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).prefix(40) {
            if line.hasPrefix("Name:") { name = line.dropFirst(5).trimmingCharacters(in: .whitespaces) }
            if line.hasPrefix("Version:") { version = line.dropFirst(8).trimmingCharacters(in: .whitespaces) }
            if line.isEmpty { break }                       // the headers end at the first blank line
        }
        return name.isEmpty ? nil : PackageRef(ecosystem: .pypi, name: name, version: version)
    }

    /// `…/gems/<name>-<version>/ext/…`: the version is the last part that starts with a digit.
    static func gemFolder(_ path: String) -> PackageRef? {
        guard let r = path.range(of: "/gems/") else { return nil }
        let folder = path[r.upperBound...].prefix { $0 != "/" }
        guard path[r.upperBound...].dropFirst(folder.count).hasPrefix("/ext"),
              let dash = folder.lastIndex(of: "-"), folder[folder.index(after: dash)...].first?.isNumber == true else { return nil }
        return PackageRef(ecosystem: .rubygems, name: String(folder[..<dash]), version: String(folder[folder.index(after: dash)...]))
    }

    // MARK: Named installs

    private enum Verb { case install, run }
    private struct Manager {
        var ecosystem: PackageEcosystem
        var verbs: [String: Verb]
        var direct: Verb?           // npx, uvx, bunx: the first word after it is a package to run
    }

    private static let npm = Manager(ecosystem: .npm, verbs: ["install": .install, "i": .install, "add": .install,
                                                              "exec": .run, "x": .run, "dlx": .run])
    private static let managers: [String: Manager] = [
        "npm": npm, "npm-cli.js": npm, "pnpm": npm, "pnpm.cjs": npm, "yarn": npm, "yarn.js": npm, "yarn.cjs": npm,
        "bun": npm, "npx": Manager(ecosystem: .npm, verbs: [:], direct: .run), "npx-cli.js": Manager(ecosystem: .npm, verbs: [:], direct: .run),
        "bunx": Manager(ecosystem: .npm, verbs: [:], direct: .run),
        "pip": Manager(ecosystem: .pypi, verbs: ["install": .install]),
        "uv": Manager(ecosystem: .pypi, verbs: ["add": .install, "install": .install]),
        "uvx": Manager(ecosystem: .pypi, verbs: [:], direct: .run),
        "pipx": Manager(ecosystem: .pypi, verbs: ["install": .install, "run": .run]),
        "poetry": Manager(ecosystem: .pypi, verbs: ["add": .install]),
        "cargo": Manager(ecosystem: .crates, verbs: ["add": .install, "install": .install]),
        "gem": Manager(ecosystem: .rubygems, verbs: ["install": .install]),
        "go": Manager(ecosystem: .go, verbs: ["get": .install, "install": .install, "run": .run]),
        "composer": Manager(ecosystem: .packagist, verbs: ["require": .install]),
    ]
    /// Flags whose next word is a value, not a package.
    private static let valueFlags: Set<String> = [
        "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "--registry", "-i", "--index-url",
        "--extra-index-url", "-t", "--target", "--prefix", "--python", "-p", "--version", "-v", "--git", "--path",
        "--source", "--cwd", "-C", "--dir", "--workspace", "-w", "--filter", "--with", "--from", "--index",
        "--root", "--features", "--tag", "--branch", "--rev", "--group", "-G", "--manifest-path", "--spec",
    ]
    private static let interpreters: Set<String> = ["node", "python", "python3", "ruby", "env", "bun"]

    /// The packages a package manager's command line installs or runs: `npm install a b@2`, `pip install x==1.0`,
    /// `npx y`, `python -m pip install z`. Names only, no paths, URLs or files. An empty version is unknown.
    static func namedInstalls(_ args: [String]) -> [InstallTarget] {
        var i = 0
        var found: (Manager, String)?
        // The manager is among the first words: `npm …`, `node …/npm-cli.js …`, `python3 -m pip …`.
        while i < min(args.count, 5) {
            let word = (args[i] as NSString).lastPathComponent
            let key = word.hasPrefix("pip") && word.dropFirst(3).allSatisfy({ $0.isNumber || $0 == "." }) ? "pip" : word
            if let m = managers[key] { found = (m, key); i += 1; break }
            guard interpreters.contains(word) || word.hasPrefix("python") || word == "-m" || word.hasPrefix("-") else { return [] }
            i += 1
        }
        guard let (manager, key) = found else { return [] }
        var verb = manager.direct
        var detail = key
        if verb == nil {
            // `uv pip install`, `uv tool install`, `pnpm dlx`: the verb is the first word that is one.
            while i < args.count, verb == nil {
                let w = args[i]
                if let v = manager.verbs[w] { verb = v; detail += " " + w }
                else if w.hasPrefix("-") || ["pip", "tool"].contains(w) { if valueFlags.contains(w) { i += 1 } }
                else { return [] }                          // another command: `npm run build`, `go build`
                i += 1
            }
        }
        guard let verb else { return [] }
        var out: [InstallTarget] = []
        while i < args.count {
            let w = args[i]
            i += 1
            if w == "--" { if verb == .run { break } else { continue } }
            if w.hasPrefix("-") {
                if valueFlags.contains(w) { i += 1 }
                continue
            }
            if let ref = parseSpec(w, manager.ecosystem) {
                out.append(InstallTarget(package: ref, how: verb == .run ? .run : .install, detail: detail))
            }
            if verb == .run { break }                       // what follows is the package's own arguments
        }
        return out
    }

    /// `name`, `name@1.2.3`, `@scope/name@1.2.3`, `name==1.0`, `name[extra]>=2`, `module/path@v1.2.3`.
    static func parseSpec(_ word: String, _ eco: PackageEcosystem) -> PackageRef? {
        let w = word.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        guard !w.isEmpty, !w.hasPrefix("."), !w.hasPrefix("~"), !w.contains("://"), !w.hasPrefix("git+"),
              !w.hasPrefix("file:"), !w.hasPrefix("link:"), !w.hasPrefix("npm:"), !w.contains("$") else { return nil }
        switch eco {
        case .pypi:
            guard !w.contains("/"), !w.hasSuffix(".whl"), !w.hasSuffix(".tar.gz"), !w.hasSuffix(".txt") else { return nil }
            let nameEnd = w.firstIndex { "[=<>!~; @".contains($0) } ?? w.endIndex
            let name = String(w[..<nameEnd])
            var version = ""
            if let r = w.range(of: "==") { version = String(w[r.upperBound...].prefix { !",; ".contains($0) }) }
            return name.isEmpty ? nil : PackageRef(ecosystem: eco, name: name, version: version)
        case .go:
            guard w.contains("/") || w.contains("."), !w.hasSuffix(".go") else { return nil }
            let parts = w.split(separator: "@", maxSplits: 1).map(String.init)
            let version = parts.count == 2 && parts[1] != "latest" ? parts[1] : ""
            return PackageRef(ecosystem: eco, name: parts[0], version: version)
        case .npm:
            if w.contains("/") && !w.hasPrefix("@") { return nil }    // a path or a GitHub shorthand
            guard let at = w.dropFirst().lastIndex(of: "@") else { return PackageRef(ecosystem: eco, name: w, version: "") }
            let version = String(w[w.index(after: at)...])
            // A range or a tag isn't a version: the name alone, and only an every-version record matches.
            let exact = version.first?.isNumber == true && !version.contains(where: { " ^~<>=*|x".contains($0) })
            return PackageRef(ecosystem: eco, name: String(w[..<at]), version: exact ? version : "")
        default:
            guard !w.contains("/") || eco == .packagist else { return nil }
            let sep = w.firstIndex { $0 == "@" || $0 == ":" } ?? w.endIndex
            let version = sep < w.endIndex ? String(w[w.index(after: sep)...]) : ""
            return PackageRef(ecosystem: eco, name: String(w[..<sep]),
                              version: version.first?.isNumber == true ? version : "")
        }
    }
}
