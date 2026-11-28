import Foundation

/// What a project has installed, read from its lockfile: one pure parser per format, tolerant of what it doesn't
/// know (a line it can't read is skipped, never fatal). Lockfiles list every dependency, not only the direct ones,
/// which is what a malicious-package check needs: the bad version usually arrives through something else.
enum Lockfiles {
    static let fixedNames: [String: PackageEcosystem] = [
        "package-lock.json": .npm, "npm-shrinkwrap.json": .npm, ".package-lock.json": .npm, "pnpm-lock.yaml": .npm,
        "yarn.lock": .npm, "bun.lock": .npm,
        "poetry.lock": .pypi, "uv.lock": .pypi, "Pipfile.lock": .pypi, "pylock.toml": .pypi,
        "go.sum": .go, "Cargo.lock": .crates, "Gemfile.lock": .rubygems, "composer.lock": .packagist,
        "packages.lock.json": .nuget,
    ]

    static func ecosystem(_ fileName: String) -> PackageEcosystem? {
        if let e = fixedNames[fileName] { return e }
        return fileName.hasPrefix("requirements") && fileName.hasSuffix(".txt") ? .pypi : nil
    }

    static func parse(fileName: String, text: String) -> [PackageRef] {
        let refs: [PackageRef]
        switch fileName {
        case "package-lock.json", "npm-shrinkwrap.json", ".package-lock.json": refs = npmLock(text)
        case "pnpm-lock.yaml": refs = pnpm(text)
        case "yarn.lock": refs = yarn(text)
        case "bun.lock": refs = bun(text)
        case "poetry.lock", "uv.lock", "pylock.toml": refs = tomlPackages(text, .pypi, needsSource: false)
        case "Cargo.lock": refs = tomlPackages(text, .crates, needsSource: true)
        case "Pipfile.lock": refs = pipfile(text)
        case "go.sum": refs = goSum(text)
        case "Gemfile.lock": refs = gemfile(text)
        case "composer.lock": refs = composer(text)
        case "packages.lock.json": refs = nuget(text)
        default: refs = ecosystem(fileName) == .pypi ? requirements(text) : []
        }
        var seen = Set<PackageRef>()
        return refs.filter { !$0.name.isEmpty && !$0.version.isEmpty && seen.insert($0).inserted }
    }

    /// `requests-2.31.0.dist-info` in a virtual environment's site-packages.
    static func distInfo(_ folder: String) -> PackageRef? {
        guard folder.hasSuffix(".dist-info"), let dash = folder.firstIndex(of: "-") else { return nil }
        let name = String(folder[..<dash])
        let version = String(folder[folder.index(after: dash)...].dropLast(".dist-info".count))
        return name.isEmpty || version.isEmpty ? nil : PackageRef(ecosystem: .pypi, name: name, version: version)
    }

    // MARK: npm family

    static func npmLock(_ text: String) -> [PackageRef] {
        guard let obj = json(text) else { return [] }
        var out: [PackageRef] = []
        if let packages = obj["packages"] as? [String: Any] {
            for (path, value) in packages {
                guard let p = value as? [String: Any], let r = path.range(of: "node_modules/", options: .backwards),
                      p["link"] as? Bool != true, let version = p["version"] as? String else { continue }
                let name = p["name"] as? String ?? String(path[r.upperBound...])
                out.append(PackageRef(ecosystem: .npm, name: name, version: version))
            }
        } else if let deps = obj["dependencies"] as? [String: Any] {
            func walk(_ deps: [String: Any]) {
                for (name, value) in deps {
                    guard let d = value as? [String: Any] else { continue }
                    if let v = d["version"] as? String { out.append(PackageRef(ecosystem: .npm, name: name, version: v)) }
                    if let nested = d["dependencies"] as? [String: Any] { walk(nested) }
                }
            }
            walk(deps)
        }
        return out
    }

    /// Keys under `packages:` and `snapshots:`: `/name/1.0.0` (v5), `/name@1.0.0(peer@2)` (v6), `name@1.0.0` (v9).
    static func pnpm(_ text: String) -> [PackageRef] {
        var out: [PackageRef] = []
        var inSection = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if !raw.hasPrefix(" ") { inSection = raw == "packages:" || raw == "snapshots:"; continue }
            guard inSection, raw.hasPrefix("  "), !raw.hasPrefix("   "), raw.hasSuffix(":") else { continue }
            var key = String(raw.dropFirst(2).dropLast()).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
            if key.hasPrefix("/") { key.removeFirst() }
            if let paren = key.firstIndex(of: "(") { key = String(key[..<paren]) }
            if let at = key.lastIndex(of: "@"), at != key.startIndex {
                out.append(PackageRef(ecosystem: .npm, name: String(key[..<at]), version: String(key[key.index(after: at)...])))
            } else if let slash = key.lastIndex(of: "/") {
                var version = String(key[key.index(after: slash)...])
                if let u = version.firstIndex(of: "_") { version = String(version[..<u]) }
                out.append(PackageRef(ecosystem: .npm, name: String(key[..<slash]), version: version))
            }
        }
        return out.filter { !$0.version.contains(":") }
    }

    /// v1 (`name@^1:` then `  version "1.2.3"`) and Berry (`"name@npm:^1":` then `  version: 1.2.3`).
    static func yarn(_ text: String) -> [PackageRef] {
        var out: [PackageRef] = []
        var name: String?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if !raw.hasPrefix(" "), !raw.hasPrefix("#"), raw.hasSuffix(":") {
                let first = raw.dropLast().split(separator: ",").first.map {
                    $0.trimmingCharacters(in: CharacterSet(charactersIn: " \"")) } ?? ""
                if let at = first.lastIndex(of: "@"), at != first.startIndex, first != "__metadata" {
                    name = String(first[..<at])
                } else { name = nil }
                continue
            }
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard let n = name, raw.hasPrefix("  "), !raw.hasPrefix("    "), line.hasPrefix("version") else { continue }
            let v = line.dropFirst("version".count).trimmingCharacters(in: CharacterSet(charactersIn: ": \""))
            if !v.contains("use.local") { out.append(PackageRef(ecosystem: .npm, name: n, version: v)) }
            name = nil
        }
        return out
    }

    /// bun.lock: `"key": ["name@1.2.3", ...]` under `packages`.
    static func bun(_ text: String) -> [PackageRef] {
        let pattern = #"\[\s*"((?:@[^"@/]+/)?[^"@]+)@([^"]+)""#
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap { m in
            let version = ns.substring(with: m.range(at: 2))
            guard !version.contains(":") else { return nil }      // workspace:, link:, file:, github:
            return PackageRef(ecosystem: .npm, name: ns.substring(with: m.range(at: 1)), version: version)
        }
    }

    // MARK: Python

    static func requirements(_ text: String) -> [PackageRef] {
        let pattern = #"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)"#
        guard let re = try? NSRegularExpression(pattern: pattern, options: .anchorsMatchLines) else { return [] }
        let ns = text as NSString
        return re.matches(in: text, range: NSRange(location: 0, length: ns.length)).map {
            PackageRef(ecosystem: .pypi, name: ns.substring(with: $0.range(at: 1)), version: ns.substring(with: $0.range(at: 2)))
        }
    }

    static func pipfile(_ text: String) -> [PackageRef] {
        guard let obj = json(text) else { return [] }
        var out: [PackageRef] = []
        for section in ["default", "develop"] {
            for (name, value) in obj[section] as? [String: Any] ?? [:] {
                guard let v = (value as? [String: Any])?["version"] as? String else { continue }
                out.append(PackageRef(ecosystem: .pypi, name: name, version: v.trimmingCharacters(in: CharacterSet(charactersIn: "=<>~! "))))
            }
        }
        return out
    }

    /// `[[package]]` blocks with top-level `name = "…"` and `version = "…"` (poetry, uv, pylock, Cargo). Your own
    /// projects in the file (uv's editable or virtual source, Cargo's workspace crates without a registry source)
    /// aren't packages from a registry.
    static func tomlPackages(_ text: String, _ eco: PackageEcosystem, needsSource: Bool) -> [PackageRef] {
        var out: [PackageRef] = []
        var name: String?, version: String?, registry = false, own = false, inPackage = false
        func flush() {
            if inPackage, let n = name, let v = version, !own, registry || !needsSource {
                out.append(PackageRef(ecosystem: eco, name: n, version: v))
            }
            name = nil; version = nil; registry = false; own = false
        }
        func value(_ line: Substring) -> String {
            String(line.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: CharacterSet(charactersIn: " \""))
        }
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("[") {
                if line == "[[package]]" || line == "[[packages]]" { flush(); inPackage = true }
                else if !line.hasPrefix("[package.") && !line.hasPrefix("[packages.") { flush(); inPackage = false }
                continue
            }
            guard inPackage else { continue }
            if line.hasPrefix("name = ") || line.hasPrefix("name=") { name = name ?? value(line) }
            else if line.hasPrefix("version = ") || line.hasPrefix("version=") { version = version ?? value(line) }
            else if line.hasPrefix("source = ") {
                if line.contains("registry") { registry = true }
                if line.contains("editable") || line.contains("virtual") || line.contains("directory") || line.contains("path =") { own = true }
            }
        }
        flush()
        return out
    }

    // MARK: Others

    static func goSum(_ text: String) -> [PackageRef] {
        text.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ")
            guard parts.count >= 2 else { return nil }
            var version = String(parts[1])
            if version.hasSuffix("/go.mod") { version = String(version.dropLast(7)) }
            return PackageRef(ecosystem: .go, name: String(parts[0]), version: version)
        }
    }

    /// `    name (1.2.3)` under a `specs:` (a platform suffix such as `-arm64-darwin` dropped).
    static func gemfile(_ text: String) -> [PackageRef] {
        var out: [PackageRef] = []
        var inSpecs = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if !line.hasPrefix(" ") { inSpecs = false; continue }
            if line.trimmingCharacters(in: .whitespaces) == "specs:" { inSpecs = true; continue }
            guard inSpecs, line.hasPrefix("    "), !line.hasPrefix("     "),
                  let open = line.firstIndex(of: "("), line.hasSuffix(")") else { continue }
            let name = line[..<open].trimmingCharacters(in: .whitespaces)
            var version = String(line[line.index(after: open)..<line.index(before: line.endIndex)])
            if let dash = version.firstIndex(of: "-") { version = String(version[..<dash]) }
            out.append(PackageRef(ecosystem: .rubygems, name: name, version: version))
        }
        return out
    }

    static func composer(_ text: String) -> [PackageRef] {
        guard let obj = json(text) else { return [] }
        return ["packages", "packages-dev"].flatMap { key in
            (obj[key] as? [[String: Any]] ?? []).compactMap { p in
                guard let n = p["name"] as? String, let v = p["version"] as? String else { return nil }
                return PackageRef(ecosystem: .packagist, name: n, version: v)
            }
        }
    }

    static func nuget(_ text: String) -> [PackageRef] {
        guard let obj = json(text), let frameworks = obj["dependencies"] as? [String: Any] else { return [] }
        return frameworks.values.flatMap { deps in
            (deps as? [String: Any] ?? [:]).compactMap { name, value -> PackageRef? in
                guard let d = value as? [String: Any], d["type"] as? String != "Project",
                      let v = d["resolved"] as? String else { return nil }
                return PackageRef(ecosystem: .nuget, name: name, version: v)
            }
        }
    }

    private static func json(_ text: String) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
    }
}
