import Foundation

// The malicious-package list (ADR 0024): OSV.dev's MAL- records, fed by the OpenSSF malicious-packages project, kept
// as one small text index per ecosystem. A match is an exact name and version, so it is proof, not a sign (0023).

enum PackageEcosystem: String, CaseIterable, Codable, Sendable {
    case npm, pypi = "PyPI", go = "Go", crates = "crates.io", rubygems = "RubyGems", packagist = "Packagist", nuget = "NuGet"

    /// OSV's folder name for the ecosystem.
    var osv: String { rawValue }
    var title: String { rawValue }

    /// The name as the registry compares it: PyPI ignores case and treats `-`, `_` and `.` alike (PEP 503), crates
    /// treat `-` and `_` alike, Packagist and NuGet ignore case. npm doesn't: its old capitalised packages are other
    /// packages (`Orchestrator` is listed, gulp's `orchestrator` isn't). Go module paths are exact.
    func normalize(_ name: String) -> String {
        switch self {
        case .npm, .go, .rubygems: return name
        case .pypi:
            return name.lowercased().replacingOccurrences(of: "[-_.]+", with: "-", options: .regularExpression)
        case .crates: return name.lowercased().replacingOccurrences(of: "_", with: "-")
        case .packagist, .nuget: return name.lowercased()
        }
    }
}

/// One installed package, as a lockfile or a package folder names it.
struct PackageRef: Hashable, Codable, Sendable {
    var ecosystem: PackageEcosystem
    var name: String
    var version: String

    var key: String { ecosystem.rawValue + "\t" + ecosystem.normalize(name) }
    var label: String { "\(name) \(version)" }
}

/// One MAL- record for one package: every version, a list, or ranges.
struct MalwareRecord: Equatable, Sendable {
    struct Range: Equatable, Sendable {
        var introduced: String
        var fixed: String?
        var lastAffected: String?
    }

    var id: String
    var allVersions = false
    var versions: Set<String> = []
    var ranges: [Range] = []

    /// An empty version is unknown (`npm install x`): only a record for every version covers it.
    func covers(_ version: String) -> Bool {
        if allVersions || versions.contains(version) { return true }
        if version.isEmpty { return false }
        let v = version.hasPrefix("v") ? String(version.dropFirst()) : version
        if versions.contains(v) { return true }
        return ranges.contains { r in
            (r.introduced == "0" || PackageVersion.compare(v, r.introduced) >= 0)
                && (r.fixed.map { PackageVersion.compare(v, $0) < 0 } ?? true)
                && (r.lastAffected.map { PackageVersion.compare(v, $0) <= 0 } ?? true)
        }
    }

    /// `*`, `=1.0.1,1.0.2` or `>1.2.0<1.3.0` (fixed) / `>1.2.0<=1.2.9` (last affected), ranges joined by `|`.
    var spec: String {
        if allVersions { return "*" }
        var parts: [String] = []
        if !versions.isEmpty { parts.append("=" + versions.sorted().joined(separator: ",")) }
        for r in ranges {
            parts.append(">" + r.introduced + (r.fixed.map { "<" + $0 } ?? r.lastAffected.map { "<=" + $0 } ?? ""))
        }
        return parts.joined(separator: "|")
    }

    init(id: String, allVersions: Bool = false, versions: Set<String> = [], ranges: [Range] = []) {
        self.id = id; self.allVersions = allVersions; self.versions = versions; self.ranges = ranges
    }

    init?(id: String, spec: String) {
        self.id = id
        if spec == "*" { allVersions = true; return }
        for part in spec.split(separator: "|") {
            if part.hasPrefix("=") {
                versions.formUnion(part.dropFirst().split(separator: ",").map(String.init))
            } else if part.hasPrefix(">") {
                let body = part.dropFirst()
                if let r = body.range(of: "<=") {
                    ranges.append(Range(introduced: String(body[..<r.lowerBound]), lastAffected: String(body[r.upperBound...])))
                } else if let r = body.range(of: "<") {
                    ranges.append(Range(introduced: String(body[..<r.lowerBound]), fixed: String(body[r.upperBound...])))
                } else {
                    ranges.append(Range(introduced: String(body)))
                }
            }
        }
        if versions.isEmpty && ranges.isEmpty { return nil }
    }
}

/// Version order good enough for ranges in malware records: numbers compare as numbers, a pre-release
/// (`1.0.0-beta`, `1.0rc1`) sorts before its release. Not a full semver or PEP 440 implementation: records name
/// exact versions far more often than ranges (15,000 lists and 500 ranges among npm's 225,000).
enum PackageVersion {
    static func compare(_ a: String, _ b: String) -> Int {
        let (am, ap) = split(a), (bm, bp) = split(b)
        for i in 0..<max(am.count, bm.count) {
            let x = i < am.count ? am[i] : "0", y = i < bm.count ? bm[i] : "0"
            let c = component(x, y)
            if c != 0 { return c }
        }
        switch (ap.isEmpty, bp.isEmpty) {
        case (true, true): return 0
        case (true, false): return 1
        case (false, true): return -1
        default: return ap < bp ? -1 : ap > bp ? 1 : 0
        }
    }

    private static func split(_ v: String) -> ([String], String) {
        var s = v.hasPrefix("v") ? String(v.dropFirst()) : v
        if let plus = s.firstIndex(of: "+") { s = String(s[..<plus]) }
        var pre = ""
        if let dash = s.firstIndex(of: "-") { pre = String(s[s.index(after: dash)...]); s = String(s[..<dash]) }
        var main: [String] = []
        for part in s.split(separator: ".") {
            // "0rc1": the number, then the rest as a pre-release.
            let digits = part.prefix { $0.isNumber }
            main.append(digits.isEmpty ? String(part) : String(digits))
            if digits.count < part.count, pre.isEmpty { pre = String(part.dropFirst(digits.count)) }
        }
        return (main, pre)
    }

    private static func component(_ x: String, _ y: String) -> Int {
        if let a = Int(x), let b = Int(y) { return a < b ? -1 : a > b ? 1 : 0 }
        return x < y ? -1 : x > y ? 1 : 0
    }
}

/// The index: lines of `name<TAB>id<TAB>spec`, one file per ecosystem. Kept on disk and read line by line for the
/// names a scan is looking for, so a quarter of a million records never sit in memory.
enum MalwareIndex {
    /// The index lines one OSV record adds (none for a withdrawn record), with the record's id and last change.
    static func lines(fromOSV data: Data, ecosystem: PackageEcosystem) -> (id: String, modified: String, lines: [String])? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = obj["id"] as? String, id.hasPrefix("MAL-") else { return nil }
        let modified = obj["modified"] as? String ?? ""
        if obj["withdrawn"] != nil { return (id, modified, []) }
        var out: [String] = []
        for case let a as [String: Any] in obj["affected"] as? [Any] ?? [] {
            guard let pkg = a["package"] as? [String: Any], let name = pkg["name"] as? String,
                  (pkg["ecosystem"] as? String)?.hasPrefix(ecosystem.osv) ?? false,
                  !name.contains("\t"), !name.contains("\n") else { continue }
            var record = MalwareRecord(id: id)
            record.versions = Set((a["versions"] as? [String] ?? []).filter { !$0.contains("|") && !$0.contains(",") })
            for case let r as [String: Any] in a["ranges"] as? [Any] ?? [] where r["type"] as? String != "GIT" {
                var range: MalwareRecord.Range?
                for case let ev as [String: String] in r["events"] as? [Any] ?? [] {
                    if let i = ev["introduced"] {
                        if let open = range { record.ranges.append(open) }
                        range = MalwareRecord.Range(introduced: i)
                    } else if let f = ev["fixed"] { range?.fixed = f; if let r = range { record.ranges.append(r) }; range = nil }
                    else if let l = ev["last_affected"] { range?.lastAffected = l; if let r = range { record.ranges.append(r) }; range = nil }
                }
                if let open = range { record.ranges.append(open) }
            }
            // "Introduced 0, never fixed" is every version: most records say it that way.
            if record.ranges.contains(where: { $0.introduced == "0" && $0.fixed == nil && $0.lastAffected == nil }) {
                record = MalwareRecord(id: id, allVersions: true)
            } else if record.versions.isEmpty && record.ranges.isEmpty {
                record.allVersions = true       // a malicious package with no versions named: all of it
            }
            out.append(ecosystem.normalize(name) + "\t" + id + "\t" + record.spec)
        }
        return (id, modified, out)
    }

    /// The records in an index that cover any of `wanted` (all one ecosystem), by package.
    static func matches(in index: Data, ecosystem: PackageEcosystem, wanted: Set<PackageRef>) -> [PackageRef: MalwareRecord] {
        var byName: [String: [PackageRef]] = [:]
        for ref in wanted where ref.ecosystem == ecosystem { byName[ecosystem.normalize(ref.name), default: []].append(ref) }
        guard !byName.isEmpty else { return [:] }
        var found: [PackageRef: MalwareRecord] = [:]
        forEachLine(index) { line in
            guard let tab = line.firstIndex(of: "\t"), let refs = byName[String(line[..<tab])] else { return }
            let rest = line[line.index(after: tab)...].split(separator: "\t", maxSplits: 1)
            guard rest.count == 2, let record = MalwareRecord(id: String(rest[0]), spec: String(rest[1])) else { return }
            for ref in refs where found[ref] == nil && record.covers(ref.version) { found[ref] = record }
        }
        return found
    }

    /// Replaces every line of the given records with their new lines (a changed or withdrawn record).
    static func merged(_ index: Data, replacing ids: Set<String>, with lines: [String]) -> Data {
        var out: [String] = []
        forEachLine(index) { line in
            let parts = line.split(separator: "\t", maxSplits: 2)
            if parts.count == 3, ids.contains(String(parts[1])) { return }
            out.append(String(line))
        }
        out.append(contentsOf: lines)
        return Data((out.joined(separator: "\n") + (out.isEmpty ? "" : "\n")).utf8)
    }

    static func count(_ index: Data) -> Int { index.reduce(0) { $1 == 10 ? $0 + 1 : $0 } }

    private static func forEachLine(_ data: Data, _ body: (Substring) -> Void) {
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) { body(line) }
    }
}
