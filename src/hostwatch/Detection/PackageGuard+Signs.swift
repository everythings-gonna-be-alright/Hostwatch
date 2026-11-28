import Foundation

// Package guard, layer 4 (ADR 0024): what the collector's containment reported, the names it compares installs
// with, and the opt-in check of how new a package is.

extension PackageGuard {
    /// The names lookalikes are compared with: the built-in list and the packages your projects share.
    var known: [String: Set<String>] {
        var out: [String: Set<String>] = [:]
        for (eco, names) in PackageNames.builtIn { out[eco.osv, default: []].formUnion(names.map(eco.normalize)) }
        for (eco, names) in projectNames { out[eco, default: []].formUnion(names) }
        return out
    }

    /// What the collector gets: the mode, the lists, the contained places and hosts, the known names.
    func collectorConfig(home: String = NSHomeDirectory()) -> [String: Any] {
        let fm = FileManager.default
        let npmrc = fm.contents(atPath: home + "/.npmrc").map { String(decoding: $0, as: UTF8.self) }
        let pip = (fm.contents(atPath: home + "/.config/pip/pip.conf") ?? fm.contents(atPath: home + "/.pip/pip.conf"))
            .map { String(decoding: $0, as: UTF8.self) }
        var config: [String: Any] = [
            "mode": mode.rawValue,
            "contain": ["read": InstallContainment.readPaths(home: home), "write": InstallContainment.writePaths(home: home),
                        "hosts": InstallContainment.configuredRegistries(npmrc: npmrc, pipConf: pip)],
            "known": known.mapValues { $0.sorted() },
        ]
        if !collectorLists.isEmpty { config["lists"] = collectorLists }
        return config
    }

    /// A `guard_contain` line: recorded like a stop, and returned for its story.
    func contained(_ obj: [String: Any]) -> PackageStop? {
        func str(_ k: String) -> String { obj[k] as? String ?? "" }
        guard let eco = PackageEcosystem(rawValue: str("ecosystem")), !str("package").isEmpty, !str("tried").isEmpty else { return nil }
        let stop = PackageStop(package: PackageRef(ecosystem: eco, name: str("package"), version: str("version")), malwareID: "",
                               how: str("how"), detail: str("detail"), program: str("path"), args: str("args"), date: Date(),
                               what: str("tried"), target: str("target"), enforced: obj["enforced"] as? Bool ?? false)
        return record(stop)
    }

    /// One entry per package, action and target an hour: an install retried ten times is one line and one story.
    func record(_ stop: PackageStop) -> PackageStop? {
        if stops.contains(where: { $0.package == stop.package && $0.what == stop.what && $0.target == stop.target
                                   && $0.detail == stop.detail && stop.date.timeIntervalSince($0.date) < 3600 }) { return nil }
        stops.insert(stop, at: 0)
        if stops.count > 200 { stops.removeLast(stops.count - 200) }
        save()
        return stop
    }

    /// A `guard_install` line: a package installed by name. With the age check on, a package first published in the
    /// last week is a sign (`onSign`).
    func installSeen(_ obj: [String: Any]) {
        guard ageCheck, let eco = PackageEcosystem(rawValue: obj["ecosystem"] as? String ?? ""),
              let name = obj["package"] as? String, !name.isEmpty else { return }
        let ref = PackageRef(ecosystem: eco, name: name, version: "")
        guard !(known[eco.osv]?.contains(eco.normalize(name)) ?? false) else { return }     // well known: not new
        let detail = obj["detail"] as? String ?? eco.title
        Task {
            guard let first = await PackageAge.firstPublished(ref, session: session),
                  PackageAge.isNew(first) else { return }
            let stop = PackageStop(package: ref, malwareID: "", how: "install", detail: detail, program: obj["path"] as? String ?? "",
                                   args: obj["args"] as? String ?? "", date: Date(), what: "new",
                                   target: first.formatted(date: .abbreviated, time: .omitted), enforced: false)
            if let s = record(stop) { onSign?(s) }
        }
    }

    /// For the Claude Code guard: the names in `refs` first published in the last week (none with the check off).
    func newPackages(_ refs: [PackageRef]) async -> [(PackageRef, Date)] {
        guard ageCheck else { return [] }
        var out: [(PackageRef, Date)] = []
        for ref in refs.prefix(3) where !(known[ref.ecosystem.osv]?.contains(ref.ecosystem.normalize(ref.name)) ?? false) {
            if let d = await PackageAge.firstPublished(ref, session: session), PackageAge.isNew(d) { out.append((ref, d)) }
        }
        return out
    }
}

/// When a package was first published, from the public registry of its language: only the name is sent, and only
/// with the age check on. Scoped npm names (`@company/x`) are never asked about: they are often private.
enum PackageAge {
    static let newDays = 7.0

    static func isNew(_ first: Date, now: Date = Date()) -> Bool { now.timeIntervalSince(first) < newDays * 86_400 }

    static func url(_ ref: PackageRef) -> URL? {
        let name = ref.name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ref.name
        switch ref.ecosystem {
        case .npm: return ref.name.hasPrefix("@") ? nil : URL(string: "https://registry.npmjs.org/\(name)")
        case .pypi: return URL(string: "https://pypi.org/pypi/\(name)/json")
        case .crates: return URL(string: "https://crates.io/api/v1/crates/\(name)")
        case .rubygems: return URL(string: "https://rubygems.org/api/v1/versions/\(name).json")
        default: return nil
        }
    }

    static func firstPublished(_ ref: PackageRef, session: URLSession) async -> Date? {
        guard let url = url(ref) else { return nil }
        var request = URLRequest(url: url, timeoutInterval: 3)
        request.setValue("Hostwatch", forHTTPHeaderField: "User-Agent")       // crates.io refuses requests without one
        guard let (data, response) = try? await session.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return firstPublished(json: data, ref.ecosystem)
    }

    /// The earliest publish time in a registry's answer. Pure.
    static func firstPublished(json data: Data, _ eco: PackageEcosystem) -> Date? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) else { return nil }
        let dates: [String]
        switch eco {
        case .npm: dates = [((obj as? [String: Any])?["time"] as? [String: Any])?["created"] as? String].compactMap { $0 }
        case .pypi:
            let releases = (obj as? [String: Any])?["releases"] as? [String: [[String: Any]]] ?? [:]
            dates = releases.values.flatMap { $0.compactMap { $0["upload_time_iso_8601"] as? String } }
        case .crates: dates = [((obj as? [String: Any])?["crate"] as? [String: Any])?["created_at"] as? String].compactMap { $0 }
        case .rubygems: dates = (obj as? [[String: Any]] ?? []).compactMap { $0["created_at"] as? String }
        default: dates = []
        }
        return dates.compactMap(parse).min()
    }

    private static func parse(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }
}
