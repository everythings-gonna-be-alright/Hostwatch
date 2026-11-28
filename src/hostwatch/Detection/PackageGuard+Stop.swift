import Foundation

// Package guard, layer 3 (ADR 0024): the compact lists the collector stops installs with, what it stopped, the check
// the Claude Code guard asks, and Strict's quarantine of a listed package that arrived anyway.

/// An install or install script the collector stopped.
struct PackageStop: Codable, Identifiable, Equatable, Sendable {
    var package: PackageRef
    var malwareID: String
    var how: String             // "script" or "install"
    var detail: String          // postinstall, npm install
    var program: String
    var args: String
    var date: Date

    var id: String { package.key + "\t" + package.version + "\t" + detail + "\t" + date.ISO8601Format() }
    var advisory: URL? { malwareID.isEmpty ? nil : URL(string: "https://osv.dev/vulnerability/\(malwareID)") }

    /// "Stopped the postinstall script of x 1.0", "Stopped npm install of x".
    var sentence: String {
        how == "script" ? "Stopped the \(detail) script of \(package.label)"
            : "Stopped \(detail) of \(package.version.isEmpty ? package.name : package.label)"
    }
}

/// A listed package's folder Strict moved out of a project, and where to put it back.
struct QuarantinedPackage: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var package: PackageRef
    var malwareID: String
    var original: String
    var stored: String
    var date: Date
}

extension PackageGuard {
    // MARK: The lists in memory

    /// Rebuilds the in-memory lists from the sealed indexes, then sends them to the collector.
    func refreshListed() {
        let directory = self.directory
        let ecos = PackageEcosystem.allCases.filter { lists[$0.osv] != nil }
        Task {
            let built = await Task.detached(priority: .utility) { () -> ListedPackages in
                var l = ListedPackages()
                for eco in ecos {
                    if let index = Vault.shared.read(directory.appendingPathComponent("\(eco.osv).idx")) { l.add(index: index, ecosystem: eco) }
                }
                return l
            }.value
            listed = built
            collectorLists = built.payload
            sendToCollector(lists: true)
        }
    }

    /// The collector's config: stop or not, and the lists (kept by the model and sent again on every connect).
    func sendToCollector(lists: Bool) {
        guard !collectorLists.isEmpty || !lists else { return }
        onCollectorConfig?(["enforce": mode.enforces, "lists": collectorLists])
    }

    /// The record id listing this package, nil when none does: for the Claude Code guard, before a command runs.
    func listedID(_ ref: PackageRef) -> String? {
        guard enabled, let record = listed.record(for: ref) else { return nil }
        if !record.id.isEmpty { return record.id }
        return recordID(ref) ?? "a malicious-package record"
    }

    /// An every-version record's id, from the index (the lists in memory keep only names).
    func recordID(_ ref: PackageRef) -> String? {
        guard let index = Vault.shared.read(indexURL(ref.ecosystem)) else { return nil }
        return MalwareIndex.matches(in: index, ecosystem: ref.ecosystem, wanted: [ref])[ref]?.id
    }

    // MARK: What the collector stopped

    /// A `guard_package` line: recorded, newest first, and returned for its story.
    func stopped(_ obj: [String: Any]) -> PackageStop? {
        func str(_ k: String) -> String { obj[k] as? String ?? "" }
        guard let eco = PackageEcosystem(rawValue: str("ecosystem")), !str("package").isEmpty else { return nil }
        let ref = PackageRef(ecosystem: eco, name: str("package"), version: str("version"))
        let id = str("malware").isEmpty ? recordID(ref) ?? "" : str("malware")
        let stop = PackageStop(package: ref, malwareID: id, how: str("how"), detail: str("detail"),
                               program: str("path"), args: str("args"), date: Date())
        // One install runs a script many times over (a retry, each workspace): one entry a minute is enough.
        if let last = stops.first, last.package == ref, last.detail == stop.detail, stop.date.timeIntervalSince(last.date) < 60 { return nil }
        stops.insert(stop, at: 0)
        if stops.count > 200 { stops.removeLast(stops.count - 200) }
        save()
        return stop
    }

    func dismissStop(_ stop: PackageStop) {
        stops.removeAll { $0.id == stop.id }
        save()
    }

    // MARK: Quarantine (Strict)

    var quarantineDirectory: URL { directory.appendingPathComponent("quarantine", isDirectory: true) }

    /// Moves a listed npm package's folders out of the project (the version in their package.json must match).
    /// Other ecosystems keep their packages in shared places (site-packages, the Go and Cargo caches): the story
    /// gives the fix instead.
    func quarantine(_ f: PackageFinding) {
        guard f.package.ecosystem == .npm else { return }
        for folder in Self.installedFolders(f) {
            let id = UUID().uuidString
            let dest = quarantineDirectory.appendingPathComponent(id, isDirectory: true)
            do {
                try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
                let stored = dest.appendingPathComponent((folder as NSString).lastPathComponent)
                try FileManager.default.moveItem(atPath: folder, toPath: stored.path)
                quarantined.insert(QuarantinedPackage(id: id, package: f.package, malwareID: f.malwareID, original: folder,
                                                      stored: stored.path, date: Date()), at: 0)
            } catch {
                lastError = "\(f.package.label) couldn't be moved to quarantine: \(error.localizedDescription)"
            }
        }
        save()
    }

    /// Puts it back where it was, unless something new is there now.
    func restore(_ q: QuarantinedPackage) {
        guard !FileManager.default.fileExists(atPath: q.original) else {
            lastError = "\(q.package.label) wasn't restored: \(q.original) exists again"
            return
        }
        do {
            try FileManager.default.moveItem(atPath: q.stored, toPath: q.original)
            try? FileManager.default.removeItem(atPath: (q.stored as NSString).deletingLastPathComponent)
            quarantined.removeAll { $0.id == q.id }
            save()
        } catch {
            lastError = "\(q.package.label) couldn't be restored: \(error.localizedDescription)"
        }
    }

    /// Deletes it for good.
    func deleteQuarantined(_ q: QuarantinedPackage) {
        try? FileManager.default.removeItem(atPath: (q.stored as NSString).deletingLastPathComponent)
        quarantined.removeAll { $0.id == q.id }
        save()
    }

    /// `node_modules/<name>` and one level of nesting below it, where the version matches the finding.
    nonisolated static func installedFolders(_ f: PackageFinding) -> [String] {
        let fm = FileManager.default
        let dir = (f.lockfile as NSString).deletingLastPathComponent
        let modules = dir.hasSuffix("/node_modules") ? dir : (dir as NSString).appendingPathComponent("node_modules")
        var candidates = [(modules as NSString).appendingPathComponent(f.package.name)]
        for item in (try? fm.contentsOfDirectory(atPath: modules)) ?? [] where !item.hasPrefix(".") {
            let parents = item.hasPrefix("@")
                ? ((try? fm.contentsOfDirectory(atPath: "\(modules)/\(item)")) ?? []).map { "\(modules)/\(item)/\($0)" }
                : ["\(modules)/\(item)"]
            for parent in parents { candidates.append("\(parent)/node_modules/\(f.package.name)") }
        }
        return candidates.filter { path in
            guard let data = fm.contents(atPath: path + "/package.json"),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
            return obj["name"] as? String == f.package.name && obj["version"] as? String == f.package.version
        }
    }
}
