import Foundation

/// `--package-scan [folder]`: finds projects (Spotlight, or only `folder`), brings the lists they need up to date in
/// a scratch folder kept between runs (never your own), and prints what was checked and found, with timings.
@MainActor
func runPackageScan(_ folder: String?) -> Never {
    let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-package-scan", isDirectory: true)
    let defaults = UserDefaults(suiteName: "hostwatch-package-scan") ?? .standard
    defaults.removeObject(forKey: "packageGuardFolders")
    let g = PackageGuard(directory: scratch, defaults: defaults)
    var done = false
    Task {
        let t0 = Date()
        let paths = await PackageGuard.discover(folders: folder.map { [$0] } ?? [])
            .filter { folder == nil || $0.hasPrefix(folder!) }
        print("Projects: \(Set(paths.map { ($0 as NSString).deletingLastPathComponent }).count), lockfiles \(paths.count)"
              + String(format: " (%.1f s)", Date().timeIntervalSince(t0)))
        var byEco: [PackageEcosystem: Int] = [:]
        for p in paths { if let e = PackageScan.ecosystem(at: p) { byEco[e, default: 0] += PackageScan.packages(at: p).count } }
        for (e, n) in byEco.sorted(by: { $0.value > $1.value }) { print("  \(e.title): \(n) packages") }
        for eco in byEco.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            let t = Date()
            let changed = await g.updateList(eco)
            let s = g.lists[eco.osv]
            print("List \(eco.title): \(s?.count ?? 0) records, \(changed ? "updated" : "unchanged")"
                  + String(format: " (%.1f s)", Date().timeIntervalSince(t)) + (g.lastError.isEmpty ? "" : " — \(g.lastError)"))
        }
        let t = Date()
        g.seed(paths)
        await g.scan(all: true)
        print(String(format: "Checked in %.1f s", Date().timeIntervalSince(t)))
        if g.findings.isEmpty { print("No malicious packages found.") }
        for f in g.findings { print("FOUND \(f.package.label) (\(f.package.ecosystem.title)) \(f.malwareID) in \(f.lockfile)") }
        // The compact lists the collector gets (layer 3): their size, and a lookup's cost.
        let tl = Date()
        var listed = ListedPackages()
        for eco in byEco.keys { if let index = Vault.shared.read(g.indexURL(eco)) { listed.add(index: index, ecosystem: eco) } }
        let wire = (try? JSONSerialization.data(withJSONObject: listed.payload))?.count ?? 0
        print(String(format: "Collector lists: %d names, %.1f MB on the wire, built in %.2f s", listed.count,
                     Double(wire) / 1_048_576, Date().timeIntervalSince(tl)))
        let probes = (0..<100_000).map { PackageRef(ecosystem: .npm, name: "probe-\($0)", version: "1.0.0") }
        let tp = Date()
        let hits = probes.filter { listed.record(for: $0) != nil }.count
        print(String(format: "Lookups: %.2f µs each (%d hits in 100,000 made-up names)",
                     Date().timeIntervalSince(tp) / 100_000 * 1_000_000, hits))
        g.save()
        done = true
    }
    while !done { RunLoop.main.run(until: Date().addingTimeInterval(0.2)) }
    exit(0)
}
