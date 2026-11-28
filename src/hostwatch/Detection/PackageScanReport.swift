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
        g.save()
        done = true
    }
    while !done { RunLoop.main.run(until: Date().addingTimeInterval(0.2)) }
    exit(0)
}
