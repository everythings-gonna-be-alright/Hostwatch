import Combine
import Foundation

// Package guard, layers 1 and 2 (ADR 0024): the malicious-package lists for the ecosystems your projects use, and
// every lockfile on the Mac checked against them, again whenever a lockfile changes or a list grows.

/// A listed package version installed in a project.
struct PackageFinding: Codable, Identifiable, Equatable, Sendable {
    var package: PackageRef
    var malwareID: String
    var lockfile: String
    var found: Date

    var id: String { package.key + "\t" + package.version + "\t" + lockfile }
    var project: String { PackageScan.projectName(lockfile) }
    var advisory: URL? { URL(string: "https://osv.dev/vulnerability/\(malwareID)") }
}

/// Decisions over paths and lists, without I/O.
enum PackageScan {
    /// Lockfiles that belong to a project you work on, not to a package, a cache or an app.
    static func isProjectLockfile(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        guard Lockfiles.ecosystem(name) != nil || name == "pyvenv.cfg" else { return false }
        if name == ".package-lock.json" { return path.hasSuffix("/node_modules/.package-lock.json")
            && !path.dropLast("/node_modules/.package-lock.json".count).contains("/node_modules/") }
        let skip = ["/node_modules/", "/.Trash/", "/Library/", "/.cache/", "/site-packages/", "/.cargo/registry/",
                    "/go/pkg/mod/", ".app/Contents/", "/.npm/", "/.pnpm-store/", "/vendor/bundle/"]
        return !skip.contains(where: path.contains)
    }

    /// The project's folder name: `~/code/shop/package-lock.json` → "shop".
    static func projectName(_ lockfile: String) -> String {
        var dir = (lockfile as NSString).deletingLastPathComponent
        for inner in ["/node_modules", "/.venv", "/venv"] where dir.hasSuffix(inner) { dir = String(dir.dropLast(inner.count)) }
        return (dir as NSString).lastPathComponent
    }

    /// The packages a lockfile (or a virtual environment, by its `pyvenv.cfg`) has installed.
    static func packages(at path: String) -> [PackageRef] {
        let name = (path as NSString).lastPathComponent
        if name == "pyvenv.cfg" {
            let lib = ((path as NSString).deletingLastPathComponent as NSString).appendingPathComponent("lib")
            let fm = FileManager.default
            return ((try? fm.contentsOfDirectory(atPath: lib)) ?? []).filter { $0.hasPrefix("python") }.flatMap { py in
                ((try? fm.contentsOfDirectory(atPath: "\(lib)/\(py)/site-packages")) ?? []).compactMap(Lockfiles.distInfo)
            }
        }
        guard let data = FileManager.default.contents(atPath: path), data.count < 64 << 20 else { return [] }
        return Lockfiles.parse(fileName: name, text: String(decoding: data, as: UTF8.self))
    }

    static func ecosystem(at path: String) -> PackageEcosystem? {
        let name = (path as NSString).lastPathComponent
        return name == "pyvenv.cfg" ? .pypi : Lockfiles.ecosystem(name)
    }

    /// When it last changed: a virtual environment by its site-packages, which every install touches.
    static func stamp(_ path: String) -> Date? {
        var target = path
        if path.hasSuffix("pyvenv.cfg") {
            let lib = ((path as NSString).deletingLastPathComponent as NSString).appendingPathComponent("lib")
            if let py = (try? FileManager.default.contentsOfDirectory(atPath: lib))?.first(where: { $0.hasPrefix("python") }) {
                target = "\(lib)/\(py)/site-packages"
            }
        }
        return (try? FileManager.default.attributesOfItem(atPath: target))?[.modificationDate] as? Date
    }
}

@MainActor
final class PackageGuard: ObservableObject {
    struct ListState: Codable, Equatable, Sendable {
        var updated: Date
        var modified: String        // the newest record's change time, where the next update starts
        var count: Int
    }

    private struct Saved: Codable {
        var lists: [String: ListState] = [:]
        var lockfiles: [String: Date] = [:]
        var findings: [PackageFinding] = []
        var dismissed: [String] = []
        var discovered: Date?
        var stops: [PackageStop]? = []
        var quarantined: [QuarantinedPackage]? = []
    }

    @Published private(set) var findings: [PackageFinding] = []
    @Published private(set) var lists: [String: ListState] = [:]
    @Published private(set) var lockfiles: [String: Date] = [:]
    @Published private(set) var busy = ""            // what it is doing now, empty when idle
    @Published var lastError = ""
    /// Watch finds what is installed. Ask also stops listed packages' installs and scripts. Strict also moves a
    /// listed package that arrived anyway to quarantine.
    @Published var mode: ProtectionMode {
        didSet {
            defaults.set(mode.rawValue, forKey: "packageGuardMode")
            if mode != .off { tick() }
            sendToCollector(lists: false)
        }
    }
    var enabled: Bool { mode != .off }
    @Published var stops: [PackageStop] = []
    @Published var quarantined: [QuarantinedPackage] = []
    /// The lists in memory, for the collector and the Claude Code guard.
    var listed = ListedPackages()
    /// The collector's part: the mode and the compact lists (`HUDModel.packageConfig`).
    var onCollectorConfig: (([String: Any]) -> Void)?
    var collectorLists: [String: Any] = [:]
    /// Folders you added, scanned besides what Spotlight finds.
    @Published private(set) var folders: [String]

    /// A new finding: the app raises its story.
    var onFinding: ((PackageFinding) -> Void)?

    let directory: URL
    private let defaults: UserDefaults
    private var dismissed = Set<String>()
    private var discovered: Date?
    private var timer: Timer?
    private var running = false

    static let refreshInterval: TimeInterval = 24 * 3600
    static let osvBase = "https://osv-vulnerabilities.storage.googleapis.com"
    /// More changes than this since the last update: the whole list again is cheaper than one request each.
    static let incrementalLimit = 2000

    var session: URLSession = URLSession(configuration: {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 60
        c.timeoutIntervalForResource = 900
        return c
    }(), delegate: SameHostRedirects(), delegateQueue: nil)

    init(directory: URL = AppPaths.support.appendingPathComponent("packages", isDirectory: true), defaults: UserDefaults = .standard) {
        self.directory = directory
        self.defaults = defaults
        let enabledBefore = defaults.object(forKey: "packageGuardEnabled") as? Bool ?? true
        mode = defaults.string(forKey: "packageGuardMode").flatMap(ProtectionMode.init(rawValue:)) ?? (enabledBefore ? .ask : .off)
        folders = defaults.stringArray(forKey: "packageGuardFolders") ?? []
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let data = Vault.shared.read(stateURL), let saved = try? JSONDecoder().decode(Saved.self, from: data) {
            lists = saved.lists; lockfiles = saved.lockfiles; findings = saved.findings
            dismissed = Set(saved.dismissed); discovered = saved.discovered
            stops = saved.stops ?? []; quarantined = saved.quarantined ?? []
        }
    }

    var stateURL: URL { directory.appendingPathComponent("state.json") }
    func indexURL(_ eco: PackageEcosystem) -> URL { directory.appendingPathComponent("\(eco.osv).idx") }

    func start() {
        refreshListed()
        tick()
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    /// Hourly: find projects once a day, bring the lists your projects need up to date, and scan what changed.
    func tick(force: Bool = false) {
        guard enabled, !running else { return }
        running = true
        Task {
            defer { running = false; busy = "" }
            if force || discovered.map({ Date().timeIntervalSince($0) > Self.refreshInterval }) ?? true {
                busy = "Finding projects"
                let found = await Self.discover(folders: folders)
                for path in found where lockfiles[path] == nil { lockfiles[path] = .distantPast }
                lockfiles = lockfiles.filter { FileManager.default.fileExists(atPath: $0.key) }
                discovered = Date()
            }
            let inUse = Set(lockfiles.keys.compactMap(PackageScan.ecosystem))
            var listsChanged = false
            for eco in PackageEcosystem.allCases where inUse.contains(eco) {
                let state = lists[eco.osv]
                guard force || state.map({ Date().timeIntervalSince($0.updated) > Self.refreshInterval }) ?? true else { continue }
                busy = "Updating the \(eco.title) list"
                if await updateList(eco) { listsChanged = true }
            }
            if listsChanged { refreshListed() }
            busy = "Checking projects"
            await scan(all: listsChanged || force)
            save()
        }
    }

    func scanNow() { tick(force: true) }

    /// Lockfiles to check from now (the command-line scan, tests).
    func seed(_ paths: [String]) {
        for path in paths where lockfiles[path] == nil { lockfiles[path] = .distantPast }
    }

    func addFolder(_ path: String) {
        guard !folders.contains(path) else { return }
        folders.append(path)
        defaults.set(folders, forKey: "packageGuardFolders")
        discovered = nil
        tick()
    }

    func removeFolder(_ path: String) {
        folders.removeAll { $0 == path }
        defaults.set(folders, forKey: "packageGuardFolders")
    }

    /// You dealt with it: gone, and the same package in the same lockfile isn't reported again.
    func dismiss(_ finding: PackageFinding) {
        dismissed.insert(finding.id)
        findings.removeAll { $0.id == finding.id }
        save()
    }

    // MARK: Lists

    /// Brings one list up to date: the changes since last time, or the whole export the first time (and after a long
    /// gap). True when the index changed.
    func updateList(_ eco: PackageEcosystem) async -> Bool {
        do {
            if let state = lists[eco.osv], let ids = try await changedIDs(eco, since: state.modified), ids.count <= Self.incrementalLimit {
                guard !ids.isEmpty else { lists[eco.osv]?.updated = Date(); return false }
                var lines: [String] = [], newest = state.modified
                for id in ids {
                    let url = URL(string: "\(Self.osvBase)/\(eco.osv)/\(id).json")!
                    let (data, response) = try await session.data(from: url)
                    guard (response as? HTTPURLResponse)?.statusCode == 200,
                          let record = MalwareIndex.lines(fromOSV: data, ecosystem: eco) else { continue }
                    lines += record.lines
                    newest = max(newest, record.modified)
                }
                let old = Vault.shared.read(indexURL(eco)) ?? Data()
                let merged = MalwareIndex.merged(old, replacing: Set(ids), with: lines)
                try Vault.shared.write(merged, to: indexURL(eco))
                lists[eco.osv] = ListState(updated: Date(), modified: newest, count: MalwareIndex.count(merged))
                lastError = ""
                return true
            }
            let (file, response) = try await session.download(from: URL(string: "\(Self.osvBase)/\(eco.osv)/all.zip")!)
            defer { try? FileManager.default.removeItem(at: file) }
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            let built = try await Task.detached(priority: .utility) { try Self.buildIndex(zip: file, eco) }.value
            // A list that suddenly shrinks to a fraction is a broken download, not good news: keep the old one.
            if let state = lists[eco.osv], built.count < state.count / 2 { throw URLError(.cannotParseResponse) }
            try Vault.shared.write(built.index, to: indexURL(eco))
            lists[eco.osv] = ListState(updated: Date(), modified: built.modified, count: built.count)
            lastError = ""
            return true
        } catch {
            lastError = "The \(eco.title) list couldn't be updated: \(error.localizedDescription)"
            return false
        }
    }

    /// The MAL- records changed since `since`, newest first, from OSV's change list (read only as far as needed).
    /// Nil when there are too many: the caller downloads the whole list instead.
    private func changedIDs(_ eco: PackageEcosystem, since: String) async throws -> [String]? {
        let (bytes, response) = try await session.bytes(from: URL(string: "\(Self.osvBase)/\(eco.osv)/modified_id.csv")!)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        var ids: [String] = []
        for try await line in bytes.lines {
            let parts = line.split(separator: ",", maxSplits: 1)
            guard parts.count == 2 else { continue }
            if String(parts[0]) <= since { break }
            let id = String(parts[1])
            if id.hasPrefix("MAL-") { ids.append(id) }
            if ids.count > Self.incrementalLimit { return nil }
        }
        return ids
    }

    nonisolated static func buildIndex(zip: URL, _ eco: PackageEcosystem) throws -> (index: Data, modified: String, count: Int) {
        let reader = try ZipReader(url: zip)
        var lines: [String] = [], newest = ""
        reader.forEach(where: { $0.hasPrefix("MAL-") }) { _, data in
            guard let record = MalwareIndex.lines(fromOSV: data, ecosystem: eco) else { return }
            lines += record.lines
            newest = max(newest, record.modified)
        }
        guard !lines.isEmpty || reader.names.isEmpty else { throw ZipReader.ZipError.damaged }
        return (Data((lines.joined(separator: "\n") + "\n").utf8), newest, lines.count)
    }

    // MARK: Projects

    /// Lockfiles and virtual environments, from Spotlight and the folders you added.
    nonisolated static func discover(folders: [String]) async -> [String] {
        await Task.detached(priority: .utility) {
            let names = Array(Lockfiles.fixedNames.keys) + ["pyvenv.cfg"]
            let query = names.map { "kMDItemFSName == \"\($0)\"" }.joined(separator: " || ")
                + " || kMDItemFSName == \"requirements*.txt\"c"
            var found = Set<String>()
            for root in [NSHomeDirectory()] + folders {
                for path in spotlight(query, in: root) where PackageScan.isProjectLockfile(path) { found.insert(path) }
            }
            // Spotlight skips folders it doesn't index: the ones you added are walked too, a few levels deep.
            for folder in folders { walk(folder, depth: 4) { if PackageScan.isProjectLockfile($0) { found.insert($0) } } }
            return Array(found.prefix(5000))
        }.value
    }

    nonisolated private static func spotlight(_ query: String, in root: String) -> [String] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/mdfind")
        p.arguments = ["-onlyin", root, query]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self).split(separator: "\n").map(String.init)
    }

    nonisolated private static func walk(_ dir: String, depth: Int, _ body: (String) -> Void) {
        guard depth >= 0, let items = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        for item in items {
            let path = (dir as NSString).appendingPathComponent(item)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                if item == ".venv" || item == "venv" { body(path + "/pyvenv.cfg") }
                if item == "node_modules" { body(path + "/.package-lock.json") }
                if !item.hasPrefix("."), item != "node_modules", item != "Library" { walk(path, depth: depth - 1, body) }
            } else { body(path) }
        }
    }

    /// Checks the lockfiles that changed (or all of them, after a list grew), and raises a story for each new finding.
    func scan(all: Bool) async {
        let due = lockfiles.filter { path, scanned in all || (PackageScan.stamp(path) ?? .distantPast) > scanned }.map(\.key)
        guard !due.isEmpty else { return }
        let directory = self.directory
        let result = await Task.detached(priority: .utility) { () -> (found: [PackageFinding], stamps: [String: Date]) in
            var byLockfile: [String: [PackageRef]] = [:], stamps: [String: Date] = [:]
            for path in due {
                stamps[path] = PackageScan.stamp(path) ?? Date()
                byLockfile[path] = PackageScan.packages(at: path)
            }
            let wanted = Set(byLockfile.values.joined())
            var records: [PackageRef: MalwareRecord] = [:]
            for eco in Set(wanted.map(\.ecosystem)) {
                guard let index = Vault.shared.read(directory.appendingPathComponent("\(eco.osv).idx")) else { continue }
                records.merge(MalwareIndex.matches(in: index, ecosystem: eco, wanted: wanted)) { a, _ in a }
            }
            var found: [PackageFinding] = []
            for (path, refs) in byLockfile {
                for ref in refs { if let r = records[ref] { found.append(PackageFinding(package: ref, malwareID: r.id, lockfile: path, found: Date())) } }
            }
            return (found, stamps)
        }.value
        let scanned = Set(due)
        let previous = Dictionary(findings.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        // A lockfile's findings are what it has now: a removed or upgraded package drops out.
        findings.removeAll { scanned.contains($0.lockfile) }
        for var f in result.found where !dismissed.contains(f.id) {
            if let old = previous[f.id] { f.found = old.found } else {
                if mode == .strict { quarantine(f) }
                onFinding?(f)
            }
            findings.append(f)
        }
        findings.sort { $0.found > $1.found }
        lockfiles.merge(result.stamps) { _, new in new }
    }

    func save() {
        let saved = Saved(lists: lists, lockfiles: lockfiles, findings: findings, dismissed: Array(dismissed), discovered: discovered,
                          stops: stops, quarantined: quarantined)
        if let data = try? JSONEncoder().encode(saved) { try? Vault.shared.write(data, to: stateURL) }
    }

    /// Projects the guard knows, by ecosystem: for the page.
    var projectCount: Int { Set(lockfiles.keys.map { ($0 as NSString).deletingLastPathComponent }).count }
}
