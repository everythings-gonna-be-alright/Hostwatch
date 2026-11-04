import Foundation
@testable import Hostwatch

/// Isolates tests from the user's data: a scratch signing database (set before the shared cache
/// is first used) and no background validation or disk writes.
enum TestEnv {
    static let ready: Void = {
        let db = FileManager.default.temporaryDirectory
            .appendingPathComponent("hostwatch-tests-\(UUID().uuidString).json")
        setenv("HOSTWATCH_SIGNING_DB", db.path, 1)
        SigningCache.shared.live = false
        ProcessList.startLookup = { _ in nil }      // deterministic collector output
    }()
}

let home = FileManager.default.homeDirectoryForCurrentUser.path

func event(_ kind: EventKind, pid: Int = 100, ppid: Int = 1, name: String? = nil, proc: String = "",
           target: String = "", extra: String = "", parent: String = "", host: String = "",
           hostSource: String = "", args: String = "") -> ActivityEvent {
    _ = TestEnv.ready
    let actor = kind == .exec ? target : proc
    return ActivityEvent(kind: kind, time: "12:00:00", pid: pid, ppid: ppid,
                         name: name ?? (actor as NSString).lastPathComponent, proc: proc.isEmpty ? actor : proc,
                         target: target, extra: extra, parent: parent, host: host, hostSource: hostSource, args: args)
}

func exec(_ target: String, pid: Int, ppid: Int, parent: String, args: String = "") -> ActivityEvent {
    event(.exec, pid: pid, ppid: ppid, proc: target, target: target, parent: parent, args: args)
}

func net(_ proc: String, pid: Int, to target: String, host: String = "", proto: String = "TCP") -> ActivityEvent {
    event(.net, pid: pid, proc: proc, target: target, extra: proto, host: host, hostSource: host.isEmpty ? "" : "dns")
}

func file(_ proc: String, pid: Int, _ mode: String, _ path: String) -> ActivityEvent {
    event(.file, pid: pid, proc: proc, target: path, extra: mode)
}

/// Feeds events with advancing time through a story engine and a domain registry, like the app.
@MainActor
final class Scenario {
    let stories = StoryEngine(persistent: false)
    let domains: DomainRegistry
    let beacons = BeaconDetector()
    private(set) var clock = Date(timeIntervalSince1970: 1_800_000_000)

    init(learningMinutes: Double = 0) {
        stories.liveLookups = false
        domains = DomainRegistry(replayLearningUntil: clock.addingTimeInterval(learningMinutes * 60))
    }

    func feed(_ e: ActivityEvent, after seconds: TimeInterval = 2) {
        clock = clock.addingTimeInterval(seconds)
        var e = e
        if e.kind == .net {                       // same order as HUDModel.consumeLines
            if let d = domains.observe(e, at: clock) { e.newDomain = d }
            if let b = beacons.observe(e, at: clock) { e.beacon = b }
            e.rawIP = NetSignals.isRawIP(e)
        }
        lastEvent = e
        stories.ingest(e, decidedSafe: false, at: clock)
    }

    /// The last event as the app would show it (with its network signals).
    private(set) var lastEvent: ActivityEvent?

    var fired: [Story] { stories.stories }
}

/// Real binaries in a temp folder (a download/temp location) for signing tests.
enum Binaries {
    static let dir: URL = {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-bin-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()

    @discardableResult
    static func run(_ tool: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    /// A copy of /bin/echo: Apple-signed as is, or turned unsigned / ad-hoc / quarantined.
    static func make(_ name: String, unsigned: Bool = false, adhoc: Bool = false, quarantined: Bool = false) -> String {
        let path = dir.appendingPathComponent(name).path
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.copyItem(atPath: "/bin/echo", toPath: path)
        if unsigned { run("/usr/bin/codesign", ["--remove-signature", path]) }
        if adhoc { run("/usr/bin/codesign", ["-f", "-s", "-", path]) }
        if quarantined { run("/usr/bin/xattr", ["-w", "com.apple.quarantine", "0083;6720a0b0;Chrome;", path]) }
        return path
    }
}

/// A throwaway UserDefaults suite. Its name is a file path in a temporary folder, so the settings never land in
/// ~/Library/Preferences (removing a suite there doesn't stick: the preferences daemon writes an empty plist back).
/// The folder is emptied when the test run ends and again at the next run.
func scratchDefaults(_ prefix: String = "hostwatch-tests") -> UserDefaults {
    ScratchDefaults.lock.lock()
    if !ScratchDefaults.started {
        ScratchDefaults.started = true
        try? FileManager.default.removeItem(at: ScratchDefaults.folder)            // leftovers from an earlier run
        try? FileManager.default.createDirectory(at: ScratchDefaults.folder, withIntermediateDirectories: true)
        atexit { ScratchDefaults.removeAll() }
    }
    let name = ScratchDefaults.folder.appendingPathComponent("\(prefix)-\(UUID().uuidString)").path
    ScratchDefaults.names.append(name)
    ScratchDefaults.lock.unlock()
    return UserDefaults(suiteName: name)!
}

enum ScratchDefaults {
    nonisolated(unsafe) static var names: [String] = []
    nonisolated(unsafe) static var started = false
    static let lock = NSLock()
    static let folder = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-test-defaults", isDirectory: true)

    static func removeAll() {
        for name in names { UserDefaults.standard.removePersistentDomain(forName: name) }
        try? FileManager.default.removeItem(at: folder)
    }
}
