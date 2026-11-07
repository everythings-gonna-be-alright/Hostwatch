import AppKit
import Darwin

/// What happens to a held process when you don't answer in time.
enum HoldTimeoutAction: String, CaseIterable {
    case resume, kill

    var title: String { self == .resume ? "Let It Continue" : "Kill It" }
}

/// What the kernel says about a live process right now.
struct ProcessFacts: Equatable {
    var uid: uid_t
    var path: String

    static func live(_ pid: Int32) -> ProcessFacts? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return ProcessFacts(uid: info.pbi_uid, path: n > 0 ? String(cString: buf) : "")
    }
}

struct HeldProcess: Identifiable {
    let id = UUID()
    let pid: Int32
    let path: String
    let reason: String
    let event: ActivityEvent
    let since: Date
    let deadline: Date
    var name: String { (path as NSString).lastPathComponent }
}

/// Opt-in "hold": freezes (SIGSTOP) your own processes the moment they do something
/// suspicious, and waits for you to allow or kill them. Best effort: the process has already
/// run for a few milliseconds when its event arrives. Fails open: a detached watchdog resumes
/// the process shortly after the deadline even if Hostwatch quits or crashes.
@MainActor
final class ProcessHold: ObservableObject {
    @Published private(set) var held: [HeldProcess] = []
    @Published var enabled: Bool {
        didSet {
            UserDefaults.standard.set(enabled, forKey: "holdSuspicious")
            if !enabled { for h in held { release(h, kill: false) } }
        }
    }
    @Published var timeoutAction: HoldTimeoutAction {
        didSet { UserDefaults.standard.set(timeoutAction.rawValue, forKey: "holdTimeoutAction") }
    }
    let timeout: TimeInterval = 60
    static let maxHeld = 5
    /// A held process is never kept stopped longer than this, whatever happens to the app.
    static let watchdogGrace: TimeInterval = 5

    /// Called when the list changes (the app shows or hides the Held panel).
    var onChange: (() -> Void)?
    /// "Always Allow": mark the held event's pattern Safe.
    var onAlwaysAllow: ((ActivityEvent) -> Void)?
    /// Outcomes for the log ("allowed curl 4242", …).
    @Published private(set) var lastOutcome = ""

    // Seams for tests.
    var signal: (Int32, Int32) -> Int32 = { Darwin.kill($0, $1) }
    var inspect: (Int32) -> ProcessFacts? = { ProcessFacts.live($0) }
    var startWatchdog: (Int32, TimeInterval) -> Process? = ProcessHold.watchdog
    var now: () -> Date = { Date() }
    private var watchdogs: [UUID: Process] = [:]
    private var timer: Timer?

    init(defaults: UserDefaults = .standard) {
        enabled = defaults.bool(forKey: "holdSuspicious")                 // off unless you turn it on
        timeoutAction = HoldTimeoutAction(rawValue: defaults.string(forKey: "holdTimeoutAction") ?? "") ?? .resume
    }

    // MARK: Policy

    /// Story stages worth stopping a process for, with the wording shown to you.
    static let holdStages: [StoryStage] = [.encodedCommand, .credential, .persistence, .unquarantine,
                                           .runFromDrop, .swappedBinary]

    /// Why this event's process should be held, or nil. Patterns marked Safe (by you, a rule, or
    /// as routine) never are; neither is anything that isn't new or a strong story stage.
    static func reason(for e: ActivityEvent, stages: [(StoryStage, String)], status: SignatureStatus) -> String? {
        guard status != .safe else { return nil }
        if let hit = stages.first(where: { holdStages.contains($0.0) }) { return hit.1 }
        if e.kind == .exec, e.isFirst, e.signatureRisk == .high, status == .unclassified {
            return "new high-risk pattern" + (e.signatureReason.isEmpty ? "" : ": \(e.signatureReason)")
        }
        return nil
    }

    /// Processes that are never frozen: the system UI, terminals and editors you type into,
    /// and Hostwatch itself.
    static func isProtected(_ path: String) -> Bool {
        path.isEmpty
            || path.hasPrefix("/System/Library/CoreServices/") || path.hasPrefix("/System/Applications/")
            || path == "/sbin/launchd" || StoryEngine.isOwn(path)
            || (path.contains(".app/Contents/MacOS/") && SignatureBuilder.shellHosts.contains { path.contains($0) })
    }

    // MARK: Holding

    /// Holds the event's process if the hold is on and the event deserves it. Returns true if held.
    @discardableResult
    func consider(_ e: ActivityEvent, stages: [(StoryStage, String)], status: SignatureStatus) -> Bool {
        guard enabled, let why = Self.reason(for: e, stages: stages, status: status) else { return false }
        let pid = Int32(clamping: e.pid)
        let path = e.kind == .exec ? e.target : e.proc
        guard pid > 1, pid != getpid(), held.count < Self.maxHeld,
              !held.contains(where: { $0.pid == pid }), !Self.isProtected(path),
              // Still the same program (not exited, pid not reused), and yours: root processes are off-limits.
              let facts = inspect(pid), facts.uid == getuid(), facts.path == path,
              signal(pid, SIGSTOP) == 0
        else { return false }
        let start = now()
        let h = HeldProcess(pid: pid, path: path, reason: why, event: e, since: start,
                            deadline: start.addingTimeInterval(timeout))
        if let w = startWatchdog(pid, timeout + Self.watchdogGrace) { watchdogs[h.id] = w }
        held.append(h)
        scheduleTimer()
        onChange?()
        return true
    }

    func allow(_ h: HeldProcess) { release(h, kill: false); lastOutcome = "Allowed \(h.name) (\(h.pid))" }

    func alwaysAllow(_ h: HeldProcess) {
        onAlwaysAllow?(h.event)
        release(h, kill: false)
        lastOutcome = "Allowed \(h.name) (\(h.pid)) and marked its pattern Safe"
    }

    func kill(_ h: HeldProcess) { release(h, kill: true); lastOutcome = "Killed \(h.name) (\(h.pid))" }

    /// Lets everything go (quit, or the hold turned off).
    func releaseAll() { for h in held { release(h, kill: false) } }

    private func release(_ h: HeldProcess, kill: Bool) {
        guard held.contains(where: { $0.id == h.id }) else { return }
        // Only signal the process we stopped: if it exited and the pid was reused, leave it alone.
        if inspect(h.pid)?.path == h.path {
            _ = signal(h.pid, kill ? SIGKILL : SIGCONT)
        }
        watchdogs.removeValue(forKey: h.id)?.terminate()
        held.removeAll { $0.id == h.id }
        if held.isEmpty { timer?.invalidate(); timer = nil }
        onChange?()
    }

    /// Applies the timeout action to expired holds and drops processes that went away.
    func tick() {
        let t = now()
        for h in held {
            if inspect(h.pid)?.path != h.path {
                watchdogs.removeValue(forKey: h.id)?.terminate()
                held.removeAll { $0.id == h.id }
                onChange?()
            } else if t >= h.deadline {
                if timeoutAction == .kill { kill(h) } else { allow(h) }
                lastOutcome += " (no answer in \(Int(timeout)) s)"
            }
        }
    }

    private func scheduleTimer() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    /// A detached `sh` that resumes the process after `delay`, so it can't stay frozen if
    /// Hostwatch dies. SIGCONT to a running (or reused) pid does nothing.
    nonisolated static func watchdog(pid: Int32, after delay: TimeInterval) -> Process? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", "sleep \(Int(delay.rounded(.up))); kill -CONT \(pid) 2>/dev/null"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        return p
    }
}
