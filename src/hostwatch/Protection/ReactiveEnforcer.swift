import Darwin
import Foundation

/// Protection's engine until Endpoint Security: it acts on a launch or a protected file's open as soon as its event
/// arrives, a few milliseconds late. It stops (SIGKILL) what's blocked and pauses (SIGSTOP) what's asked about. It
/// can't undo what already happened: a paused program may have read the file. Hold's rules apply: only your own
/// processes (root's are off-limits), never the system UI, terminals or Hostwatch, at most a few paused at once, and a
/// detached watchdog resumes a paused process even if Hostwatch dies. source: docs/adr/0011-protection.md
@MainActor
final class ReactiveEnforcer {
    static let maxPaused = 5
    static let pauseTimeout: TimeInterval = 30

    // Seams for tests.
    var signal: (Int32, Int32) -> Int32 = { Darwin.kill($0, $1) }
    var inspect: (Int32) -> ProcessFacts? = { ProcessFacts.live($0) }
    var startWatchdog: (Int32, TimeInterval) -> Process? = ProcessHold.watchdog
    private var watchdogs: [Int32: Process] = [:]

    var pausedCount: Int { watchdogs.count }

    /// Whether this process may be acted on: still the same program, yours, and not one that must never stop.
    func mayAct(pid: Int, path: String) -> Bool {
        let p = Int32(clamping: pid)
        guard p > 1, p != getpid(), !ProcessHold.isProtected(path),
              let facts = inspect(p), facts.uid == getuid(), facts.path == path else { return false }
        return true
    }

    /// Stops it for good. False when it may not be acted on (or is gone already).
    @discardableResult
    func stop(pid: Int, path: String) -> Bool {
        guard mayAct(pid: pid, path: path) else { return false }
        return signal(Int32(clamping: pid), SIGKILL) == 0
    }

    /// Pauses it while you decide. False when it may not be acted on, or too many are paused already.
    func pause(pid: Int, path: String) -> Bool {
        let p = Int32(clamping: pid)
        guard watchdogs.count < Self.maxPaused, watchdogs[p] == nil, mayAct(pid: pid, path: path),
              signal(p, SIGSTOP) == 0 else { return false }
        if let w = startWatchdog(p, Self.pauseTimeout + ProcessHold.watchdogGrace) { watchdogs[p] = w }
        return true
    }

    /// Ends a pause: stopped for good, or let go. Only the program that was paused (the pid may have been reused).
    func release(pid: Int, path: String, stop: Bool) {
        let p = Int32(clamping: pid)
        if inspect(p)?.path == path { _ = signal(p, stop ? SIGKILL : SIGCONT) }
        watchdogs.removeValue(forKey: p)?.terminate()
    }

    /// Lets everything go (quit, pause, or a mode turned off).
    func releaseAll() {
        for (p, w) in watchdogs { _ = signal(p, SIGCONT); w.terminate() }
        watchdogs = [:]
    }
}
