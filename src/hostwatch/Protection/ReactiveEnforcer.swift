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
    /// Paused here with SIGSTOP (its watchdog, when one could be started, is in `watchdogs`).
    private var localPaused: Set<Int32> = []

    /// The root collector's hold, when it runs as the service: it suspends a program invisibly to your shell where
    /// macOS allows, SIGSTOPs it otherwise, and lets everything go if Hostwatch goes away. Set by the app.
    struct Remote {
        /// False when the collector can't be asked (not connected): then it's paused here.
        var hold: (Int32) -> Bool
        var release: (Int32, Bool) -> Void
    }
    var remote: Remote?
    /// Programs the collector holds, and how ("task", "signal", or nil while its answer is on the way).
    private var remoteHeld: [Int32: String?] = [:]
    /// Called when a hold's method is known, so a question can say "type fg" when the shell saw a stop.
    var onMethodKnown: ((Int32) -> Void)?

    var pausedCount: Int { localPaused.count + remoteHeld.count }

    /// Paused the way your shell sees (SIGSTOP): an interactive shell then reports "Job has stopped", and after Allow
    /// the program goes on in the background until you type fg.
    func pausedTheShellWay(_ pid: Int) -> Bool {
        let p = Int32(clamping: pid)
        if localPaused.contains(p) { return true }
        if case .some(.some(let m)) = remoteHeld[p] { return m == "signal" }
        return false
    }

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
        guard pausedCount < Self.maxPaused, !localPaused.contains(p), remoteHeld[p] == nil, mayAct(pid: pid, path: path) else { return false }
        if let remote, remote.hold(p) {
            remoteHeld[p] = .some(nil)                      // the collector answers in a moment
            // No answer within a second: paused here instead, so a question never waits on a running program.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
                MainActor.assumeIsolated {
                    if case .some(.none) = self?.remoteHeld[p] { self?.holdResult(pid: Int(p), method: "none") }
                }
            }
            return true
        }
        return pauseLocally(p)
    }

    private func pauseLocally(_ p: Int32) -> Bool {
        guard signal(p, SIGSTOP) == 0 else { return false }
        localPaused.insert(p)
        if let w = startWatchdog(p, Self.pauseTimeout + ProcessHold.watchdogGrace) { watchdogs[p] = w }
        return true
    }

    /// The collector's answer: held invisibly, held with SIGSTOP, or not at all (then it's paused here, as before).
    func holdResult(pid: Int, method: String) {
        let p = Int32(clamping: pid)
        guard remoteHeld[p] != nil else { return }
        if method == "none" {
            remoteHeld[p] = nil
            _ = pauseLocally(p)
        } else {
            remoteHeld[p] = .some(method)
        }
        onMethodKnown?(p)
    }

    /// Ends a pause: stopped for good, or let go. Only the program that was paused (the pid may have been reused).
    func release(pid: Int, path: String, stop: Bool) {
        let p = Int32(clamping: pid)
        if remoteHeld.removeValue(forKey: p) != nil {
            remote?.release(p, stop && inspect(p)?.path == path)   // only the program that was held is stopped
            return
        }
        if inspect(p)?.path == path { _ = signal(p, stop ? SIGKILL : SIGCONT) }
        localPaused.remove(p)
        watchdogs.removeValue(forKey: p)?.terminate()
    }

    /// Lets everything go (quit, pause, or a mode turned off).
    func releaseAll() {
        for p in localPaused { _ = signal(p, SIGCONT) }
        for w in watchdogs.values { w.terminate() }
        localPaused = []
        watchdogs = [:]
        for p in remoteHeld.keys { remote?.release(p, false) }
        remoteHeld = [:]
    }
}
