import Darwin
import Foundation

/// Holds a program while the app asks you about it, the way your shell can't see: the threads are suspended through
/// the task port (root can do this for programs without the hardened runtime), so an interactive shell doesn't report
/// "Job has stopped" and take the terminal back. macOS refuses that for its own programs (curl, python…): those are
/// paused with SIGSTOP, as before, and the app says so. Only the connected user's processes, never pid 1 or ours, and
/// every hold ends: on the app's answer, when the app goes away, or after the time limit. source: docs/adr/0011-protection.md
final class AgentHold: @unchecked Sendable {
    enum Method: String { case task, signal, none }

    /// The app's own limit is 30 s; this one only catches an app that never answered.
    static let limit: TimeInterval = 40

    private struct Held { let method: Method; let client: ObjectIdentifier; let until: Date }
    private let lock = NSLock()
    private var held: [Int32: Held] = [:]
    private var watching = false

    /// {"hold": {"pid": 123}} → a "hold_result" line with the method used.
    func hold(_ cfg: [String: Any], from client: AgentClient) {
        guard let raw = cfg["pid"] as? Int else { return }
        let pid = Int32(clamping: raw)
        var method = Method.none
        if pid > 1, pid != getpid(), let uid = ProcessList.uid(Int(pid)), uid == client.uid {
            if Self.suspendTask(pid) { method = .task } else if kill(pid, SIGSTOP) == 0 { method = .signal }
        }
        if method != .none {
            lock.lock()
            held[pid] = Held(method: method, client: ObjectIdentifier(client), until: Date().addingTimeInterval(Self.limit))
            lock.unlock()
            startWatchdog()
        }
        let line = #"{"kind":"hold_result","pid":\#(pid),"method":"\#(method.rawValue)"}"# + "\n"
        _ = client.send(Data(line.utf8))
    }

    /// {"release": {"pid": 123, "stop": false}}: let go, or stop for good. Only what this client held.
    func release(_ cfg: [String: Any], from client: AgentClient) {
        guard let raw = cfg["pid"] as? Int else { return }
        let pid = Int32(clamping: raw)
        lock.lock()
        guard let h = held[pid], h.client == ObjectIdentifier(client) else { lock.unlock(); return }
        held[pid] = nil
        lock.unlock()
        end(pid, h.method, stop: cfg["stop"] as? Bool == true)
    }

    /// The app went away: everything it held goes on (a hold must never outlive the question).
    func releaseAll(of client: AgentClient) {
        lock.lock()
        let mine = held.filter { $0.value.client == ObjectIdentifier(client) }
        for pid in mine.keys { held[pid] = nil }
        lock.unlock()
        for (pid, h) in mine { end(pid, h.method, stop: false) }
    }

    private func end(_ pid: Int32, _ method: Method, stop: Bool) {
        if stop { kill(pid, SIGKILL) }
        switch method {
        case .task: _ = Self.resumeTask(pid)              // a suspended task finishes dying (or goes on) once resumed
        case .signal: if !stop { kill(pid, SIGCONT) }
        case .none: break
        }
    }

    private func startWatchdog() {
        lock.lock()
        defer { lock.unlock() }
        guard !watching else { return }
        watching = true
        Thread.detachNewThread { [self] in
            while true {
                Thread.sleep(forTimeInterval: 1)
                lock.lock()
                let now = Date()
                let expired = held.filter { $0.value.until < now }
                for pid in expired.keys { held[pid] = nil }
                let empty = held.isEmpty
                if empty { watching = false }
                lock.unlock()
                for (pid, h) in expired { end(pid, h.method, stop: false) }
                if empty { return }
            }
        }
    }

    private static func suspendTask(_ pid: Int32) -> Bool {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return false }
        defer { mach_port_deallocate(mach_task_self_, task) }
        return task_suspend(task) == KERN_SUCCESS
    }

    private static func resumeTask(_ pid: Int32) -> Bool {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return false }
        defer { mach_port_deallocate(mach_task_self_, task) }
        return task_resume(task) == KERN_SUCCESS
    }
}
