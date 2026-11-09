import AppKit
import SwiftUI

/// Who really started an event's process: the recorded launches in memory first (short-lived shells), then the
/// process list recorded around that moment (long-lived ancestors: a terminal, Claude Code), then what is running now.
extension AppDelegate {
    func launchChainText(for event: ActivityEvent) -> String { launchChainReport(for: event).text }

    func launchChainReport(for event: ActivityEvent) -> LaunchChainReport {
        let at = event.ts > 0 ? event.ts : Date().timeIntervalSince1970
        // The latest launch of each pid at or before the event (history is newest first).
        var launches: [Int: ActivityEvent] = [:]
        var earlier: [LaunchStep] = []
        for e in model.history where e.kind == .exec && (e.ts == 0 || e.ts <= at + 1) {
            if e.pid == event.pid, e.id != event.id, e.ts <= at {
                // The same pid ran something else first (sh exec'ing bash): shown, but not a parent.
                earlier.append(LaunchStep(pid: e.pid, ppid: e.ppid, path: e.target, args: e.args, source: .launch))
                continue
            }
            if launches[e.pid] == nil { launches[e.pid] = e }
        }
        let snapshot = ProcessHistory(directory: history.directory).snapshot(at: Date(timeIntervalSince1970: at))
        let listed = Dictionary((snapshot?.processes ?? []).map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let chain = LaunchChain.build(from: event.ppid) { pid in
            if let e = launches[pid] { return LaunchStep(pid: pid, ppid: e.ppid, path: e.target, args: e.args, source: .launch) }
            if let p = listed[pid] { return LaunchStep(pid: pid, ppid: p.ppid, path: p.path, args: p.args, source: .list) }
            let path = ProcessList.path(pid)
            guard !path.isEmpty else { return nil }
            return LaunchStep(pid: pid, ppid: ProcessList.parent(pid), path: path, args: "", source: .live)
        }
        let session = event.session > 0 ? model.sessions.session(event.session)?.name : nil
        let path = event.kind == .exec && !event.target.isEmpty ? event.target : event.proc
        let process = LaunchStep(pid: event.pid, ppid: event.ppid, path: path, args: event.kind == .exec ? event.args : "",
                                 source: .launch)
        return LaunchChainReport(process: process, steps: chain.steps, broken: chain.broken, session: session,
                                 earlier: Array(earlier.prefix(3)))
    }

    /// Events ▸ right-click ▸ Show Launch Chain: its own small window, one per request.
    func showLaunchChain(for event: ActivityEvent) {
        let report = launchChainReport(for: event)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 520),
                              styleMask: [.titled, .closable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        window.titlebarAppearsTransparent = true
        window.title = "Launch Chain: \(event.name)"
        window.isReleasedWhenClosed = false
        window.collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        window.contentMinSize = NSSize(width: 480, height: 320)
        let close: () -> Void = { [weak window] in window?.close() }
        window.contentView = NSHostingView(rootView: LaunchChainView(report: report, close: close))
        window.center()
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] note in
            MainActor.assumeIsolated { self?.askWindows.removeAll { $0 === note.object as? NSWindow } }
        }
        askWindows.append(window)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }
}
