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
        var own: ActivityEvent?             // a connection's or file's process: its own launch, for its command line
        for e in model.history where e.kind == .exec && (e.ts == 0 || e.ts <= at + 1) {
            if e.pid == event.pid, e.id != event.id, e.ts <= at {
                // A file or network event's process, or a launch known only by its pid: its own launch record.
                if event.kind != .exec || event.ppid == 0, own == nil { own = e; continue }
                // The same pid ran something else first (sh exec'ing bash): shown, but not a parent.
                earlier.append(LaunchStep(pid: e.pid, ppid: e.ppid, path: e.target, args: e.args, source: .launch))
                continue
            }
            if launches[e.pid] == nil { launches[e.pid] = e }
        }
        let snapshot = ProcessHistory(directory: history.directory).snapshot(at: Date(timeIntervalSince1970: at),
                                                                            cache: Self.processDayCache)
        let listed = Dictionary((snapshot?.processes ?? []).map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let chain = LaunchChain.build(from: event.ppid > 0 ? event.ppid : own?.ppid ?? 0) { pid in
            if let e = launches[pid] { return LaunchStep(pid: pid, ppid: e.ppid, path: e.target, args: e.args, source: .launch) }
            if let p = listed[pid] { return LaunchStep(pid: pid, ppid: p.ppid, path: p.path, args: p.args, source: .list) }
            let path = ProcessList.path(pid)
            guard !path.isEmpty else { return nil }
            return LaunchStep(pid: pid, ppid: ProcessList.parent(pid), path: path, args: "", source: .live)
        }
        let session = event.session > 0 ? model.sessions.session(event.session)?.name : nil
        let path = event.kind == .exec && !event.target.isEmpty ? event.target : event.proc
        let args = event.kind == .exec ? event.args : own?.args ?? listed[event.pid]?.args ?? ""
        let process = LaunchStep(pid: event.pid, ppid: event.ppid, path: path, args: args, source: .launch)
        return LaunchChainReport(process: process, steps: chain.steps, broken: chain.broken, session: session,
                                 earlier: Array(earlier.prefix(3)))
    }

    /// Today's process list, read once for a batch of lookups (a triage batch asks for 40 chains at once).
    static let processDayCache = ProcessDayCache()

    /// Triage context for a pattern: who started its example, only when that example's own launch is still in the
    /// recorded events (same pid, same program). Otherwise nil: a reused pid would tell a wrong story.
    func triageContext(for entry: SignatureEntry) -> TriageContext? {
        let program = entry.kind == .exec ? entry.exampleTarget : entry.exampleProc
        guard entry.examplePid > 0,
              let launch = model.history.first(where: { $0.kind == .exec && $0.pid == entry.examplePid && $0.target == program })
        else { return nil }
        let report = launchChainReport(for: launch)
        guard !report.steps.isEmpty else { return nil }
        let names = (report.steps.reversed().map { CodingAgent.of($0.path)?.title ?? $0.name } + [report.process.name])
        let trail = names.count > 5 ? ([names[0], "…"] + names.suffix(3)).joined(separator: " › ") : names.joined(separator: " › ")
        let session = model.sessions.session(forPid: entry.examplePid)?.name
        return TriageContext(trail: trail, origin: report.summary, session: session,
                             command: entry.kind == .exec ? launch.args : "")
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
