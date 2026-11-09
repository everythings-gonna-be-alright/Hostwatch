import AppKit

/// Who really started an event's process: the recorded launches in memory first (short-lived shells), then the
/// process list recorded around that moment (long-lived ancestors: a terminal, Claude Code), then what is running now.
extension AppDelegate {
    func launchChainText(for event: ActivityEvent) -> String {
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
        return LaunchChain.text(chain, session: session, earlier: Array(earlier.prefix(3)))
    }

    /// Events ▸ right-click ▸ Show Launch Chain.
    func showLaunchChain(for event: ActivityEvent) {
        let alert = NSAlert()
        alert.messageText = "Who started \(event.name) (pid \(event.pid))"
        alert.informativeText = "Rebuilt from what Hostwatch recorded, so it works after the processes have exited."
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 620, height: 220))
        text.string = launchChainText(for: event)
        text.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        text.isEditable = false
        text.drawsBackground = false
        let scroll = NSScrollView(frame: text.frame)
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        alert.accessoryView = scroll
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Copy")
        if alert.runModal() == .alertSecondButtonReturn {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text.string, forType: .string)
        }
    }
}
