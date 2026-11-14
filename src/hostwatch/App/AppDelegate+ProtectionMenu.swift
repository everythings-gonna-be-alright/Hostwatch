import AppKit
import UniformTypeIdentifiers

/// The Protection menu (menu bar) and the timed pause both menus offer: every security switch reachable from the
/// keyboard and Help ▸ search, not only from the Rules page. Also File ▸ Export Events.
extension AppDelegate {
    /// Pause lengths offered everywhere: a pause always ends by itself.
    static let pauseChoices: [(title: String, minutes: Double)] = [("15 Minutes", 15), ("1 Hour", 60), ("Until Tomorrow", -1)]

    func protectionMenuItems() -> [NSMenuItem] {
        let status = NSMenuItem(title: "", action: #selector(protectionStatus), keyEquivalent: "")
        status.target = self
        let pause = NSMenuItem(title: "Pause Protection", action: nil, keyEquivalent: "")
        pause.submenu = pauseSubmenu()
        let resume = item("Resume Protection", #selector(resumeProtection))
        var items: [NSMenuItem] = [status, .separator(), pause, resume, .separator()]
        for area in ProtectionArea.allCases {
            items.append(modeSubmenu(area.title, ProtectionMode.allCases.map { ($0.short, "\(area.rawValue)|\($0.rawValue)") }))
        }
        items.append(modeSubmenu("Network", FirewallMode.allCases.map { ($0.short, "net|\($0.rawValue)") }))
        items += [.separator(), item("Hold Suspicious Processes", #selector(toggleHold)), .separator(),
                  item("Start Collector…", #selector(toggleCollector)), .separator(),
                  item("Protection Overview", #selector(openProtectionOverview))]
        return items
    }

    func pauseSubmenu() -> NSMenu {
        let menu = NSMenu()
        for choice in Self.pauseChoices {
            let mi = item(choice.title, #selector(pauseProtection(_:)))
            mi.representedObject = choice.minutes
            menu.addItem(mi)
        }
        return menu
    }

    private func modeSubmenu(_ title: String, _ choices: [(String, String)]) -> NSMenuItem {
        let holder = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        let menu = NSMenu()
        for (name, tag) in choices {
            let mi = item(name, #selector(setProtectionMode(_:)))
            mi.representedObject = tag
            menu.addItem(mi)
        }
        holder.submenu = menu
        return holder
    }

    /// "Protecting", "Rehearsing", "Paused until 14:20": the menu's first line, never clickable.
    var protectionStatusTitle: String {
        let state = protection.state(network: firewall.mode)
        switch state {
        case .paused: return "Paused until \(protection.pausedUntil?.formatted(date: .omitted, time: .shortened) ?? "")"
        case .off: return "Protection is off"
        default: return state.word ?? ""
        }
    }

    @objc func protectionStatus() {}

    @objc func pauseProtection(_ sender: NSMenuItem) {
        guard let minutes = sender.representedObject as? Double else { return }
        if minutes > 0 {
            protection.pause(minutes: minutes)
        } else if let tomorrow = Calendar.current.date(byAdding: .day, value: 1, to: Calendar.current.startOfDay(for: Date())) {
            protection.pause(minutes: tomorrow.timeIntervalSinceNow / 60)
        }
    }

    @objc func resumeProtection() { protection.resume() }

    @objc func setProtectionMode(_ sender: NSMenuItem) {
        guard let tag = sender.representedObject as? String else { return }
        let parts = tag.split(separator: "|").map(String.init)
        guard parts.count == 2 else { return }
        if parts[0] == "net" {
            if let mode = FirewallMode(rawValue: parts[1]) { firewall.mode = mode }
        } else if let area = ProtectionArea(rawValue: parts[0]), let mode = ProtectionMode(rawValue: parts[1]) {
            protection.setMode(mode, for: area)
        }
    }

    /// Checkmarks and enabled state for the Protection items, when a menu opens. Nil: not one of them.
    func validateProtectionItem(_ mi: NSMenuItem) -> Bool? {
        switch mi.action {
        case #selector(protectionStatus):
            mi.title = protectionStatusTitle
            return false
        case #selector(pauseProtection(_:)):
            return !protection.paused && protection.state(network: firewall.mode) != .off
        case #selector(resumeProtection):
            return protection.paused
        case #selector(setProtectionMode(_:)):
            let parts = (mi.representedObject as? String)?.split(separator: "|").map(String.init) ?? []
            guard parts.count == 2 else { return false }
            let current = parts[0] == "net" ? firewall.mode.rawValue
                : ProtectionArea(rawValue: parts[0]).map { protection.mode($0).rawValue } ?? ""
            mi.state = current == parts[1] ? .on : .off
            return true
        default:
            return nil
        }
    }

    @objc func openProtectionOverview() {
        rulesTab.open(.protectionOverview)
        model.windowTab = 4
        openActivityWindow(fullScreen: false)
    }

    // MARK: Export

    /// The events in the list (what you see, up to its limit) as JSON lines, secrets already masked.
    @objc func exportEvents() {
        let events = selectedEvents.isEmpty ? model.history : selectedEvents
        guard !events.isEmpty else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "jsonl") ?? .json]
        panel.nameFieldStringValue = "Hostwatch events \(Date().formatted(.iso8601.year().month().day())).jsonl"
        panel.message = selectedEvents.isEmpty ? "The \(events.count) events in the list." : "The \(events.count) selected events."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // A file you asked for, outside Hostwatch's data: written plain on purpose, so other tools can read it.
        try? EventExport.jsonLines(events).write(to: url, options: .atomic)
    }
}
