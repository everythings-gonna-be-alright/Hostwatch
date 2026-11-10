import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

extension AppDelegate {
    // MARK: Menu bar

    func setUpStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = MenuBarIcon.image
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        statusItem = item
    }

    /// The tray menu: a glance and a few quick actions. Settings live in the Settings window,
    /// commands in the app's menu bar, row actions on right-click.
    func menuNeedsUpdate(_ menu: NSMenu) {
        guard menu === statusItem?.menu else { return }
        menu.removeAllItems()

        let state = model.paused ? "Paused" : model.connected ? "Live" : collector.isRunning ? "Starting…" : "Collector off"
        var attention: [String] = []
        if stories.activeCount > 0 { attention.append("\(stories.activeCount) open \(stories.activeCount == 1 ? "story" : "stories")") }
        let highRisk = signatures.newHighRiskCount()
        if highRisk > 0 { attention.append("\(highRisk) high-risk") }
        let status = NSMenuItem(title: ([state] + attention).joined(separator: " · "), action: nil, keyEquivalent: "")
        status.image = symbol("circle.fill", color: model.paused ? .systemYellow : model.connected ? .systemGreen : .systemOrange)
        status.isEnabled = false
        menu.addItem(status)
        if !hold.held.isEmpty {
            let held = item("\(hold.held.count) \(hold.held.count == 1 ? "process" : "processes") held — Review…",
                            #selector(showHeld), symbol: "pause.circle.fill")
            menu.addItem(held)
        }
        if firewall.fallback != nil {
            menu.addItem(item("Firewall turned itself to Watch…", #selector(openFirewallPane), symbol: "exclamationmark.triangle.fill"))
        }
        // Counts what it opens: known-bad matches in open stories this week (dismissed or deleted ones don't count).
        let knownBad = stories.openKnownBadMatches(since: Date().addingTimeInterval(-7 * 86400))
        if knownBad > 0 {
            menu.addItem(item("\(knownBad) known-bad \(knownBad == 1 ? "match" : "matches") this week…", #selector(openStories),
                              symbol: "xmark.octagon.fill"))
        }
        if intel.vulnerabilitiesEnabled, intel.unfixedCount > 0 {
            let n = intel.unfixedCount
            let title = intel.pendingUpdate != nil ? "A macOS update fixes \(n) exploited \(n == 1 ? "flaw" : "flaws")…"
                : "\(n) exploited macOS \(n == 1 ? "flaw" : "flaws") since your last update…"
            menu.addItem(item(title, #selector(showVulnerabilities), symbol: "exclamationmark.shield.fill"))
        }
        if claudeGuard.enabled, claudeGuard.status == .missing {
            menu.addItem(item("Claude Code guard was removed — Restore", #selector(restoreClaudeGuard),
                              symbol: "exclamationmark.shield.fill"))
        }
        if claudeGuard.recentBlocked > 0 {
            let n = claudeGuard.recentBlocked
            menu.addItem(item("Claude Code: \(n) \(n == 1 ? "action" : "actions") blocked today…", #selector(openGuardLog),
                              symbol: "xmark.shield.fill"))
        }
        if case .learning(let wave, _) = baseline.phase {
            let learning = NSMenuItem(title: "Learning this Mac's normal behaviour (wave \(wave) of 3)", action: nil, keyEquivalent: "")
            learning.image = symbol("hourglass")
            learning.isEnabled = false
            menu.addItem(learning)
        }
        if let release = updates.available {
            menu.addItem(item("\(release.name) Available…", #selector(showAvailableUpdate),
                              symbol: "arrow.down.circle.fill"))
        }
        if !collector.isRunning, !model.connected {
            let start = item("Start Collector…", #selector(toggleCollector), symbol: "play.circle")
            start.isEnabled = collector.state != .starting
            menu.addItem(start)
        }
        menu.addItem(.separator())

        menu.addItem(item("Open Hostwatch", #selector(openWindowed), key: "o", symbol: "macwindow"))
        // Doors into the window, without counters: 1,068 New patterns or 161 new domains aren't tasks (the tabs show
        // what needs you).
        menu.addItem(item("Stories", #selector(openStories), symbol: "point.3.connected.trianglepath.dotted"))
        menu.addItem(item("Patterns", #selector(openPatterns), symbol: "square.stack.3d.up"))
        let domainsItem = item("Network", #selector(openDomains), symbol: "network.badge.shield.half.filled")
        domainsItem.toolTip = "Firewall and domains"
        menu.addItem(domainsItem)
        menu.addItem(.separator())

        menu.addItem(item(model.paused ? "Resume Live Stream" : "Pause Live Stream", #selector(togglePause),
                          symbol: model.paused ? "play.fill" : "pause.fill"))
        let hud = item("Show HUD", #selector(toggleOverlay), key: "h", modifiers: [.control, .option, .command])
        hud.state = model.overlayEnabled ? .on : .off
        menu.addItem(hud)
        let holdItem = item("Hold Suspicious Processes", #selector(toggleHold))
        holdItem.state = hold.enabled ? .on : .off
        holdItem.toolTip = "Freeze your own processes the moment they do something suspicious, and ask you."
        menu.addItem(holdItem)
        menu.addItem(.separator())
        menu.addItem(item("Settings…", #selector(showSettings), key: ","))
        menu.addItem(item("Quit Hostwatch", #selector(quit), key: "q"))
    }

    // MARK: App menu bar

    /// Shown while a Hostwatch window makes the app regular.
    func makeMainMenu() -> NSMenu {
        let main = NSMenu()
        func submenu(_ title: String, _ items: [NSMenuItem]) {
            let holder = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            let menu = NSMenu(title: title)
            items.forEach(menu.addItem)
            holder.submenu = menu
            main.addItem(holder)
        }
        func std(_ title: String, _ action: Selector, _ key: String = "",
                 _ mods: NSEvent.ModifierFlags = .command) -> NSMenuItem {
            let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
            mi.keyEquivalentModifierMask = mods
            return mi
        }
        func tagged(_ mi: NSMenuItem, _ value: Any) -> NSMenuItem { mi.representedObject = value; return mi }

        let hideOthers = std("Hide Others", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option])
        submenu("Hostwatch", [
            std("About Hostwatch", #selector(NSApplication.orderFrontStandardAboutPanel(_:))),
            item("Check for Updates…", #selector(checkForUpdates)),
            .separator(),
            item("Settings…", #selector(showSettings), key: ","),
            .separator(),
            std("Hide Hostwatch", #selector(NSApplication.hide(_:)), "h"),
            hideOthers,
            std("Show All", #selector(NSApplication.unhideAllApplications(_:))),
            .separator(),
            std("Quit Hostwatch", #selector(NSApplication.terminate(_:)), "q"),
        ])
        submenu("Edit", [
            std("Undo", Selector(("undo:")), "z"),
            std("Redo", Selector(("redo:")), "z", [.command, .shift]),
            .separator(),
            std("Cut", #selector(NSText.cut(_:)), "x"),
            std("Copy", #selector(NSText.copy(_:)), "c"),
            std("Paste", #selector(NSText.paste(_:)), "v"),
            std("Select All", #selector(NSText.selectAll(_:)), "a"),
            .separator(),
            std("Find", #selector(NSResponder.performTextFinderAction(_:)), "f").withTag(Int(NSTextFinder.Action.showFindInterface.rawValue)),
        ])

        // Shown in this order (⌘1–⌘5); the tag is the window tab's index.
        let tabs = [("Events", 0), ("Patterns", 1), ("Rules", 4), ("Stories", 2), ("Network", 3)].enumerated().map { i, tab in
            tagged(item(tab.0, #selector(showTab(_:)), key: "\(i + 1)"), tab.1)
        }
        let showFilter = NSMenuItem(title: "Show", action: nil, keyEquivalent: "")
        let filters = NSMenu()
        for f in SignatureFilter.allCases { filters.addItem(tagged(item(f.title, #selector(setFilter(_:))), f.rawValue)) }
        showFilter.submenu = filters
        let kinds = EventKind.allCases.map { tagged(item($0.title, #selector(toggleKindItem(_:))), $0.rawValue) }
        submenu("View", tabs + [
            .separator(),
            item("Running Now", #selector(toggleRunningNow), key: "r", modifiers: [.command, .option]),
            item("Time Travel", #selector(toggleTimeTravel), key: "t", modifiers: [.command, .option]),
            item("Earlier", #selector(timeTravelEarlier), key: "["),
            item("Later", #selector(timeTravelLater), key: "]"),
            .separator(), showFilter, .separator()] + kinds + [
            .separator(),
            item("Show HUD", #selector(toggleOverlay), key: "h", modifiers: [.control, .option, .command]),
            std("Enter Full Screen", #selector(NSWindow.toggleFullScreen(_:)), "f", [.command, .control]),
        ])

        let marks = SignatureStatus.allCases.map {
            tagged(item("Mark \($0.title)", #selector(markSelection(_:))), $0.rawValue)
        }
        submenu("Activity", [
            item("Pause Live Stream", #selector(togglePause)),
            item("Clear Events", #selector(clearEvents), key: "k"),
            .separator(),
            item("Ask AI About Selection…", #selector(askAboutSelection), key: "\r"),
            item("Watch Selected Process Closely…", #selector(watchSelection), key: "w", modifiers: [.command, .option]),
        ] + marks + [
            item("Exclude Selection…", #selector(excludeSelection)),
            .separator(),
            item("Start Collector", #selector(toggleCollector)),
        ])
        let windowMenu = NSMenu(title: "Window")
        [std("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
         std("Zoom", #selector(NSWindow.performZoom(_:))),
         std("Close", #selector(NSWindow.performClose(_:)), "w"),
         .separator(),
         item("Activity Window", #selector(openWindowed), key: "0"),
         item("Held Processes", #selector(showHeld)),
         .separator(),
         std("Bring All to Front", #selector(NSApplication.arrangeInFront(_:)))].forEach(windowMenu.addItem)
        let windowHolder = NSMenuItem(title: "Window", action: nil, keyEquivalent: "")
        windowHolder.submenu = windowMenu
        main.addItem(windowHolder)
        NSApp.windowsMenu = windowMenu
        let helpMenu = NSMenu(title: "Help")
        [item("Hostwatch Help", #selector(openHelp)),
         .separator(),
         item("Use with Claude Code…", #selector(showAISettings)),
         item("Collector Log", #selector(showCollectorLog)),
         item("Full Disk Access Settings…", #selector(openFDA))].forEach(helpMenu.addItem)
        let helpHolder = NSMenuItem(title: "Help", action: nil, keyEquivalent: "")
        helpHolder.submenu = helpMenu
        main.addItem(helpHolder)
        NSApp.helpMenu = helpMenu
        return main
    }

    /// Checkmarks, titles and enabled state for menu items, at the moment a menu opens.
    func validateMenuItem(_ mi: NSMenuItem) -> Bool {
        switch mi.action {
        case #selector(showTab(_:)):
            mi.state = activityWindow?.isVisible == true && model.windowTab == mi.representedObject as? Int ? .on : .off
        case #selector(setFilter(_:)):
            mi.state = model.signatureFilter.rawValue == mi.representedObject as? String ? .on : .off
        case #selector(toggleKindItem(_:)):
            mi.state = model.visibleKinds.contains { $0.rawValue == mi.representedObject as? String } ? .on : .off
        case #selector(toggleOverlay):
            mi.state = model.overlayEnabled ? .on : .off
        case #selector(toggleHold):
            mi.state = hold.enabled ? .on : .off
        case #selector(toggleTimeTravel):
            mi.state = travel.active ? .on : .off
        case #selector(timeTravelEarlier), #selector(timeTravelLater):
            return travel.active
        case #selector(clearEvents):
            return !travel.active
        case #selector(toggleRunningNow):
            mi.state = running.showing && model.windowTab == 0 ? .on : .off
        case #selector(togglePause):
            mi.title = model.paused ? "Resume Live Stream" : "Pause Live Stream"
        case #selector(toggleCollector):
            if mi.menu !== statusItem?.menu {
                mi.title = collector.isRunning ? "Stop Collector" : "Start Collector…"
            }
            return collector.state != .starting && (collector.isRunning || !model.connected)
        case #selector(showHeld):
            return !hold.held.isEmpty
        case #selector(checkForUpdates):
            return !updates.checking
        case #selector(askAboutSelection), #selector(markSelection(_:)), #selector(excludeSelection), #selector(watchSelection):
            return !selectedEvents.isEmpty || (model.windowTab == 1 && !signatures.selection.isEmpty
                                               && mi.action == #selector(markSelection(_:)))
        default:
            break
        }
        return true
    }

    /// Events selected in the Events tab (newest first).
    var selectedEvents: [ActivityEvent] {
        guard activityWindow?.isKeyWindow == true, model.windowTab == 0, !model.eventSelection.isEmpty else { return [] }
        return model.history.filter { model.eventSelection.contains($0.id) }
    }

    @objc func showTab(_ sender: NSMenuItem) {
        guard let tab = sender.representedObject as? Int else { return }
        model.windowTab = tab
        openActivityWindow(fullScreen: false)
    }

    @objc func setFilter(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let f = SignatureFilter(rawValue: raw) else { return }
        model.signatureFilter = f
    }

    @objc func toggleKindItem(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let kind = EventKind(rawValue: raw) else { return }
        model.toggle(kind)
    }

    @objc func askAboutSelection() {
        guard let first = selectedEvents.first else { return }
        openAskAI(for: first)
    }

    @objc func watchSelection() {
        guard let first = selectedEvents.first else { return }
        openWatch(for: first)
    }

    @objc func markSelection(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let status = SignatureStatus(rawValue: raw) else { return }
        let keys = model.windowTab == 1 ? signatures.keys(forSelection: signatures.selection) : selectedEvents.map(\.signatureKey)
        signatures.set(status, keys: Array(Set(keys)))
    }

    /// Asks which exclusion to add for the selected event.
    @objc func excludeSelection() {
        guard let e = selectedEvents.first else { return }
        let alert = NSAlert()
        alert.messageText = "Exclude \(e.name)?"
        alert.informativeText = "Excluded events are hidden from the HUD and the event list. Edit them any time in "
            + "Settings ▸ Exclusions."
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 360, height: 26), pullsDown: false)
        for (title, pattern) in e.exclusionSuggestions {
            popup.addItem(withTitle: title)
            popup.lastItem?.representedObject = pattern
        }
        alert.accessoryView = popup
        alert.addButton(withTitle: "Exclude")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn,
              let pattern = popup.selectedItem?.representedObject as? String else { return }
        model.addExclusion(pattern)
    }

    @objc func toggleRunningNow() {
        model.windowTab = 0                   // in Time Travel: what was running at the playhead
        running.showing.toggle()
        openActivityWindow(fullScreen: false)
    }

    /// Running Now ▸ Show Spawn in Timeline.
    func showSpawn(pid: Int, start: Date) {
        running.showing = false
        model.windowTab = 0
        openActivityWindow(fullScreen: false)
        travel.reveal(pid: pid, start: start)
    }

    @objc func toggleTimeTravel() {
        if travel.active { travel.exit(); return }
        model.windowTab = 0                   // Running Now stays: it then shows the playhead's moment
        openActivityWindow(fullScreen: false)
        travel.enter()
    }

    @objc func timeTravelEarlier() { travel.step(-1) }
    @objc func timeTravelLater() { travel.step(1) }

    /// Opens the Events tab in time travel, with `date` inside the shown slice.
    func showInTimeline(_ date: Date) {
        model.windowTab = 0
        openActivityWindow(fullScreen: false)
        travel.enter(at: date.addingTimeInterval(min(travel.span / 2, 60)))
    }

    @objc func checkForUpdates() { updates.checkAndReport() }

    @objc func showAvailableUpdate() {
        if let release = updates.available { updates.presentAvailable(release) }
    }

    @objc func showBaselineReport() { openBaselineReport() }

    @objc func showVulnerabilities() {
        openActivityWindow(fullScreen: false)
        sheets.showVulns = true
    }

    /// A domain's details: risk score, programs, connections, Ask AI.
    func openDomainDetails(_ domain: String) {
        guard let record = domains.records[domain] else { return }
        let connections = model.history.filter {
            $0.kind == .net && ($0.registrableDomain == domain || $0.host == domain || $0.host.hasSuffix("." + domain))
        }
        let details = DomainDetails(record: record, connections: Array(connections.prefix(200)),
                                    knownBad: intel.reason(forDomain: domain))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: 820),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Domain: \(domain)"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: DomainDetailView(
            details: details, analysis: details.analysis, domains: domains,
            markKnown: { [weak self] known in self?.domains.setKnown([domain], known) },
            showInTimeline: { [weak self] date in self?.showInTimeline(date) }))
        window.center()
        window.collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] note in
            MainActor.assumeIsolated {
                details.analysis.cancel()
                self?.askWindows.removeAll { $0 === note.object as? NSWindow }
            }
        }
        askWindows.append(window)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// The whole chain of a story, event by event (double-click a story).
    func openStoryDetails(_ story: Story) {
        let details = StoryDetails(story: story, historyDirectory: history.directory, live: model.history)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 760),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Story: \(story.title)"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: StoryDetailView(
            details: details, actions: actions,
            dismiss: { [weak self, weak window] in self?.stories.dismiss(story.id); window?.close() },
            ignore: { [weak self, weak window] in self?.stories.ignoreAlways(story.id); window?.close() }))
        window.center()
        window.collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] note in
            MainActor.assumeIsolated { self?.askWindows.removeAll { $0 === note.object as? NSWindow } }
        }
        askWindows.append(window)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// The baseline lives in the Rules tab.
    func openBaselineReport() {
        rulesTab.segment = .needsYou
        rulesTab.chosen = true
        model.windowTab = 4
        openActivityWindow(fullScreen: false)
    }

    @objc func showSettings() { openSettings(nil) }
    @objc func showAISettings() { openSettings(.ai) }
    @objc func showCollectorLog() { collector.openLog() }

    func openSettings(_ pane: SettingsPane?) { settings.show(pane) }

    @objc func openFirewallPane() { openSettings(.firewall) }

    @objc func showHeld() {
        refreshHeldPanel()
        heldPanel?.makeKeyAndOrderFront(nil)
    }

    @objc func openHelp() {
        // The docs on the website (built from docs/reference.md).
        if let url = URL(string: "https://everythings-gonna-be-alright.github.io/Hostwatch/docs/") {
            NSWorkspace.shared.open(url)
        }
    }

    func symbol(_ name: String, color: NSColor? = nil) -> NSImage? {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        guard let color else { return image }
        return image?.withSymbolConfiguration(.init(paletteColors: [color]).applying(.init(scale: .small)))
    }

    func item(_ title: String, _ action: Selector, key: String = "",
                      modifiers: NSEvent.ModifierFlags = .command, symbol name: String? = nil) -> NSMenuItem {
        let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
        mi.keyEquivalentModifierMask = modifiers
        mi.target = self
        if let name { mi.image = NSImage(systemSymbolName: name, accessibilityDescription: nil) }
        return mi
    }

    // MARK: Actions

    @objc func toggleOverlay() { model.overlayEnabled.toggle() }

    @objc func resetOverlayFrame() {
        model.overlayScale = 1.0
        model.overlayWidth = 360
        model.overlayRows = 24
        guard let panel, let visible = NSScreen.main?.visibleFrame else { return }
        let size = overlaySize()
        panel.setFrame(NSRect(x: visible.maxX - size.width - 14, y: visible.maxY - size.height - 14,
                              width: size.width, height: size.height), display: true)
    }

    @objc func openPatterns() {
        model.windowTab = 1
        openActivityWindow(fullScreen: false)
    }

    @objc func togglePause() { model.paused.toggle() }
    @objc func clearEvents() { model.clear() }
    @objc func quit() { NSApp.terminate(nil) }
    @objc func openFullScreen() { openActivityWindow(fullScreen: true) }
    @objc func openWindowed() { openActivityWindow(fullScreen: false) }
    @objc func openFDA() { Collector.openFullDiskAccessSettings() }

    @objc func toggleCollector() {
        if collector.isRunning { collector.stop(via: model) } else { startCollector() }
    }

    /// The service is registered and waits in System Settings ▸ Login Items: say so, with the way there.
    func showServiceApproval() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Allow Hostwatch's collector in the background"
        alert.informativeText = "macOS lists Hostwatch's collector under System Settings ▸ General ▸ Login Items ▸ "
            + "Allow in the Background. Turn it on once: it then starts at boot as a background service and never asks for "
            + "your password at launch again."
        alert.addButton(withTitle: "Open Login Items…")
        alert.addButton(withTitle: "Later")
        if alert.runModal() == .alertFirstButtonReturn { collector.daemon.openLoginItems() }
    }

    /// Checks Full Disk Access first so a missing grant doesn't cost a password prompt.
    func startCollector() {
        if Collector.appearsToHaveFullDiskAccess {
            collector.start()
        } else {
            showFullDiskAccessAlert(afterFailure: false)
        }
    }


    /// The Full Disk Access setup window (one at a time); it notices the grant by itself.
    func showFullDiskAccessAlert(afterFailure: Bool) {
        NSApp.activate(ignoringOtherApps: true)
        if let accessWindow { accessWindow.makeKeyAndOrderFront(nil); return }
        let setup = FullDiskAccessSetup(afterFailure: afterFailure)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 600),
                              styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.title = "Full Disk Access"
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.hidesOnDeactivate = false
        let close: () -> Void = { [weak window] in window?.close() }
        window.contentView = NSHostingView(rootView: FullDiskAccessView(
            setup: setup,
            start: { [weak self] in close(); self?.collector.start() },
            close: close,
            startAnyway: afterFailure ? nil : { [weak self] in close(); self?.collector.start() }))
        window.center()
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { setup.stop(); self?.accessWindow = nil }
        }
        accessWindow = window
        // In front of everything when it appears (even at login, before Hostwatch is the active app);
        // an ordinary window after that, so System Settings can come forward.
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }
}

extension NSMenuItem {
    func withTag(_ tag: Int) -> NSMenuItem { self.tag = tag; return self }
}
