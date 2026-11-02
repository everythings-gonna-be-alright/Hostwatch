import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSMenuItemValidation, NSWindowDelegate {
    private let signatures = SignatureStore()
    private let stories = StoryEngine()
    private let domains = DomainRegistry()
    private let domainsState = DomainsViewState()
    private let rulesTab = RulesTabState()
    /// Processes Hostwatch saw start that still run heavy (CPU or memory).
    private let vitals = ProcessVitals()
    private let heavyStrip = HeavyStripState()
    private lazy var model = HUDModel(signatures: signatures, stories: stories, domains: domains)
    private lazy var classifier = PatternClassifier(store: signatures)
    private lazy var ruleBook = RuleBook(store: signatures)
    private let collector = Collector()
    private let history = HistoryRecorder()
    private let hold = ProcessHold()
    private let updates = UpdateChecker()
    private lazy var metrics = MetricsStore(directory: { [history] in history.directory })
    private lazy var travel = TimeTravel(history: history, stories: stories, domains: domains, metrics: metrics)
    private var heldPanel: NSPanel?
    private var panel: NSPanel?
    private var statusItem: NSStatusItem?
    private lazy var settings = SettingsWindowController(context: SettingsContext(
        model: model, collector: collector, history: history, hold: hold, domains: domains, stories: stories,
        signatures: signatures, classifier: classifier, editorDraft: editorDraft, updates: updates,
        baseline: baseline, openBaseline: { [weak self] in self?.openBaselineReport() },
        toggleCollector: { [weak self] in self?.toggleCollector() },
        resetOverlayFrame: { [weak self] in self?.resetOverlayFrame() },
        customHistorySize: { [weak self] in self?.customHistorySize() },
        changeHistoryLocation: { [weak self] in self?.changeHistoryLocation() },
        clearHistory: { [weak self] in self?.clearHistory() },
        reset: { [weak self] plan in
            guard let self else { return }
            Reset.run(plan, collector: self.collector, model: self.model, historyDir: self.history.directory)
        }))
    private var activityWindow: NSWindow?
    private let editorDraft = EditorDraft()
    private var cancellables = Set<AnyCancellable>()
    private var activityFullScreen = false
    private var hotKey: GlobalHotKey?
    private var terminating = false

    private lazy var actions = HUDActions(
        openFullScreen: { [weak self] in self?.openActivityWindow(fullScreen: true) },
        openExclusions: { [weak self] in self?.openSettings(.exclusions) },
        toggleCollector: { [weak self] in self?.toggleCollector() },
        quit: { NSApp.terminate(nil) },
        askAI: { [weak self] event in self?.openAskAI(for: event) },
        askStory: { [weak self] story in self?.openAskAI(for: story) },
        openStories: { [weak self] in self?.openStories() },
        openSettings: { [weak self] in self?.openSettings(nil) },
        exclude: { [weak self] pattern in self?.model.addExclusion(pattern) },
        showInTimeline: { [weak self] date in self?.showInTimeline(date) },
        openBaseline: { [weak self] in self?.openBaselineReport() },
        openDomain: { [weak self] domain in self?.openDomainDetails(domain) },
        openStory: { [weak self] story in self?.openStoryDetails(story) }
    )
    private var askWindows: [NSWindow] = []
    /// Learns this Mac's normal behaviour in waves after the first launch (a fresh pattern store).
    private lazy var baseline = BaselineLearner(store: signatures, classifier: classifier,
                                                freshInstall: signatures.total == 0)

    /// Opening the app again (Finder, Dock, Spotlight) shows the activity window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { openActivityWindow(fullScreen: false) }
        return true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        collector.onNeedsFullDiskAccess = { [weak self] in self?.showFullDiskAccessAlert(afterFailure: true) }
        setUpPanel()
        setUpStatusItem()
        // ⌃⌥⌘H toggles the HUD from anywhere (Carbon hot keys need no Accessibility permission).
        hotKey = GlobalHotKey(keyCode: UInt32(kVK_ANSI_H),
                              modifiers: UInt32(controlKey | optionKey | cmdKey)) { [weak self] in
            self?.model.overlayEnabled.toggle()
        }
        setUpHold()
        baseline.schedule()               // first run: waves at 5, 15 and 60 minutes
        // Only draw events while the window or the HUD is actually on screen.
        NotificationCenter.default.addObserver(forName: NSWindow.didChangeOcclusionStateNotification,
                                               object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateUIVisibility() }
        }
        model.onTop = { [weak self] procs, read, write in self?.metrics.receiveTop(procs, diskRead: read, diskWrite: write) }
        model.onVitals = { [weak self] samples in self?.vitals.receive(samples) }
        metrics.heavyProvider = { [weak self] in self?.vitals.snapshot ?? [] }      // recorded for Time Travel
        model.onEvent = { [weak self] event in if event.kind == .exec { self?.vitals.noteLaunch(event) } }
        vitals.onHeavyUntrusted = { [weak self] launch, tracked in
            guard let self else { return }
            let cpu = Int(self.vitals.cpuAverage(tracked, at: Date()))
            let note = "\(launch.name) keeps running heavy (\(cpu)% CPU, \(ProcessVitals.memory(tracked.memNow))) "
                + "and isn't trusted code: the cryptominer pattern"
            _ = self.stories.ingest(launch.event, decidedSafe: false, extra: [(.heavyUntrusted, note)])
        }
        metrics.start()                   // CPU, memory, network every 5 s (recorded for Time Travel)
        updates.schedule()                // daily, if allowed in Settings ▸ General
        model.connect()
        setUpHistory()
        // The list isn't empty after a restart; launches from before it are still followed if running.
        model.restoreRecent(from: history.directory) { [weak self] in
            guard let self else { return }
            for e in self.model.history.reversed() where e.kind == .exec && e.pstart > 0 { self.vitals.noteLaunch(e) }
        }
        _ = ruleBook                      // load approved rules and apply them before events arrive
        // Signing: re-score a binary's patterns if its signature turns out invalid; trust the
        // developers of already-installed apps on first run, then re-score everything.
        SigningCache.shared.onChange = { [weak self] path in
            self?.signatures.reassess { SignatureStore.subjectPath($0) == path }
        }
        SigningCache.shared.seedTrustFromInstalledApps { [weak self] in self?.signatures.reassess() }
        // First run: domains already in recorded history are the baseline for "new domain".
        domains.seedBaseline(fromHistory: history.directory)

        // The main window opens with the app (the setup window, if needed, comes in front of it).
        openActivityWindow(fullScreen: false)

        // Start the bundled collector unless one (e.g. run-agent.sh) is already serving.
        if collector.startAtLaunch {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                guard let self, !self.model.connected else { return }
                self.startCollector()
            }
        }
    }

    // MARK: Hold

    private func setUpHold() {
        model.hold = hold
        hold.onAlwaysAllow = { [weak self] e in
            self?.signatures.set(.safe, keys: [e.signatureKey], note: "allowed while held")
        }
        hold.onChange = { [weak self] in self?.refreshHeldPanel() }
    }

    /// The floating "Hostwatch paused a process" panel, shown while anything is held.
    private func refreshHeldPanel() {
        guard !hold.held.isEmpty else {
            heldPanel?.orderOut(nil)
            return
        }
        if heldPanel == nil {
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 520, height: 200),
                                styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
                                backing: .buffered, defer: false)
            panel.title = "Held by Hostwatch"
            panel.titlebarAppearsTransparent = true
            panel.level = .floating
            panel.isReleasedWhenClosed = false
            panel.hidesOnDeactivate = false
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            let host = NSHostingController(rootView: HeldView(hold: hold) { [weak self] e in
                self?.openAskAI(for: e)
            })
            host.sizingOptions = [.preferredContentSize]
            panel.contentViewController = host
            heldPanel = panel
        }
        guard let panel = heldPanel else { return }
        if !panel.isVisible {
            if let screen = NSScreen.main?.visibleFrame {
                panel.setFrameTopLeftPoint(NSPoint(x: screen.maxX - panel.frame.width - 20, y: screen.maxY - 20))
            }
            panel.orderFrontRegardless()
        }
    }

    @objc private func toggleHold() { hold.enabled.toggle() }

    // MARK: History

    private func setUpHistory() {
        // Keep the recorder's filters in sync for "Apply Exclusions to History".
        // Kind toggles only change what is shown, so history always records every kind.
        model.$exclusionText
            .sink { [weak self] text in
                self?.history.updateFilters(exclusions: ExclusionRules(text: text).lines,
                                            kinds: EventKind.allCases.map(\.rawValue))
            }
            .store(in: &cancellables)
        history.start()
    }

    @objc private func customHistorySize() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Maximum history size"
        alert.informativeText = "Total size of all history files, in GB. The oldest files are deleted when the limit is reached."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 120, height: 24))
        field.stringValue = String(format: "%g", Double(history.maxBytes) / 1e9)
        alert.accessoryView = field
        alert.addButton(withTitle: "Set")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let text = field.stringValue.replacingOccurrences(of: ",", with: ".")
        guard let gb = Double(text), gb >= 0.01, gb <= 100_000 else { NSSound.beep(); return }
        history.maxBytes = Int64(gb * 1e9)
    }

    @objc private func changeHistoryLocation() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.directoryURL = history.directory
        panel.prompt = "Use Folder"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        history.directory = url
    }

    @objc private func clearHistory() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Delete all history files?"
        alert.informativeText = "This removes all recorded activity and resource history (activity-*, metrics-*) in \(history.directory.path)."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            history.clearHistory()
            metrics.archive.removeAll()
        }
    }

    // MARK: Overlay panel

    private func setUpPanel() {
        let size = overlaySize()
        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.contentView = NSHostingView(rootView: HUDView(model: model, stories: stories, collector: collector, signatures: signatures, metrics: metrics, vitals: vitals, actions: actions))
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle, .fullScreenAuxiliary]

        let autosave = "HostwatchOverlay"
        if !panel.setFrameUsingName(autosave), let screen = NSScreen.main {
            let visible = screen.visibleFrame
            panel.setFrameOrigin(NSPoint(x: visible.maxX - panel.frame.width - 14,
                                         y: visible.maxY - panel.frame.height - 14))
        }
        panel.setFrameAutosaveName(autosave)
        resizeOverlay(panel)

        // Click-through by default; "interactive" mode lets you drag it and use its buttons.
        model.$overlayClickThrough
            .sink { [weak panel] clickThrough in
                panel?.ignoresMouseEvents = clickThrough
                panel?.isMovableByWindowBackground = !clickThrough
            }
            .store(in: &cancellables)

        self.panel = panel
        model.$overlayRows.combineLatest(model.$overlayWidth, model.$overlayScale, model.$overlayShowResources)
            .dropFirst()
            .sink { [weak self] _ in
                DispatchQueue.main.async { if let self, let panel = self.panel { self.resizeOverlay(panel) } }
            }
            .store(in: &cancellables)
        model.$overlayEnabled
            .sink { [weak self] _ in DispatchQueue.main.async { self?.refreshOverlayVisibility() } }
            .store(in: &cancellables)
    }

    /// Room for the configured rows at the configured text size, plus header and padding.
    private func overlaySize() -> NSSize {
        let s = model.overlayScale
        let rows = CGFloat(model.overlayRows) * (rowHeight(s) + 1)
        return NSSize(width: model.overlayWidth + 2, height: (rows + model.overlayChrome(s)).rounded(.up))
    }

    /// Applies the size while keeping the top-right corner fixed, clamped to the screen.
    private func resizeOverlay(_ panel: NSPanel) {
        var size = overlaySize()
        let old = panel.frame
        if let visible = (panel.screen ?? NSScreen.main)?.visibleFrame {
            size.height = min(size.height, visible.height)
            size.width = min(size.width, visible.width)
        }
        let frame = NSRect(x: old.maxX - size.width, y: old.maxY - size.height,
                           width: size.width, height: size.height)
        panel.setFrame(frame, display: true)
    }

    /// Visible when enabled, except while the activity window is full screen.
    private func refreshOverlayVisibility() {
        guard let panel else { return }
        if model.overlayEnabled && !activityFullScreen {
            panel.orderFrontRegardless()
        } else {
            panel.orderOut(nil)
        }
        updateUIVisibility()
    }

    /// The event list and HUD redraw only while one of them is visible (not closed, minimised,
    /// hidden or fully covered); the model buffers events meanwhile.
    private func updateUIVisibility() {
        func onScreen(_ window: NSWindow?) -> Bool {
            guard let window, window.isVisible else { return false }
            return window.occlusionState.contains(.visible)
        }
        model.uiVisible = onScreen(activityWindow) || onScreen(panel)
    }

    // MARK: Menu bar

    private func setUpStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = NSImage(systemSymbolName: "waveform.path.ecg", accessibilityDescription: "Hostwatch")
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
        let storiesItem = item("Stories", #selector(openStories), symbol: "point.3.connected.trianglepath.dotted")
        if stories.activeCount > 0 { storiesItem.badge = NSMenuItemBadge(count: stories.activeCount) }
        menu.addItem(storiesItem)
        let patterns = item("Patterns", #selector(openPatterns), symbol: "square.stack.3d.up")
        let unreviewed = signatures.count(.unclassified)
        if unreviewed > 0 { patterns.badge = NSMenuItemBadge(count: unreviewed) }
        menu.addItem(patterns)
        let domainsItem = item("Domains", #selector(openDomains), symbol: "globe")
        if domains.newCount > 0 { domainsItem.badge = NSMenuItemBadge(count: domains.newCount) }
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
        let tabs = [("Events", 0), ("Patterns", 1), ("Rules", 4), ("Stories", 2), ("Domains", 3)].enumerated().map { i, tab in
            tagged(item(tab.0, #selector(showTab(_:)), key: "\(i + 1)"), tab.1)
        }
        let showFilter = NSMenuItem(title: "Show", action: nil, keyEquivalent: "")
        let filters = NSMenu()
        for f in SignatureFilter.allCases { filters.addItem(tagged(item(f.title, #selector(setFilter(_:))), f.rawValue)) }
        showFilter.submenu = filters
        let kinds = EventKind.allCases.map { tagged(item($0.title, #selector(toggleKindItem(_:))), $0.rawValue) }
        submenu("View", tabs + [
            .separator(),
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
        case #selector(askAboutSelection), #selector(markSelection(_:)), #selector(excludeSelection):
            return !selectedEvents.isEmpty || (model.windowTab == 1 && !signatures.selection.isEmpty
                                               && mi.action == #selector(markSelection(_:)))
        default:
            break
        }
        return true
    }

    /// Events selected in the Events tab (newest first).
    private var selectedEvents: [ActivityEvent] {
        guard activityWindow?.isKeyWindow == true, model.windowTab == 0, !model.eventSelection.isEmpty else { return [] }
        return model.history.filter { model.eventSelection.contains($0.id) }
    }

    @objc private func showTab(_ sender: NSMenuItem) {
        guard let tab = sender.representedObject as? Int else { return }
        model.windowTab = tab
        openActivityWindow(fullScreen: false)
    }

    @objc private func setFilter(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let f = SignatureFilter(rawValue: raw) else { return }
        model.signatureFilter = f
    }

    @objc private func toggleKindItem(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let kind = EventKind(rawValue: raw) else { return }
        model.toggle(kind)
    }

    @objc private func askAboutSelection() {
        guard let first = selectedEvents.first else { return }
        openAskAI(for: first)
    }

    @objc private func markSelection(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let status = SignatureStatus(rawValue: raw) else { return }
        let keys = model.windowTab == 1 ? Array(signatures.selection) : selectedEvents.map(\.signatureKey)
        signatures.set(status, keys: Array(Set(keys)))
    }

    /// Asks which exclusion to add for the selected event.
    @objc private func excludeSelection() {
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

    @objc private func toggleTimeTravel() {
        if travel.active { travel.exit(); return }
        model.windowTab = 0
        openActivityWindow(fullScreen: false)
        travel.enter()
    }

    @objc private func timeTravelEarlier() { travel.step(-1) }
    @objc private func timeTravelLater() { travel.step(1) }

    /// Opens the Events tab in time travel, with `date` inside the shown slice.
    private func showInTimeline(_ date: Date) {
        model.windowTab = 0
        openActivityWindow(fullScreen: false)
        travel.enter(at: date.addingTimeInterval(min(travel.span / 2, 60)))
    }

    @objc private func checkForUpdates() { updates.checkAndReport() }

    @objc private func showAvailableUpdate() {
        if let release = updates.available { updates.presentAvailable(release) }
    }

    @objc private func showBaselineReport() { openBaselineReport() }

    /// A domain's details: risk score, programs, connections, Ask AI.
    private func openDomainDetails(_ domain: String) {
        guard let record = domains.records[domain] else { return }
        let connections = model.history.filter {
            $0.kind == .net && ($0.registrableDomain == domain || $0.host == domain || $0.host.hasSuffix("." + domain))
        }
        let details = DomainDetails(record: record, connections: Array(connections.prefix(200)))
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
    private func openStoryDetails(_ story: Story) {
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
    private func openBaselineReport() {
        rulesTab.segment = .needsYou
        rulesTab.chosen = true
        model.windowTab = 4
        openActivityWindow(fullScreen: false)
    }

    @objc private func showSettings() { openSettings(nil) }
    @objc private func showAISettings() { openSettings(.ai) }
    @objc private func showCollectorLog() { collector.openLog() }

    func openSettings(_ pane: SettingsPane?) { settings.show(pane) }

    @objc private func showHeld() {
        refreshHeldPanel()
        heldPanel?.makeKeyAndOrderFront(nil)
    }

    @objc private func openHelp() {
        if let url = URL(string: "https://github.com/\(UpdateChecker.repository)/blob/main/docs/reference.md") {
            NSWorkspace.shared.open(url)
        }
    }

    private func symbol(_ name: String, color: NSColor? = nil) -> NSImage? {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        guard let color else { return image }
        return image?.withSymbolConfiguration(.init(paletteColors: [color]).applying(.init(scale: .small)))
    }

    private func item(_ title: String, _ action: Selector, key: String = "",
                      modifiers: NSEvent.ModifierFlags = .command, symbol name: String? = nil) -> NSMenuItem {
        let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
        mi.keyEquivalentModifierMask = modifiers
        mi.target = self
        if let name { mi.image = NSImage(systemSymbolName: name, accessibilityDescription: nil) }
        return mi
    }

    // MARK: Actions

    @objc private func toggleOverlay() { model.overlayEnabled.toggle() }

    @objc private func resetOverlayFrame() {
        model.overlayScale = 1.0
        model.overlayWidth = 360
        model.overlayRows = 24
        guard let panel, let visible = NSScreen.main?.visibleFrame else { return }
        let size = overlaySize()
        panel.setFrame(NSRect(x: visible.maxX - size.width - 14, y: visible.maxY - size.height - 14,
                              width: size.width, height: size.height), display: true)
    }

    @objc private func openPatterns() {
        model.windowTab = 1
        openActivityWindow(fullScreen: false)
    }

    @objc private func togglePause() { model.paused.toggle() }
    @objc private func clearEvents() { model.clear() }
    @objc private func quit() { NSApp.terminate(nil) }
    @objc private func openFullScreen() { openActivityWindow(fullScreen: true) }
    @objc private func openWindowed() { openActivityWindow(fullScreen: false) }
    @objc private func openFDA() { Collector.openFullDiskAccessSettings() }

    @objc private func toggleCollector() {
        if collector.isRunning { collector.stop(via: model) } else { startCollector() }
    }

    /// Checks Full Disk Access first so a missing grant doesn't cost a password prompt.
    private func startCollector() {
        if Collector.appearsToHaveFullDiskAccess {
            collector.start()
        } else {
            showFullDiskAccessAlert(afterFailure: false)
        }
    }

    private var accessWindow: NSWindow?

    /// The Full Disk Access setup window (one at a time); it notices the grant by itself.
    private func showFullDiskAccessAlert(afterFailure: Bool) {
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

    // MARK: Windows

    /// One window per question; evidence is collected as soon as it opens.
    /// A whole story: Claude sees the chain first, then the latest step in detail.
    private func openAskAI(for story: Story) {
        guard let last = story.steps.last else { return }
        let related = story.steps.dropLast().map(\.event)
        openAskAI(for: last.event, related: related, preface: StoryEngine.evidence(for: story),
                  title: "Ask AI: \(story.title)", classifyPattern: false)
    }

    @objc private func openDomains() {
        model.windowTab = 3
        openActivityWindow(fullScreen: false)
    }

    @objc private func openStories() {
        model.windowTab = 2
        openActivityWindow(fullScreen: false)
    }

    private func openAskAI(for event: ActivityEvent, related: [ActivityEvent]? = nil, preface: String = "",
                           title: String? = nil, classifyPattern: Bool = true) {
        let related = related ?? model.history.filter { $0.pid == event.pid && $0.id != event.id }
        let analysis = AIAnalysis(event: event, related: related, preface: preface)
        analysis.patternStatus = signatures.status(for: event)
        analysis.patternRisk = signatures.entry(event.signatureKey)?.risk ?? event.signatureRisk
        let key = event.signatureKey
        if classifyPattern {
            analysis.onVerdict = { [weak self, weak analysis] verdict, summary in
                guard let self else { return }
                let onDevice = analysis?.engine == .onDevice
                // A single verdict classifies the event's pattern unless you already decided it
                // (never Safe for a high-risk pattern: see SignatureStore.suggest).
                self.signatures.suggest(SignatureStatus(verdict: verdict), key: key,
                                        source: onDevice ? "on-device" : "claude", note: summary)
            }
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 820),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = title ?? "Ask AI: \(event.name)"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: AskAIView(analysis: analysis))
        window.center()
        // If the activity window is full screen, open as a normal window over it.
        window.collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] note in
            MainActor.assumeIsolated {
                analysis.cancel()
                self?.askWindows.removeAll { $0 === note.object as? NSWindow }
            }
        }
        askWindows.append(window)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func openActivityWindow(fullScreen: Bool) {
        let window = activityWindow ?? makeActivityWindow()
        activityWindow = window
        // A regular app gets a Dock icon and Cmd-Tab entry, which full screen relies on.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        updateUIVisibility()
        if fullScreen && !window.styleMask.contains(.fullScreen) {
            DispatchQueue.main.async { window.toggleFullScreen(nil) }
        }
    }

    private func makeActivityWindow() -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Hostwatch"
        window.isReleasedWhenClosed = false
        window.collectionBehavior = [.fullScreenPrimary]
        // Hosting controller bridges the SwiftUI .toolbar/.searchable/title into a native,
        // unified Liquid Glass toolbar.
        let host = NSHostingController(rootView: ActivityWindowView(model: model, stories: stories, domains: domains, domainsState: domainsState, rulesTab: rulesTab, vitals: vitals, heavyStrip: heavyStrip, rules: ruleBook, baseline: baseline, collector: collector, history: history,
                                                                   signatures: signatures, classifier: classifier, travel: travel, metrics: metrics, actions: actions))
        host.sceneBridgingOptions = [.toolbars, .title]
        // Only enforce the minimum size; by default the controller resizes the window to each tab's
        // preferred size (e.g. the small empty Stories view), which reset the window on tab switch.
        host.sizingOptions = [.minSize]
        window.contentViewController = host
        window.toolbarStyle = .unified
        window.setContentSize(NSSize(width: 1100, height: 680))
        window.setFrameAutosaveName("HostwatchActivity")
        window.center()
        window.delegate = self
        return window
    }

    // The overlay would only duplicate the full-screen window, so hide it there.
    func windowDidEnterFullScreen(_ notification: Notification) {
        guard notification.object as? NSWindow === activityWindow else { return }
        activityFullScreen = true
        refreshOverlayVisibility()
    }

    func windowDidExitFullScreen(_ notification: Notification) {
        guard notification.object as? NSWindow === activityWindow else { return }
        activityFullScreen = false
        refreshOverlayVisibility()
    }

    func windowWillClose(_ notification: Notification) {
        guard notification.object as? NSWindow === activityWindow else { return }
        DispatchQueue.main.async { [weak self] in self?.updateUIVisibility() }   // after it's gone
        activityFullScreen = false
        refreshOverlayVisibility()
        NSApp.setActivationPolicy(.accessory)
    }

    // MARK: Termination

    /// Quitting from anywhere (menu, overlay ×, full-screen Quit, Cmd-Q) stops
    /// the collector we started before the app exits.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        hold.releaseAll()                 // never leave a process frozen behind
        history.stop()
        signatures.save(sync: true)
        stories.save()
        domains.save()
        guard collector.isRunning, !terminating else { return .terminateNow }
        terminating = true
        var replied = false
        let reply = {
            guard !replied else { return }
            replied = true
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        collector.stop(via: model) { reply() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { reply() }
        return .terminateLater
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

@main
enum Entry {
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--mcp") { MCPServer().run() }      // read-only MCP server for Claude Code
        if args.contains("--suggest-rules") { runRuleSuggestionDryRun() }
        if let i = args.firstIndex(of: "--signature-report"), i + 1 < args.count {
            runSignatureReport(args[i + 1])
        }
        if let i = args.firstIndex(of: "--signing-check"), i + 1 < args.count {
            runSigningCheck(Array(args[(i + 1)...]))
        }
        if let i = args.firstIndex(of: "--story-replay"), i + 1 < args.count {
            MainActor.assumeIsolated { runStoryReplay(args[i + 1]) }
        }
        if args.contains("--metrics-probe") { runMetricsProbe() }
        if let i = args.firstIndex(of: "--compress-history"), i + 1 < args.count {
            runCompressHistory(args[i + 1])
        }
        if let i = args.firstIndex(of: "--time-travel-probe") {
            runTimeTravelProbe(i + 1 < args.count ? args[i + 1] : nil)
        }
        // The collector itself (root, started by the launcher below): the flag comes first.
        if args.count > 1, args[1] == collectorFlag { runCollectorAgent(Array(args.dropFirst(2))) }
        if let i = args.firstIndex(of: collectorLauncherFlag) {
            runCollectorLauncher(Array(args[(i + 1)...]))
        }
        // Plain AppKit lifecycle: a SwiftUI App needs a scene, and its only one (an empty Settings
        // window) was shown on every launch/reopen.
        MainActor.assumeIsolated {
            let app = NSApplication.shared
            app.delegate = appDelegate
            app.mainMenu = appDelegate.makeMainMenu()
            app.run()
        }
    }

    @MainActor private static let appDelegate = AppDelegate()
}

private extension NSMenuItem {
    func withTag(_ tag: Int) -> NSMenuItem { self.tag = tag; return self }
}
