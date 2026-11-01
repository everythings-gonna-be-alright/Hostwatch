import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private let signatures = SignatureStore()
    private let stories = StoryEngine()
    private let domains = DomainRegistry()
    private let domainsState = DomainsViewState()
    private lazy var model = HUDModel(signatures: signatures, stories: stories, domains: domains)
    private lazy var classifier = PatternClassifier(store: signatures)
    private lazy var ruleBook = RuleBook(store: signatures)
    private let collector = Collector()
    private let history = HistoryRecorder()
    private let hold = ProcessHold()
    private var heldPanel: NSPanel?
    private var panel: NSPanel?
    private var statusItem: NSStatusItem?
    private var editorWindow: NSWindow?
    private var activityWindow: NSWindow?
    private let editorDraft = EditorDraft()
    private var cancellables = Set<AnyCancellable>()
    private var activityFullScreen = false
    private var hotKey: GlobalHotKey?
    private var terminating = false

    private lazy var actions = HUDActions(
        openFullScreen: { [weak self] in self?.openActivityWindow(fullScreen: true) },
        openExclusions: { [weak self] in self?.openEditor() },
        toggleCollector: { [weak self] in self?.toggleCollector() },
        quit: { NSApp.terminate(nil) },
        askAI: { [weak self] event in self?.openAskAI(for: event) },
        askStory: { [weak self] story in self?.openAskAI(for: story) },
        openStories: { [weak self] in self?.openStories() }
    )
    private var askWindows: [NSWindow] = []

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
        model.connect()
        setUpHistory()
        _ = ruleBook                      // load approved rules and apply them before events arrive
        // Signing: re-score a binary's patterns if its signature turns out invalid; trust the
        // developers of already-installed apps on first run, then re-score everything.
        SigningCache.shared.onChange = { [weak self] path in
            self?.signatures.reassess { SignatureStore.subjectPath($0) == path }
        }
        SigningCache.shared.seedTrustFromInstalledApps { [weak self] in self?.signatures.reassess() }
        // First run: domains already in recorded history are the baseline for "new domain".
        domains.seedBaseline(fromHistory: history.directory)

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

    @objc private func setHoldTimeout(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let action = HoldTimeoutAction(rawValue: raw) else { return }
        hold.timeoutAction = action
    }

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

    private func historyMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "History", action: nil, keyEquivalent: "")
        let sub = NSMenu()

        let status = NSMenuItem(title: history.statusText, action: nil, keyEquivalent: "")
        status.isEnabled = false
        sub.addItem(status)
        sub.addItem(.separator())

        let record = item("Record Activity History", #selector(toggleHistory))
        record.state = history.enabled ? .on : .off
        sub.addItem(record)
        let apply = item("Apply Exclusions to History", #selector(toggleHistoryExclusions))
        apply.state = history.applyExclusions ? .on : .off
        apply.toolTip = "Off: record everything the collector sees. On: record only what passes your exclusions."
        sub.addItem(apply)

        let sizeItem = NSMenuItem(title: "Max Size: \(HistoryRecorder.format(history.maxBytes))", action: nil, keyEquivalent: "")
        let sizes = NSMenu()
        for bytes in HistoryRecorder.sizePresets {
            let mi = item(HistoryRecorder.format(bytes), #selector(setHistorySize(_:)))
            mi.representedObject = NSNumber(value: bytes)
            mi.state = bytes == history.maxBytes ? .on : .off
            sizes.addItem(mi)
        }
        sizes.addItem(.separator())
        let custom = item("Custom…", #selector(customHistorySize))
        custom.state = HistoryRecorder.sizePresets.contains(history.maxBytes) ? .off : .on
        sizes.addItem(custom)
        sizeItem.submenu = sizes
        sub.addItem(sizeItem)
        sub.addItem(.separator())

        sub.addItem(item("Show History in Finder", #selector(revealHistory)))
        sub.addItem(item("Change Location…", #selector(changeHistoryLocation)))
        sub.addItem(item("Clear History…", #selector(clearHistory)))
        parent.submenu = sub
        return parent
    }

    @objc private func toggleHistory() { history.enabled.toggle() }
    @objc private func toggleHistoryExclusions() { history.applyExclusions.toggle() }
    @objc private func revealHistory() { history.revealInFinder() }

    @objc private func setHistorySize(_ sender: NSMenuItem) {
        guard let bytes = (sender.representedObject as? NSNumber)?.int64Value else { return }
        history.maxBytes = bytes
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
        alert.informativeText = "This removes every activity-*.jsonl file in \(history.directory.path)."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { history.clearHistory() }
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
        panel.contentView = NSHostingView(rootView: HUDView(model: model, stories: stories, collector: collector, signatures: signatures, actions: actions))
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
        model.$overlayRows.combineLatest(model.$overlayWidth, model.$overlayScale)
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
        return NSSize(width: model.overlayWidth + 2, height: (rows + 62 * s).rounded(.up))
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

    /// Rebuilt on every open so the "Exclude" submenus reflect the rows on screen.
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        // The main window first.
        menu.addItem(item("Activity Window", #selector(openWindowed), key: "o", symbol: "list.bullet.rectangle"))
        menu.addItem(item("Full Screen Activity", #selector(openFullScreen), key: "f", modifiers: [.command, .control],
                          symbol: "arrow.up.left.and.arrow.down.right"))
        menu.addItem(.separator())

        // Then status: is it watching, and is there anything to look at?
        let state = model.paused ? "Paused" : model.connected ? "Live" : collector.isRunning ? "Starting…" : "Collector off"
        var attention: [String] = []
        if stories.activeCount > 0 { attention.append("\(stories.activeCount) open \(stories.activeCount == 1 ? "story" : "stories")") }
        let highRisk = signatures.newHighRiskCount()
        if highRisk > 0 { attention.append("\(highRisk) high-risk") }
        let status = NSMenuItem(title: ([state] + attention).joined(separator: " · "), action: nil, keyEquivalent: "")
        status.image = symbol("circle.fill", color: model.paused ? .systemYellow : model.connected ? .systemGreen : .systemOrange)
        status.isEnabled = false
        menu.addItem(status)
        if !collector.isRunning, !model.connected {
            let start = item("Start Collector…", #selector(toggleCollector), symbol: "play.circle")
            start.isEnabled = collector.state != .starting
            menu.addItem(start)
        }
        menu.addItem(.separator())

        // What you open.
        let storiesItem = item("Stories", #selector(openStories), symbol: "point.3.connected.trianglepath.dotted")
        if stories.activeCount > 0 { storiesItem.badge = NSMenuItemBadge(count: stories.activeCount) }
        storiesItem.toolTip = "Suspicious chains of activity, correlated along the process tree"
        menu.addItem(storiesItem)
        let patterns = item("Patterns", #selector(openPatterns), key: "p", modifiers: [.command, .shift],
                            symbol: "square.stack.3d.up")
        let unreviewed = signatures.count(.unclassified)
        if unreviewed > 0 { patterns.badge = NSMenuItemBadge(count: unreviewed) }
        patterns.toolTip = "\(highRisk) high-risk · \(unreviewed) new · "
            + "\(signatures.count(.suspicious) + signatures.count(.dangerous)) flagged"
        menu.addItem(patterns)
        let domainsItem = item("Domains", #selector(openDomains), symbol: "globe")
        if domains.newCount > 0 { domainsItem.badge = NSMenuItemBadge(count: domains.newCount) }
        domainsItem.toolTip = domains.isLearning ? "Learning this Mac's usual domains"
            : "Domains contacted for the first time are new"
        menu.addItem(domainsItem)

        menu.addItem(.sectionHeader(title: "Live Stream"))
        menu.addItem(item(model.paused ? "Resume" : "Pause", #selector(togglePause),
                          symbol: model.paused ? "play.fill" : "pause.fill"))
        menu.addItem(item("Clear", #selector(clearEvents), symbol: "trash"))
        menu.addItem(showMenu())
        menu.addItem(exclusionsMenu())

        menu.addItem(.sectionHeader(title: "HUD"))
        let hud = item("Show HUD", #selector(toggleOverlay), key: "h", modifiers: [.control, .option, .command])
        hud.state = model.overlayEnabled ? .on : .off
        menu.addItem(hud)
        let clickThrough = item("Click-Through", #selector(toggleClickThrough))
        clickThrough.state = model.overlayClickThrough ? .on : .off
        clickThrough.toolTip = "Turn off to move, resize and double-click the HUD."
        menu.addItem(clickThrough)
        menu.addItem(appearanceMenu())

        menu.addItem(.separator())
        menu.addItem(detectionMenu())
        menu.addItem(collectorMenu())
        menu.addItem(historyMenu())
        menu.addItem(.separator())
        menu.addItem(item("Quit Hostwatch", #selector(quit), key: "q"))
    }

    private func symbol(_ name: String, color: NSColor? = nil) -> NSImage? {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        guard let color else { return image }
        return image?.withSymbolConfiguration(.init(paletteColors: [color]).applying(.init(scale: .small)))
    }

    /// Event kinds plus the pattern-status filter (both apply to the HUD and the event list).
    private func showMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "Show", action: nil, keyEquivalent: "")
        parent.image = symbol("line.3.horizontal.decrease.circle")
        let sub = NSMenu()
        sub.addItem(.sectionHeader(title: "Event Kinds"))
        for kind in EventKind.allCases {
            let mi = item(kind.title, #selector(toggleKind(_:)))
            mi.representedObject = kind.rawValue
            mi.state = model.visibleKinds.contains(kind) ? .on : .off
            sub.addItem(mi)
        }
        sub.addItem(.sectionHeader(title: "By Pattern Status"))
        for filter in SignatureFilter.allCases {
            let mi = item(filter.title, #selector(setSignatureFilter(_:)))
            mi.representedObject = filter.rawValue
            mi.state = model.signatureFilter == filter ? .on : .off
            sub.addItem(mi)
        }
        parent.submenu = sub
        return parent
    }

    private func exclusionsMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "Exclusions", action: nil, keyEquivalent: "")
        parent.image = symbol("eye.slash")
        let sub = NSMenu()
        let events = Array(model.overlayEvents)
        sub.addItem(.sectionHeader(title: "Hide From What's on the HUD"))
        addExcludeSubmenu(to: sub, title: "Process", patterns: events.map(\.name))
        addExcludeSubmenu(to: sub, title: "Host", patterns: events.compactMap { e in
            e.exclusionSuggestions.first { $0.1.hasPrefix("net:") }?.1
        })
        addExcludeSubmenu(to: sub, title: "Folder", patterns: events.compactMap { e in
            e.exclusionSuggestions.first { $0.1.hasPrefix("file:") }?.1
        })
        sub.addItem(.separator())
        sub.addItem(item("Edit Exclusions…", #selector(openEditor), key: ","))
        parent.submenu = sub
        return parent
    }

    /// Background, tint, text size and size reset in one place.
    private func appearanceMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "Appearance", action: nil, keyEquivalent: "")
        parent.image = symbol("paintbrush")
        let sub = NSMenu()
        sub.addItem(.sectionHeader(title: "Background"))
        for style in OverlayBackground.allCases {
            let mi = item(style.title, #selector(setBackgroundStyle(_:)))
            mi.representedObject = style.rawValue
            mi.state = model.overlayBackground == style ? .on : .off
            sub.addItem(mi)
        }
        let tint = NSMenuItem(title: "Tint", action: nil, keyEquivalent: "")
        let tints = NSMenu()
        for percent in [15, 30, 45, 60, 75, 90] {
            let mi = item("\(percent)%", #selector(setBackgroundOpacity(_:)))
            mi.representedObject = NSNumber(value: Double(percent) / 100)
            mi.state = abs(model.overlayOpacity - Double(percent) / 100) < 0.01 ? .on : .off
            tints.addItem(mi)
        }
        tint.submenu = tints
        tint.isEnabled = model.overlayBackground != .transparent
        sub.addItem(tint)
        sub.addItem(.sectionHeader(title: "Text Size"))
        for (name, scale) in HUDModel.scaleOptions {
            let mi = item(name, #selector(setScale(_:)))
            mi.representedObject = NSNumber(value: Double(scale))
            mi.state = abs(model.overlayScale - scale) < 0.01 ? .on : .off
            sub.addItem(mi)
        }
        sub.addItem(.separator())
        let hint = NSMenuItem(title: model.overlayClickThrough
                              ? "To move or resize, turn off Click-Through"
                              : "Drag the header to move, the ◣ corner to resize", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        sub.addItem(hint)
        sub.addItem(item("Reset Size & Position", #selector(resetOverlayFrame)))
        parent.submenu = sub
        return parent
    }

    /// Detection tuning that changes what counts as trusted or new.
    private func detectionMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "Detection", action: nil, keyEquivalent: "")
        parent.image = symbol("shield.lefthalf.filled")
        let sub = NSMenu()
        let brew = item("Trust Homebrew-Installed Tools", #selector(toggleTrustHomebrew))
        brew.state = SigningCache.shared.trustHomebrew ? .on : .off
        brew.toolTip = "Treat tools in Homebrew's Cellar (with an install receipt) like a trusted developer. "
            + "/opt/homebrew is writable by your user, so a planted binary there would be trusted too."
        sub.addItem(brew)
        let holdItem = item("Hold Suspicious Processes", #selector(toggleHold))
        holdItem.state = hold.enabled ? .on : .off
        holdItem.toolTip = "Freeze your own processes the moment they do something suspicious (piped or encoded "
            + "command, password or key read, login item, quarantine removal…) and ask you. Best effort: "
            + "very quick commands can finish first."
        sub.addItem(holdItem)
        if hold.enabled {
            let timeoutMenu = NSMenu()
            for action in HoldTimeoutAction.allCases {
                let mi = item(action.title, #selector(setHoldTimeout(_:)))
                mi.representedObject = action.rawValue
                mi.state = hold.timeoutAction == action ? .on : .off
                timeoutMenu.addItem(mi)
            }
            let timeoutItem = NSMenuItem(title: "If No Answer in \(Int(hold.timeout)) s", action: nil, keyEquivalent: "")
            timeoutItem.indentationLevel = 1
            timeoutItem.submenu = timeoutMenu
            sub.addItem(timeoutItem)
        }

        // Which AI classifies new patterns and answers Ask.
        sub.addItem(.sectionHeader(title: "AI Engine"))
        let status = classifier.localStatus
        for engine in AIEngine.allCases {
            let mi = item(engine.title, #selector(setAIEngine(_:)))
            mi.representedObject = engine.rawValue
            mi.state = classifier.engine == engine ? .on : .off
            mi.toolTip = engine.help
            sub.addItem(mi)
        }
        let statusItem = NSMenuItem(title: status.label, action: nil, keyEquivalent: "")
        statusItem.image = symbol(status.isReady ? "checkmark.circle" : "exclamationmark.circle",
                                  color: status.isReady ? .systemGreen : .systemOrange)
        statusItem.isEnabled = false
        sub.addItem(statusItem)
        let mcp = item("Use with Claude Code…", #selector(showMCPSetup))
        mcp.toolTip = "Let Claude Code investigate this Mac's recorded activity through Hostwatch's read-only MCP server."
        sub.addItem(mcp)
        sub.addItem(.separator())
        let learning = item(domains.isLearning ? "End Domain Learning Now" : "Domain Learning Finished",
                            #selector(endDomainLearning))
        learning.isEnabled = domains.isLearning
        sub.addItem(learning)
        parent.submenu = sub
        return parent
    }

    @objc private func toggleTrustHomebrew() {
        SigningCache.shared.trustHomebrew.toggle()
        signatures.reassess()
    }

    @objc private func endDomainLearning() { domains.endLearning() }
    /// The one command that registers Hostwatch's read-only MCP server with Claude Code.
    static var mcpCommand: String {
        let exe = Bundle.main.executablePath ?? "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch"
        return "claude mcp add --scope user hostwatch -- \"\(exe)\" --mcp"
    }

    @objc private func showMCPSetup() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Investigate with Claude Code"
        alert.informativeText = """
        Hostwatch includes a read-only MCP server. Add it to Claude Code once, then ask things like \
        "what talked to new domains last night?" or "walk me through story #1".

        \(Self.mcpCommand)

        Claude only sees what you ask about; secrets are masked. Nothing can be changed through it. \
        If you move Hostwatch.app, run the command again.
        """
        alert.addButton(withTitle: "Copy Command")
        alert.addButton(withTitle: "Close")
        if alert.runModal() == .alertFirstButtonReturn {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(Self.mcpCommand, forType: .string)
        }
    }

    @objc private func setAIEngine(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let engine = AIEngine(rawValue: raw) else { return }
        classifier.engine = engine
    }

    private func collectorMenu() -> NSMenuItem {
        let parent = NSMenuItem(title: "Collector", action: nil, keyEquivalent: "")
        parent.image = symbol("antenna.radiowaves.left.and.right")
        let sub = NSMenu()
        let status = NSMenuItem(title: collector.statusText, action: nil, keyEquivalent: "")
        status.isEnabled = false
        sub.addItem(status)
        sub.addItem(.separator())
        if collector.isRunning {
            sub.addItem(item("Stop Collector", #selector(toggleCollector)))
        } else {
            let start = item(model.connected ? "Running Externally" : "Start Collector…", #selector(toggleCollector))
            start.isEnabled = !model.connected && collector.state != .starting
            sub.addItem(start)
        }
        let atLaunch = item("Start at Launch", #selector(toggleStartAtLaunch))
        atLaunch.state = collector.startAtLaunch ? .on : .off
        sub.addItem(atLaunch)
        sub.addItem(.separator())
        sub.addItem(item("Show Log", #selector(showLog)))
        sub.addItem(item("Open Full Disk Access Settings", #selector(openFDA)))
        parent.submenu = sub
        return parent
    }

    private func addExcludeSubmenu(to menu: NSMenu, title: String, patterns: [String]) {
        var seen = Set<String>()
        let unique = patterns.filter { !$0.isEmpty && seen.insert($0).inserted }.prefix(15)
        let parent = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for pattern in unique {
            let mi = item(pattern, #selector(excludePattern(_:)))
            mi.representedObject = pattern
            sub.addItem(mi)
        }
        parent.submenu = sub
        parent.isEnabled = !unique.isEmpty
        menu.addItem(parent)
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

    @objc private func setScale(_ sender: NSMenuItem) {
        guard let v = (sender.representedObject as? NSNumber)?.doubleValue else { return }
        model.overlayScale = CGFloat(v)
    }

    @objc private func resetOverlayFrame() {
        model.overlayScale = 1.0
        model.overlayWidth = 360
        model.overlayRows = 24
        guard let panel, let visible = NSScreen.main?.visibleFrame else { return }
        let size = overlaySize()
        panel.setFrame(NSRect(x: visible.maxX - size.width - 14, y: visible.maxY - size.height - 14,
                              width: size.width, height: size.height), display: true)
    }

    @objc private func setBackgroundStyle(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let style = OverlayBackground(rawValue: raw) else { return }
        model.overlayBackground = style
    }

    @objc private func setBackgroundOpacity(_ sender: NSMenuItem) {
        guard let value = (sender.representedObject as? NSNumber)?.doubleValue else { return }
        model.overlayOpacity = value
    }

    @objc private func setSignatureFilter(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let f = SignatureFilter(rawValue: raw) else { return }
        model.signatureFilter = f
    }

    @objc private func openPatterns() {
        model.windowTab = 1
        openActivityWindow(fullScreen: false)
    }

    @objc private func toggleClickThrough() { model.overlayClickThrough.toggle() }
    @objc private func togglePause() { model.paused.toggle() }
    @objc private func clearEvents() { model.clear() }
    @objc private func quit() { NSApp.terminate(nil) }
    @objc private func openFullScreen() { openActivityWindow(fullScreen: true) }
    @objc private func openWindowed() { openActivityWindow(fullScreen: false) }
    @objc private func toggleStartAtLaunch() { collector.startAtLaunch.toggle() }
    @objc private func showLog() { collector.openLog() }
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

    private func showFullDiskAccessAlert(afterFailure: Bool) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Hostwatch needs Full Disk Access"
        alert.informativeText = """
        macOS only lets the collector (eslogger) watch processes and files when the app that \
        starts it has Full Disk Access.

        1. Click Open Settings.
        2. Turn on Hostwatch. If it is not listed, click + and choose:
           \(Bundle.main.bundlePath)
        3. Quit and reopen Hostwatch.

        After each rebuild, remove the old Hostwatch entry and add it again.
        """
        alert.alertStyle = afterFailure ? .warning : .informational
        alert.addButton(withTitle: "Open Settings")
        if !afterFailure { alert.addButton(withTitle: "Start Anyway") }
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            Collector.openFullDiskAccessSettings()
        case .alertSecondButtonReturn where !afterFailure:
            collector.start()
        default:
            break
        }
    }

    @objc private func toggleKind(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let kind = EventKind(rawValue: raw) else { return }
        model.toggle(kind)
    }

    @objc private func excludePattern(_ sender: NSMenuItem) {
        guard let pattern = sender.representedObject as? String else { return }
        model.addExclusion(pattern)
    }

    // MARK: Windows

    @objc private func openEditor() {
        if editorWindow == nil {
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 560, height: 480),
                styleMask: [.titled, .closable, .resizable],
                backing: .buffered,
                defer: false
            )
            window.title = "Hostwatch Exclusions"
            window.isReleasedWhenClosed = false
            window.contentView = NSHostingView(rootView: ExclusionsEditor(model: model, draft: editorDraft) { [weak window] in
                window?.close()
            })
            window.center()
            editorWindow = window
        }
        editorDraft.text = model.exclusionText
        NSApp.activate(ignoringOtherApps: true)
        editorWindow?.makeKeyAndOrderFront(nil)
    }

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
        let key = event.signatureKey
        if classifyPattern {
            analysis.onVerdict = { [weak self, weak analysis] verdict, summary in
                guard let self else { return }
                let onDevice = analysis?.engine == .onDevice
                // Same guard as triage: the on-device model never marks a high-risk pattern Safe.
                if onDevice, verdict == .safe, self.signatures.entry(key)?.risk == .high { return }
                // A single verdict classifies the event's pattern unless you already decided it.
                self.signatures.suggest(SignatureStatus(verdict: verdict), key: key,
                                        source: onDevice ? "on-device" : "claude", note: summary)
            }
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 720),
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
        let host = NSHostingController(rootView: ActivityWindowView(model: model, stories: stories, domains: domains, domainsState: domainsState, rules: ruleBook, collector: collector, history: history,
                                                                   signatures: signatures, classifier: classifier, actions: actions))
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
        if let i = args.firstIndex(of: collectorLauncherFlag) {
            runCollectorLauncher(Array(args[(i + 1)...]))
        }
        // Plain AppKit lifecycle: a SwiftUI App needs a scene, and its only one (an empty Settings
        // window) was shown on every launch/reopen.
        MainActor.assumeIsolated {
            let app = NSApplication.shared
            app.delegate = appDelegate
            app.mainMenu = makeMainMenu()
            app.run()
        }
    }

    @MainActor private static let appDelegate = AppDelegate()

    /// Shown while the activity window makes the app regular; the Edit menu keeps ⌘C/⌘V/⌘A working.
    @MainActor private static func makeMainMenu() -> NSMenu {
        let main = NSMenu()
        func submenu(_ title: String, _ items: [NSMenuItem]) {
            let holder = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            let menu = NSMenu(title: title)
            items.forEach(menu.addItem)
            holder.submenu = menu
            main.addItem(holder)
        }
        func item(_ title: String, _ action: Selector, _ key: String, _ mods: NSEvent.ModifierFlags = .command) -> NSMenuItem {
            let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
            mi.keyEquivalentModifierMask = mods
            return mi
        }
        submenu("Hostwatch", [
            item("Hide Hostwatch", #selector(NSApplication.hide(_:)), "h"),
            .separator(),
            item("Quit Hostwatch", #selector(NSApplication.terminate(_:)), "q"),
        ])
        submenu("Edit", [
            item("Undo", Selector(("undo:")), "z"),
            item("Redo", Selector(("redo:")), "z", [.command, .shift]),
            .separator(),
            item("Cut", #selector(NSText.cut(_:)), "x"),
            item("Copy", #selector(NSText.copy(_:)), "c"),
            item("Paste", #selector(NSText.paste(_:)), "v"),
            item("Select All", #selector(NSText.selectAll(_:)), "a"),
        ])
        submenu("Window", [
            item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
            item("Close", #selector(NSWindow.performClose(_:)), "w"),
            item("Toggle Full Screen", #selector(NSWindow.toggleFullScreen(_:)), "f", [.command, .control]),
        ])
        return main
    }
}
