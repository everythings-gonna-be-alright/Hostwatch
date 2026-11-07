import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

extension AppDelegate {
    // MARK: Demo (screenshots)

    /// Fills the app with Demo's made-up activity and opens the scene asked for.
    func runDemo() {
        #if DEMO
        model.demoConnect()
        domains.endLearning()
        firewall.mode = .ask
        for line in Demo.lines() { model.receive(line) }
        model.flushUI()
        firewall.relayStatus("on", "")
        signatures.showSeenOnce = true
        running.request = { [weak self] in
            self?.running.receive(Demo.runningList())
            return true
        }
        if let frame = NSScreen.main?.visibleFrame, let window = activityWindow {
            window.setFrame(NSRect(x: frame.midX - 640, y: frame.midY - 390, width: 1280, height: 780), display: true)
        }
        model.overlayEnabled = Demo.scene == "hud"
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [self] in
            // A few decisions, as if made over the past days.
            let safeKeys = model.history.filter { ["git", "ssh", "python3"].contains($0.name) }.map(\.signatureKey)
            signatures.set(.safe, keys: Array(Set(safeKeys)), note: "demo")
            let cleanerLaunch = model.history.first { $0.kind == .exec && $0.name == "CleanMyDisk" }
            // DEMO_SEARCH=text: the search field filled in (screenshots of a filtered list).
            if let q = ProcessInfo.processInfo.environment["DEMO_SEARCH"], !q.isEmpty { model.searchText = q }
            switch Demo.scene {
            case "hud":
                model.overlayEnabled = true
                activityWindow?.orderOut(nil)
            case "running":
                model.windowTab = 0
                running.showing = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [self] in
                    running.selection = running.rows.first { $0.name == "CleanMyDisk" }?.id
                    running.showInfo = true
                }
            case "patterns": model.windowTab = 1
            case "stories":
                model.windowTab = 2
                if let story = stories.stories.first { openStoryDetails(story) }
            case "network": model.windowTab = 3
            case "firewall":
                model.windowTab = 3
                let ask = ActivityEvent(kind: .net, time: "", pid: 4471, ppid: 3306, name: "node",
                                        proc: "/usr/local/bin/node", target: "104.16.24.35:443", extra: "TCP", parent: "/bin/zsh",
                                        host: "registry.npmjs.org", hostSource: "dns")
                firewall.handleAsk(key: "demo", event: ask)
            case "watch":
                if let e = cleanerLaunch {
                    openWatch(for: e)
                    if let (id, w) = watches.first {
                        w.session.receive(WatchMessage(id: id, state: "done", detail: "time limit", profile: Demo.watchProfile()))
                    }
                }
            case "live":
                // New events keep arriving, like a real Mac (for the website's video).
                model.windowTab = 0
                var i = 0
                Timer.scheduledTimer(withTimeInterval: 0.9, repeats: true) { [weak self] _ in
                    MainActor.assumeIsolated {
                        self?.model.receive(Demo.liveLine(i))
                        i += 1
                    }
                }
            default:
                model.windowTab = 0
                if let e = cleanerLaunch { model.eventSelection = [e.id] }
            }
        }
        #endif
    }

    // MARK: Hold

    func setUpHold() {
        model.hold = hold
        hold.onAlwaysAllow = { [weak self] e in
            self?.signatures.set(.safe, keys: [e.signatureKey], note: "allowed while held")
        }
        hold.onChange = { [weak self] in self?.refreshHeldPanel() }
    }

    /// The floating "Hostwatch paused a process" panel, shown while anything is held.
    func refreshHeldPanel() {
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

    @objc func toggleHold() { hold.enabled.toggle() }

    // MARK: Firewall

    func setUpFirewall() {
        firewall.status = { [weak self] e in self?.signatures.status(for: e) ?? .unclassified }
        firewall.knownBad = { [weak self] e in self?.intel.check(e)?.summary ?? "" }
        firewall.markPattern = { [weak self] key, status in
            self?.signatures.set(status, keys: [key], note: status == .safe ? "allowed in Firewall" : "blocked in Firewall")
        }
        firewall.answer = { [weak self] key, pass, ttl in self?.model.sendFirewallAnswer(key: key, pass: pass, ttl: ttl) }
        firewall.onPromptsChange = { [weak self] in self?.refreshFirewallPanels() }
        firewall.flushAnswers = { [weak self] in self?.model.sendFirewall(flush: true) }
        firewall.onModeChange = { [weak self] mode in self?.model.firewallMode = mode.collector }
        model.onFirewallAsk = { [weak self] key, event in self?.firewall.handleAsk(key: key, event: event) }
        model.onFirewallStatus = { [weak self] state, detail in self?.firewall.relayStatus(state, detail) }
        model.onWatch = { [weak self] message in self?.watches[message.id]?.session.receive(message) }
        model.firewallMode = firewall.mode.collector
    }

    /// A window per question, in the middle of the screen; each closes when answered.
    func refreshFirewallPanels() {
        let live = Set(firewall.prompts.map(\.id))
        for (id, panel) in firewallPanels where !live.contains(id) {
            panel.orderOut(nil)
            firewallPanels[id] = nil
        }
        var added = false
        for prompt in firewall.prompts where firewallPanels[prompt.id] == nil {
            let panel = QuestionPanel.make(FirewallPromptView(firewall: firewall, id: prompt.id))
            QuestionPanel.show(panel, slot: firewallPanels.count)
            firewallPanels[prompt.id] = panel
            added = true
        }
        if added { NSSound(named: "Tink")?.play() }
    }

    // MARK: Claude Code guard

    func setUpClaudeGuard() {
        claudeGuard.listed = { [weak self] host in
            MainActor.assumeIsolated {
                guard let intel = self?.intel, intel.enabled else { return nil }
                if host.first?.isNumber == true { return intel.listedIP(host, port: "") }
                return intel.listedDomain(host)?.detail
            }
        }
        claudeGuard.onPromptsChange = { [weak self] in self?.refreshGuardPanel() }
        claudeGuard.start()
    }

    /// "Claude Code wants to run a command": in front of everything while Hostwatch is asking.
    func refreshGuardPanel() {
        guard !claudeGuard.prompts.isEmpty else {
            guardPanel?.orderOut(nil)
            return
        }
        if guardPanel == nil { guardPanel = QuestionPanel.make(GuardPromptView(claudeGuard: claudeGuard)) }
        guard let panel = guardPanel, !panel.isVisible else { return }
        QuestionPanel.show(panel, slot: 0)
        NSSound(named: "Funk")?.play()
    }

    @objc func openGuardLog() {
        settings.showGuardLog()
    }

    @objc func restoreClaudeGuard() { claudeGuard.setEnabled(true) }

    // MARK: History

    func setUpHistory() {
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

    @objc func customHistorySize() {
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

    @objc func changeHistoryLocation() {
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

    @objc func clearHistory() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Delete all history files?"
        alert.informativeText = "This removes all recorded activity, resource and process history (activity-*, metrics-*, processes-*) in \(history.directory.path)."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            history.clearHistory()
            metrics.archive.removeAll()
            ProcessHistory(directory: history.directory).archive.removeAll()
            processRecorder.reset()
        }
    }
}
