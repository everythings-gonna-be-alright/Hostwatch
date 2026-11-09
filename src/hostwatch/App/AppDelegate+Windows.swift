import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

extension AppDelegate {
    // MARK: Windows

    /// One window per question; evidence is collected as soon as it opens.
    /// A whole story: Claude sees the chain first, then the latest step in detail.
    func openAskAI(for story: Story) {
        guard let last = story.steps.last else { return }
        let related = story.steps.dropLast().map(\.event)
        openAskAI(for: last.event, related: related, preface: StoryEngine.evidence(for: story),
                  title: "Ask AI: \(story.title)", classifyPattern: false)
    }

    @objc func openDomains() {
        model.windowTab = 3
        openActivityWindow(fullScreen: false)
    }

    @objc func openStories() {
        model.windowTab = 2
        openActivityWindow(fullScreen: false)
    }

    func openAskAI(for event: ActivityEvent, related: [ActivityEvent]? = nil, preface: String = "",
                           title: String? = nil, classifyPattern: Bool = true) {
        let related = related ?? model.history.filter { $0.pid == event.pid && $0.id != event.id }
        // The threat-list match (a connection's, or a program file's hash) goes into the window and the evidence.
        var event = event
        if event.knownBad.isEmpty, let bad = intel.flag(for: event) { event.knownBad = bad }
        let analysis = AIAnalysis(event: event, related: related, preface: preface, lineage: launchChainText(for: event))
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

    /// Watch Closely: records what the event's process (and what it starts) does, in its own window.
    func openWatch(for event: ActivityEvent, seconds: Double = 60) {
        let path = event.kind == .exec ? event.target : event.proc
        let session = WatchSession(pid: event.pid, name: event.name, path: path.isEmpty ? ProcessList.path(event.pid) : path,
                                   seconds: seconds)
        session.send = AppPaths.isDemo ? { _ in true } : { [weak self] watch in self?.model.sendWatch(watch) ?? false }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 860),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Watch Closely: \(event.name)"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: WatchView(session: session))
        window.center()
        window.collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        let id = session.id
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let w = self.watches.removeValue(forKey: id) else { return }
                if w.session.isRecording { w.session.stop() }
                w.session.analysis?.cancel()
            }
        }
        watches[id] = (session, window)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        session.start()
    }

    func openActivityWindow(fullScreen: Bool) {
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

    func makeActivityWindow() -> NSWindow {
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
        let host = NSHostingController(rootView: ActivityWindowView(model: model, stories: stories, domains: domains, networkState: networkState, firewall: firewall, rulesTab: rulesTab, vitals: vitals, heavyStrip: heavyStrip, intel: intel, sheets: sheets, rules: ruleBook, baseline: baseline, collector: collector, history: history,
                                                                   signatures: signatures, classifier: classifier, travel: travel, metrics: metrics, running: running, actions: actions))
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
        protection.releaseAll()
        history.stop()
        signatures.save(sync: true)
        stories.save()
        domains.save()
        firewall.save()
        protection.save()
        // A background service keeps running after the app quits: nothing to stop.
        guard collector.isRunning, !collector.usesDaemon, !terminating else { return .terminateNow }
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
