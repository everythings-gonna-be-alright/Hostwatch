import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSMenuItemValidation, NSWindowDelegate {
    let signatures = SignatureStore()
    /// The Full Disk Access setup window (one at a time); it notices the grant by itself.
    var accessWindow: NSWindow?
    let stories = StoryEngine()
    let domains = DomainRegistry()
    let networkState = NetworkViewState()
    let rulesTab = RulesTabState()
    /// Processes Hostwatch saw start that still run heavy (CPU or memory).
    let vitals = ProcessVitals()
    let running = RunningProcesses()
    let heavyStrip = HeavyStripState()
    /// Threat lists and exploited macOS vulnerabilities (downloaded daily, matched locally).
    let intel = ThreatIntel()
    /// Claude Code's actions, checked before they run (a PreToolUse hook asks this app).
    let claudeGuard = ClaudeGuard()
    var guardPanel: NSPanel?
    /// Firewall rules; Watch mode lists what they would block (nothing is blocked yet).
    let firewall = FirewallMonitor()
    /// One window per waiting question.
    var firewallPanels: [UUID: NSPanel] = [:]
    let sheets = WindowSheetState()
    let sessions = AgentSessions()
    lazy var model = HUDModel(signatures: signatures, stories: stories, domains: domains, sessions: sessions)
    lazy var classifier = PatternClassifier(store: signatures)
    lazy var ruleBook = RuleBook(store: signatures)
    let collector = Collector()
    let history = HistoryRecorder()
    let hold = ProcessHold()
    let updates = UpdateChecker()
    lazy var metrics = MetricsStore(directory: { [history] in history.directory })
    lazy var processRecorder = ProcessRecorder(directory: { [history] in history.directory })
    lazy var travel = TimeTravel(history: history, stories: stories, domains: domains, metrics: metrics)
    var heldPanel: NSPanel?
    var panel: NSPanel?
    var statusItem: NSStatusItem?
    lazy var settings = SettingsWindowController(context: SettingsContext(
        model: model, collector: collector, history: history, hold: hold, domains: domains, stories: stories,
        signatures: signatures, classifier: classifier, editorDraft: editorDraft, updates: updates,
        baseline: baseline, intel: intel, claudeGuard: claudeGuard, firewall: firewall, openBaseline: { [weak self] in self?.openBaselineReport() },
        showNetwork: { [weak self] in self?.openDomains() },
        toggleCollector: { [weak self] in self?.toggleCollector() },
        resetOverlayFrame: { [weak self] in self?.resetOverlayFrame() },
        customHistorySize: { [weak self] in self?.customHistorySize() },
        changeHistoryLocation: { [weak self] in self?.changeHistoryLocation() },
        clearHistory: { [weak self] in self?.clearHistory() },
        reset: { [weak self] plan in
            guard let self else { return }
            Reset.run(plan, collector: self.collector, model: self.model, historyDir: self.history.directory)
        }))
    var activityWindow: NSWindow?
    let editorDraft = EditorDraft()
    var cancellables = Set<AnyCancellable>()
    var activityFullScreen = false
    var hotKey: GlobalHotKey?
    var terminating = false

    lazy var actions = HUDActions(
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
        openFirewallSettings: { [weak self] in self?.openSettings(.firewall) },
        watch: { [weak self] event in self?.openWatch(for: event) },
        showSpawn: { [weak self] pid, start in self?.showSpawn(pid: pid, start: start) },
        openStory: { [weak self] story in self?.openStoryDetails(story) }
    )
    var askWindows: [NSWindow] = []
    /// Watch Closely windows, by session id.
    var watches: [String: (session: WatchSession, window: NSWindow)] = [:]
    /// Learns this Mac's normal behaviour in waves after the first launch (a fresh pattern store).
    lazy var baseline = BaselineLearner(store: signatures, classifier: classifier,
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
        if !AppPaths.isDemo { baseline.schedule() }               // first run: waves at 5, 15 and 60 minutes
        // Only draw events while the window or the HUD is actually on screen.
        NotificationCenter.default.addObserver(forName: NSWindow.didChangeOcclusionStateNotification,
                                               object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateUIVisibility() }
        }
        model.onTop = { [weak self] procs, read, write in self?.metrics.receiveTop(procs, diskRead: read, diskWrite: write) }
        model.onVitals = { [weak self] samples in self?.vitals.receive(samples) }
        model.onProcessList = { [weak self] list in
            self?.running.receive(list)
            self?.processRecorder.receive(list)             // about once a minute, for Running Now in Time Travel
            self?.sessions.learn(list)
        }
        claudeGuard.onRequest = { [weak self] request in
            self?.sessions.learn(hookAgentPid: request.agentPid, sessionID: request.session, cwd: request.cwd)
        }
        travel.onProcesses = { [weak self] snapshot, moment in self?.running.showRecorded(snapshot, at: moment) }
        running.historyDirectory = history.directory
        // Asked for only while the window is on screen.
        running.request = { [weak self] in
            guard let self, self.activityWindow?.isVisible == true,
                  self.activityWindow?.occlusionState.contains(.visible) == true else { return true }
            return self.model.requestProcesses()
        }
        metrics.heavyProvider = { [weak self] in self?.vitals.snapshot ?? [] }      // recorded for Time Travel
        model.onEvent = { [weak self] event in
            guard let self else { return }
            if event.kind == .exec { self.vitals.noteLaunch(event) }
            if event.kind == .net { self.firewall.observe(event, status: self.signatures.status(for: event)) }
        }
        model.intel = intel
        intel.seenDomains = { [weak self] in
            let since = Date().addingTimeInterval(-30 * 86400)
            return (self?.domains.records.values.filter { $0.lastSeen >= since } ?? []).map { ($0.domain, $0.programs) }
        }
        stories.onFired = { [weak self] story in
            self?.signatures.reopen(keys: story.steps.map(\.event.signatureKey), reason: "part of a story: \(story.title)")
        }
        intel.onHit = { [weak self] hit, event in
            guard let self else { return }
            // A program that contacted known malware infrastructure, or is a known malware file: everything it
            // was trusted to do goes back to you.
            if !hit.path.isEmpty {
                self.signatures.reopen(keys: self.signatures.safeKeys(program: hit.path),
                                       reason: "\(hit.process) \(hit.kind == .file ? "is known malware" : "contacted \(hit.indicator)") (\(hit.source))")
            }
            // A connection already carries the match into its story; a file (hashed later) and a past
            // contact found by the retro-check join or start one here.
            if hit.kind == .file, let event {
                _ = self.stories.ingest(event, decidedSafe: false, extra: [(.knownBad, hit.summary)])
            } else if hit.retro {
                var past = ActivityEvent(kind: .net, time: "", pid: 0, ppid: 0, name: hit.process.isEmpty ? "?" : hit.process,
                                         proc: hit.path, target: hit.indicator, extra: "TCP", parent: "", host: hit.indicator,
                                         hostSource: "dns")
                past.knownBad = hit.summary + " (contacted earlier)"
                _ = self.stories.ingest(past, decidedSafe: false)
            }
        }
        if !AppPaths.isDemo {
            intel.start()
            setUpClaudeGuard()
        }
        setUpFirewall()
        // A pattern an open story points at is kept while the story is open, even a one-off.
        signatures.inUse = { [weak self] in
            Set((self?.stories.stories ?? []).filter { !$0.dismissed }.flatMap(\.steps).map(\.event.signatureKey))
        }
        vitals.onHeavyUntrusted = { [weak self] launch, tracked in
            guard let self else { return }
            let cpu = Int(self.vitals.cpuAverage(tracked, at: Date()))
            let note = "\(launch.name) keeps running heavy (\(cpu)% CPU, \(ProcessVitals.memory(tracked.memNow))) "
                + "and isn't trusted code: the cryptominer pattern"
            _ = self.stories.ingest(launch.event, decidedSafe: false, extra: [(.heavyUntrusted, note)])
        }
        metrics.start()                   // CPU, memory, network every 5 s (recorded for Time Travel)
        if !AppPaths.isDemo {
            processRecorder.enabled = { [weak self] in self?.history.enabled == true }
            processRecorder.request = { [weak self] in _ = self?.model.requestProcesses() }
            processRecorder.start()           // the process list once a minute (Running Now in Time Travel)
        }
        if !AppPaths.isDemo {
            updates.schedule()            // daily, if allowed in Settings ▸ General
            model.connect()
        }
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

        if AppPaths.isDemo { runDemo(); return }
        // Start the bundled collector unless one (e.g. run-agent.sh) is already serving.
        if collector.startAtLaunch {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                guard let self, !self.model.connected else { return }
                self.startCollector()
            }
        }
    }

}
