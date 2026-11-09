import AppKit
import SwiftUI

/// Everything the Settings panes read or change.
@MainActor
struct SettingsContext {
    let model: HUDModel
    let collector: Collector
    let history: HistoryRecorder
    let hold: ProcessHold
    let domains: DomainRegistry
    let stories: StoryEngine
    let signatures: SignatureStore
    let classifier: PatternClassifier
    let editorDraft: EditorDraft
    let updates: UpdateChecker
    let baseline: BaselineLearner
    let intel: ThreatIntel
    let claudeGuard: ClaudeGuard
    let firewall: FirewallMonitor
    let openBaseline: () -> Void
    let showNetwork: () -> Void
    // Actions that need the app (alerts, panels, window frames).
    let toggleCollector: () -> Void
    let resetOverlayFrame: () -> Void
    let customHistorySize: () -> Void
    let changeHistoryLocation: () -> Void
    let clearHistory: () -> Void
    let reset: (ResetPlan) -> Void
}

/// Small view state for the panes (SwiftUI's @State needs a macro plugin the CLT lacks).
@MainActor
final class SettingsState: ObservableObject {
    @Published var fullDiskAccess = Collector.appearsToHaveFullDiskAccess
    @Published var copied = false
    @Published var mcpEnabled = MCPAccess.isEnabled()
    /// The registration command with a fresh token: shown once (only its hash is kept).
    @Published var mcpCommand: String?
    @Published var mcpError: String?
    @Published var refresh = 0
    @Published var showReset = false
    @Published var showGuardLog = false
    @Published var guardCopied = false
    @Published var heavyHighlight = UserDefaults.standard.object(forKey: "heavyHighlight") as? Bool ?? true {
        didSet { UserDefaults.standard.set(heavyHighlight, forKey: "heavyHighlight") }
    }
    @Published var heavyCPU: Double = { let v = UserDefaults.standard.double(forKey: "heavyCPUPercent"); return v > 0 ? v : 50 }() {
        didSet { UserDefaults.standard.set(heavyCPU, forKey: "heavyCPUPercent") }
    }
    @Published var heavyMemory: Double = { let v = UserDefaults.standard.double(forKey: "heavyMemoryGB"); return v > 0 ? v : 1 }() {
        didSet { UserDefaults.standard.set(heavyMemory, forKey: "heavyMemoryGB") }
    }
    @Published var resetPlan = ResetPlan()
    @Published var abuseKeyDraft = ""
    @Published var showKeySheet = false
    @Published var baselineAutoRules = UserDefaults.standard.object(forKey: "baselineAutoRules") as? Bool ?? true {
        didSet { UserDefaults.standard.set(baselineAutoRules, forKey: "baselineAutoRules") }
    }
}

enum SettingsPane: Int, CaseIterable {
    case general, hud, detection, firewall, ai, exclusions, history

    var title: String {
        switch self {
        case .general: return "General"
        case .hud: return "HUD"
        case .detection: return "Detection"
        case .firewall: return "Firewall"
        case .ai: return "AI"
        case .exclusions: return "Exclusions"
        case .history: return "History"
        }
    }

    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .hud: return "rectangle.inset.topright.filled"
        case .detection: return "shield.lefthalf.filled"
        case .firewall: return "network.badge.shield.half.filled"
        case .ai: return "sparkles"
        case .exclusions: return "eye.slash"
        case .history: return "clock.arrow.circlepath"
        }
    }
}

/// The Settings window (⌘,): toolbar tabs, like System Settings-era Mac apps.
@MainActor
final class SettingsWindowController: NSWindowController {
    private let tabs = SettingsTabs()
    private let state = SettingsState()

    init(context c: SettingsContext) {
        tabs.tabStyle = .toolbar
        for pane in SettingsPane.allCases {
            let view: AnyView
            switch pane {
            case .general: view = AnyView(GeneralPane(collector: c.collector, updates: c.updates, ui: state,
                                                      toggleCollector: c.toggleCollector, reset: c.reset))
            case .hud: view = AnyView(HUDPane(model: c.model, reset: c.resetOverlayFrame))
            case .detection: view = AnyView(DetectionPane(hold: c.hold, domains: c.domains, stories: c.stories,
                                                          signatures: c.signatures, baseline: c.baseline, intel: c.intel,
                                                          openBaseline: c.openBaseline, ui: state))
            case .firewall: view = AnyView(FirewallPane(firewall: c.firewall, signatures: c.signatures, showNetwork: c.showNetwork))
            case .ai: view = AnyView(AIPane(classifier: c.classifier, signatures: c.signatures, claudeGuard: c.claudeGuard, ui: state))
            case .exclusions: view = AnyView(ExclusionsPane(model: c.model, draft: c.editorDraft))
            case .history: view = AnyView(HistoryPane(history: c.history, custom: c.customHistorySize,
                                                      changeLocation: c.changeHistoryLocation, clear: c.clearHistory))
            }
            let host = NSHostingController(rootView: view.frame(width: 560).fixedSize(horizontal: false, vertical: true))
            host.sizingOptions = [.preferredContentSize]
            host.title = pane.title          // the window shows the selected tab's title
            let item = NSTabViewItem(viewController: host)
            item.label = pane.title
            item.image = NSImage(systemSymbolName: pane.symbol, accessibilityDescription: pane.title)
            tabs.addTabViewItem(item)
        }
        let window = NSWindow(contentViewController: tabs)
        window.title = SettingsPane.general.title
        window.styleMask = [.titled, .closable]
        window.toolbarStyle = .preference
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("HostwatchSettings")
        super.init(window: window)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    /// Settings ▸ AI with the Claude Code guard's log open.
    func showGuardLog() {
        show(.ai)
        state.showGuardLog = true
    }

    func show(_ pane: SettingsPane? = nil) {
        state.fullDiskAccess = Collector.appearsToHaveFullDiskAccess
        state.copied = false
        state.mcpEnabled = MCPAccess.isEnabled()
        if let pane { tabs.selectedTabViewItemIndex = pane.rawValue }
        if window?.isVisible != true { window?.center() }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}

/// Keeps the window title on the selected tab's name.
final class SettingsTabs: NSTabViewController {
    override func tabView(_ tabView: NSTabView, didSelect item: NSTabViewItem?) {
        super.tabView(tabView, didSelect: item)
        if let label = item?.label { view.window?.title = label }
    }
}

// MARK: - Panes

/// Shared look: a grouped form, sized to its content; a long one (`height`) scrolls at a fixed height instead
/// of growing past the screen.
private struct Pane<Content: View>: View {
    var height: CGFloat? = nil
    @ViewBuilder var content: Content
    var body: some View {
        if let height {
            Form { content }.formStyle(.grouped).frame(height: height)
        } else {
            Form { content }.formStyle(.grouped).scrollDisabled(true)
        }
    }
}

struct Footnote: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

private struct GeneralPane: View {
    @ObservedObject var collector: Collector
    @ObservedObject var updates: UpdateChecker
    @ObservedObject var ui: SettingsState
    let toggleCollector: () -> Void
    let reset: (ResetPlan) -> Void
    private var fullDiskAccess: Bool { ui.fullDiskAccess }
    @StateObject private var loginItem = LoginItem()

    var body: some View {
        Pane(height: 640) {        // long since the service and encryption rows: scrolls like Detection and AI
            Section {
                Toggle("Open Hostwatch at login", isOn: Binding(get: { loginItem.isOn }, set: { loginItem.set($0) }))
                if loginItem.needsApproval {
                    LabeledContent("Waiting for your approval") {
                        Button("Open Login Items…") { loginItem.openLoginItems() }
                    }
                }
                if let problem = loginItem.problem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.callout)
                }
            } header: {
                Text("Startup")
            } footer: {
                Footnote("Off by default. When on, Hostwatch is listed in System Settings ▸ General ▸ Login Items, "
                         + "where you can also remove it.")
            }
            Section {
                LabeledContent("Status") {
                    HStack {
                        Text(collector.statusText).foregroundStyle(.secondary)
                        if collector.usesDaemon, collector.daemon.needsApproval {
                            Button("Open Login Items…") { collector.daemon.openLoginItems() }
                        } else {
                            Button(collector.isRunning ? (collector.usesDaemon ? "Remove…" : "Stop") : "Start…", action: toggleCollector)
                                .disabled(collector.state == .starting && !collector.usesDaemon)
                        }
                    }
                }
                Toggle(collector.usesDaemon ? "Register the collector when Hostwatch opens" : "Start collector when Hostwatch opens",
                       isOn: $collector.startAtLaunch)
                LabeledContent("Log") { Button("Show Collector Log") { collector.openLog() } }
            } header: {
                Text("Collector")
            } footer: {
                if collector.usesDaemon {
                    Footnote("The collector runs as a background service: registered once with your password, approved once "
                             + "in Login Items, then started by macOS at boot. Remove… unregisters it (your password again).")
                }
            }
            Section {
                LabeledContent("Full Disk Access") {
                    HStack {
                        Label(fullDiskAccess ? "Granted" : "Not granted",
                              systemImage: fullDiskAccess ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(fullDiskAccess ? .green : .orange)
                        Button("Open Settings…") { Collector.openFullDiskAccessSettings() }
                    }
                }
                LabeledContent("Data on disk") {
                    let v = Vault.shared
                    Label(v.isSealed ? "Encrypted, key in the \(v.backend.rawValue)" : "Not encrypted",
                          systemImage: v.isSealed ? "lock.fill" : "lock.open")
                        .foregroundStyle(v.isSealed ? .green : .orange)
                        .help(v.problem ?? "Patterns, stories, history and logs are sealed with a key only Hostwatch's own code can use.")
                }
            } header: {
                Text("Permissions")
            } footer: {
                Footnote("The collector watches processes and files only when Hostwatch has Full Disk Access. "
                         + "After a rebuild, remove Hostwatch from the list and add it again.")
            }
            Section {
                LabeledContent("Version \(updates.currentVersion)") {
                    HStack {
                        Text(updates.statusText).foregroundStyle(.secondary).lineLimit(1)
                        if let release = updates.available {
                            Button("Open Release Page") { NSWorkspace.shared.open(release.url) }
                        } else {
                            Button("Check Now") { updates.checkAndReport() }.disabled(updates.checking)
                        }
                    }
                }
                Toggle("Check for updates automatically", isOn: $updates.automatic)
            } header: {
                Text("Updates")
            } footer: {
                Footnote("Once a day Hostwatch asks GitHub (api.github.com) for the latest release; nothing "
                         + "about this Mac is sent, and nothing is downloaded or installed by itself.")
            }
            Section {
                LabeledContent("Start over") {
                    Button("Reset Hostwatch…") { ui.resetPlan = ResetPlan(); ui.showReset = true }
                }
            } header: {
                Text("Reset")
            } footer: {
                Footnote("Erase patterns, the baseline, settings or history, then restart as on the first launch.")
            }
        }
        .onAppear { loginItem.refresh() }             // changed in System Settings meanwhile
        .sheet(isPresented: $ui.showReset) {
            ResetSheet(plan: $ui.resetPlan,
                       cancel: { ui.showReset = false },
                       reset: { ui.showReset = false; reset(ui.resetPlan) })
        }
    }
}

/// Choose what to erase. The default erases everything, like a fresh install.
private struct ResetSheet: View {
    @Binding var plan: ResetPlan
    let cancel: () -> Void
    let reset: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "arrow.counterclockwise.circle.fill")
                    .font(.system(size: 34)).foregroundStyle(.red)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Reset Hostwatch?").font(.headline)
                    Text("Hostwatch stops the collector, erases what you choose and opens again, as on the first "
                         + "launch. This can't be undone.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            VStack(alignment: .leading, spacing: 10) {
                option($plan.data, "Patterns, decisions and baseline",
                       "Patterns and what you marked, stories, domains, your rules, baseline rules and review, "
                       + "signing facts, the MCP token.")
                option($plan.settings, "Settings",
                       "HUD, window, detection, AI, exclusions and history options.")
                option($plan.history, "Event history and logs",
                       "Recorded events (Time Travel), resource history and the collector log.")
            }
            Text("Full Disk Access stays granted; remove it in System Settings if you want.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                Button("Reset and Restart", role: .destructive, action: reset)
                    .keyboardShortcut(.defaultAction)
                    .disabled(plan.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func option(_ on: Binding<Bool>, _ title: String, _ detail: String) -> some View {
        Toggle(isOn: on) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.checkbox)
    }
}

private struct HUDPane: View {
    @ObservedObject var model: HUDModel
    let reset: () -> Void

    var body: some View {
        Pane {
            Section {
                Toggle("Show HUD", isOn: $model.overlayEnabled)
                Toggle("Click-through", isOn: $model.overlayClickThrough)
                Toggle("Show CPU, memory, network and disk", isOn: $model.overlayShowResources)
            } footer: {
                Footnote("Toggle from anywhere with ⌃⌥⌘H. Turn off click-through to move it by its header, "
                         + "resize it from the left edge (width), the bottom edge (height) or the ◣ corner (both), "
                         + "double-click rows and right-click to exclude.")
            }
            Section {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Background")
                    HStack(spacing: 14) {
                        ForEach(OverlayBackground.allCases, id: \.self) { style in
                            HUDBackgroundTile(style: style, tint: model.overlayOpacity,
                                              selected: model.overlayBackground == style)
                                .onTapGesture { withAnimation(.snappy) { model.overlayBackground = style } }
                        }
                    }
                    Text(model.overlayBackground.detail).font(.callout).foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
                LabeledContent("Contrast") {
                    Slider(value: $model.overlayOpacity, in: 0...1) {
                        EmptyView()
                    } minimumValueLabel: {
                        Text("Lighter").font(.caption).foregroundStyle(.secondary)
                    } maximumValueLabel: {
                        Text("Darker").font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(width: 260)
                }
                .help("How dark the background is under the HUD's white text")
                if model.overlayOpacity < 0.25 {
                    Label("Low contrast: white text can be hard to read over bright windows.", systemImage: "eye")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Picker("Text size", selection: $model.overlayScale) {
                    ForEach(HUDModel.scaleOptions, id: \.1) { Text($0.0).tag($0.1) }
                }
                LabeledContent("Size and position") { Button("Reset", action: reset) }
            } header: {
                Text("Appearance")
            } footer: {
                Footnote("Contrast darkens the background under the white text. With Reduce Transparency on "
                         + "(System Settings ▸ Accessibility ▸ Display), glass shows as Solid.")
            }
        }
    }
}

private struct DetectionPane: View {
    @ObservedObject var hold: ProcessHold
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var stories: StoryEngine
    let signatures: SignatureStore
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var intel: ThreatIntel
    let openBaseline: () -> Void
    @ObservedObject var ui: SettingsState

    var body: some View {
        let _ = ui.refresh
        Pane(height: 640) {
            Section {
                Toggle("Hold suspicious processes", isOn: $hold.enabled)
                Picker("If you don't answer in \(Int(hold.timeout)) s", selection: $hold.timeoutAction) {
                    ForEach(HoldTimeoutAction.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .disabled(!hold.enabled)
            } header: {
                Text("Hold")
            } footer: {
                Footnote("Freezes your own process the moment it pipes a download into a shell, reads saved "
                         + "passwords, installs a login item or removes the download quarantine, and asks you. "
                         + "Best effort: very quick commands can finish first. If Hostwatch quits, held "
                         + "processes continue.")
            }
            Section {
                Toggle("Trust new apps from developers you trust", isOn: $ui.baselineAutoRules)
            } header: {
                Text("Baseline")
            } footer: {
                Footnote("A new app signed by a developer you already trust (valid, not quarantined, not in Downloads) "
                         + "gets its own baseline rule by itself. Each rule trusts only the kinds of behaviour the app "
                         + "showed in its first week; anything new for it comes to Needs You. macOS's own tools are always "
                         + "trusted. A rule you delete isn't made again by itself.")
            }
            Section {
                Toggle("Highlight heavy processes in Events", isOn: $ui.heavyHighlight)
                Picker("CPU (average over 30 s)", selection: $ui.heavyCPU) {
                    Text("25% of a core").tag(25.0); Text("50% of a core").tag(50.0)
                    Text("1 full core").tag(100.0); Text("2 cores").tag(200.0)
                }
                .disabled(!ui.heavyHighlight)
                Picker("Memory", selection: $ui.heavyMemory) {
                    Text("500 MB").tag(0.5); Text("1 GB").tag(1.0); Text("2 GB").tag(2.0); Text("4 GB").tag(4.0)
                }
                .disabled(!ui.heavyHighlight)
            } header: {
                Text("Heavy processes")
            } footer: {
                Footnote("A process Hostwatch saw start that keeps using this much gets a 🔥 badge on its launch in "
                         + "Events, the HUD and a strip above the list. Unsigned or downloaded ones also count toward a story "
                         + "(the cryptominer pattern).")
            }
            Section {
                LabeledContent("Patterns") {
                    HStack {
                        Text(baseline.statusText).foregroundStyle(.secondary).lineLimit(1)
                        Button("Show in Rules", action: openBaseline)
                        Button(baseline.running ? "Updating…" : "Update Baseline") { Task { await baseline.buildNow() } }
                            .disabled(baseline.running)
                    }
                }
                LabeledContent("Domain learning") {
                    HStack {
                        Text(domains.isLearning
                             ? "Learning until \(domains.learningUntil.formatted(date: .omitted, time: .shortened))"
                             : "Finished").foregroundStyle(.secondary)
                        if domains.isLearning { Button("End Now") { domains.endLearning(); ui.refresh += 1 } }
                    }
                }
                LabeledContent("Ignored stories") {
                    HStack {
                        Text("\(stories.ignoredCount)").foregroundStyle(.secondary).monospacedDigit()
                        Button("Reset") { stories.clearIgnored(); ui.refresh += 1 }
                            .disabled(stories.ignoredCount == 0)
                    }
                }
            } header: {
                Text("Baselines")
            } footer: {
                Footnote("Patterns: three waves (5, 15, 60 min) after the first launch trust ordinary signed activity "
                         + "and leave anything unsigned, downloaded or high-risk for you. Domains: while learning, "
                         + "what trusted software reaches becomes usual instead of new. "
                         + "Ignored stories are chains you chose to never be alerted about again.")
            }
            ThreatSections(intel: intel, ui: ui)
        }
    }
}

private struct AIPane: View {
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var signatures: SignatureStore
    let claudeGuard: ClaudeGuard
    @ObservedObject var ui: SettingsState
    @ObservedObject var usage = ClaudeUsage.shared

    var body: some View {
        let status = classifier.localStatus
        Pane(height: 640) {
            Section {
                Picker("Engine", selection: $classifier.engine) {
                    ForEach(AIEngine.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.radioGroup)
                LabeledContent("Local model") {
                    Label(status.label, systemImage: status.isReady ? "checkmark.circle.fill" : "exclamationmark.circle")
                        .foregroundStyle(status.isReady ? .green : .orange)
                }
                ClaudeUsageRow(usage: usage)
            } header: {
                Text("Classifying new patterns and Ask AI")
            } footer: {
                Footnote(classifier.engine.help)
            }
            AIModelSettings()
            Section {
                Toggle("Suggest for new patterns automatically", isOn: $classifier.autoClassify)
                Toggle("Accept AI suggestions without asking", isOn: Binding(
                    get: { signatures.autoAcceptAI },
                    set: { signatures.autoAcceptAI = $0; ui.refresh += 1 }))
            } header: {
                Text("Suggestions")
            } footer: {
                Footnote("AI suggests a status for new patterns; you accept it in Rules ▸ Needs You. Every 90 s it "
                         + "looks at up to 40 new patterns (seen for over a minute). Accepting by itself skips "
                         + "high-risk patterns, and no AI ever trusts a high-risk pattern or an interpreter or shell "
                         + "(python, bash, node…): those stay your decision.")
            }
            ClaudeGuardSection(claudeGuard: claudeGuard, ui: ui)
            Section {
                Toggle("Allow Claude Code to read Hostwatch data (MCP)", isOn: Binding(
                    get: { ui.mcpEnabled },
                    set: { on in on ? newToken() : disableMCP() }))
                if let command = ui.mcpCommand {
                    Text(command)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    LabeledContent("Run it once in Terminal") {
                        Button(ui.copied ? "Copied" : "Copy Command") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(command, forType: .string)
                            ui.copied = true
                        }
                        .buttonStyle(.borderedProminent)
                    }
                } else if ui.mcpEnabled {
                    LabeledContent("Token") {
                        HStack {
                            Text("Issued · shown only once").foregroundStyle(.secondary)
                            Button("New Token…") { newToken() }
                                .help("Creates a new token and command; Claude Code registrations with the old one stop working")
                        }
                    }
                }
                if let error = ui.mcpError { Text(error).foregroundStyle(.red) }
                let sessions = MCPAccess.recentSessions()
                if !sessions.isEmpty {
                    LabeledContent("Recent sessions") {
                        VStack(alignment: .trailing, spacing: 2) {
                            ForEach(Array(sessions.enumerated()), id: \.offset) { _, s in
                                Text("\(s.0.formatted(date: .abbreviated, time: .shortened)) · "
                                     + "\(s.1 == .allowed ? "allowed" : "refused (\(s.1.rawValue))") · "
                                     + (s.2 as NSString).lastPathComponent)
                                    .foregroundStyle(s.1 == .allowed ? Color.secondary : Color.orange)
                            }
                        }
                        .font(.system(size: 11).monospacedDigit())
                    }
                }
            } header: {
                Text("Use with Claude Code")
            } footer: {
                Footnote("Read-only access to recorded activity for Claude Code. Off until you allow it; then "
                         + "Claude Code must present the token from this command. Hostwatch keeps only the "
                         + "token's hash, so copy the command now. New Token or turning access off cuts off "
                         + "every earlier registration. Secrets are masked; nothing can be changed through it.")
            }
        }
        .sheet(isPresented: $ui.showGuardLog) {
            ClaudeGuardLogView(claudeGuard: claudeGuard) { ui.showGuardLog = false }
        }
    }
}

/// All-time Claude tokens and cost, one line; per feature in the tooltip.
private struct ClaudeUsageRow: View {
    @ObservedObject var usage: ClaudeUsage

    var body: some View {
        let all = usage.totals.all
        LabeledContent {
            HStack(spacing: 8) {
                if all.runs == 0 {
                    Text("None yet").foregroundStyle(.secondary)
                } else {
                    Text("\(ClaudeUsage.short(all.tokens)) tokens · \(ClaudeUsage.dollars(all.cost))").monospacedDigit()
                    Button("Reset") { usage.reset() }
                        .controlSize(.small)
                        .help("Start counting from zero")
                }
            }
        } label: {
            Text("Claude usage")
            if all.runs > 0 {
                Text("\(all.runs) \(all.runs == 1 ? "run" : "runs") since \(usage.totals.since.formatted(date: .abbreviated, time: .omitted))")
            }
        }
        .help(detail)
    }

    private var detail: String {
        let all = usage.totals.all
        guard all.runs > 0 else { return "Tokens Hostwatch sends to and gets from Claude, over all runs." }
        var lines = ClaudeUsage.Feature.allCases.compactMap { f -> String? in
            let t = usage.tally(f)
            return t.runs == 0 ? nil
                : "\(f.title): \(ClaudeUsage.short(t.tokens)) tokens, \(ClaudeUsage.dollars(t.cost)), \(t.runs) runs"
        }
        lines.append("In \(ClaudeUsage.short(all.input)) (\(ClaudeUsage.short(all.cached)) cached) · out \(ClaudeUsage.short(all.output))")
        return lines.joined(separator: "\n")
    }
}

extension AIPane {
    fileprivate func newToken() {
        do {
            let token = try MCPAccess.issueToken()
            ui.mcpCommand = MCPAccess.command(token: token)
            ui.mcpEnabled = true
            ui.mcpError = nil
            ui.copied = false
        } catch {
            ui.mcpError = "Couldn't create a token: \(error.localizedDescription)"
        }
    }

    fileprivate func disableMCP() {
        MCPAccess.disable()
        ui.mcpEnabled = false
        ui.mcpCommand = nil
    }
}

private struct ExclusionsPane: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var draft: EditorDraft

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(exclusionHelp)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $draft.text)
                .font(.system(size: 12, design: .monospaced))
                .autocorrectionDisabled()
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.08)))
                .frame(height: 300)
            HStack {
                Button("Restore Defaults") { draft.text = defaultExclusions }
                Spacer()
                Button("Revert") { draft.text = model.exclusionText }
                    .disabled(draft.text == model.exclusionText)
                Button("Save") { model.exclusionText = draft.text }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                    .disabled(draft.text == model.exclusionText)
            }
        }
        .padding(20)
        .onAppear { if draft.text.isEmpty { draft.text = model.exclusionText } }
    }
}

private struct HistoryPane: View {
    @ObservedObject var history: HistoryRecorder
    let custom: () -> Void
    let changeLocation: () -> Void
    let clear: () -> Void

    var body: some View {
        Pane {
            Section {
                Toggle("Record activity history", isOn: $history.enabled)
                Toggle("Apply exclusions to history", isOn: $history.applyExclusions)
                Picker("Maximum size", selection: Binding(
                    get: { history.maxBytes },
                    set: { if $0 < 0 { custom() } else { history.maxBytes = $0 } })) {
                    ForEach(HistoryRecorder.sizePresets, id: \.self) { Text(HistoryRecorder.format($0)).tag($0) }
                    if !HistoryRecorder.sizePresets.contains(history.maxBytes) {
                        Text(HistoryRecorder.format(history.maxBytes)).tag(history.maxBytes)
                    }
                    Divider()
                    Text("Custom…").tag(Int64(-1))
                }
            } footer: {
                Footnote("Exclusions off: record everything the collector sees. Oldest files are removed past the "
                         + "maximum size. " + history.statusText)
            }
            Section("Location") {
                Text(history.directory.path)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .truncationMode(.middle)
                    .lineLimit(1)
                HStack {
                    Button("Change…", action: changeLocation)
                    Button("Show in Finder") { history.revealInFinder() }
                    Spacer()
                    Button("Clear History…", role: .destructive, action: clear)
                }
            }
        }
    }
}

/// Threat lists (downloaded daily, matched on this Mac) and the exploited-vulnerabilities check: sections
/// of Settings ▸ Detection.
private struct ThreatSections: View {
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var ui: SettingsState

    var body: some View {
        let _ = intel.revision
        Group {
            Section {
                Toggle("Check against known threats", isOn: $intel.enabled)
                ForEach([ThreatIntel.Feed.hagezi, .feodo]) { feed in feedRow(feed) }
                keyedListsRow
                LabeledContent("Lists") {
                    HStack(spacing: 8) {
                        Text(updatedText).foregroundStyle(.secondary)
                        if intel.updating { ProgressView().controlSize(.small) }
                        Button("Update Now") { Task { await intel.update() } }.disabled(intel.updating)
                    }
                }
            } header: {
                Text("Known threats")
            } footer: {
                Footnote("Lists are downloaded once a day and every connection's domain and IP, and the SHA-256 of new "
                         + "unsigned or downloaded programs (with the key), are checked on this Mac. Nothing about your Mac "
                         + "is sent. A match is a Dangerous story, a red KNOWN BAD tag and risk 100 for the domain.")
            }
            Section {
                Toggle("Watch for exploited macOS vulnerabilities", isOn: $intel.vulnerabilitiesEnabled)
                feedRow(.kev)
                LabeledContent("This Mac") {
                    Text(intel.pendingUpdate.map { "\(intel.osVersion) · \($0) is waiting" } ?? intel.osVersion)
                        .foregroundStyle(.secondary).lineLimit(1)
                }
            } header: {
                Text("macOS vulnerabilities")
            } footer: {
                Footnote("Apple flaws that CISA lists as exploited in the wild, compared with your last macOS update and "
                         + "any update waiting in Software Update. Shown in Overview.")
            }
        }
    }

    /// ThreatFox and MalwareBazaar share the one abuse.ch key: one row, with Add Key… (a sheet, like
    /// System Settings' "Set Password…") or, once added, their status and a menu.
    private var keyedListsRow: some View {
        let states = [ThreatIntel.Feed.threatfox, .bazaar].compactMap { intel.states[$0.rawValue] }
        let error = states.compactMap(\.error).first
        let updated = states.compactMap(\.updated).max()
        let count = states.reduce(0) { $0 + $1.count }
        return LabeledContent {
            HStack(spacing: 8) {
                if intel.apiKey == nil {
                    Button("Add Key…") { ui.showKeySheet = true }
                } else {
                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).lineLimit(1)
                    } else if let updated {
                        Text("\(count.formatted()) entries · \(StoryEngine.ago(updated))").foregroundStyle(.secondary)
                    } else {
                        Text("not downloaded yet").foregroundStyle(.secondary)
                    }
                    Menu {
                        Button("Replace Key…") { ui.showKeySheet = true }
                        Button("Remove Key", role: .destructive) { intel.apiKey = nil }
                    } label: { Image(systemName: "ellipsis.circle") }
                        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                        .help("abuse.ch key")
                }
            }
            .font(.callout)
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text("ThreatFox and MalwareBazaar")
                Text(intel.apiKey == nil ? "Malware families, C2 servers and file hashes · needs a free abuse.ch key"
                     : "Malware families, C2 servers and file hashes · abuse.ch key in the Keychain")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .sheet(isPresented: $ui.showKeySheet) { AbuseKeySheet(intel: intel, ui: ui) }
    }

    private var updatedText: String {
        let dates = ThreatIntel.Feed.allCases.compactMap { intel.states[$0.rawValue]?.updated }
        return intel.updating ? "Updating…" : dates.max().map { "Updated \(StoryEngine.ago($0))" } ?? "Not downloaded yet"
    }

    private func feedRow(_ feed: ThreatIntel.Feed) -> some View {
        let state = intel.states[feed.rawValue]
        let missingKey = feed.needsKey && intel.apiKey == nil
        return LabeledContent {
            Group {
                if missingKey {
                    Text("needs the free abuse.ch key").foregroundStyle(.secondary)
                } else if let error = state?.error {
                    Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).lineLimit(1)
                } else if let updated = state?.updated {
                    Text("\((state?.count ?? 0).formatted()) \(feed == .kev ? "Apple flaws" : "entries") · \(StoryEngine.ago(updated))")
                        .foregroundStyle(.secondary)
                } else {
                    Text("not downloaded yet").foregroundStyle(.secondary)
                }
            }
            .font(.callout)
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text(feed.title)
                Text(feed.detail).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// "Add Key…": the abuse.ch key in a small sheet (Return saves, Esc cancels).
private struct AbuseKeySheet: View {
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var ui: SettingsState

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(intel.apiKey == nil ? "Add abuse.ch Key" : "Replace abuse.ch Key").font(.headline)
            Text("A free key adds ThreatFox and MalwareBazaar: malware families, C2 servers and file hashes. It's kept "
                 + "in your Keychain and only sent to abuse.ch to download the lists.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            SecureField("Key", text: $ui.abuseKeyDraft, prompt: Text("Paste your key"))
                .textFieldStyle(.roundedBorder)
                .labelsHidden()
                .onSubmit(save)
            HStack {
                Link("Get a free key", destination: URL(string: "https://auth.abuse.ch/")!)
                Spacer()
                Button("Cancel", role: .cancel) { close() }.keyboardShortcut(.cancelAction)
                Button("Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(ui.abuseKeyDraft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func save() {
        let key = ui.abuseKeyDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return }
        intel.apiKey = key
        close()
        Task { await intel.update() }
    }

    private func close() {
        ui.abuseKeyDraft = ""
        ui.showKeySheet = false
    }
}
