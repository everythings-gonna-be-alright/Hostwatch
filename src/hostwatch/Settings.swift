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
    // Actions that need the app (alerts, panels, window frames).
    let toggleCollector: () -> Void
    let resetOverlayFrame: () -> Void
    let customHistorySize: () -> Void
    let changeHistoryLocation: () -> Void
    let clearHistory: () -> Void
}

/// Small view state for the panes (SwiftUI's @State needs a macro plugin the CLT lacks).
@MainActor
final class SettingsState: ObservableObject {
    @Published var fullDiskAccess = Collector.appearsToHaveFullDiskAccess
    @Published var trustHomebrew = SigningCache.shared.trustHomebrew
    @Published var copied = false
    @Published var refresh = 0
}

enum SettingsPane: Int, CaseIterable {
    case general, hud, detection, ai, exclusions, history

    var title: String {
        switch self {
        case .general: return "General"
        case .hud: return "HUD"
        case .detection: return "Detection"
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
            case .general: view = AnyView(GeneralPane(collector: c.collector, ui: state, toggleCollector: c.toggleCollector))
            case .hud: view = AnyView(HUDPane(model: c.model, reset: c.resetOverlayFrame))
            case .detection: view = AnyView(DetectionPane(hold: c.hold, domains: c.domains, stories: c.stories,
                                                          signatures: c.signatures, ui: state))
            case .ai: view = AnyView(AIPane(classifier: c.classifier, ui: state))
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

    func show(_ pane: SettingsPane? = nil) {
        state.fullDiskAccess = Collector.appearsToHaveFullDiskAccess
        state.copied = false
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

/// Shared look: a grouped form, sized to its content.
private struct Pane<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        Form { content }
            .formStyle(.grouped)
            .scrollDisabled(true)
    }
}

private struct Footnote: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

private struct GeneralPane: View {
    @ObservedObject var collector: Collector
    @ObservedObject var ui: SettingsState
    let toggleCollector: () -> Void
    private var fullDiskAccess: Bool { ui.fullDiskAccess }

    var body: some View {
        Pane {
            Section("Collector") {
                LabeledContent("Status") {
                    HStack {
                        Text(collector.statusText).foregroundStyle(.secondary)
                        Button(collector.isRunning ? "Stop" : "Start…", action: toggleCollector)
                            .disabled(collector.state == .starting)
                    }
                }
                Toggle("Start collector when Hostwatch opens", isOn: $collector.startAtLaunch)
                LabeledContent("Log") { Button("Show Collector Log") { collector.openLog() } }
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
            } header: {
                Text("Permissions")
            } footer: {
                Footnote("The collector watches processes and files only when Hostwatch has Full Disk Access. "
                         + "After a rebuild, remove Hostwatch from the list and add it again.")
            }
        }
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
            } footer: {
                Footnote("Toggle from anywhere with ⌃⌥⌘H. Turn off click-through to move it by its header, "
                         + "resize it from the ◣ corner, double-click rows and right-click to exclude.")
            }
            Section("Appearance") {
                Picker("Background", selection: $model.overlayBackground) {
                    ForEach(OverlayBackground.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                LabeledContent("Tint") {
                    Slider(value: $model.overlayOpacity, in: 0.15...0.9)
                        .frame(width: 220)
                }
                .disabled(model.overlayBackground == .transparent)
                Picker("Text size", selection: $model.overlayScale) {
                    ForEach(HUDModel.scaleOptions, id: \.1) { Text($0.0).tag($0.1) }
                }
                LabeledContent("Size and position") { Button("Reset", action: reset) }
            }
        }
    }
}

private struct DetectionPane: View {
    @ObservedObject var hold: ProcessHold
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var stories: StoryEngine
    let signatures: SignatureStore
    @ObservedObject var ui: SettingsState

    var body: some View {
        let _ = ui.refresh
        Pane {
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
                Toggle("Trust Homebrew-installed tools", isOn: $ui.trustHomebrew)
                    .onChange(of: ui.trustHomebrew) { _, on in
                        SigningCache.shared.trustHomebrew = on
                        signatures.reassess()
                    }
            } header: {
                Text("Trust")
            } footer: {
                Footnote("Treats tools in Homebrew's Cellar (with an install receipt) like a trusted developer. "
                         + "/opt/homebrew is writable by your user, so a planted binary there would be trusted too.")
            }
            Section {
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
                Footnote("While learning, domains are recorded as usual instead of new. "
                         + "Ignored stories are chains you chose to never be alerted about again.")
            }
        }
    }
}

private struct AIPane: View {
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var ui: SettingsState

    var body: some View {
        let status = classifier.localStatus
        Pane {
            Section {
                Picker("Engine", selection: $classifier.engine) {
                    ForEach(AIEngine.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.radioGroup)
                LabeledContent("On-device model") {
                    Label(status.label, systemImage: status.isReady ? "checkmark.circle.fill" : "exclamationmark.circle")
                        .foregroundStyle(status.isReady ? .green : .orange)
                }
            } header: {
                Text("Classifying new patterns and Ask AI")
            } footer: {
                Footnote(classifier.engine.help + " High-risk patterns are never marked Safe on-device.")
            }
            Section {
                Text(AppDelegate.mcpCommand)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                LabeledContent("") {
                    Button(ui.copied ? "Copied" : "Copy Command") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(AppDelegate.mcpCommand, forType: .string)
                        ui.copied = true
                    }
                }
            } header: {
                Text("Use with Claude Code")
            } footer: {
                Footnote("Run this once to let Claude Code investigate recorded activity through Hostwatch's "
                         + "read-only MCP server. Secrets are masked; nothing can be changed through it.")
            }
        }
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
