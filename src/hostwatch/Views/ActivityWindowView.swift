import AppKit
import SwiftUI

// MARK: - Full-screen activity window

/// The one "Show" filter, identical on the Events and Patterns tabs: a scope bar (like Finder's search or
/// Mail's filters) with every choice visible and its count, one selected. Narrow windows drop the icons;
/// the narrowest falls back to a pop-up menu. View ▸ Show has the same choices.
struct ShowFilterPicker: View {
    @Binding var filter: SignatureFilter
    /// How many rows each choice would show in this tab (events on Events, patterns on Patterns).
    let counts: [SignatureFilter: Int]
    /// In a very narrow toolbar, a popup menu instead of the buttons (never on Patterns: one click, like Events).
    var allowsMenu = true

    var body: some View {
        ViewThatFits(in: .horizontal) {
            bar(counts, icons: true)
            bar(counts, icons: false)
            if allowsMenu {
                Picker("Show", selection: $filter) {
                    ForEach(SignatureFilter.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .labelsHidden()                                   // the bar's own "Show" names it already
                .fixedSize()
            }
        }
        .help("Show: filter by how patterns are decided (Events, Patterns and the HUD)")
    }

    private func bar(_ counts: [SignatureFilter: Int], icons: Bool) -> some View {
        ShowButtons(selection: $filter, items: SignatureFilter.allCases.map {
            .init(value: $0, title: $0.short, symbol: $0.symbol, help: $0.explanation, count: counts[$0])
        }, icons: icons)
    }
}

/// The Events tab's Show buttons: a capsule per choice with its icon, a short name and how many it shows. Shared, so
/// every Show row (Events, Patterns, the network map) looks and works the same.
struct ShowButtons<Value: Hashable>: View {
    struct Item {
        let value: Value
        let title: String
        let symbol: String
        var help = ""
        var count: Int? = nil
    }

    @Binding var selection: Value
    let items: [Item]
    var icons = true

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                let selected = selection == item.value
                Button { selection = item.value } label: {
                    HStack(spacing: 5) {
                        if icons {
                            Image(systemName: item.symbol)
                                .symbolVariant(selected ? .fill : .none)
                                .font(.system(size: 11, weight: .medium))
                        }
                        Text(item.title).font(.system(size: 12, weight: selected ? .semibold : .regular))
                        if let n = item.count {
                            Text(n.formatted())
                                .font(.system(size: 11).monospacedDigit())
                                .foregroundStyle(selected ? Color.accentColor.opacity(0.85) : Color.secondary)
                        }
                    }
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .foregroundStyle(selected ? Color.accentColor : Color.primary.opacity(0.8))
                    .background(Capsule().fill(selected ? Color.accentColor.opacity(0.16) : Color.primary.opacity(0.05)))
                    .overlay(Capsule().strokeBorder(selected ? Color.accentColor.opacity(0.35) : Color.clear, lineWidth: 0.5))
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .help(item.help)
                .accessibilityLabel("\(item.title)\(item.count.map { ", \($0)" } ?? "")")
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .fixedSize()
    }
}

struct ActivityWindowView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var stories: StoryEngine
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var networkState: NetworkViewState
    /// Addresses that tried to connect since you last looked: the Network tab's badge.
    @ObservedObject var incoming: IncomingBadge
    @ObservedObject var firewall: FirewallMonitor
    let rulesTab: RulesTabState
    @ObservedObject var vitals: ProcessVitals
    @ObservedObject var heavyStrip: HeavyStripState
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var sheets: WindowSheetState
    @ObservedObject var rules: RuleBook
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var collector: Collector
    /// The collector or the network filter stopped by itself: the same alert as the notification and the red dot.
    @ObservedObject var alerts: CriticalAlerts
    @ObservedObject var history: HistoryRecorder
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var travel: TimeTravel
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var running: RunningProcesses
    let actions: HUDActions
    /// Protection ▸ Packages (ADR 0024).
    var packages: PackageGuard? = nil

    var traveling: Bool { travel.active && model.windowTab == 0 }
    /// Time Travel on the Network tab: the map follows the playhead.
    var mapTraveling: Bool { travel.active && model.windowTab == 3 }

    /// The hours around the playhead, as the map counts them: from the hour the window starts to the playhead's.
    static func mapWindow(_ travel: TimeTravel) -> DateInterval {
        let end = MapTime.date(MapTime.hour(travel.playhead) + 1)
        let start = MapTime.date(MapTime.hour(travel.playhead.addingTimeInterval(-travel.span)))
        return DateInterval(start: start, end: end)
    }
    /// Time Travel rows, derived only when the events or a filter change (not on every playhead or hover update).
    @StateObject private var travelRows = TravelRowsCache()
    /// The live list's rows, remade only when the list or a filter changed (not on every redraw: 5,000 status
    /// lookups per redraw made the Events tab open late).
    @StateObject private var liveRows = TravelRowsCache()
    /// The Patterns tab's rows, kept across tab switches and built ahead, in the background.
    @StateObject private var patternList = PatternListModel()
    /// Sessions replayed from the Time Travel window's events.
    @StateObject private var travelSessions = ReplayedSessions()
    @StateObject private var visited = VisitedTabs()
    private var visitedTabs: Set<Int> {
        get { visited.tabs }
        nonmutating set { visited.tabs = newValue }
    }
    /// Events ▸ Running Now instead of the event list.
    /// In Time Travel it shows what was running at the playhead.
    private var runningNow: Bool { running.showing && model.windowTab == 0 }

    var body: some View {
        VStack(spacing: 0) {
            // Off by your choice (Start), or stopped behind your back while the service still reads as on (the alert).
            let collectorOff = (!collector.isRunning || alerts.active.contains(.collectorDown)) && !model.connected
            let filterStopped = alerts.active.contains(.filterStopped) && firewall.fallback == nil
            VStack(spacing: 0) {
                if collectorOff { collectorBanner }
                if filterStopped { filterBanner }
            }
            .animation(.snappy, value: collectorOff)
            .animation(.snappy, value: filterStopped)
            VulnerabilityBanner(intel: intel, sheets: sheets)
            FirewallFallbackBanner(firewall: firewall, openSettings: actions.openFirewallSettings)
            // A search left in the field filters quietly: say so where you look, with the way out.
            if searchFiltering && !showsHistoryScope { SearchActiveBar(text: searchText); Divider() }
            // Every tab visited stays alive and *attached*: the tabs sit side by side in a strip as wide as all of
            // them, slid so the current one shows. Hiding a tab (opacity, zIndex changes) made SwiftUI detach or
            // re-add its AppKit table, and re-attaching a table costs ~2 ms per cell view (a sample showed 0.6 s of
            // every switch in NSTableView _setWindow:). A slide is only a position change.
            GeometryReader { geo in
                let tabs = Array(visitedTabs).sorted()
                let index = CGFloat(tabs.firstIndex(of: model.windowTab) ?? 0)
                HStack(spacing: 0) {
                    ForEach(tabs, id: \.self) { tab in
                        HiddenTabGate(shown: model.windowTab == tab) { tabContent(tab) }
                            .equatable()
                            .frame(width: geo.size.width, height: geo.size.height)
                            .allowsHitTesting(model.windowTab == tab)
                            .accessibilityHidden(model.windowTab != tab)
                    }
                }
                .frame(width: geo.size.width, height: geo.size.height, alignment: .leading)
                .offset(x: -index * geo.size.width)
            }
            .clipped()
            .onAppear { visitedTabs.insert(model.windowTab) }
            // The other tabs are built ahead, one at a time once the window has settled, so a first visit is as quick as
            // any other (building one took 100 to 330 ms, which froze the first switch to it).
            .task {
                for tab in 0...4 {
                    try? await Task.sleep(for: .seconds(tab == 0 ? 2 : 0.8))
                    if !visitedTabs.contains(tab) { visitedTabs.insert(tab) }
                }
            }
            .onChange(of: model.windowTab) { _, tab in visitedTabs.insert(tab) }
        }
        .frame(minWidth: 1240, minHeight: 720)     // the toolbar (window controls, five tabs, title, buttons, search) fits whole from here; every page adapts above it
        // The Patterns rows are ready before the tab is opened.
        .onAppear {
            patternList.sessionGroups = { [weak sessions = model.sessions] in
                (sessions?.sessions ?? []).map { .init(id: $0.id, name: $0.topic, keys: $0.keys, live: $0.isLive, agent: $0.agent, facts: $0.groupFacts) }
            }
            if !patternList.built { patternList.build(signatures, filter: model.signatureFilter) }
        }
        .sheet(isPresented: $sheets.showVulns) { VulnerabilityList(intel: intel, close: { sheets.showVulns = false }) }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if traveling || mapTraveling { TimelineBar(travel: travel).transition(.move(edge: .bottom).combined(with: .opacity)) }
        }
        .animation(.smooth(duration: 0.25), value: traveling || mapTraveling)
        // Time Travel searches all recorded history (scope All History), in the background.
        .onChange(of: model.searchText) { _, text in if traveling && !runningNow { travel.search(text) } }
        .onChange(of: traveling) { _, on in
            // A story's filter belongs to that visit to Time Travel.
            if !on, model.onlyStory != nil { model.onlyPids = nil; model.onlyStory = nil }
            if on && !runningNow { travel.search(model.searchText) }
            syncRunningMoment()
        }
        .onChange(of: runningNow) { _, on in
            if traveling && !on { travel.search(model.searchText) }
            syncRunningMoment()
        }
        // Native window toolbar (bridged by NSHostingController): Liquid Glass controls + search.
        .toolbar { toolbarContent }
        .navigationTitle("Hostwatch")
        .navigationSubtitle(subtitle)
    }

    /// One tab's content (built on first visit, then kept).
    @ViewBuilder private func tabContent(_ tab: Int) -> some View {
        switch tab {
            case 0:
                // The Events tab's own bars live in the tab, not above the strip: added and removed on every switch,
                // they changed the strip's height and made every visited tab (their tables too) lay out again.
                VStack(spacing: 8) {
                    VStack(spacing: 0) { eventsBars }
                    eventsBody
                }
                .padding(.horizontal, 12).padding(.top, 10)
                .background(PageBackdrop(accent: AreaAccent.events))
            default:
                otherTab(tab)
            }
    }

    @ViewBuilder private var eventsBody: some View {
                if runningNow {
                    RunningProcessesView(running: running, signatures: signatures, search: model.searchText,
                                         history: model.history, showSpawn: { row in
                                             if let start = row.started { actions.showSpawn(row.pid, start) }
                                         }, actions: actions, grouping: model.eventGrouping,
                                         sessions: shownSessions.map { .init(id: $0.id, topic: $0.topic, facts: $0.facts, agent: $0.agent, pids: $0.pids) },
                                         strip: AnyView(MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)),
                                         charts: AnyView(ResourceCharts(metrics: metrics, travel: travel, traveling: traveling)))
                } else {
                    eventsList
                }
    }

    @ViewBuilder private func otherTab(_ tab: Int) -> some View {
        switch tab {
            case 1: patternsAndProtection(.patterns)
            case 2: StoriesView(stories: model.stories, search: model.searchText, actions: actions)
            case 3: NetworkView(domains: domains, firewall: firewall, signatures: signatures, state: networkState,
                                search: model.searchText, sessionTag: { model.sessions.session(forDestination: $0)?.name },
                                openDetails: actions.openDomain,
                                openFirewallSettings: actions.openFirewallSettings, knownBad: { intel.reason(forDomain: $0) },
                                openStories: { model.windowTab = 2 },
                                storyAbout: { StoryEngine.networkStory(about: $0, in: stories.stories) }, hud: actions,
                                travelWindow: mapTraveling ? Self.mapWindow(travel) : nil,
                                onScreen: model.windowShown && model.windowTab == 3)
            default: patternsAndProtection(.protection)
            }
    }

    /// The Events tab's bars: filters, heavy processes, and Time Travel's banners.
    @ViewBuilder private var eventsBars: some View {
            if let story = model.onlyStory {
                HStack(spacing: 8) {
                    Image(systemName: "point.3.connected.trianglepath.dotted").foregroundStyle(.secondary)
                    Text("\(Text("Only the events of this story:").foregroundStyle(.secondary)) \(Text(story).fontWeight(.medium))")
                    Spacer(minLength: 8)
                    Button("Show All Events") { model.onlyPids = nil; model.onlyStory = nil }
                        .buttonStyle(.glass).controlSize(.small)
                }
                .font(.callout)
                .lineLimit(1)
                .padding(.horizontal, 12).padding(.vertical, 6)
                Divider()
            }
            filterBar
            if !runningNow {
                heavySection
                Color.clear.frame(height: 0)
                    .onReceive(model.sessions.objectWillChange) { _ in
                        // A live session's tree grows: the filter follows it, and the groupings too.
                        DispatchQueue.main.async {
                            guard model.windowTab == 0 else { return }
                            if signatures.groupBySession { patternList.request(signatures) { model.signatureFilter } }
                            if let id = model.onlySession, let s = model.sessions.session(id), s.pids != model.onlySessionPids {
                                model.onlySessionPids = s.pids
                            }
                        }
                    }
            }
            if traveling {
                if showsHistoryScope { HistorySearchScopeBar(travel: travel, text: $model.searchText); Divider() }
                TimeTravelBanner(travel: travel, shown: runningNow ? running.rows.count : travel.listed.count,
                                 noun: runningNow ? "processes" : "events"); Divider()
            }
    }

    /// The Patterns tab (the table, Needs You, Rules, Decisions) and the Protection tab: one sidebar style, each
    /// with its own section. Links between them open the page in whichever tab holds it.
    private func patternsAndProtection(_ scope: RulesScope) -> some View {
        RulesView(book: rules, signatures: signatures, classifier: classifier, baseline: baseline, tab: rulesTab,
                  scope: scope,
                  allPatterns: scope == .patterns ? AnyView(PatternsView(signatures: signatures, classifier: classifier,
                                                                          actions: actions, filter: $model.signatureFilter,
                                                                          list: patternList, active: model.windowTab == 1
                                                                          )) : nil,
                  protection: model.protection, networkMap: networkState.map, firewall: firewall, packages: packages,
                  showPatterns: { app in
                      signatures.scope = nil
                      signatures.search = app
                      rulesTab.open(.allPatterns)
                      model.windowTab = 1
                  },
                  showKeys: { title, keys in
                      signatures.search = ""
                      signatures.scope = .init(title: title, keys: Set(keys))
                      rulesTab.open(.allPatterns)
                      model.windowTab = 1
                  },
                  showNetwork: { model.windowTab = 3 })
    }

    /// Running Now follows the playhead while traveling, the present otherwise.
    private func syncRunningMoment() {
        travel.processesWanted = traveling && runningNow
        if !travel.processesWanted { running.showLive() }
    }

    /// The search field holds text on a tab it filters (Rules has no search).
    private var searchFiltering: Bool {
        model.windowTab != 4 && !searchText.wrappedValue.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// Time Travel's search bar (with its All History / This Window scope) takes the place of the plain one.
    private var showsHistoryScope: Bool {
        traveling && !runningNow && model.searchText.trimmingCharacters(in: .whitespaces).count >= TimeTravel.minSearchLength
    }

    /// One search field, routed to whichever tab is showing.
    /// What the search field searches on this tab, nil where there is nothing to search.
    private var searchPrompt: String? {
        switch model.windowTab {
        case 0: "Name, path, host, PID"
        case 1: "Process or pattern"
        case 2: "Chain, process, path"
        case 3: "Domain, host, program"
        default: nil
        }
    }

    private var searchText: Binding<String> {
        model.windowTab == 1 ? $signatures.search : $model.searchText
    }

    private var subtitle: String {
        // Protection's state costs no toolbar room: "Live · Rehearsing", "Live · Protection paused".
        let state = (model.connected ? (model.paused ? "List paused" : "Live") : "Collector off")
            + (model.protection?.state(network: firewall.mode).word.map { " · \($0)" } ?? "")
        if traveling {
            return "History · " + travel.playhead.formatted(.dateTime.weekday(.abbreviated).hour().minute())
        }
        switch model.windowTab {
        case 0: return state                         // the list is capped at 5,000, so its count said nothing
        case 1: return "\(state) · \(signatures.total) patterns"
        case 2: return "\(state) · \(stories.activeCount) open stories"
        case 3:
            return "\(state) · \(domains.newCount) new domains" + (firewall.prompts.isEmpty ? "" : " · \(firewall.prompts.count) waiting")
        default: return state                       // Protection: the state already says whether you are protected
        }
    }

    /// The order here is the ⌘1–⌘5 order (the View menu matches).
    private var windowTabs: [WindowTabBar.Tab] {
        // A badge means "this needs you", as on Apple's own tabs and icons: what waits for your answer (accent) and
        // dangerous stories (red). New domains and ordinary stories are information, so they stay in the subtitle.
        let waiting = rules.proposals.count + (baseline.report?.review.count ?? 0)
        let dangerous = stories.stories.filter { !$0.dismissed && $0.severity == .dangerous }.count
        return [
            .init(id: 0, title: "Events", symbol: "list.bullet.rectangle"),
            .init(id: 1, title: "Patterns", symbol: "square.stack.3d.up",
                  badge: rules.running ? "…" : waiting > 0 ? "\(waiting)" : nil, badgeTint: .secondary),
            .init(id: 4, title: "Protection", symbol: "shield.lefthalf.filled"),
            .init(id: 2, title: "Stories", symbol: "point.3.connected.trianglepath.dotted",
                  badge: dangerous > 0 ? "\(dangerous)" : nil, badgeTint: .red),
            // Waiting connections first (your answer), else who tried to connect to this Mac (attention).
            .init(id: 3, title: "Network", symbol: "network.badge.shield.half.filled",
                  badge: !firewall.prompts.isEmpty ? "\(firewall.prompts.count)" : incoming.count > 0 ? "\(incoming.count)" : nil,
                  badgeTint: firewall.prompts.isEmpty ? .orange : .secondary),
        ]
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            WindowTabBar(tabs: windowTabs, selection: $model.windowTab)
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Toggle(isOn: Binding(get: { travel.active }, set: { on in
                // Running Now stays on: in Time Travel it shows what was running at the playhead.
                // The Network tab travels in place (its map follows the playhead), every other tab goes to Events.
                if on { if model.windowTab != 3 { model.windowTab = 0 }; travel.enter() } else { travel.exit() }
            })) {
                Label("Time Travel", systemImage: "clock.arrow.circlepath")
            }
            .help("Travel through recorded activity (⌥⌘T)")
            Button { model.paused.toggle() } label: {
                Label(model.paused ? "Resume" : "Pause", systemImage: model.paused ? "play.fill" : "pause.fill")
            }
            .help(model.paused ? "Resume the list" : "Pause the list to read it. Detection keeps running.")
            .disabled(traveling || runningNow)
            Toggle(isOn: $model.overlayEnabled) {
                Label("HUD", systemImage: "rectangle.inset.topright.filled")
            }
            .help("Show or hide the HUD overlay (⌃⌥⌘H)")
            Button(action: actions.openSettings) { Label("Settings", systemImage: "gearshape") }
                .help("Settings (⌘,)")
        }
        // Search where there is something to search: Protection has none, so no field there. A fixed spacer gives it
        // its own glass capsule, as the system search field had: items side by side share one otherwise.
        ToolbarSpacer(.fixed, placement: .primaryAction)
        ToolbarItem(placement: .primaryAction) {
            if let prompt = searchPrompt {
                ToolbarSearchField(text: searchText, prompt: prompt).frame(minWidth: 180, idealWidth: 260, maxWidth: 320)
            }
        }
    }

    /// Nothing is watched while the collector is off: say so where you look, with the fix. A floating glass panel,
    /// inset from the window's edges, nearly neutral so the words keep their contrast.
    private var collectorBanner: some View {
        let starting = collector.state == .starting
        // Stopped while the service still reads as on: Start would be Remove…, so the way is Settings.
        let stopped = collector.isRunning
        let at = alerts.since[.collectorDown].map { $0.formatted(date: .omitted, time: .standard) }
        return problemBanner(
            title: "Hostwatch isn't watching",
            detail: stopped ? "The collector stopped\(at.map { " at \($0)" } ?? ""). Nothing is recorded or protected until it runs again."
                : "The collector is off. Start it to see activity again.") {
            if starting { ProgressView().controlSize(.small) }
            if stopped {
                Button("Collector Settings") { alerts.onOpen(.collectorDown) }
                    .buttonStyle(.glass).controlSize(.large)
            } else {
                Button(starting ? "Starting…" : "Start Collector", action: actions.toggleCollector)
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .disabled(starting)
            }
        }
    }

    private var filterBanner: some View {
        let at = alerts.since[.filterStopped].map { " at \($0.formatted(date: .omitted, time: .standard))" } ?? ""
        return problemBanner(title: "The network filter stopped",
                             detail: "It stopped by itself\(at). Connections pass without being checked.") {
            Button("Network Firewall") { alerts.onOpen(.filterStopped) }.buttonStyle(.glass).controlSize(.large)
        }
    }

    /// Protection stopped: an orange card above the tabs, what happened in a line, and the way to fix it.
    private func problemBanner<Actions: View>(title: String, detail: String,
                                              @ViewBuilder actions: () -> Actions) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .offset(y: -1)                       // a triangle's weight sits low: up a point looks centred
                .frame(width: 30, height: 30)
                .background(Color.orange.gradient, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer(minLength: 12)
            actions()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        // An orange layer, an orange hairline and a soft shadow lift it off the list. The words stay white.
        // The orange as its own layer between the glass and the words: a glass tint over a dark window turns brown.
        .background(LinearGradient(colors: [Color.orange.opacity(0.42), Color.orange.opacity(0.24)],
                                   startPoint: .leading, endPoint: .trailing),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Color.orange.opacity(0.45), lineWidth: 1))
        .shadow(color: .black.opacity(0.25), radius: 12, y: 4)
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, 4)
        .transition(.move(edge: .top).combined(with: .opacity))
        .accessibilityElement(children: .contain)
    }

    /// Slim bar under the toolbar: which events to show, and the pattern tally.
    /// No Groups · By Process · By AI Session, for the Events list and Running Now alike.
    private func groupingPicker(compact: Bool = false) -> some View {
        HStack(spacing: 12) {
            Divider().frame(height: 16)
            if !compact { Text("Group").font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).fixedSize() }
            IconSegments(grouping: $model.eventGrouping, compact: compact)
            .help(runningNow ? "Group the processes: flat, under their parent process, or under the AI session (Claude Code…) they belong to"
                  : "Group the list: flat, one row per program, or one row per AI session (Claude Code…) with its events under it")
        }
    }

    /// The first version of the bar that fits the window. Its controls keep their size, so a bar wider than the
    /// window made the page wider and cut both ends off: full, then compact, then compact scrolling sideways.
    private var filterBar: some View {
        ViewThatFits(in: .horizontal) {
            filterRow(compact: false)
            filterRow(compact: true)
            ScrollView(.horizontal, showsIndicators: false) { filterRow(compact: true) }
        }
    }

    private func filterRow(compact: Bool) -> some View {
        HStack(spacing: 12) {
            let heavyCount = heavy.entries.count
            // Where the heavy card folds to: a flame and the count while something runs heavy.
            IconSegments(selection: $running.showing, items: [
                .init(value: false, title: "Events", symbol: "list.bullet"),
                .init(value: true, title: heavyCount > 0 ? "Running Now  \(heavyCount)" : "Running Now",
                      symbol: heavyCount > 0 ? "flame.fill" : "cpu"),
            ], compact: compact)
            .help(traveling ? "Events: what happened in the window · Running Now: what was running at the playhead (⌥⌘R)"
                  : "Events: what happened · Running Now: every process running at this moment (⌥⌘R)")
            if runningNow {
                groupingPicker(compact: compact)
                if running.isRecorded {
                    Text(running.recordedAt.map { "Recorded \($0.formatted(date: .omitted, time: .standard)) · once a minute" }
                         ?? "Nothing recorded at this moment")
                        .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                } else if let updated = running.updated {
                    Text("Updated \(updated.formatted(date: .omitted, time: .standard)) · every \(Int(RunningProcesses.interval)) s")
                        .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer(minLength: 0)
            } else {
                Divider().frame(height: 16)
                if !compact { Text("Show").font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).fixedSize() }
                KindFilters(model: model, feed: model.live)
                if compact {
                    // One pop-up instead of the row of buttons: All Activity, New, Important…
                    Picker("Show", selection: $model.signatureFilter) {
                        ForEach(SignatureFilter.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    .help("Show: filter by how patterns are decided")
                } else if traveling {
                    ShowFilterPicker(filter: $model.signatureFilter, counts: travelDerived.counts)
                } else {
                    LiveShowFilter(feed: model.live, filter: $model.signatureFilter, shown: model.windowTab == 0 && model.windowShown,
                                   counts: { liveDerived.counts })
                }
                groupingPicker(compact: compact)
                if model.onlySession != nil {
                    Button("All Sessions") { model.onlySession = nil; model.onlySessionPids = nil }
                        .buttonStyle(.glass).controlSize(.small).font(.system(size: 11))
                }
                Spacer(minLength: 0)
                // The patterns of the events the list shows: its filters, search and kinds decide.
                ClassifyAllButton(classifier: classifier, signatures: signatures, shown: {
                    let rows = (traveling ? travelDerived : liveDerived).rows
                    return Set(rows.flatMap { $0.children ?? [$0] }.filter { !$0.isGroup }.map(\.event.signatureKey).filter { !$0.isEmpty })
                }, selected: {
                    // Selected events (inside groups too): their patterns.
                    let rows = (traveling ? travelDerived : liveDerived).rows
                    return Set(rows.flatMap { $0.children ?? [$0] }.filter { !$0.isGroup && model.eventSelection.contains($0.id) }
                        .map(\.event.signatureKey).filter { !$0.isEmpty })
                }, selectShown: {
                    let rows = (traveling ? travelDerived : liveDerived).rows
                    model.eventSelection = Set(rows.flatMap { $0.children ?? [$0] }.filter { !$0.isGroup }.map(\.id))
                }, active: model.windowTab == 0 && !runningNow)
            }
        }
        .controlSize(.small)
        .buttonBorderShape(.capsule)                    // every toolbar button the shape of the Show and Group controls
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    /// Heavy processes, live or at the Time Travel playhead (recorded every 5 s): one design for both.
    private var heavy: HeavyContext {
        let _ = vitals.revision
        if traveling {
            return HeavyContext(entries: travel.sampleAtPlayhead?.heavy ?? [], at: travel.playhead, live: false,
                                events: { pid in travel.events.first { $0.kind == .exec && $0.pid == pid } })
        }
        return vitals.liveContext
    }

    @ViewBuilder private var heavySection: some View {
        let context = heavy
        let current = Set(context.entries.map(\.pid))
        let fresh = current.subtracting(heavyStrip.folded)
        // Live, the card shows a newly heavy process once and folds after 20 s (or ×) into Running Now's flame.
        // Time Travel and Show Only These keep it: there you came for it.
        // A story's filter has its own bar: the strip's "Show Only These" would only repeat it.
        if model.onlyStory == nil, !context.entries.isEmpty, !context.live || model.onlyPids != nil || !fresh.isEmpty {
            HeavyStrip(context: context, state: heavyStrip, onlyThese: model.onlyPids != nil, toggleOnlyThese: {
                model.onlyPids = model.onlyPids == nil ? context.pids : nil
            }, actions: actions, fold: context.live && model.onlyPids == nil ? { heavyStrip.fold(current, current: current) } : nil)
            .task(id: fresh) {
                guard context.live, !fresh.isEmpty else { return }
                try? await Task.sleep(for: .seconds(20))
                guard !Task.isCancelled, model.onlyPids == nil else { return }
                withAnimation(.snappy(duration: 0.25)) { heavyStrip.fold(current, current: current) }
            }
        } else if model.onlyPids != nil, model.onlyStory == nil {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle").foregroundStyle(.secondary)
                Text(traveling ? "Nothing ran heavy at this moment." : "Those processes are no longer heavy.")
                    .foregroundStyle(.secondary)
                Button("Show All Events") { model.onlyPids = nil }.buttonStyle(.glass).controlSize(.small)
            }
            .font(.callout)
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
    }

    /// Show Spawn in Timeline: the launch selected, with whatever filter would hide it relaxed.
    private func revealLaunch(_ event: ActivityEvent) {
        let q = model.searchText.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty && !event.matches(q) { model.searchText = "" }
        model.onlyPids = nil
        if !model.visibleKinds.contains(.exec) { model.toggle(.exec) }
        if !model.passes(event, model.signatureFilter) { model.signatureFilter = .all }
        model.eventSelection = [event.id]
    }

    /// Rows (and Show counts) for the Time Travel list, from the cache when nothing they depend on changed.
    private var travelDerived: TravelRowsCache.Result {
        let key = TravelRowsCache.Key(revision: travel.revision, showingSearch: travel.showingSearch,
                                      kinds: model.visibleKinds, filter: model.signatureFilter,
                                      search: model.searchText, only: model.onlyPids, exclusions: model.exclusionText,
                                      signatures: signatures.revision, order: model.eventOrder,
                                      grouping: model.eventGrouping, sessions: sessionsStamp)
        return travelRows.result(for: key) {
            TravelRowsCache.Result(rows: makeRows(model.filtered(travel.listed, applyExclusions: true)),
                                   counts: model.showCounts(travel.listed, applyExclusions: true))
        }
    }

    /// The sessions the list's events belong to: live ones, or the ones replayed from the Time Travel window.
    var shownSessions: [AgentSession] {
        traveling ? travelSessions.sessions(for: travel, named: model.sessions.sessions) : model.sessions.sessions
    }

    /// `reuse`: rows from the last build whose status and session can't have changed (a new batch rebuilds
    /// only its own events, not all 5,000).
    private func makeRows(_ events: [ActivityEvent], reuse: [UUID: EventItem] = [:]) -> [EventItem] {
        let sessions = shownSessions
        func session(_ e: ActivityEvent) -> AgentSession? {
            if traveling { return sessions.first { $0.pids.contains(e.pid) } }
            return e.session > 0 ? model.sessions.session(e.session) : nil
        }
        let items = events.map { e -> EventItem in
            if let kept = reuse[e.id] { return kept }
            let status = model.statusAndReviewed(e).status
            let s = session(e)
            // Known bad sorts above Dangerous.
            return EventItem(event: e, status: status, statusRank: intel.flag(for: e) != nil ? -1 : signatures.rank(status),
                             session: s?.topic ?? "", agent: s?.agent)
        }
        // The list is already newest first: only sort for another column or direction.
        let newestFirst = model.eventOrder.count == 1 && model.eventOrder[0].keyPath == \EventItem.seq
            && model.eventOrder[0].order == .reverse
        let sorted = newestFirst ? items : items.sorted(using: model.eventOrder)
        switch model.eventGrouping {
        case .none: return sorted
        case .process: return EventItem.groupedByProcess(sorted)
        case .session:
            return EventItem.groupedBySession(sorted, sessions: sessions.map {
                .init(id: $0.id, topic: $0.topic, facts: $0.groupFacts, agent: $0.agent, pids: $0.pids)
            })
        }
    }

    /// A stamp of the sessions a grouping depends on (their count and members). Not their event counts: those
    /// move with every event, and the rows are rebuilt for new events anyway.
    private var sessionsStamp: Int {
        shownSessions.reduce(0) { $0 &* 31 &+ $1.id &* 7 &+ $1.pids.count &* 3 &+ ($1.ended == nil ? 0 : 1) }
    }

    /// The live rows and Show counts, from the cache when nothing they depend on changed (the window's body runs
    /// for every observed object, far more often than a batch arrives).
    private var liveDerived: TravelRowsCache.Result {
        let key = TravelRowsCache.Key(revision: model.history.count &* 1_000_003 &+ (model.history.first?.seq ?? 0),
                                      showingSearch: false, kinds: model.visibleKinds, filter: model.signatureFilter,
                                      search: model.searchText, only: model.onlyPids, exclusions: model.exclusionText,
                                      signatures: signatures.revision, order: model.eventOrder,
                                      grouping: model.eventGrouping, sessions: sessionsStamp)
        return liveRows.result(for: key) { previous, previousKey in
            var reuse: [UUID: EventItem] = [:]
            if let previous, let previousKey, previousKey.signatures == key.signatures, previousKey.sessions == key.sessions {
                for row in previous.rows {
                    if let kids = row.children { for k in kids { reuse[k.id] = k } } else { reuse[row.id] = row }
                }
            }
            return TravelRowsCache.Result(rows: makeRows(model.searchResults, reuse: reuse), counts: model.showCounts(model.history))
        }
    }


    /// Right-click on a group row.
    private var eventsList: some View {
        let derived = traveling ? travelDerived : liveDerived
        let rows = derived.rows
        // Search hits span days: their Time column shows the day too.
        let withDay = traveling && travel.showingSearch
        let detail = model.eventInfo ? Self.selectedEvent(rows, model.eventSelection) : nil
        return VStack(spacing: 0) {
          HStack(spacing: 10) {
            EventsTable(rows: rows, version: derived.version,
                        feed: traveling ? nil : model.live, derive: traveling ? nil : { liveDerived },
                        onScreen: model.windowTab == 0 && model.windowShown,
                        withDay: withDay, grouped: model.eventGrouping != .none,
                        selection: $model.eventSelection, sortOrder: $model.eventOrder,
                        flag: { intel.flag(for: $0) }, badge: { heavy.badge(for: $0) },
                        // The end of a Time Travel window's list: its next older page.
                        onReachEnd: traveling && !withDay ? { travel.loadMore() } : nil,
                        onDoubleClick: { item in
                            // A search hit opens its moment; elsewhere the details panel, as in Running Now.
                            if withDay { travel.reveal(item.event) } else { model.eventInfo = true }
                        },
                        menu: eventMenu, groupLinks: groupLinks)
            .onChange(of: travel.focusID) { _, id in
                guard let id, let event = travel.events.first(where: { $0.id == id }) else { return }
                revealLaunch(event)                 // selecting the row scrolls the list to it
            }
            .listCard()
            // The details float beside the list, as Network's inspector does: the list keeps its height.
            if let event = detail {
                EventDetailPanel(event: event, signatures: signatures, actions: actions, side: true) { model.eventInfo = false }
                    .frame(width: 360)
                    .sidePanel()
                    .transition(.move(edge: .trailing).combined(with: .opacity))
            }
          }
            HStack {
                MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)
                if !traveling { BusiestNow(feed: model.live, shown: model.windowTab == 0 && model.windowShown) }
                Spacer(minLength: 12)
                // Quiet like the rest of the status bar: it's information, the click is a convenience.
                Button { history.revealInFinder() } label: {
                    Text(history.statusText).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
                .buttonStyle(.plain)
                .help("Show history files in Finder")
                if traveling {
                    EventCountText(shown: Self.eventCount(rows), total: travel.listed.count, restored: 0, filtering: searchFiltering,
                                   always: true)
                } else {
                    LiveEventCount(feed: model.live, filtering: searchFiltering, shown: model.windowTab == 0 && model.windowShown) {
                        // Restored events are the oldest: those still listed are what live arrivals haven't pushed out.
                        (Self.eventCount(liveDerived.rows), model.history.count,
                         max(0, min(model.restoredCount, model.history.count - model.live.arrived)))
                    }
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 4)
            .padding(.vertical, 6)
        }
        .animation(.smooth(duration: 0.2), value: model.eventInfo)
    }

    /// The details panel's event: the first selected row that is an event, inside groups too.
    static func selectedEvent(_ rows: [EventItem], _ selection: Set<UUID>) -> ActivityEvent? {
        guard !selection.isEmpty else { return nil }
        for row in rows {
            if let children = row.children {
                if let hit = children.first(where: { selection.contains($0.id) }) { return hit.event }
            } else if selection.contains(row.id) {
                return row.event
            }
        }
        return nil
    }
}

/// Tabs shown at least once (kept alive, see the window body).
final class VisitedTabs: ObservableObject { @Published var tabs: Set<Int> = [] }

/// "6 of 5,000 events", with the restored count: the live version follows every batch on its own.
extension ActivityWindowView {
    /// Events in the rows (a group row counts its events, not itself).
    static func eventCount(_ rows: [EventItem]) -> Int { rows.reduce(0) { $0 + ($1.children?.count ?? 1) } }
}

private struct EventCountText: View {
    let shown: Int, total: Int, restored: Int
    let filtering: Bool

    /// Live: counts only when they say something (the list keeps the latest 5,000, so its size alone doesn't).
    var always = false

    var body: some View {
        if restored > 0 || always || shown != total { Text("·") }      // after the history size, only if something follows
        if restored > 0 {
            Text("\(restored.formatted()) from before the restart")
                .monospacedDigit()
                .help("Loaded from recorded history at launch, so the list isn't empty. Time Travel shows all of it.")
        }
        if always || shown != total {
            if restored > 0 { Text("·") }
            Text(shown == total ? "\(total.formatted()) events" : "\(shown.formatted()) of \(total.formatted()) events")
                .monospacedDigit()
                .foregroundStyle(filtering && shown != total ? Color.accentColor : .secondary)
                .fontWeight(filtering && shown != total ? .medium : .regular)
        }
    }
}

private struct LiveEventCount: View {
    @ObservedObject var feed: LiveFeed
    let filtering: Bool
    /// Whether the Events tab is on screen: hidden, counting rebuilt the Events rows for every batch.
    let shown: Bool
    let numbers: () -> (shown: Int, total: Int, restored: Int)

    var body: some View {
        if shown {
            let n = numbers()
            EventCountText(shown: n.shown, total: n.total, restored: n.restored, filtering: filtering)
        }
    }
}

/// The Show choices with the live list's counts, re-rendered per batch here rather than with the window.
/// Launches, connections, files: which kinds the list shows. In the Show row rather than the toolbar, so the toolbar
/// is the same on every tab (in it, Time Travel, Pause and HUD moved on Events only). The counts are in the tooltips:
/// running totals said nothing you'd act on.
private struct KindFilters: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var feed: LiveFeed

    var body: some View {
        HStack(spacing: 2) {
            ForEach(EventKind.allCases, id: \.self) { kind in
                let on = model.visibleKinds.contains(kind)
                Button { model.toggle(kind) } label: {
                    Image(systemName: kind.symbol)
                        .foregroundStyle(on ? kind.color : .secondary)
                        .opacity(on ? 1 : 0.4)
                        .frame(width: 24, height: 18)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("\(kind.title): \(feed.counts[kind, default: 0].formatted()) since launch. "
                      + (on ? "Click to hide them." : "Hidden, click to show them."))
                .accessibilityLabel(kind.title)
                .accessibilityValue(on ? "shown" : "hidden")
            }
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 2)
        .background(Capsule().fill(.quaternary.opacity(0.5)))
    }
}

private struct LiveShowFilter: View {
    @ObservedObject var feed: LiveFeed
    @Binding var filter: SignatureFilter
    /// Whether the Events tab is on screen. Hidden, it still hears every event (it observes the feed itself), and
    /// counting rebuilt the Events rows for each one, under whatever tab you were on.
    let shown: Bool
    let counts: () -> [SignatureFilter: Int]

    var body: some View { ShowFilterPicker(filter: $filter, counts: shown ? counts() : [:]) }
}

/// A tab that isn't shown skips the window's updates: every tab stays alive in the strip, and the window's body runs
/// again for any change, the current tab included, so each switch rebuilt every hidden tab too (the network map's
/// graph alone took about 150 ms of a switch). It catches up when it's shown again. What a tab observes itself
/// (its own stores) still updates it as before.
private struct HiddenTabGate<Content: View>: View, @MainActor Equatable {
    let shown: Bool
    @ViewBuilder let content: () -> Content

    var body: some View { content() }

    static func == (a: Self, b: Self) -> Bool { !a.shown && !b.shown }
}
