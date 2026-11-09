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
                .fixedSize()
            }
        }
        .help("Show: filter by how patterns are decided (Events, Patterns and the HUD)")
    }

    private func bar(_ counts: [SignatureFilter: Int], icons: Bool) -> some View {
        HStack(spacing: 4) {
            ForEach(SignatureFilter.allCases, id: \.self) { option in
                let selected = filter == option
                Button { filter = option } label: {
                    HStack(spacing: 5) {
                        if icons {
                            Image(systemName: option.symbol)
                                .symbolVariant(selected ? .fill : .none)
                                .font(.system(size: 11, weight: .medium))
                        }
                        Text(option.short).font(.system(size: 12, weight: selected ? .semibold : .regular))
                        if let n = counts[option] {
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
                .help(option.explanation)
                .accessibilityLabel("\(option.short)\(counts[option].map { ", \($0)" } ?? "")")
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
    @ObservedObject var firewall: FirewallMonitor
    let rulesTab: RulesTabState
    @ObservedObject var vitals: ProcessVitals
    @ObservedObject var heavyStrip: HeavyStripState
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var sheets: WindowSheetState
    @ObservedObject var rules: RuleBook
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var collector: Collector
    @ObservedObject var history: HistoryRecorder
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var travel: TimeTravel
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var running: RunningProcesses
    let actions: HUDActions

    var traveling: Bool { travel.active && model.windowTab == 0 }
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
            if !collector.isRunning && !model.connected { collectorBanner; Divider() }
            VulnerabilityBanner(intel: intel, sheets: sheets)
            FirewallFallbackBanner(firewall: firewall, openSettings: actions.openFirewallSettings)
            // A search left in the field filters quietly: say so where you look, with the way out.
            if searchFiltering && !showsHistoryScope { SearchActiveBar(text: searchText); Divider() }
            if model.windowTab == 0 { filterBar; Divider() }
            if model.windowTab == 0 && !runningNow {
                heavySection
                Color.clear.frame(height: 0)
                    .onReceive(model.sessions.objectWillChange) { _ in
                        // A live session's tree grows: the filter follows it, and the groupings too.
                        DispatchQueue.main.async {
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
            // Every tab visited stays alive and *attached*: the tabs sit side by side in a strip as wide as all of
            // them, slid so the current one shows. Hiding a tab (opacity, zIndex changes) made SwiftUI detach or
            // re-add its AppKit table, and re-attaching a table costs ~2 ms per cell view (a sample showed 0.6 s of
            // every switch in NSTableView _setWindow:). A slide is only a position change.
            GeometryReader { geo in
                let tabs = Array(visitedTabs).sorted()
                let index = CGFloat(tabs.firstIndex(of: model.windowTab) ?? 0)
                HStack(spacing: 0) {
                    ForEach(tabs, id: \.self) { tab in
                        tabContent(tab)
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
            .onChange(of: model.windowTab) { _, tab in visitedTabs.insert(tab) }
        }
        .frame(minWidth: 900, minHeight: 480)
        // The Patterns rows are ready before the tab is opened.
        .onAppear {
            patternList.sessionGroups = { [weak model] in
                (model?.sessions.sessions ?? []).map { .init(id: $0.id, name: $0.topic, keys: $0.keys, live: $0.isLive, agent: $0.agent, facts: $0.groupFacts) }
            }
            if !patternList.built { patternList.build(signatures, filter: model.signatureFilter) }
        }
        .sheet(isPresented: $sheets.showVulns) { VulnerabilityList(intel: intel, close: { sheets.showVulns = false }) }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if traveling { TimelineBar(travel: travel).transition(.move(edge: .bottom).combined(with: .opacity)) }
        }
        .animation(.smooth(duration: 0.25), value: traveling)
        // Time Travel searches all recorded history (scope All History), in the background.
        .onChange(of: model.searchText) { _, text in if traveling && !runningNow { travel.search(text) } }
        .onChange(of: traveling) { _, on in
            if on && !runningNow { travel.search(model.searchText) }
            syncRunningMoment()
        }
        .onChange(of: runningNow) { _, on in
            if traveling && !on { travel.search(model.searchText) }
            syncRunningMoment()
        }
        // Native window toolbar (bridged by NSHostingController): Liquid Glass controls + search.
        .toolbar { toolbarContent }
        .searchable(text: searchText, placement: .toolbar,
                    prompt: ["Name, path, host, PID", "Process or pattern", "Chain, process, path",
                             "Domain, host, program", "Not used on Rules", "Not used on Overview"][min(model.windowTab, 5)])
        .navigationTitle("Hostwatch")
        .navigationSubtitle(subtitle)
    }

    /// One tab's content (built on first visit, then kept).
    @ViewBuilder private func tabContent(_ tab: Int) -> some View {
        switch tab {
            case 0:
                if runningNow {
                    RunningProcessesView(running: running, signatures: signatures, search: model.searchText,
                                         history: model.history, showSpawn: { row in
                                             if let start = row.started { actions.showSpawn(row.pid, start) }
                                         }, actions: actions, grouping: model.eventGrouping,
                                         sessions: shownSessions.map { .init(id: $0.id, topic: $0.topic, facts: $0.facts, agent: $0.agent, pids: $0.pids) })
                } else {
                    eventsList
                }
            case 1: PatternsView(signatures: signatures, classifier: classifier, actions: actions,
                                 filter: $model.signatureFilter, list: patternList)
            case 2: StoriesView(stories: model.stories, search: model.searchText, actions: actions)
            case 3: NetworkView(domains: domains, firewall: firewall, signatures: signatures, state: networkState,
                                search: model.searchText, sessionTag: { model.sessions.session(forDestination: $0)?.name },
                                openDetails: actions.openDomain,
                                openFirewallSettings: actions.openFirewallSettings, knownBad: { intel.reason(forDomain: $0) })
            default: RulesView(book: rules, signatures: signatures, classifier: classifier, baseline: baseline, tab: rulesTab,
                               showPatterns: { app in
                                   signatures.scope = nil
                                   signatures.search = app
                                   model.windowTab = 1
                               },
                               showKeys: { title, keys in
                                   signatures.search = ""
                                   signatures.scope = .init(title: title, keys: Set(keys))
                                   model.windowTab = 1
                               })
            }
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
    private var searchText: Binding<String> {
        model.windowTab == 1 ? $signatures.search : $model.searchText
    }

    private var subtitle: String {
        let state = model.paused ? "Paused" : model.connected ? "Live" : "Collector off"
        if traveling {
            return "History · " + travel.playhead.formatted(.dateTime.weekday(.abbreviated).hour().minute())
        }
        switch model.windowTab {
        case 0: return state                         // the list is capped at 5,000, so its count said nothing
        case 1: return "\(state) · \(signatures.total) patterns"
        case 2: return "\(state) · \(stories.activeCount) open stories"
        case 3:
            return "\(state) · \(domains.newCount) new domains" + (firewall.prompts.isEmpty ? "" : " · \(firewall.prompts.count) waiting")
        default: return "\(state) · \(rules.activeCount) active rules"
        }
    }

    /// The order here is the ⌘1–⌘5 order (the View menu matches).
    private var windowTabs: [WindowTabBar.Tab] {
        let waiting = rules.proposals.count + (baseline.report?.review.count ?? 0)
        let dangerous = stories.stories.contains { !$0.dismissed && $0.severity == .dangerous }
        return [
            .init(id: 0, title: "Events", symbol: "list.bullet.rectangle"),
            .init(id: 1, title: "Patterns", symbol: "square.stack.3d.up"),
            .init(id: 4, title: "Rules", symbol: "checklist",
                  badge: rules.running ? "…" : waiting > 0 ? "\(waiting)" : nil, badgeTint: .accentColor),
            .init(id: 2, title: "Stories", symbol: "point.3.connected.trianglepath.dotted",
                  badge: stories.activeCount > 0 ? "\(stories.activeCount)" : nil, badgeTint: dangerous ? .red : .orange),
            .init(id: 3, title: "Network", symbol: "network.badge.shield.half.filled",
                  badge: !firewall.prompts.isEmpty ? "\(firewall.prompts.count)" : domains.newCount > 0 ? "\(domains.newCount)" : nil,
                  badgeTint: !firewall.prompts.isEmpty ? .orange : .purple),
        ]
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            WindowTabBar(tabs: windowTabs, selection: $model.windowTab)
        }
        ToolbarItemGroup(placement: .principal) {
          if model.windowTab == 0 && !runningNow {
            ForEach(EventKind.allCases, id: \.self) { kind in
                let on = model.visibleKinds.contains(kind)
                Button { model.toggle(kind) } label: {
                    Label { Text("\(model.counts[kind, default: 0])").monospacedDigit() } icon: {
                        Image(systemName: kind.symbol)
                    }
                    .labelStyle(.titleAndIcon)
                    .foregroundStyle(on ? kind.color : .secondary)
                    .opacity(on ? 1 : 0.45)
                }
                .help(on ? "Hide \(kind.title.lowercased())" : "Show \(kind.title.lowercased())")
            }
          }
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Toggle(isOn: Binding(get: { travel.active }, set: { on in
                // Running Now stays on: in Time Travel it shows what was running at the playhead.
                if on { model.windowTab = 0; travel.enter() } else { travel.exit() }
            })) {
                Label("Time Travel", systemImage: "clock.arrow.circlepath")
            }
            .help("Travel through recorded activity (⌥⌘T)")
            Button { model.paused.toggle() } label: {
                Label(model.paused ? "Resume" : "Pause", systemImage: model.paused ? "play.fill" : "pause.fill")
            }
            .help(model.paused ? "Resume the live stream" : "Pause the live stream")
            .disabled(traveling || runningNow)
            Button { model.clear() } label: { Label("Clear", systemImage: "trash") }
                .help("Clear the event list")
                .disabled(traveling || runningNow)
            Toggle(isOn: $model.overlayEnabled) {
                Label("HUD", systemImage: "rectangle.inset.topright.filled")
            }
            .help("Show or hide the HUD overlay (⌃⌥⌘H)")
            Button(action: actions.openSettings) { Label("Settings", systemImage: "gearshape") }
                .help("Settings (⌘,)")
        }
    }

    /// Nothing is watched while the collector is off: say so where you look, with the fix.
    private var collectorBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text("The collector is off, so nothing is being watched.").fontWeight(.medium)
            Spacer()
            Button(collector.state == .starting ? "Starting…" : "Start Collector", action: actions.toggleCollector)
                .buttonStyle(.glassProminent)
                .disabled(collector.state == .starting)
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.10))
    }

    /// Slim bar under the toolbar: which events to show, and the pattern tally.
    /// No Groups · By Process · By AI Session, for the Events list and Running Now alike.
    private var groupingPicker: some View {
        HStack(spacing: 12) {
            Divider().frame(height: 16)
            Text("Group").font(.system(size: 11)).foregroundStyle(.secondary)
            Picker("Group", selection: $model.eventGrouping) {
                ForEach(EventGrouping.allCases, id: \.self) { Label($0.title, systemImage: $0.symbol).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help(runningNow ? "Group the processes: flat, under their parent process, or under the AI session (Claude Code…) they belong to"
                  : "Group the list: flat, one row per program, or one row per AI session (Claude Code…) with its events under it")
        }
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            Picker("View", selection: $running.showing) {
                Label("Events", systemImage: "list.bullet").tag(false)
                Label("Running Now", systemImage: "cpu").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help(traveling ? "Events: what happened in the window · Running Now: what was running at the playhead (⌥⌘R)"
                  : "Events: what happened · Running Now: every process running at this moment (⌥⌘R)")
            if runningNow {
                groupingPicker
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
                Text("Show").font(.system(size: 11)).foregroundStyle(.secondary)
                if traveling {
                    ShowFilterPicker(filter: $model.signatureFilter, counts: travelDerived.counts)
                } else {
                    LiveShowFilter(feed: model.live, filter: $model.signatureFilter, counts: { liveDerived.counts })
                }
                groupingPicker
                if model.onlySession != nil {
                    Button("All Sessions") { model.onlySession = nil; model.onlySessionPids = nil }
                        .buttonStyle(.link).font(.system(size: 11))
                }
                Spacer(minLength: 0)
                ClassifyAllButton(classifier: classifier, signatures: signatures)
            }
        }
        .controlSize(.small)
        .buttonBorderShape(.capsule)                    // every toolbar button the shape of the Show and Group controls
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    @ViewBuilder
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
        if !context.entries.isEmpty {
            HeavyStrip(context: context, state: heavyStrip, onlyThese: model.onlyPids != nil, toggleOnlyThese: {
                model.onlyPids = model.onlyPids == nil ? context.pids : nil
            }, actions: actions)
        } else if model.onlyPids != nil {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle").foregroundStyle(.secondary)
                Text(traveling ? "Nothing ran heavy at this moment." : "Those processes are no longer heavy.")
                    .foregroundStyle(.secondary)
                Button("Show All Events") { model.onlyPids = nil }.buttonStyle(.link)
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
        return VStack(spacing: 0) {
            EventsTable(rows: rows, version: derived.version,
                        feed: traveling ? nil : model.live, derive: traveling ? nil : { liveDerived },
                        withDay: withDay, grouped: model.eventGrouping != .none,
                        selection: $model.eventSelection, sortOrder: $model.eventOrder,
                        flag: { intel.flag(for: $0) }, badge: { heavy.badge(for: $0) },
                        // The end of a Time Travel window's list: its next older page.
                        onReachEnd: traveling && !withDay ? { travel.loadMore() } : nil,
                        onDoubleClick: { item in
                            // A search hit opens its moment; elsewhere a double-click asks the AI.
                            if withDay { travel.reveal(item.event) } else { actions.askAI(item.event) }
                        },
                        menu: eventMenu, groupLinks: groupLinks)
            .onChange(of: travel.focusID) { _, id in
                guard let id, let event = travel.events.first(where: { $0.id == id }) else { return }
                revealLaunch(event)                 // selecting the row scrolls the list to it
            }
            Divider()
            HStack {
                MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)
                Spacer(minLength: 12)
                Button(history.statusText) { history.revealInFinder() }
                    .buttonStyle(.link)
                    .help("Show history files in Finder")
                Text("·")
                if traveling {
                    EventCountText(shown: rows.count, total: travel.listed.count, restored: 0, filtering: searchFiltering)
                } else {
                    LiveEventCount(feed: model.live, filtering: searchFiltering) { (liveDerived.rows.count, model.history.count, model.restoredCount) }
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }
}

/// Tabs shown at least once (kept alive, see the window body).
final class VisitedTabs: ObservableObject { @Published var tabs: Set<Int> = [] }

/// "6 of 5,000 events", with the restored count: the live version follows every batch on its own.
private struct EventCountText: View {
    let shown: Int, total: Int, restored: Int
    let filtering: Bool

    var body: some View {
        if restored > 0 {
            Text("\(restored) from before the restart ·")
                .help("Loaded from recorded history at launch, so the list isn't empty. Time Travel shows all of it.")
        }
        Text(shown == total ? "\(total) events" : "\(shown) of \(total) events")
            .monospacedDigit()
            .foregroundStyle(filtering && shown != total ? Color.accentColor : .secondary)
            .fontWeight(filtering && shown != total ? .medium : .regular)
    }
}

private struct LiveEventCount: View {
    @ObservedObject var feed: LiveFeed
    let filtering: Bool
    let numbers: () -> (shown: Int, total: Int, restored: Int)

    var body: some View {
        let n = numbers()
        EventCountText(shown: n.shown, total: n.total, restored: n.restored, filtering: filtering)
    }
}

/// The Show choices with the live list's counts, re-rendered per batch here rather than with the window.
private struct LiveShowFilter: View {
    @ObservedObject var feed: LiveFeed
    @Binding var filter: SignatureFilter
    let counts: () -> [SignatureFilter: Int]

    var body: some View { ShowFilterPicker(filter: $filter, counts: counts()) }
}
