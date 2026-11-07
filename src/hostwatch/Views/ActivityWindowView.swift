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

    var body: some View {
        ViewThatFits(in: .horizontal) {
            bar(counts, icons: true)
            bar(counts, icons: false)
            Picker("Show", selection: $filter) {
                ForEach(SignatureFilter.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .fixedSize()
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

    private var traveling: Bool { travel.active && model.windowTab == 0 }
    /// Time Travel rows, derived only when the events or a filter change (not on every playhead or hover update).
    @StateObject private var travelRows = TravelRowsCache()
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
            if model.windowTab == 0 && !runningNow { heavySection }
            if traveling {
                if showsHistoryScope { HistorySearchScopeBar(travel: travel, text: $model.searchText); Divider() }
                TimeTravelBanner(travel: travel, shown: runningNow ? running.rows.count : travel.listed.count,
                                 noun: runningNow ? "processes" : "events"); Divider()
            }
            switch model.windowTab {
            case 0:
                if runningNow {
                    RunningProcessesView(running: running, signatures: signatures, search: model.searchText,
                                         history: model.history, showSpawn: { row in
                                             if let start = row.started { actions.showSpawn(row.pid, start) }
                                         }, actions: actions)
                } else {
                    eventsList
                }
            case 1: PatternsView(signatures: signatures, classifier: classifier, actions: actions,
                                 filter: $model.signatureFilter)
            case 2: StoriesView(stories: model.stories, search: model.searchText, actions: actions)
            case 3: NetworkView(domains: domains, firewall: firewall, signatures: signatures, state: networkState,
                                search: model.searchText, openDetails: actions.openDomain,
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
        .frame(minWidth: 900, minHeight: 480)
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
        case 0: return "\(state) · \(model.history.count) events"
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
                ShowFilterPicker(filter: $model.signatureFilter,
                                 counts: traveling ? travelDerived.counts : model.showCounts(model.history))
                Spacer(minLength: 0)
                ClassifyAllButton(classifier: classifier, signatures: signatures)
            }
        }
        .controlSize(.small)
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
                                      signatures: signatures.revision, order: model.eventOrder)
        return travelRows.result(for: key) {
            TravelRowsCache.Result(rows: makeRows(model.filtered(travel.listed, applyExclusions: true)),
                                   counts: model.showCounts(travel.listed, applyExclusions: true))
        }
    }

    private func makeRows(_ events: [ActivityEvent]) -> [EventItem] {
        let items = events.map { e -> EventItem in
            let status = signatures.status(for: e)
            // Known bad sorts above Dangerous.
            return EventItem(event: e, status: status, statusRank: intel.flag(for: e) != nil ? -1 : signatures.rank(status))
        }
        // The list is already newest first: only sort for another column or direction.
        let newestFirst = model.eventOrder.count == 1 && model.eventOrder[0].keyPath == \EventItem.seq
            && model.eventOrder[0].order == .reverse
        return newestFirst ? items : items.sorted(using: model.eventOrder)
    }

    private var eventsList: some View {
        let rows = traveling ? travelDerived.rows : makeRows(model.searchResults)
        // Search hits span days: their Time column shows the day too.
        let withDay = traveling && travel.showingSearch
        let lastRowID = rows.last?.id
        return VStack(spacing: 0) {
          ScrollViewReader { proxy in
            Table(rows, selection: $model.eventSelection, sortOrder: $model.eventOrder) {
                TableColumn("Time", value: \.seq) { item in
                    Text(withDay ? item.event.dayTime : item.event.time).foregroundStyle(.secondary).monospacedDigit()
                        // The end of a Time Travel window's list: its next older page.
                        .onAppear { if traveling, !withDay, item.id == lastRowID { travel.loadMore() } }
                }
                .width(min: 56, ideal: withDay ? 104 : 60, max: withDay ? 130 : 72)
                TableColumn("Kind", value: \.kind) { item in
                    Image(systemName: item.event.kind.symbol)
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(item.event.kind.color)
                        .help(item.event.kind.title)
                }
                .width(min: 20, ideal: 24, max: 32)
                TableColumn("Status", value: \.statusRank) { item in
                    HStack(spacing: 4) {
                        if let bad = intel.flag(for: item.event) {
                            // A listed destination or file outranks the pattern's own status (often Safe: the
                            // pattern is the program's connections in general).
                            KnownBadPill()
                                .help("On a threat list: \(bad)\nThe pattern itself is \(item.status.title.lowercased()).")
                        } else {
                            StatusPill(status: item.status)
                        }
                        if intel.flag(for: item.event) != nil {
                            EmptyView()                   // the known-bad pill says it all
                        } else if case .heavy = heavy.badge(for: item.event) {
                            Image(systemName: "flame.fill").foregroundStyle(.orange)
                                .help("Still running and using a lot of CPU or memory")
                        } else if !item.event.beacon.isEmpty {
                            Image(systemName: "dot.radiowaves.right").foregroundStyle(.red)
                                .help("BEACON: connects \(item.event.beacon)")
                        } else if item.event.rawIP {
                            Image(systemName: "number").foregroundStyle(.orange)
                                .help("RAW IP: public IP on an unusual port with no DNS lookup")
                        } else if !item.event.newDomain.isEmpty {
                            Image(systemName: "globe.badge.chevron.backward").foregroundStyle(.purple)
                                .help("NEW DOMAIN: first contact with \(item.event.newDomain)")
                        } else if item.event.isFirst {
                            Image(systemName: "sparkle").foregroundStyle(.yellow)
                                .help("First time this pattern was ever seen")
                                .accessibilityLabel("First seen")
                        }
                    }
                }
                .width(min: 70, ideal: 84, max: 100)
                TableColumn("Process", value: \.name) { item in
                    Text(item.event.name).fontWeight(.semibold).lineLimit(1).help(item.event.proc)
                }
                .width(min: 60, ideal: 110, max: 150)
                TableColumn("PID", value: \.pid) { item in
                    Text(String(item.event.pid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("PPID", value: \.ppid) { item in
                    Text(String(item.event.ppid)).foregroundStyle(.secondary).monospacedDigit()
                }
                .width(min: 38, ideal: 48, max: 64)
                TableColumn("Detail", value: \.detail) { item in
                    HStack(spacing: 6) {
                        if let bad = intel.flag(for: item.event) { KnownBadTag(detail: bad) }
                        if let badge = heavy.badge(for: item.event) { VitalBadgeView(badge: badge) }
                        if item.event.kind == .file {
                            FileModeIcon(mode: item.event.extra)
                            Text(item.event.target).truncationMode(.middle).help(item.event.target)
                        } else if item.event.kind == .net, !item.event.extra.isEmpty {
                            ProtocolTag(proto: item.event.extra)
                            Text(item.event.fullDetail.dropFirst(item.event.extra.count).trimmingCharacters(in: .whitespaces))
                                .truncationMode(.middle).help(item.event.target)
                        } else {
                            Text(item.event.fullDetail).truncationMode(.middle).help(item.event.target)
                        }
                    }
                }
                .width(min: 200, ideal: 900)
            }
            .font(.system(size: 12, design: .monospaced))
            .contextMenu(forSelectionType: UUID.self) { ids in
                if let id = ids.first, let item = rows.first(where: { $0.id == id }) { rowMenu(item.event) }
            } primaryAction: { ids in
                guard let id = ids.first, let item = rows.first(where: { $0.id == id }) else { return }
                // A search hit opens its moment; elsewhere a double-click asks the AI.
                if withDay { travel.reveal(item.event) } else { actions.askAI(item.event) }
            }
            .onChange(of: travel.focusID) { _, id in
                guard let id, let event = travel.events.first(where: { $0.id == id }) else { return }
                revealLaunch(event)
                DispatchQueue.main.async { proxy.scrollTo(id, anchor: .center) }
            }
          }
            Divider()
            HStack {
                MetricsStrip(metrics: metrics, travel: travel, traveling: traveling)
                Spacer(minLength: 12)
                Button(history.statusText) { history.revealInFinder() }
                    .buttonStyle(.link)
                    .help("Show history files in Finder")
                Text("·")
                let total = traveling ? travel.listed.count : model.history.count
                if !traveling, model.restoredCount > 0 {
                    Text("\(model.restoredCount) from before the restart ·")
                        .help("Loaded from recorded history at launch, so the list isn't empty. Time Travel shows all of it.")
                }
                Text(rows.count == total ? "\(total) events" : "\(rows.count) of \(total) events")
                    .monospacedDigit()
                    .foregroundStyle(searchFiltering && rows.count != total ? Color.accentColor : .secondary)
                    .fontWeight(searchFiltering && rows.count != total ? .medium : .regular)
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    @ViewBuilder
    private func rowMenu(_ event: ActivityEvent) -> some View {
        if traveling && travel.showingSearch && event.ts > 0 {
            Button("Show in Timeline") { travel.reveal(event) }
            Divider()
        }
        Button("Ask AI: Is This Dangerous?…") { actions.askAI(event) }
        Button("Watch \(event.name) Closely…") { actions.watch(event) }
        Divider()
        Text("Pattern: \(event.signatureProcess) → \(event.signaturePattern)")
        ForEach(SignatureStatus.allCases, id: \.self) { status in
            Button("Mark Pattern \(status.title)") { signatures.set(status, keys: [event.signatureKey]) }
        }
        Menu("Mark All \(event.kind.title) From This Process") {
            ForEach(SignatureStatus.allCases, id: \.self) { status in
                Button(status == .unclassified ? "Clear Rule" : status.title) {
                    signatures.setProcessRule(status, kind: event.kind, process: event.signatureProcess)
                }
                .disabled(status == .safe && !SignatureStore.canTrustWholeProcess(event.signatureProcess))
            }
        }
        Menu("Exclude") {
            ForEach(event.exclusionSuggestions, id: \.1) { title, pattern in
                Button(title) { model.addExclusion(pattern) }
            }
            Divider()
            Button("Edit Exclusions…", action: actions.openExclusions)
        }
        Divider()
        Button("Copy Detail") { copy(event.target) }
        Button("Copy Process Path") { copy(event.proc) }
            .disabled(event.proc.isEmpty)
        if event.kind == .file || event.kind == .exec {
            Button("Reveal in Finder") {
                NSWorkspace.shared.selectFile(event.target, inFileViewerRootedAtPath: "")
            }
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
