import AppKit
import SwiftUI

/// The window's tab bar: icon and title per tab, counts as small badges; icons only when the window is
/// narrow. (The native segmented control drops the icons and puts counts into the titles.)
struct WindowTabBar: View {
    struct Tab: Identifiable {
        let id: Int              // HUDModel.windowTab
        let title: String
        let symbol: String
        var badge: String? = nil
        var badgeTint: Color = .secondary
    }

    let tabs: [Tab]
    @Binding var selection: Int

    var body: some View {
        ViewThatFits(in: .horizontal) {
            bar(showTitles: true)
            bar(showTitles: false)
        }
    }

    private func bar(showTitles: Bool) -> some View {
        HStack(spacing: 2) {
            ForEach(Array(tabs.enumerated()), id: \.element.id) { i, tab in
                let selected = selection == tab.id
                Button { selection = tab.id } label: {
                    HStack(spacing: 5) {
                        Image(systemName: tab.symbol)
                            .symbolVariant(selected ? .fill : .none)
                            .font(.system(size: 12, weight: .medium))
                        if showTitles { Text(tab.title).font(.system(size: 12, weight: selected ? .semibold : .regular)) }
                        if let badge = tab.badge {
                            Text(badge)
                                .font(.system(size: 10, weight: .semibold).monospacedDigit())
                                .foregroundStyle(.white)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(tab.badgeTint))
                        }
                    }
                    .padding(.horizontal, showTitles ? 10 : 8)
                    .padding(.vertical, 5)
                    .foregroundStyle(selected ? Color.primary : Color.secondary)
                    .background {
                        if selected { Capsule().fill(Color.primary.opacity(0.12)) }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .help("\(tab.title) (⌘\(i + 1))")
                .accessibilityLabel(tab.title)
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .padding(3)
    }
}

/// Overview: "is my Mac OK?" in ten seconds, in the style of System Settings' status pages. A status header,
/// four tiles that lead to their tab, then only what needs action (one row each, with its button), then the
/// protection status as grouped rows, then the last 24 hours. The all-clear stays quiet.
struct OverviewView: View {
    @ObservedObject var model: HUDModel
    @ObservedObject var collector: Collector
    @ObservedObject var stories: StoryEngine
    @ObservedObject var domains: DomainRegistry
    @ObservedObject var rules: RuleBook
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var vitals: ProcessVitals
    @ObservedObject var history: HistoryRecorder
    @ObservedObject var metrics: MetricsStore
    @ObservedObject var intel: ThreatIntel
    let actions: HUDActions
    /// Opens Rules ▸ Needs You.
    let openNeedsYou: () -> Void
    /// Off only for rendering previews (scroll views don't render offscreen).
    var scrollable = true
    @StateObject private var ui = OverviewState()

    var body: some View {
        let _ = signatures.revision
        let _ = intel.revision
        Group {
            if scrollable { ScrollView { page } } else { page }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $ui.showVulns) { VulnerabilityList(intel: intel, close: { ui.showVulns = false }) }
    }

    private var page: some View {
        VStack(alignment: .leading, spacing: 28) {
            header
            tiles
            attentionSection
            protectionSection
            lastDaySection
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 28)
        .frame(maxWidth: 860)
        .frame(maxWidth: .infinity)
    }

    // MARK: State

    private var watching: Bool { model.connected || collector.isRunning }
    private var dangerous: [Story] { stories.stories.filter { !$0.dismissed && $0.severity == .dangerous } }
    private var openStories: [Story] { stories.stories.filter { !$0.dismissed }.sorted { $0.lastSeen > $1.lastSeen } }
    private var recentHits: [ThreatHit] {
        let since = Date().addingTimeInterval(-7 * 86400)
        return intel.hits.filter { $0.date >= since }.reversed()
    }
    private var needsYou: Int { (baseline.report?.review.count ?? 0) + rules.proposals.count }
    private var unfixed: Int { intel.vulnerabilitiesEnabled ? intel.unfixedCount : 0 }

    private enum Level { case ok, attention, danger }
    private var level: Level {
        if !recentHits.isEmpty || !dangerous.isEmpty { return .danger }
        if !watching || unfixed > 0 || !openStories.isEmpty { return .attention }
        return .ok
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: level == .ok ? "checkmark.shield.fill" : level == .danger ? "xmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 44))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(level == .ok ? Color.green : level == .danger ? Color.red : Color.orange)
                .contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.largeTitle.weight(.semibold))
                Text(subtitle).font(.title3).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }

    private var title: String {
        switch level {
        case .ok: return "Your Mac looks fine"
        case .danger: return "Something needs a look"
        case .attention: return watching ? "A few things to check" : "Hostwatch isn't watching"
        }
    }

    private var subtitle: String {
        if !watching { return "Start the collector to see what happens on this Mac." }
        let watched = model.counts.values.reduce(0, +)
        return level == .ok ? "Watching processes, files and connections · \(watched.formatted()) events this session"
            : "Watching processes, files and connections"
    }

    // MARK: Tiles

    private var tiles: some View {
        HStack(spacing: 12) {
            Tile(value: needsYou, title: "Needs You", symbol: "checklist", tint: .accentColor) { openNeedsYou() }
            Tile(value: openStories.count, title: "Stories", symbol: "point.3.connected.trianglepath.dotted",
                 tint: dangerous.isEmpty ? .orange : .red) { model.windowTab = 2 }
            Tile(value: recentHits.count, title: "Known Bad", symbol: "xmark.octagon", tint: .red) { model.windowTab = 2 }
            Tile(value: vitals.heavyNow.count, title: "Heavy Now", symbol: "flame", tint: .orange) { model.windowTab = 0 }
        }
    }

    // MARK: Needs attention

    @ViewBuilder private var attentionSection: some View {
        let rows = attentionRows
        Section2(title: "Needs attention") {
            if rows.isEmpty {
                RowGroup {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark.circle.fill").font(.title2).foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Nothing needs your attention").font(.body.weight(.medium))
                            Text("New things to decide, suspicious chains and known threats appear here.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(.vertical, 4)
                }
            } else {
                RowGroup {
                    ForEach(Array(rows.enumerated()), id: \.offset) { i, row in
                        if i > 0 { Divider().padding(.leading, 44) }
                        row
                    }
                }
            }
        }
    }

    private var attentionRows: [AttentionRow] {
        var rows: [AttentionRow] = []
        if !watching {
            rows.append(AttentionRow(symbol: "eye.slash", tint: .orange, title: "The collector isn't running",
                                     detail: collector.statusText, action: "Start…", perform: actions.toggleCollector))
        }
        var covered = Set<UUID>()
        for h in recentHits.prefix(3) {
            let story = stories.stories.first { $0.steps.contains { $0.stage == .knownBad && ($0.note.contains(h.indicator) || $0.detail.contains(h.indicator)) } }
            if let story { covered.insert(story.id) }
            rows.append(AttentionRow(symbol: "xmark.octagon.fill", tint: .red,
                                     title: "\(h.process.isEmpty ? "A program" : h.process) \(h.kind == .file ? "is known malware" : "contacted \(h.indicator)")",
                                     detail: h.summary + (h.retro ? " · found in earlier activity" : "") + " · " + StoryEngine.ago(h.date),
                                     action: story == nil ? "Show Stories" : "Open Story",
                                     perform: { if let story { actions.openStory(story) } else { model.windowTab = 2 } }))
        }
        for story in dangerous.filter({ !covered.contains($0.id) }).prefix(3) {
            let known = story.steps.first { $0.stage == .knownBad }
            rows.append(AttentionRow(symbol: known == nil ? "exclamationmark.triangle.fill" : "xmark.octagon.fill", tint: .red,
                                     title: known.map { "\($0.name) contacted known malware infrastructure" } ?? story.title,
                                     detail: (known?.note ?? story.stages.map(\.title).joined(separator: " · ")) + " · " + StoryEngine.ago(story.lastSeen),
                                     action: "Open Story", perform: { actions.openStory(story) }))
        }
        if unfixed > 0 {
            rows.append(AttentionRow(symbol: "exclamationmark.shield.fill", tint: .orange,
                                     title: intel.pendingUpdate.map { "Install \($0)" } ?? "Exploited macOS flaws since your last update",
                                     detail: "\(unfixed) actively exploited \(unfixed == 1 ? "flaw" : "flaws") \(intel.pendingUpdate == nil ? "published after your last update" : "fixed by it")",
                                     action: "Software Update", perform: VulnerabilityList.openSoftwareUpdate,
                                     secondary: "Details", performSecondary: { ui.showVulns = true }))
        }
        if needsYou > 0 {
            let apps = baseline.report?.review.prefix(3).map(\.app).joined(separator: ", ") ?? ""
            rows.append(AttentionRow(symbol: "checklist", tint: .accentColor,
                                     title: "\(needsYou) \(needsYou == 1 ? "thing" : "things") to decide",
                                     detail: apps.isEmpty ? "\(rules.proposals.count) rule proposals from Claude" : apps + ((baseline.report?.review.count ?? 0) > 3 ? "…" : ""),
                                     action: "Review", perform: openNeedsYou))
        }
        for h in vitals.snapshot.filter(\.untrusted).prefix(2) {
            rows.append(AttentionRow(symbol: "flame.fill", tint: .orange, title: "\(h.name) is running heavy",
                                     detail: "Untrusted program · \(Int(h.cpu))% CPU · \(ProcessVitals.memory(h.mem))",
                                     action: "Show", perform: { model.windowTab = 0 }))
        }
        return rows
    }

    // MARK: Protection

    private var protectionSection: some View {
        Section2(title: "Protection") {
            RowGroup {
                StatusRow(symbol: "dot.radiowaves.left.and.right", state: watching ? .on : .off, title: "Collector",
                          detail: model.connected ? "Watching processes, files and connections" : collector.statusText)
                Divider().padding(.leading, 44)
                StatusRow(symbol: "checkmark.seal", state: baseline.phase == .done ? .on : baseline.phase == .idle ? .off : .pending,
                          title: "Baseline", detail: baseline.statusText, label: baseline.phase == .idle ? "Not set up" : nil)
                Divider().padding(.leading, 44)
                StatusRow(symbol: "xmark.shield", state: threatState, title: "Known threats", detail: threatText)
                Divider().padding(.leading, 44)
                StatusRow(symbol: "exclamationmark.shield", state: !intel.vulnerabilitiesEnabled ? .off : unfixed > 0 ? .warning : .on,
                          title: "macOS", detail: macText, accessory: intel.vulns.isEmpty ? nil : AnyView(
                            Button("Details") { ui.showVulns = true }.buttonStyle(.link)))
                Divider().padding(.leading, 44)
                StatusRow(symbol: "clock.arrow.circlepath", state: history.enabled ? .on : .off, title: "History",
                          detail: history.statusText.replacingOccurrences(of: "History ", with: "")
                            .replacingOccurrences(of: "Zero KB", with: "0 KB"))
            }
        }
    }

    private var threatState: StatusRow.State {
        guard intel.enabled else { return .off }
        if intel.updating { return .pending }
        return intel.states[ThreatIntel.Feed.hagezi.rawValue]?.updated == nil ? .pending : .on
    }

    private var threatText: String {
        guard intel.enabled else { return "Off · Settings ▸ Threat Intelligence" }
        if intel.updating { return "Updating the lists…" }
        let lists = ThreatIntel.Feed.allCases.filter { $0 != .kev && intel.states[$0.rawValue]?.updated != nil }
        let entries = lists.reduce(0) { $0 + (intel.states[$1.rawValue]?.count ?? 0) }
        guard let updated = lists.compactMap({ intel.states[$0.rawValue]?.updated }).max() else { return "Lists not downloaded yet" }
        return "\(entries.formatted()) entries from \(lists.count) \(lists.count == 1 ? "list" : "lists") · updated \(StoryEngine.ago(updated))"
    }

    private var macText: String {
        guard intel.vulnerabilitiesEnabled else { return "Not checked · Settings ▸ Threat Intelligence" }
        let version = intel.osVersion.replacingOccurrences(of: "Version ", with: "")
        if let pending = intel.pendingUpdate { return "\(version) · \(pending) is waiting" }
        let recent = intel.recentVulns().count
        if unfixed > 0 { return "\(version) · \(unfixed) exploited \(unfixed == 1 ? "flaw" : "flaws") since your last update" }
        return recent == 0 ? "\(version) · no newly exploited flaws in 90 days"
            : "\(version) · up to date for \(recent) recently exploited \(recent == 1 ? "flaw" : "flaws")"
    }

    // MARK: Last 24 hours

    private var lastDaySection: some View {
        let since = Date().addingTimeInterval(-24 * 3600)
        let fresh = signatures.allEntries.filter { $0.firstSeen >= since }
        let decided = fresh.filter { $0.status != .unclassified }.count
        let newDomains = domains.records.values.filter { $0.firstSeen >= since && !$0.baseline }.count
        let storiesToday = stories.stories.filter { $0.lastSeen >= since }.count
        return Section2(title: "Last 24 hours") {
            RowGroup {
                HStack(spacing: 0) {
                    Figure(value: fresh.count, label: "new patterns")
                    Figure(value: decided, label: "decided for you", detail: fresh.isEmpty ? nil : "\(decided * 100 / max(fresh.count, 1))%")
                    Figure(value: newDomains, label: "new domains")
                    Figure(value: storiesToday, label: storiesToday == 1 ? "story" : "stories")
                }
                .padding(.vertical, 6)
            }
        }
    }
}

// MARK: - Building blocks

/// A section title above a group, like System Settings.
private struct Section2<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline).foregroundStyle(.secondary).padding(.leading, 4)
            content
        }
    }
}

/// Grouped rows on a rounded background (System Settings' inset group).
private struct RowGroup<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color(nsColor: .controlBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.primary.opacity(0.07), lineWidth: 0.5))
    }
}

/// A big number with its label; the whole tile leads to its tab.
private struct Tile: View {
    let value: Int
    let title: String
    let symbol: String
    let tint: Color
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            VStack(alignment: .leading, spacing: 8) {
                Image(systemName: symbol)
                    .font(.title3)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(value > 0 ? tint : Color.secondary)
                Text("\(value)").font(.system(size: 28, weight: .semibold, design: .rounded).monospacedDigit())
                    .foregroundStyle(value > 0 ? Color.primary : Color.secondary)
                Text(title).font(.callout).foregroundStyle(.secondary)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color(nsColor: .controlBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(value > 0 ? tint.opacity(0.35) : Color.primary.opacity(0.07), lineWidth: value > 0 ? 1 : 0.5))
            .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title): \(value)")
        .help("Open \(title)")
    }
}

/// One thing to act on: icon, what, why, and the button that does it.
private struct AttentionRow: View {
    let symbol: String
    let tint: Color
    let title: String
    let detail: String
    let action: String
    let perform: () -> Void
    var secondary: String? = nil
    var performSecondary: () -> Void = {}

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.title3)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium)).lineLimit(1).truncationMode(.middle)
                Text(detail).font(.callout).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer(minLength: 12)
            if let secondary { Button(secondary, action: performSecondary).buttonStyle(.glass) }
            Button(action, action: perform).buttonStyle(.glass)
        }
        .controlSize(.regular)
        .padding(.vertical, 8)
    }
}

/// A protection line: icon, name, what it's doing, and an on/off/warning state.
private struct StatusRow: View {
    enum State { case on, off, pending, warning }
    let symbol: String
    let state: State
    let title: String
    let detail: String
    var accessory: AnyView? = nil
    /// Overrides the state's word ("Not set up").
    var label: String? = nil

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.body)
                .foregroundStyle(.secondary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.body)
                Text(detail).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            }
            Spacer(minLength: 12)
            if let accessory { accessory }
            HStack(spacing: 5) {
                Circle().fill(color).frame(width: 8, height: 8)
                Text(label ?? stateLabel).font(.callout).foregroundStyle(.secondary)
            }
            .frame(minWidth: 70, alignment: .trailing)
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
    }

    private var color: Color {
        switch state { case .on: return .green; case .off: return .secondary; case .pending: return .yellow; case .warning: return .orange }
    }
    private var stateLabel: String {
        switch state { case .on: return "On"; case .off: return "Off"; case .pending: return "Starting"; case .warning: return "Check" }
    }
}

/// "142 new patterns" in the last-24-hours row.
private struct Figure: View {
    let value: Int
    let label: String
    var detail: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(value.formatted()).font(.title2.weight(.semibold).monospacedDigit())
                if let detail { Text(detail).font(.callout).foregroundStyle(.secondary) }
            }
            Text(label).font(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

final class OverviewState: ObservableObject {
    @Published var showVulns = false
}

/// The sheet: actively exploited macOS flaws (CISA), newest first, and whether this Mac is protected.
struct VulnerabilityList: View {
    @ObservedObject var intel: ThreatIntel
    let close: () -> Void

    static func openSoftwareUpdate() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Actively exploited macOS vulnerabilities").font(.title3.weight(.semibold))
                Text("From CISA's Known Exploited Vulnerabilities list · this Mac: \(intel.osVersion)"
                     + (intel.osUpdated.map { ", updated \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""))
                    .font(.callout).foregroundStyle(.secondary)
            }
            .padding(20)
            Divider()
            List(intel.vulns.prefix(60)) { v in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(v.cve).font(.body.monospaced().weight(.semibold)).textSelection(.enabled)
                        Text(v.component).font(.caption.weight(.medium)).padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Capsule().fill(Color.secondary.opacity(0.15)))
                        if v.ransomware {
                            Text("Ransomware").font(.caption.weight(.semibold)).foregroundStyle(.red)
                        }
                        Spacer()
                        Text("added \(v.dateAdded.formatted(date: .abbreviated, time: .omitted))").font(.caption).foregroundStyle(.secondary)
                    }
                    Text(v.description).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 10) {
                        switch intel.status(v) {
                        case .likelyFixed(let date):
                            Label("Likely fixed: macOS was updated \(date.formatted(date: .abbreviated, time: .omitted))",
                                  systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        case .fixedByPendingUpdate(let update):
                            Label("Fixed by the waiting update (\(update))", systemImage: "arrow.down.circle.fill").foregroundStyle(.orange)
                        case .notFixed:
                            Label("Not fixed by your last macOS update", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                        if let advisory = v.advisory, let url = URL(string: advisory) {
                            Link("Apple advisory", destination: url)
                        }
                    }
                    .font(.caption)
                }
                .padding(.vertical, 4)
            }
            Divider()
            HStack {
                Text("CISA doesn't name fixed versions: \"likely fixed\" means macOS was updated after the flaw was listed.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Software Update") { Self.openSoftwareUpdate() }
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 720, height: 560)
    }
}
