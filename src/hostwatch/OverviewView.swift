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

/// Overview: "is my Mac OK?" in ten seconds: protection status, what needs you, stories, heavy
/// processes and the last 24 hours, each card leading to its tab.
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
    @StateObject private var ui = OverviewState()

    private let columns = [GridItem(.adaptive(minimum: 320), spacing: 14, alignment: .top)]

    var body: some View {
        let _ = signatures.revision
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                headline
                LazyVGrid(columns: columns, alignment: .leading, spacing: 14) {
                    protectionCard
                    needsYouCard
                    knownBadCard
                    storiesCard
                    vulnerabilitiesCard
                    heavyCard
                    lastDayCard
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .sheet(isPresented: $ui.showVulns) { VulnerabilityList(intel: intel, close: { ui.showVulns = false }) }
    }

    // MARK: Headline

    private var dangerous: [Story] { stories.stories.filter { !$0.dismissed && $0.severity == .dangerous } }

    private var headline: some View {
        let ok = (model.connected || collector.isRunning) && dangerous.isEmpty && recentHits.isEmpty
        return HStack(spacing: 12) {
            Image(systemName: ok ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.system(size: 34))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(ok ? Color.green : dangerous.isEmpty ? Color.orange : Color.red)
            VStack(alignment: .leading, spacing: 2) {
                Text(ok ? "Your Mac looks fine" : !dangerous.isEmpty ? "Something needs a look"
                     : "Hostwatch isn't watching right now")
                    .font(.title2.weight(.semibold))
                Text(summary).font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var summary: String {
        var parts: [String] = []
        if !recentHits.isEmpty { parts.append("\(recentHits.count) known-bad \(recentHits.count == 1 ? "match" : "matches")") }
        if intel.vulnerabilitiesEnabled, intel.pendingUpdate != nil, intel.unfixedCount > 0 {
            parts.append("a macOS update fixes \(intel.unfixedCount) exploited \(intel.unfixedCount == 1 ? "flaw" : "flaws")")
        }
        if !dangerous.isEmpty { parts.append("\(dangerous.count) dangerous \(dangerous.count == 1 ? "story" : "stories")") }
        let waiting = needsYou
        if waiting > 0 { parts.append("\(waiting) \(waiting == 1 ? "thing" : "things") to decide") }
        if !vitals.heavyNow.isEmpty { parts.append("\(vitals.heavyNow.count) heavy \(vitals.heavyNow.count == 1 ? "process" : "processes")") }
        return parts.isEmpty ? "Nothing needs you. Hostwatch keeps watching." : parts.joined(separator: " · ")
    }

    private var needsYou: Int { (baseline.report?.review.count ?? 0) + rules.proposals.count }

    // MARK: Threats

    private var recentHits: [ThreatHit] {
        let since = Date().addingTimeInterval(-7 * 86400)
        return intel.hits.filter { $0.date >= since }.reversed()
    }

    private var threatListsText: String {
        guard intel.enabled else { return "off (Settings ▸ Threat Intelligence)" }
        if intel.updating { return "updating…" }
        let domains = intel.states[ThreatIntel.Feed.hagezi.rawValue]
        guard let updated = domains?.updated else { return "not downloaded yet" }
        return "\(domains?.count.formatted() ?? "0") entries · updated \(StoryEngine.ago(updated))"
    }

    private var knownBadCard: some View {
        let hits = recentHits
        return OverviewCard(title: "Known bad", symbol: "xmark.octagon", count: hits.count, tint: .red) {
            if !intel.enabled {
                Text("Threat lists are off.").foregroundStyle(.secondary)
            } else if hits.isEmpty {
                Text("No contact with known malware in the last 7 days.").foregroundStyle(.secondary)
            } else {
                ForEach(hits.prefix(3)) { h in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Image(systemName: h.kind == .file ? "doc.fill" : "globe").foregroundStyle(.red)
                            Text(h.kind == .file ? (h.path as NSString).lastPathComponent : h.indicator).fontWeight(.semibold)
                                .lineLimit(1).truncationMode(.middle)
                            if !h.process.isEmpty { Text("· \(h.process)").foregroundStyle(.secondary).lineLimit(1) }
                            Spacer(minLength: 4)
                            Text(StoryEngine.ago(h.date)).font(.caption).foregroundStyle(.secondary)
                        }
                        Text(h.summary + (h.retro ? " · contacted earlier" : "")).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }
                }
                Button("Show Stories") { model.windowTab = 2 }.buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    private var vulnerabilitiesCard: some View {
        let recent = intel.recentVulns()
        let unfixed = intel.unfixedCount
        return OverviewCard(title: "macOS vulnerabilities", symbol: "exclamationmark.shield", count: unfixed,
                            tint: unfixed > 0 ? .orange : .green) {
            if !intel.vulnerabilitiesEnabled {
                Text("Off (Settings ▸ Threat Intelligence).").foregroundStyle(.secondary)
            } else if recent.isEmpty {
                Text(intel.states[ThreatIntel.Feed.kev.rawValue]?.updated == nil ? "Not checked yet."
                     : "No newly exploited macOS flaws in the last 90 days.").foregroundStyle(.secondary)
            } else {
                if let pending = intel.pendingUpdate {
                    Label("\(pending) is waiting: it fixes \(unfixed) actively exploited \(unfixed == 1 ? "flaw" : "flaws").",
                          systemImage: "arrow.down.circle.fill").foregroundStyle(.orange)
                } else if unfixed > 0 {
                    Label("\(unfixed) exploited \(unfixed == 1 ? "flaw was" : "flaws were") published after your last macOS update.",
                          systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                } else {
                    Label("Your macOS is up to date for the \(recent.count) flaws exploited in the last 90 days.",
                          systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                }
                ForEach(recent.prefix(2)) { v in
                    Text("\(v.cve) · \(v.component) · added \(v.dateAdded.formatted(date: .abbreviated, time: .omitted))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button("Show List") { ui.showVulns = true }.buttonStyle(.glass)
                    if intel.pendingUpdate != nil || unfixed > 0 {
                        Button("Open Software Update") { VulnerabilityList.openSoftwareUpdate() }.buttonStyle(.glassProminent)
                    }
                }
                .controlSize(.small)
            }
        }
    }

    // MARK: Cards

    private var protectionCard: some View {
        OverviewCard(title: "Protection", symbol: "shield.lefthalf.filled") {
            StatusLine(ok: model.connected || collector.isRunning, text: "Collector",
                       detail: model.connected ? "watching" : collector.statusText)
            StatusLine(ok: baseline.phase == .done, text: "Baseline", detail: baseline.statusText)
            StatusLine(ok: history.enabled, text: "History", detail: history.statusText)
            StatusLine(ok: intel.enabled && intel.states[ThreatIntel.Feed.hagezi.rawValue]?.updated != nil,
                       text: "Threat lists", detail: threatListsText)
            if let s = metrics.latest {
                StatusLine(ok: true, text: "This Mac",
                           detail: "CPU \(Int(s.cpu.rounded()))% · memory \(Int((s.mem * 100).rounded()))%")
            }
            if !(model.connected || collector.isRunning) {
                Button("Start Collector…", action: actions.toggleCollector).buttonStyle(.glassProminent).controlSize(.small)
            }
        }
    }

    private var needsYouCard: some View {
        OverviewCard(title: "Needs you", symbol: "checklist", count: needsYou) {
            if needsYou == 0 {
                Text("Nothing to decide.").foregroundStyle(.secondary)
            } else {
                if let review = baseline.report?.review, !review.isEmpty {
                    Text("\(review.count) app\(review.count == 1 ? "" : "s"): " + review.prefix(4).map(\.app).joined(separator: ", ")
                         + (review.count > 4 ? "…" : ""))
                        .lineLimit(2)
                }
                if !rules.proposals.isEmpty {
                    Text("\(rules.proposals.count) rule proposal\(rules.proposals.count == 1 ? "" : "s") from Claude")
                }
                Button("Open Needs You", action: openNeedsYou).buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    private var storiesCard: some View {
        let open = stories.stories.filter { !$0.dismissed }.sorted { $0.lastSeen > $1.lastSeen }
        return OverviewCard(title: "Stories", symbol: "point.3.connected.trianglepath.dotted", count: open.count,
                            tint: dangerous.isEmpty ? .orange : .red) {
            if open.isEmpty {
                Text("No suspicious chains.").foregroundStyle(.secondary)
            } else {
                ForEach(open.prefix(3)) { story in
                    Button { actions.openStory(story) } label: {
                        HStack(spacing: 6) {
                            Circle().fill(story.severity.color).frame(width: 7, height: 7)
                            Text(story.title).lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 4)
                            Text(StoryEngine.ago(story.lastSeen)).font(.caption).foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                Button("Show All Stories") { model.windowTab = 2 }.buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    private var heavyCard: some View {
        let heavy = vitals.snapshot
        return OverviewCard(title: "Heavy processes", symbol: "flame", count: heavy.count, tint: .orange) {
            if heavy.isEmpty {
                Text("Nothing you started is using a lot.").foregroundStyle(.secondary)
            } else {
                ForEach(heavy.prefix(3)) { h in
                    HStack(spacing: 6) {
                        Text(h.name).fontWeight(.medium)
                        if h.untrusted { Text("Untrusted").font(.caption2.weight(.semibold)).foregroundStyle(.red) }
                        Spacer(minLength: 4)
                        Text("\(Int(h.cpu))% · \(ProcessVitals.memory(h.mem))").font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                Button("Show in Events") { model.windowTab = 0 }.buttonStyle(.glass).controlSize(.small)
            }
        }
    }

    private var lastDayCard: some View {
        let since = Date().addingTimeInterval(-24 * 3600)
        let newPatterns = signatures.allEntries.filter { $0.firstSeen >= since }.count
        let decided = signatures.allEntries.filter { $0.firstSeen >= since && $0.status != .unclassified }.count
        let newDomains = domains.records.values.filter { $0.firstSeen >= since && !$0.baseline }.count
        let storiesToday = stories.stories.filter { $0.lastSeen >= since }.count
        return OverviewCard(title: "Last 24 hours", symbol: "clock") {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow { Number(value: newPatterns, label: "new patterns"); Number(value: decided, label: "decided automatically or by you") }
                GridRow { Number(value: newDomains, label: "new domains"); Number(value: storiesToday, label: "stories") }
            }
        }
    }
}

/// A rounded card with a header (symbol, title, optional count).
struct OverviewCard<Content: View>: View {
    let title: String
    let symbol: String
    var count: Int? = nil
    var tint: Color = .accentColor
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: symbol).symbolRenderingMode(.hierarchical).foregroundStyle(tint)
                Text(title).font(.headline)
                if let count, count > 0 {
                    Text("\(count)").font(.caption.weight(.semibold).monospacedDigit()).foregroundStyle(.white)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(tint))
                }
                Spacer()
            }
            VStack(alignment: .leading, spacing: 6) { content }
                .font(.callout)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.secondary.opacity(0.07)))
    }
}

private struct StatusLine: View {
    let ok: Bool
    let text: String
    let detail: String

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(ok ? Color.green : Color.orange).frame(width: 8, height: 8)
            Text(text).fontWeight(.medium).frame(width: 74, alignment: .leading)
            Text(detail).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
        }
    }
}

private struct Number: View {
    let value: Int
    let label: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(value)").font(.title3.weight(.semibold).monospacedDigit())
            Text(label).foregroundStyle(.secondary).lineLimit(1)
        }
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
