import AppKit
import SwiftUI

/// Rules ▸ Protection ▸ Overview, built like a System Settings pane: the state with its one next action, a card per
/// area (mode, what it does, today), then the pages to go on to as a grouped list. How enforcement works sits behind
/// the Help button, not in the page. A readable width, so rows don't stretch across a wide window.
struct ProtectionOverview: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    var connections: () -> [(FirewallEntry, FirewallDecision)] = { [] }
    let go: (RulesSegment) -> Void
    @StateObject private var help = ExpandState()

    static let readableWidth: CGFloat = 1100

    var body: some View {
        let _ = protection.revision
        let found = connections()
        VStack(alignment: .leading, spacing: 20) {
            header
            HStack(alignment: .top, spacing: 14) {
                ForEach(ProtectionArea.allCases, id: \.self) { area in AreaCard(protection: protection, area: area, go: go) }
                if let firewall { FirewallCard(firewall: firewall, connections: found, go: go) }
            }
            .fixedSize(horizontal: false, vertical: true)         // every card as tall as the tallest
            next(found)
        }
        .frame(maxWidth: Self.readableWidth, alignment: .leading)
    }

    // MARK: State

    private var state: ProtectionState {
        protection.state(network: firewall?.mode ?? .off)
    }

    private var tint: Color {
        switch state {
        case .off: .secondary
        case .rehearsing: .purple
        case .protecting: .green
        case .paused: .orange
        }
    }

    private var title: String {
        switch state {
        case .off: "Protection is off"
        case .rehearsing: "Rehearsing"
        case .protecting: "Protecting"
        case .paused: "Paused until \(protection.pausedUntil?.formatted(date: .omitted, time: .shortened) ?? "")"
        }
    }

    private var sentence: String {
        // Only areas that enforce stop anything: a watched area's blocks are "would have been".
        let areas = ProtectionArea.allCases
        let stopped = areas.filter { protection.mode($0).enforces }.reduce(0) { $0 + protection.count($1, .block) }
        let would = areas.filter { protection.mode($0) == .watch }.reduce(0) { $0 + protection.count($1, .block) }
        switch state {
        case .off: return "Nothing is checked. Start by watching: Hostwatch shows what it would stop, and stops nothing."
        case .rehearsing:
            return would == 0 ? "Nothing is stopped. Nothing would have been today."
                : "Nothing is stopped. Today \(would) would have been. Decide those in Found, then turn on Ask."
        case .protecting:
            let first = stopped == 0 ? "Nothing stopped today." : "Today \(stopped) stopped."
            return would == 0 ? first : first + " \(would) more would have been where you only watch."
        case .paused: return "Nothing is checked or stopped until then, rehearsal included."
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: state == .paused ? "pause.circle.fill" : state == .off ? "shield.slash" : "checkmark.shield.fill")
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(tint)
                .symbolRenderingMode(.hierarchical)
                .frame(width: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.title2.weight(.semibold))
                Text(sentence).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            switch state {
            case .off: Button("Start Watching") { startWatching() }.buttonStyle(.glassProminent)
            case .paused: Button("Resume") { protection.resume() }.buttonStyle(.glassProminent)
            default: Button("Pause for 15 Minutes") { protection.pause(minutes: 15) }.buttonStyle(.glass)
            }
            HelpLink { help.open.toggle() }
                .popover(isPresented: $help.open, arrowEdge: .bottom) { howItWorks }
        }
        .controlSize(.large)
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(tint.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(tint.opacity(0.22), lineWidth: 0.5))
        .accessibilityElement(children: .contain)
    }

    /// Watch everywhere: the safe first step, it stops nothing and shows what would be stopped.
    private func startWatching() {
        for area in ProtectionArea.allCases where protection.mode(area) == .off { protection.setMode(.watch, for: area) }
        if let firewall, firewall.mode == .off { firewall.mode = .watch }
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("How protection works").font(.headline)
            modeLine("Watch", "Stops nothing. What would be stopped is marked in Events and listed in Found.")
            modeLine("Ask", "Stops what you blocked. Something new waits for your answer.")
            modeLine("Strict", "Stops everything nobody allowed.")
            Divider()
            Text(protection.enforcer.text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .padding(16)
        .frame(width: 340)
    }

    private func modeLine(_ mode: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(mode).fontWeight(.semibold).frame(width: 48, alignment: .leading)
            Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Next

    /// The other pages, as System Settings lists them: a tile, a title, the value, a chevron.
    private func next(_ found: [(FirewallEntry, FirewallDecision)]) -> some View {
        let groups = ProtectedGroup.all.filter { (protection.groups[$0.id] ?? ProtectedGroupSetting()).on }.count
        let yours = protection.customPlaces.filter(\.on).count
        // The same two numbers the sidebar and the cards use: everything to review, and what would be stopped.
        let review = protection.findings.count + found.count
        let stops = protection.findings.values.filter { $0.verdict == .block }.count + found.filter { $0.1.verdict == .block }.count
        return VStack(alignment: .leading, spacing: 8) {
            VStack(spacing: 0) {
                OverviewRow(symbol: "lock.doc.fill", color: .blue, title: "Protected Files and Folders",
                            value: "\(groups) of \(ProtectedGroup.all.count) groups on" + (yours > 0 ? ", \(yours) of yours" : "")) {
                    go(.protectedFiles)
                }
                Divider().padding(.leading, 46)
                OverviewRow(symbol: "exclamationmark.shield.fill", color: stops > 0 ? .red : .gray, title: "Found",
                            value: review == 0 ? "Nothing to review" : "\(review.formatted()) to review",
                            detail: stops > 0 ? "\(stops.formatted()) would be stopped" : nil) {
                    go(.protectionFound)
                }
            }
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.35)))
            if state != .off {
                Text("Watching since \(protection.since.formatted(date: .abbreviated, time: .omitted))")
                    .font(.caption).foregroundStyle(.tertiary).padding(.leading, 4)
            }
        }
    }
}

/// A System Settings row: coloured tile, title, value (and a second, warning value), chevron. The whole row clicks.
private struct OverviewRow: View {
    let symbol: String
    let color: Color
    let title: String
    let value: String
    var detail: String? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 24, height: 24)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(color.gradient))
                Text(title)
                Spacer(minLength: 12)
                if let detail { Text(detail).foregroundStyle(.red).monospacedDigit() }
                Text(value).foregroundStyle(.secondary).monospacedDigit()
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel([title, detail, value].compactMap { $0 }.joined(separator: ", "))
    }
}

/// A card's last row: where to go from here, the same in every card.
private struct CardFooter: View {
    let title: String
    var count: Int? = nil
    let action: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Divider().padding(.bottom, 8)
            Button(action: action) {
                HStack {
                    Text(title)
                    Spacer()
                    if let count { Text(count.formatted()).foregroundStyle(.secondary).monospacedDigit() }
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                }
                .font(.callout)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }
}

/// What an Off card shows instead of empty numbers: what turning it on would give you.
private struct OffHint: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "chart.bar.xaxis")
            .font(.caption).foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Launches or Files: the four modes as a segmented control, what the chosen one does, and today's numbers.
private struct AreaCard: View {
    @ObservedObject var protection: ProtectionMonitor
    let area: ProtectionArea
    let go: (RulesSegment) -> Void

    private var mode: ProtectionMode { protection.mode(area) }

    /// The chosen mode in one sentence, in this area's words.
    private var explanation: String {
        switch (area, mode) {
        case (.launches, .off): "Launches aren't checked."
        case (.launches, .watch): "Nothing is stopped. Launches that would be are marked in Events."
        case (.launches, .ask): "Stops launches you blocked. Pauses new ones and asks you."
        case (.launches, .strict): "Stops every launch nobody allowed."
        case (.files, .off): "Protected places aren't checked."
        case (.files, .watch): "Nothing is stopped. Programs that would be are marked in Events."
        case (.files, .ask): "Stops programs you blocked. Pauses unexpected ones and asks you."
        case (.files, .strict): "Stops every program not expected in a protected place."
        }
    }

    var body: some View {
        let findings = protection.findings.values.filter { $0.area == area }.count
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                KindTile(kind: area == .launches ? .exec : .file, size: 22)
                Text(area.title).font(.headline)
            }
            Picker(area.title, selection: Binding(get: { mode }, set: { protection.setMode($0, for: area) })) {
                ForEach(ProtectionMode.allCases, id: \.self) { Text($0.short).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(explanation).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minHeight: 34, alignment: .topLeading)
            if area == .launches, mode == .strict {
                Label("Builds and scripts nobody decided yet are stopped too.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
            if mode == .off {
                OffHint(text: "Turn on Watch to see, hour by hour, what would be stopped.")
            } else {
                HStack(spacing: 24) {
                    OverviewFigure(n: protection.count(area, .block), label: mode.enforces ? "stopped today" : "would stop today",
                                   alarming: true)
                    OverviewFigure(n: protection.count(area, .ask), label: mode == .watch ? "would ask today" : "asked today",
                                   alarming: false)
                }
                ProtectionChart(points: ProtectionChart.points(protection.last24(area)),
                                stopLabel: mode.enforces ? "stopped" : "would stop",
                                askLabel: mode == .watch ? "would ask" : "asked")
            }
            Spacer(minLength: 0)
            CardFooter(title: "Found", count: findings) { go(.protectionFound) }
        }
        .modifier(OverviewCard())
    }
}

/// Network: the firewall's four modes, in the same card as Launches and Files, with what the chosen one does.
private struct FirewallCard: View {
    @ObservedObject var firewall: FirewallMonitor
    let connections: [(FirewallEntry, FirewallDecision)]
    let go: (RulesSegment) -> Void

    private var explanation: String {
        switch firewall.mode {
        case .off: "Connections aren't judged."
        case .watch: "Nothing is blocked. Connections that would be are listed in Network."
        case .ask: "Blocks what you blocked. A new connection waits for your answer."
        case .strict: "Only what's allowed connects."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                KindTile(kind: .net, size: 22)
                Text("Network").font(.headline)
            }
            Picker("Network", selection: $firewall.mode) {
                ForEach(FirewallMode.allCases, id: \.self) { Text($0.short).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(explanation).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minHeight: 34, alignment: .topLeading)
            if firewall.mode == .off {
                OffHint(text: "Turn on Watch to see, hour by hour, what would be blocked.")
            } else {
                // The same two numbers as Launches and Files: what it stops (or would), what it asks (or would).
                let block = connections.filter { $0.1.verdict == .block }.count, ask = connections.count - block
                let enforcing = firewall.mode == .ask || firewall.mode == .strict
                HStack(spacing: 24) {
                    OverviewFigure(n: enforcing ? firewall.blockedCount : block, label: enforcing ? "blocked" : "would block",
                                   alarming: true)
                    OverviewFigure(n: ask, label: enforcing ? "asked about" : "would ask", alarming: false)
                }
                // New destinations by the hour they were first seen.
                ProtectionChart(points: ProtectionChart.points(connections),
                                stopLabel: enforcing ? "blocks" : "would block", askLabel: enforcing ? "asks" : "would ask")
            }
            if !firewall.prompts.isEmpty {
                Label("\(firewall.prompts.count) waiting for your answer", systemImage: "hourglass").foregroundStyle(.orange)
                    .font(.callout)
            }
            Spacer(minLength: 0)
            CardFooter(title: "Network Firewall") { go(.firewall) }
        }
        .modifier(OverviewCard())
    }
}

/// A day's number: large and rounded, red only when something was (or would be) stopped.
private struct OverviewFigure: View {
    let n: Int
    let label: String
    let alarming: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(n.formatted()).font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit()
                .foregroundStyle(alarming && n > 0 ? Color.red : Color.primary)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The cards' shared surface.
private struct OverviewCard: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.quaternary.opacity(0.4)))
    }
}
