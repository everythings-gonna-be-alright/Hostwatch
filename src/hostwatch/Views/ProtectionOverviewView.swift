import AppKit
import SwiftUI

/// Protection ▸ Overview, built like a System Settings pane: the state with its one next action, a card per
/// area (mode, what it does, today), then the pages to go on to as a grouped list. How enforcement works sits behind
/// the Help button, not in the page. It fills the window: the charts take the spare height.
struct ProtectionOverview: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    var connections: () -> [(FirewallEntry, FirewallDecision)] = { [] }
    let go: (RulesSegment) -> Void
    @StateObject private var help = ExpandState()
    /// The charts' range, one for every card (a per-viewer convenience, kept between launches).
    @AppStorage("protectionChartRange") private var rangeRaw = ProtectionTimeline.Range.day.rawValue
    /// The visible height of the page: a tall window gives the extra height to the charts, not to empty space.
    @Environment(\.viewportHeight) private var viewport
    @StateObject private var layout = OverviewLayout()

    var body: some View {
        let _ = protection.revision
        let found = connections()
        let range = ProtectionTimeline.Range(rawValue: rangeRaw) ?? .day
        // Every card's buckets first: the cards share one scale, and their numbers are sums of these same buckets.
        var series: [ProtectionArea: [ProtectionTimeline.Bucket]] = [:]
        for area in ProtectionArea.allCases where protection.mode(area) != .off {
            series[area] = ProtectionTimeline.buckets(protection.hourly, area: area, range: range)
        }
        let network = firewall.map { $0.mode == .off ? [] : ProtectionTimeline.buckets(
            firstSeen: found.map { ($0.0.firstSeen, blocked: $0.1.verdict == .block) }, range: range) } ?? []
        // Each card on its own scale, labelled at its top: one shared scale flattened a quiet area to nothing.
        let yMax = 0
        return GlassEffectContainer(spacing: 20) { VStack(alignment: .leading, spacing: 20) {
            header
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Activity in \(range.phrase)").font(.headline)
                    Spacer()
                    Picker("Range", selection: $rangeRaw) {
                        ForEach(ProtectionTimeline.Range.allCases, id: \.self) { Text($0.title).tag($0.rawValue) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                }
                // Three across when they fit, else two and one, else one per row: the cards' mode switches don't shrink,
                // and three of them side by side pushed the page past a narrow window's edge.
                let cards = cardViews(series: series, network: network, range: range, yMax: yMax)
                let columns = Self.columns(width: layout.width, cards: cards.count)
                VStack(spacing: 14) {
                    ForEach(Array(stride(from: 0, to: cards.count, by: columns)), id: \.self) { start in
                        HStack(alignment: .top, spacing: 14) {
                            ForEach(start..<min(start + columns, cards.count), id: \.self) { cards[$0] }
                            // a short last row keeps the cards their width
                            ForEach(0..<(columns - min(columns, cards.count - start)), id: \.self) { _ in
                                Color.clear.frame(maxWidth: .infinity)
                            }
                        }
                        .fixedSize(horizontal: false, vertical: true)     // every card in a row as tall as the tallest
                    }
                }
            }
            next(found)
        }
        .frame(maxWidth: .infinity, alignment: .leading)        // a dashboard fills the window, full screen included
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { layout.content = $0; fit() }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { w in if abs(w - layout.width) >= 1 { layout.width = w } }
        .onChange(of: viewport) { fit() }
        }
    }

    /// The charts take what the window has left over: the page without its charts is the measured height minus the
    /// charts, so the fit settles in one step. Never shorter than the 120 pt a small window gets, so the page ends
    /// at the window's bottom edge at any size, full screen on a large display included.
    private func fit() {
        guard viewport > 0, layout.content > 0 else { return }
        let rest = layout.content - layout.chartHeight
        // Capped: a taller plot only stretched one busy hour across an empty field.
        let want = min(Self.chartMaxHeight, max(120, (viewport - rest).rounded(.down)))
        if abs(want - layout.chartHeight) >= 1 { layout.chartHeight = want }
    }

    // MARK: State

    /// Launches, Files and (with the firewall) Network, in that order.
    private func cardViews(series: [ProtectionArea: [ProtectionTimeline.Bucket]], network: [ProtectionTimeline.Bucket],
                           range: ProtectionTimeline.Range, yMax: Int) -> [AnyView] {
        var cards: [AnyView] = ProtectionArea.allCases.map { area in
            AnyView(AreaCard(protection: protection, area: area, buckets: series[area] ?? [], range: range, yMax: yMax,
                             chartHeight: layout.chartHeight, go: go))
        }
        if let firewall {
            cards.append(AnyView(FirewallCard(firewall: firewall, buckets: network, range: range, yMax: yMax,
                                              chartHeight: layout.chartHeight, go: go)))
        }
        return cards
    }

    /// The tallest a chart grows in a tall window.
    static let chartMaxHeight: CGFloat = 170

    /// The narrowest a card can be: its Off · Watch · Ask · Strict switch and padding.
    static let cardMinWidth: CGFloat = 270

    /// How many cards fit side by side in `width` (all of them before the width is known).
    static func columns(width: CGFloat, cards: Int, spacing: CGFloat = 14) -> Int {
        guard width > 0, cards > 0 else { return max(cards, 1) }
        let fit = Int((width + spacing) / (cardMinWidth + spacing))
        return min(cards, max(1, fit))
    }

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
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 16) {
                StatusSeal(state: state, tint: tint)
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
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) {
                ForEach(facts, id: \.title) { StatusFactView(fact: $0) }
            }
        }
        .controlSize(.large)
        .padding(18)
        .glassEffect(.regular.tint(tint.opacity(state == .off ? 0 : 0.12)), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .accessibilityElement(children: .contain)
    }

    /// The state in five facts: what is guarded, how it stops, what it guards, what waits, and for how long.
    private var facts: [StatusFact] {
        // Only Ask and Strict stop anything: a watched area is rehearsing, not protected.
        let modes = ProtectionArea.allCases.map { ($0.title, protection.mode($0).short, protection.mode($0).enforces) }
            + (firewall.map { [("Network", $0.mode.short, $0.mode == .ask || $0.mode == .strict)] } ?? [])
        let protected = modes.filter(\.2).count
        let same = Set(modes.map(\.1)).count == 1
        let guarding = same ? "\(modes[0].1) everywhere" : modes.map { "\($0.0) \($0.1)" }.joined(separator: " · ")
        let groups = ProtectedGroup.all.filter { (protection.groups[$0.id] ?? ProtectedGroupSetting()).on }.count
        let yours = protection.customPlaces.filter(\.on).count
        let waiting = protection.prompts.count + (firewall?.prompts.count ?? 0)
        let days = max(1, Calendar.current.dateComponents([.day], from: protection.since, to: Date()).day ?? 0)
        return [
            StatusFact(symbol: "shield.lefthalf.filled", title: "Protected",
                       value: protected == 0 ? "No areas" : "\(protected) of \(modes.count) areas", detail: guarding),
            lastStopped,
            StatusFact(symbol: "lock.doc", title: "Protected places", value: "\(groups + yours)",
                       detail: yours > 0 ? "\(groups) groups, \(yours) of yours" : "\(groups) of \(ProtectedGroup.all.count) groups"),
            StatusFact(symbol: "hourglass", title: "Waiting for you", value: waiting == 0 ? "Nothing" : waiting.formatted(),
                       detail: waiting == 0 ? "No questions open" : waiting == 1 ? "1 question open" : "\(waiting) questions open"),
            StatusFact(symbol: "calendar", title: "Watching", value: days == 1 ? "1 day" : "\(days) days",
                       detail: "Since \(protection.since.formatted(date: .abbreviated, time: .omitted))"),
        ]
    }

    /// The latest program stopped, or that would have been where an area only watches, and when.
    private var lastStopped: StatusFact {
        guard let last = protection.findings.values.filter({ $0.verdict == .block }).max(by: { $0.lastSeen < $1.lastSeen })
        else { return StatusFact(symbol: "hand.raised", title: "Last stopped", value: "Nothing yet", detail: "Nothing stopped so far") }
        let when = last.lastSeen.formatted(.relative(presentation: .named))
        return StatusFact(symbol: "hand.raised", title: last.enforced ? "Last stopped" : "Last would stop",
                          value: last.name.isEmpty ? last.program : last.name, detail: "\(last.area.title), \(when)")
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
                OverviewRow(symbol: "exclamationmark.shield.fill", color: stops > 0 ? .orange : .gray, title: "Found",
                            value: review == 0 ? "Nothing to review" : "\(review.formatted()) to review",
                            detail: stops > 0 ? "\(stops.formatted()) would be stopped" : nil) {
                    go(.protectionFound)
                }
            }
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
    }
}

/// The state's seal: the shield on a soft disc of the state's colour, inside two quiet rings.
private struct StatusSeal: View {
    let state: ProtectionState
    let tint: Color

    var body: some View {
        let symbol = state == .paused ? "pause.fill" : state == .off ? "shield.slash.fill" : "checkmark.shield.fill"
        ZStack {
            Circle().strokeBorder(tint.opacity(0.14), lineWidth: 1).frame(width: 66, height: 66)
            Circle().strokeBorder(tint.opacity(0.24), lineWidth: 1).frame(width: 56, height: 56)
            Image(systemName: symbol)
                .font(.system(size: 21, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(tint.gradient, in: Circle())
                .shadow(color: tint.opacity(state == .off ? 0 : 0.45), radius: 12, y: 5)
                .contentTransition(.symbolEffect(.replace))
        }
        .frame(width: 66, height: 66)
        .accessibilityHidden(true)
    }
}

/// One fact about the state: a symbol and its name, the value, and a line under it.
struct StatusFact {
    let symbol: String
    let title: String
    let value: String
    let detail: String
}

struct StatusFactView: View {
    let fact: StatusFact

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(fact.title, systemImage: fact.symbol)
                .font(.caption.weight(.medium)).foregroundStyle(.secondary)
            Text(fact.value).font(.headline).lineLimit(1).truncationMode(.middle).help(fact.value)
            Text(fact.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                .help(fact.detail)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

/// Behind the Overview: soft pools of colour, the state's own at the top, so the glass has something to refract
/// and the page reads as protecting, rehearsing or paused before a word is read.
struct ProtectionBackdrop: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor?

    private var state: ProtectionState { protection.state(network: firewall?.mode ?? .off) }

    private var tint: Color {
        switch state {
        case .off: .gray
        case .rehearsing: .purple
        case .protecting: .green
        case .paused: .orange
        }
    }

    var body: some View {
        ZStack {
            RadialGradient(colors: [tint.opacity(state == .off ? 0.08 : 0.18), .clear],
                           center: UnitPoint(x: 0.3, y: 0), startRadius: 0, endRadius: 520)
            RadialGradient(colors: [Color.cyan.opacity(0.10), .clear], center: UnitPoint(x: 1, y: 0.35),
                           startRadius: 0, endRadius: 480)
            RadialGradient(colors: [Color.indigo.opacity(0.10), .clear], center: UnitPoint(x: 0.1, y: 1),
                           startRadius: 0, endRadius: 520)
        }
        .animation(.easeInOut(duration: 0.4), value: state)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
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
                if let detail { Text(detail).foregroundStyle(.primary).monospacedDigit() }
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
struct CardFooter: View {
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

/// What an Off card shows instead of an empty chart: what turning it on gives you, and the button that does it.
struct OffHint: View {
    let text: String
    let turnOn: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "chart.bar.xaxis").font(.system(size: 26, weight: .light)).foregroundStyle(.tertiary)
            Text(text).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Turn On Watch", action: turnOn).buttonStyle(.glass)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.vertical, 12)
    }
}

/// Launches or Files: the four modes as a segmented control, what the chosen one does, and today's numbers.
private struct AreaCard: View {
    @ObservedObject var protection: ProtectionMonitor
    let area: ProtectionArea
    let buckets: [ProtectionTimeline.Bucket]
    let range: ProtectionTimeline.Range
    let yMax: Int
    let chartHeight: CGFloat
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
                OffHint(text: "Watch shows, hour by hour, what would be stopped. It stops nothing.") {
                    protection.setMode(.watch, for: area)
                }
            } else {
                let stop = mode.enforces ? "stopped" : "would stop", ask = mode == .watch ? "would ask" : "asked"
                HStack(spacing: 24) {
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.block }, label: stop, alarming: true)
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.ask }, label: ask, alarming: false)
                }
                ProtectionChart(buckets: buckets, range: range, stopLabel: stop, askLabel: ask,
                                yMax: ProtectionTimeline.sharedMax([buckets]), height: chartHeight)
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
    /// New destinations by when they were first seen, blocked (or would be) or asked about.
    let buckets: [ProtectionTimeline.Bucket]
    let range: ProtectionTimeline.Range
    let yMax: Int
    let chartHeight: CGFloat
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
                OffHint(text: "Watch shows, hour by hour, what would be blocked. It blocks nothing.") {
                    firewall.mode = .watch
                }
            } else {
                // The same two numbers as Launches and Files, summed from the chart's own buckets: new destinations
                // it blocks (or would), and asks about (or would).
                let enforcing = firewall.mode == .ask || firewall.mode == .strict
                let stop = enforcing ? "blocked" : "would block", ask = enforcing ? "asked about" : "would ask"
                HStack(spacing: 24) {
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.block }, label: stop, alarming: true)
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.ask }, label: ask, alarming: false)
                }
                ProtectionChart(buckets: buckets, range: range, stopLabel: stop, askLabel: ask,
                                yMax: ProtectionTimeline.sharedMax([buckets]), height: chartHeight)
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

/// A number in the text colour, with the chart's own colour as a dot beside its label: the pair is the chart's
/// legend too. Red stays in the bars, where it means "stopped".
struct OverviewFigure: View {
    let n: Int
    let label: String
    let alarming: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(n.formatted()).font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit()
            HStack(spacing: 5) {
                Circle().fill(alarming ? ProtectionChart.stop : ProtectionChart.ask).frame(width: 7, height: 7)
                Text(label).font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The cards' shared surface: Liquid Glass, as macOS draws widgets.
private struct OverviewCard: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

/// The charts' height for the window's size (no @State macro with the command line tools).
final class OverviewLayout: ObservableObject {
    @Published var chartHeight: CGFloat = 120
    /// The page's width, for how many cards fit side by side.
    @Published var width: CGFloat = 0
    var content: CGFloat = 0
}

/// The height of the scroll view a page sits in, for pages that fill a tall window rather than leave it empty.
struct ViewportHeightKey: EnvironmentKey {
    static let defaultValue: CGFloat = 0
}

extension EnvironmentValues {
    var viewportHeight: CGFloat {
        get { self[ViewportHeightKey.self] }
        set { self[ViewportHeightKey.self] = newValue }
    }
}
