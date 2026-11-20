import SwiftUI

/// Protected Files and Folders, above its rules: the Files area's state and mode with five facts, then what it found
/// over time beside what it found most. The Overview's pattern, for files only.
struct ProtectedFilesHeader: View {
    @ObservedObject var protection: ProtectionMonitor
    let go: (RulesSegment) -> Void
    @AppStorage("protectionChartRange") private var rangeRaw = ProtectionTimeline.Range.day.rawValue
    @StateObject private var help = ExpandState()

    private var mode: ProtectionMode { protection.fileMode }
    private var state: AreaState { AreaState(paused: protection.paused, off: mode == .off, enforces: mode.enforces) }
    private var stopLabel: String { mode.enforces ? "stopped" : "would stop" }
    private var askLabel: String { mode == .watch ? "would ask" : "asked" }

    var body: some View {
        let _ = protection.revision
        let found = protection.findings.values.filter { $0.area == .files }
        let range = ProtectionTimeline.Range(rawValue: rangeRaw) ?? .day
        VStack(alignment: .leading, spacing: 18) {
            AreaHero(symbol: "lock.doc.fill", title: "Files", state: state, sentence: sentence, facts: facts(found)) {
                AreaModePicker(title: "Files", mode: Binding(get: { mode }, set: { protection.setMode($0, for: .files) }),
                               modes: ProtectionMode.allCases.map { ($0, $0.short) })
                HelpLink { help.open.toggle() }
                    .popover(isPresented: $help.open, arrowEdge: .bottom) { howItWorks }
            } notice: {
                EmptyView()
            }
            AreaActivity(rangeRaw: $rangeRaw,
                         buckets: mode == .off ? [] : ProtectionTimeline.buckets(protection.hourly, area: .files, range: range),
                         stopLabel: stopLabel, askLabel: askLabel, off: mode == .off,
                         turnOn: { protection.setMode(.watch, for: .files) },
                         offText: "Watch shows, hour by hour, which programs would be stopped in your protected places. It stops nothing.",
                         topTitle: "Found most", topEmpty: "Nothing yet. A program opening a protected place it isn't expected in shows here.",
                         items: Array(found.sorted { ($0.count, $0.lastSeen) > ($1.count, $1.lastSeen) }.prefix(5)),
                         footer: "Review in Found", footerCount: found.count, action: { go(.protectionFound) }) { f in
                ActivityTopRow(program: f.program, name: f.name,
                               detail: (f.group.flatMap { protection.placeTitle(group: $0) }.map { $0 + " · " } ?? "") + f.pattern,
                               verdict: f.verdict == .block ? (f.enforced ? "Stopped" : "Would stop") : "Would ask",
                               blocks: f.verdict == .block, count: f.count)
            }
        }
    }

    private var sentence: String {
        let stops = protection.count(.files, .block)
        switch state {
        case .off: return "Protected places aren't checked. Turn on Watch to see who opens them, without stopping anything."
        case .paused: return "Nothing is checked or stopped until protection resumes."
        case .watching:
            return stops == 0 ? "Nothing is stopped, and nothing would have been today."
                : "Nothing is stopped. Today \(stops) would have been. Decide those in Found, then turn on Ask."
        case .protecting:
            let first = mode == .strict ? "Only expected programs and the ones you allow open protected places."
                : "Programs you blocked are stopped. Unexpected ones are paused and asked about."
            return stops == 0 ? first : first + " Today \(stops) stopped."
        }
    }

    private func facts(_ found: [ProtectionFinding]) -> [StatusFact] {
        let groups = ProtectedGroup.all.filter { (protection.groups[$0.id] ?? ProtectedGroupSetting()).on }.count
        let yours = protection.customPlaces.filter(\.on).count
        let apps = protection.appFiles
        let blocked = apps.flatMap(\.places).filter { $0.on && $0.verdict == .block }.count
        let allowed = apps.flatMap(\.places).filter { $0.on && $0.verdict == .allow }.count
        let waiting = protection.prompts.filter { $0.area == .files }.count
        // The place most found in: where the rules are worth a look first.
        let busiest = Dictionary(grouping: found.filter { $0.group != nil }) { $0.group ?? "" }
            .mapValues { $0.reduce(0) { $0 + $1.count } }.max { $0.value < $1.value }
        let last = found.filter { $0.verdict == .block }.max { $0.lastSeen < $1.lastSeen }
        return [
            StatusFact(symbol: "lock.doc", title: "Protected places", value: "\(groups + yours)",
                       detail: yours > 0 ? "\(groups) built-in, \(yours) of yours" : "\(groups) of \(ProtectedGroup.all.count) built-in"),
            StatusFact(symbol: "app.badge.checkmark", title: "App rules",
                       value: apps.isEmpty ? "None" : apps.count == 1 ? "1 app" : "\(apps.count) apps",
                       detail: apps.isEmpty ? "Every app meets the global rules" : "\(blocked) blocked, \(allowed) allowed places"),
            StatusFact(symbol: "mappin.and.ellipse", title: "Found most in",
                       value: busiest.flatMap { protection.placeTitle(group: $0.key) } ?? "Nowhere yet",
                       detail: busiest.map { "\($0.value.formatted()) times" } ?? "Nothing found so far"),
            StatusFact(symbol: "hand.raised", title: last?.enforced == true ? "Last stopped" : "Last would stop",
                       value: last.map { $0.name.isEmpty ? $0.program : $0.name } ?? "Nothing yet",
                       detail: last.map { $0.lastSeen.formatted(.relative(presentation: .named)) } ?? "Nothing stopped so far"),
            StatusFact(symbol: "hourglass", title: "Waiting for you", value: waiting == 0 ? "Nothing" : waiting.formatted(),
                       detail: waiting == 0 ? "No questions open" : waiting == 1 ? "1 question open" : "\(waiting) questions open"),
        ]
    }

    private var howItWorks: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("How file protection decides").font(.headline)
            Text("An app's own rules first, the most specific place. Then its Every protected place. Then the global "
                 + "rules: your decision on the pattern, the programs expected in the place, and the place's choice for "
                 + "any other program, Ask me or Block.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Divider()
            Text(protection.enforcer.text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .padding(16)
        .frame(width: 340)
    }
}
