import SwiftUI

/// One area's state, coloured as the Overview colours the whole: grey off, purple watching, green protecting, orange
/// paused. The Files and Network Firewall pages open with it.
enum AreaState: Equatable {
    case off, watching, protecting, paused

    init(paused: Bool, off: Bool, enforces: Bool) {
        self = paused ? .paused : off ? .off : enforces ? .protecting : .watching
    }

    var tint: Color {
        switch self {
        case .off: .secondary
        case .watching: .purple
        case .protecting: .green
        case .paused: .orange
        }
    }

    var word: String {
        switch self {
        case .off: "Off"
        case .watching: "Watching"
        case .protecting: "Protecting"
        case .paused: "Paused"
        }
    }
}

/// An area page's header, the Overview's on a smaller scale: the area's seal in its state's colour, its name and state,
/// one sentence, the mode, and five facts about this area only.
struct AreaHero<Controls: View, Notice: View>: View {
    let symbol: String
    let title: String
    let state: AreaState
    let sentence: String
    let facts: [StatusFact]
    @ViewBuilder let controls: () -> Controls
    @ViewBuilder let notice: () -> Notice

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 16) {
                AreaSeal(symbol: symbol, state: state)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(title).font(.title2.weight(.semibold))
                        Text(state.word).font(.callout.weight(.semibold))
                            .foregroundStyle(state == .off ? Color.secondary : state.tint)
                    }
                    Text(sentence).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                controls()
            }
            notice()
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) {
                ForEach(facts, id: \.title) { StatusFactView(fact: $0) }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular.tint(state.tint.opacity(state == .off ? 0 : 0.10)),
                     in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

/// The area's symbol on a soft disc of the state's colour, inside two quiet rings (the Overview's seal, per area).
private struct AreaSeal: View {
    let symbol: String
    let state: AreaState

    var body: some View {
        let tint = state == .off ? Color.gray : state.tint
        ZStack {
            Circle().strokeBorder(tint.opacity(0.14), lineWidth: 1).frame(width: 66, height: 66)
            Circle().strokeBorder(tint.opacity(0.24), lineWidth: 1).frame(width: 56, height: 56)
            Image(systemName: symbol)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(tint.gradient, in: Circle())
                .shadow(color: tint.opacity(state == .off ? 0 : 0.45), radius: 12, y: 5)
        }
        .frame(width: 66, height: 66)
        .accessibilityHidden(true)
    }
}

/// The mode switch of an area page's header, as wide as the Overview's cards make it.
struct AreaModePicker<Mode: Hashable>: View {
    let title: String
    @Binding var mode: Mode
    let modes: [(Mode, String)]

    var body: some View {
        Picker(title, selection: $mode) {
            ForEach(modes.indices, id: \.self) { i in Text(modes[i].1).tag(modes[i].0) }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
    }
}

/// An area's activity: its two numbers and chart over the chosen range, beside what it found most, and the way to
/// Found. Side by side when the window is wide, one above the other when it isn't.
struct AreaActivity<Item: Identifiable, Row: View>: View {
    @Binding var rangeRaw: String
    let buckets: [ProtectionTimeline.Bucket]
    let stopLabel: String
    let askLabel: String
    let off: Bool
    let turnOn: () -> Void
    let offText: String
    let topTitle: String
    let topEmpty: String
    let items: [Item]
    let footer: String
    let footerCount: Int
    let action: () -> Void
    @ViewBuilder let row: (Item) -> Row

    private var range: ProtectionTimeline.Range { ProtectionTimeline.Range(rawValue: rangeRaw) ?? .day }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Activity in \(range.phrase)").font(.headline)
                Spacer()
                Picker("Range", selection: $rangeRaw) {
                    ForEach(ProtectionTimeline.Range.allCases, id: \.self) { Text($0.title).tag($0.rawValue) }
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 20) {
                    chart.frame(minWidth: 380)
                    Divider()
                    top.frame(width: 330)
                }
                VStack(alignment: .leading, spacing: 14) {
                    chart
                    Divider()
                    top
                }
            }
            CardFooter(title: footer, count: footerCount, action: action)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    @ViewBuilder private var chart: some View {
        if off {
            OffHint(text: offText, turnOn: turnOn).frame(minHeight: 170)
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 24) {
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.block }, label: stopLabel, alarming: true)
                    OverviewFigure(n: buckets.reduce(0) { $0 + $1.ask }, label: askLabel, alarming: false)
                }
                ProtectionChart(buckets: buckets, range: range, stopLabel: stopLabel, askLabel: askLabel,
                                yMax: ProtectionTimeline.sharedMax([buckets]), height: 140)
            }
        }
    }

    private var top: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(topTitle).font(.subheadline.weight(.semibold))
            if items.isEmpty {
                Text(topEmpty).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(items) { row($0) }
        }
    }
}

/// One line of what an area found most: the program's icon and name, what it touched, what happens and how often.
struct ActivityTopRow: View {
    let program: String
    let name: String
    let detail: String
    let verdict: String
    let blocks: Bool
    let count: Int

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: ProcessIcons.icon(program)).resizable().frame(width: 20, height: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.callout.weight(.medium)).lineLimit(1)
                Text(detail).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).help(detail)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 1) {
                Text(verdict).font(.caption.weight(.semibold)).foregroundStyle(blocks ? Color.red : Color.orange)
                Text("\(count.formatted())×").font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }
}
