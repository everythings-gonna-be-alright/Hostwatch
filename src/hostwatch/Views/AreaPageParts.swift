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

/// Each area page's own colour: who the page is about, never a status (DESIGN.md ▸ Colour). Indigo and teal are
/// colours no status uses. The state shows as a pill in its status colour.
enum AreaAccent {
    static let files = Color.indigo
    static let network = Color.teal
    /// Found is all attention, so it wears the attention colour itself.
    static let found = Color.orange
}

/// An area page's header, unlike the Overview's on purpose: the area's tile in its own colour, its name with the state
/// as a pill, one sentence and the mode, over a wash of the area's colour, then its facts as one divided strip.
struct AreaHero<Controls: View, Notice: View>: View {
    let symbol: String
    let title: String
    let accent: Color
    let state: AreaState
    let sentence: String
    let facts: [StatusFact]
    @ViewBuilder let controls: () -> Controls
    @ViewBuilder let notice: () -> Notice

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 14) {
                AreaTile(symbol: symbol, accent: accent)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 10) {
                        Text(title).font(.title2.weight(.semibold))
                        StatePill(state: state)
                    }
                    Text(sentence).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                controls()
            }
            notice()
            FactStrip(facts: facts)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            // The wash: the area's colour from the leading edge, fading before the middle.
            LinearGradient(colors: [accent.opacity(0.20), accent.opacity(0.04), .clear],
                           startPoint: .topLeading, endPoint: UnitPoint(x: 0.7, y: 1))
                .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        }
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay {
            // A hairline of the area's colour around the leading edge, fading out.
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .strokeBorder(LinearGradient(colors: [accent.opacity(0.55), accent.opacity(0)],
                                             startPoint: .leading, endPoint: .trailing), lineWidth: 1)
                .allowsHitTesting(false)
        }
        .accessibilityElement(children: .contain)
    }
}

/// The area's symbol on a squircle of its colour, as System Settings draws a pane's icon.
private struct AreaTile: View {
    let symbol: String
    let accent: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 22, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 52, height: 52)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(accent.gradient))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.25), lineWidth: 0.5))
            .shadow(color: accent.opacity(0.35), radius: 10, y: 4)
            .accessibilityHidden(true)
    }
}

/// The state in its status colour: a dot and the word, on a soft capsule.
private struct StatePill: View {
    let state: AreaState

    var body: some View {
        let tint = state == .off ? Color.secondary : state.tint
        HStack(spacing: 5) {
            Circle().fill(tint).frame(width: 7, height: 7)
            Text(state.word).font(.caption.weight(.semibold))
        }
        .padding(.horizontal, 9).padding(.vertical, 3)
        .background(Capsule().fill(tint.opacity(0.16)))
        .foregroundStyle(state == .off ? Color.secondary : Color.primary)
        .accessibilityLabel("State: \(state.word)")
    }
}

/// The facts side by side with hairlines between, the way a stats bar reads, or a grid when the window is narrow.
private struct FactStrip: View {
    let facts: [StatusFact]

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 0) {
                ForEach(facts.indices, id: \.self) { i in
                    if i > 0 { Divider().frame(height: 46).padding(.horizontal, 14) }
                    fact(facts[i]).frame(minWidth: 120, maxWidth: .infinity, alignment: .leading)
                }
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 14)], alignment: .leading, spacing: 12) {
                ForEach(facts, id: \.title) { fact($0) }
            }
        }
        .padding(.top, 12)
        .overlay(alignment: .top) { Divider() }
    }

    private func fact(_ f: StatusFact) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(f.title, systemImage: f.symbol).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            Text(f.value).font(.system(.title3, design: .rounded).weight(.semibold)).monospacedDigit()
                .lineLimit(1).truncationMode(.middle).help(f.value)
            Text(f.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail).help(f.detail)
        }
        .accessibilityElement(children: .combine)
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
