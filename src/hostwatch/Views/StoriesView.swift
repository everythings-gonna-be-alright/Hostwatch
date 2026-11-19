import AppKit
import Darwin
import Foundation
import SwiftUI

// MARK: - Views

extension SignatureStatus {
    var color: Color { Color(nsColor: nsColor) }
}

/// Stories tab: newest first, each a card with its chain of steps.
struct StoriesView: View {
    @ObservedObject var stories: StoryEngine
    let search: String
    let actions: HUDActions

    var body: some View {
        let _ = stories.revision
        let rows = filtered
        VStack(spacing: 0) {
            content(rows)
                .frame(maxWidth: .infinity, maxHeight: .infinity)   // footer stays at the window's bottom
            Divider()
            footer
        }
    }

    @ViewBuilder
    private func content(_ rows: [Story]) -> some View {
        if rows.isEmpty {
            ContentUnavailableView {
                Label(search.isEmpty ? "No Stories Yet" : "No Matching Stories",
                      systemImage: "point.3.connected.trianglepath.dotted")
            } description: {
                Text("""
                A story appears when several suspicious steps happen in one process tree within 15 minutes, \
                e.g. an app spawning a shell that downloads and runs something, or a download that removes \
                its quarantine, runs and installs a LaunchAgent. Single events stay in Events and Patterns.
                """)
            }
        } else {
            ScrollView {
                // Each card is its own glass: in one container, cards this close would melt into each other.
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(rows) { StoryCard(story: $0, stories: stories, actions: actions) }
                }
                .padding(20)
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("\(stories.activeCount) open · \(stories.stories.count) total")
            if stories.ignoredCount > 0 {
                Text("·")
                Button("Reset \(stories.ignoredCount) ignored chains") { stories.clearIgnored() }
                    .buttonStyle(.glass).controlSize(.small)
            }
            Spacer()
        }
        .font(.system(size: 11))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var filtered: [Story] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let all = stories.stories.sorted { ($0.dismissed ? 1 : 0, $1.lastSeen) < ($1.dismissed ? 1 : 0, $0.lastSeen) }
        guard !q.isEmpty else { return all }
        return all.filter { s in
            s.title.lowercased().contains(q) || s.steps.contains { $0.detail.lowercased().contains(q) }
        }
    }
}

/// One story as a glass card, like Protection's: a seal in the story's colour with the title and one line of facts, the
/// stages it reached, its steps as a quiet list, then the ways into it and the two ways to be done with it. The colour
/// carries the state (a faint wash from the corner), never the text.
private struct StoryCard: View {
    let story: Story
    let stories: StoryEngine
    let actions: HUDActions
    @StateObject private var steps = ExpandState()

    private var tint: Color { story.severity.color }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            stagesRow
            VStack(alignment: .leading, spacing: 8) {
                stepsToggle
                if steps.open {
                    StorySteps(rows: StoryStepRow.rows(story.steps), tint: tint, askAI: actions.askAI)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .transition(.opacity)
                }
            }
            let nearby = stories.possiblyRelated(to: story)
            if !nearby.isEmpty {
                Label("Possibly related (within 30 min, no direct link): "
                      + nearby.prefix(3).map(\.title).joined(separator: " · "),
                      systemImage: "link.badge.plus")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            actionsRow
        }
        .padding(18)
        .background {
            LinearGradient(colors: [tint.opacity(0.16), tint.opacity(0.04), .clear],
                           startPoint: .topLeading, endPoint: UnitPoint(x: 0.6, y: 0.7))
                .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
                .allowsHitTesting(false)
        }
        .protectionGlass(22)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { actions.openStory(story) }
        .opacity(story.dismissed ? 0.55 : 1)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: story.severity.symbol)
                .font(.system(size: 15, weight: .bold))
                .foregroundStyle(.white)
                .frame(width: 34, height: 34)
                .background(tint.gradient, in: Circle())
                .shadow(color: tint.opacity(0.4), radius: 6, y: 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(story.title)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(facts).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    /// The steps open and close from the whole bar, not a small arrow: what it holds, at a glance (the first and
    /// last moment), and a chevron that turns.
    private var stepsToggle: some View {
        let rows = StoryStepRow.rows(story.steps)
        let span = [rows.first, rows.last].compactMap { $0.map { String($0.first.time.prefix(5)) } }
        return Button {
            withAnimation(.snappy(duration: 0.2)) { steps.open.toggle() }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .rotationEffect(.degrees(steps.open ? 90 : 0))
                    .foregroundStyle(.secondary)
                    .frame(width: 14)
                Text(rows.count == 1 ? "1 step" : "\(rows.count) steps").font(.callout.weight(.medium))
                if let a = span.first, let b = span.last {
                    Text(a == b ? a : "\(a) to \(b)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                Text(steps.open ? "Hide" : "Show").font(.callout).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(steps.open ? 0.06 : 0.045)))
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(steps.open ? "Hide the steps" : "Show the steps")
        .accessibilityLabel(steps.open ? "Hide \(rows.count) steps" : "Show \(rows.count) steps")
    }

    /// "Suspicious · from an app · 4 min ago · score 6"
    private var facts: String {
        let origin = story.origin == .developer ? "from your terminal" : story.origin == .app ? "from an app" : "in the background"
        let status = story.severity == .unclassified ? "New" : story.severity.title
        return "\(status) · \(origin) · \(StoryEngine.ago(story.lastSeen)) · score \(story.score)"
    }

    /// The stages as plain capsules (no glass on the glass card); the strong ones in the story's colour.
    private var stagesRow: some View {
        HStack(spacing: 6) {
            ForEach(story.stages, id: \.self) { stage in
                Label(stage.title, systemImage: stage.symbol)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(stage.isStrong ? tint : .primary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(stage.isStrong ? tint.opacity(0.16) : Color.primary.opacity(0.06)))
                    .lineLimit(1)
                    .fixedSize()
            }
        }
    }

    // One style, as Liquid Glass asks of a row of actions: glass capsules at the regular size in one container. The
    // ways into the story first, then the two ways to be done with it.
    private var actionsRow: some View {
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                Button { actions.openStory(story) } label: {
                    Label("Show Chain", systemImage: "point.3.connected.trianglepath.dotted")
                }
                .help("The whole chain, event by event (or double-click the story)")
                Button { actions.askStory(story) } label: { Label("Ask AI", systemImage: "sparkles") }
                // Only for a story of processes: one raised from the network (a port scan) has none to show.
                if story.steps.contains(where: { $0.pid > 0 }) {
                    Button { actions.showStoryInTimeline(story) } label: {
                        Label("Show in Timeline", systemImage: "clock.arrow.circlepath")
                    }
                    .help("Open Time Travel at this story, showing only its own events")
                }
                Spacer(minLength: 8)
                Button { stories.ignoreAlways(story.id) } label: { Label("Always Ignore", systemImage: "bell.slash") }
                    .help("Never alert again for \(story.originName) with these stages")
                Button(role: .destructive) { stories.delete(story.id) } label: { Label("Delete", systemImage: "trash") }
                    .help("Remove this story from the list")
            }
            .buttonStyle(.glass)
            .buttonBorderShape(.capsule)
        }
    }
}

/// A row of the steps list: steps of one moment, process and target together (one connection is often both
/// "outbound" and "new domain"), so it reads once with both stages' symbols.
struct StoryStepRow: Identifiable {
    let id: UUID
    let steps: [StoryStep]
    var first: StoryStep { steps[0] }

    static func rows(_ steps: [StoryStep]) -> [StoryStepRow] {
        var out: [StoryStepRow] = []
        for s in steps {
            if let last = out.last, last.first.time.prefix(8) == s.time.prefix(8), last.first.pid == s.pid,
               last.first.detail == s.detail {
                out[out.count - 1] = StoryStepRow(id: last.id, steps: last.steps + [s])
            } else {
                out.append(StoryStepRow(id: s.id, steps: [s]))
            }
        }
        return out
    }
}

/// The steps in a quiet inset panel (a plain fill: no glass on glass), soft stripes, one line each: time, stages,
/// program, then what it did. Monospace only for the data (time, address).
private struct StorySteps: View {
    let rows: [StoryStepRow]
    let tint: Color
    let askAI: (ActivityEvent) -> Void

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                line(row)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(i.isMultiple(of: 2) ? Color.clear : Color.primary.opacity(0.035))
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) { askAI(row.first.event) }
                    .help(row.steps.map(\.note).joined(separator: "\n"))
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.04)))
    }

    private func line(_ row: StoryStepRow) -> some View {
        let s = row.first
        return HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(String(s.time.prefix(8)))
                .font(.system(size: 11).monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 56, alignment: .leading)
            HStack(spacing: 3) {
                ForEach(row.steps.map(\.stage).uniqued(), id: \.self) { stage in
                    Image(systemName: stage.symbol)
                        .foregroundStyle(stage.isStrong ? tint : .secondary)
                }
            }
            .font(.system(size: 11))
            .frame(width: 40, alignment: .leading)
            .accessibilityHidden(true)
            Text(s.name)
                .font(.callout.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: 210, alignment: .leading)
                .help("\(s.name) (pid \(s.pid))")
            what(s)
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder private func what(_ s: StoryStep) -> some View {
        if s.kind == .net {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if !s.extra.isEmpty {
                    Text(s.extra)
                        .font(.system(size: 9.5, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Capsule().fill(Color.primary.opacity(0.08)))
                }
                Text(s.host.isEmpty ? s.target : s.host).font(.callout).lineLimit(1).truncationMode(.middle)
                if !s.host.isEmpty {
                    Text(s.target).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .textSelection(.enabled)
        } else {
            Text(s.detail).font(.callout).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
    }
}

private extension Array where Element: Hashable {
    func uniqued() -> [Element] { var seen = Set<Element>(); return filter { seen.insert($0).inserted } }
}

/// Pinned alert at the top of the HUD.
struct StoryBanner: View {
    let story: Story
    let s: CGFloat

    var body: some View {
        HStack(spacing: 6 * s) {
            Image(systemName: story.severity == .dangerous ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 10 * s, weight: .bold))
                .foregroundStyle(Color(nsColor: story.severity.nsColor))
            VStack(alignment: .leading, spacing: 0) {
                Text(story.title)
                    .font(.system(size: 11 * s, weight: .semibold))
                    .foregroundStyle(HUDInk.primary)
                    .lineLimit(1).truncationMode(.middle)
                Text(story.summary)
                    .font(.system(size: 10 * s))
                    .foregroundStyle(HUDInk.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 2)
            Text(StoryEngine.ago(story.lastSeen))
                .font(.system(size: 9.5 * s).monospacedDigit())
                .foregroundStyle(HUDInk.tertiary)
        }
        .padding(.horizontal, 7 * s)
        .padding(.vertical, 4 * s)
        .background(RoundedRectangle(cornerRadius: 8 * s, style: .continuous)
            .fill(Color(nsColor: story.severity.nsColor).opacity(0.35)))
    }
}
