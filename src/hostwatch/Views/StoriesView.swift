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
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(rows) { StoryCard(story: $0, stories: stories, actions: actions) }
                }
                .padding(16)
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("\(stories.activeCount) open · \(stories.stories.count) total")
            if stories.ignoredCount > 0 {
                Text("·")
                Button("Reset \(stories.ignoredCount) ignored chains") { stories.clearIgnored() }
                    .buttonStyle(.link)
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

private struct StoryCard: View {
    let story: Story
    let stories: StoryEngine
    let actions: HUDActions

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                StatusPill(status: story.severity)
                Text(story.title)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 8)
                Text("\(story.origin == .developer ? "from your terminal" : story.origin == .app ? "from an app" : "background")")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text(StoryEngine.ago(story.lastSeen))
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            // Stage chips.
            HStack(spacing: 6) {
                ForEach(story.stages, id: \.self) { stage in
                    Label(stage.title, systemImage: stage.symbol)
                        .font(.system(size: 11, weight: .medium))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(story.severity.color.opacity(stage.isStrong ? 0.22 : 0.10)))
                }
                Spacer()
                Text("score \(story.score)").font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
            }
            DisclosureGroup("\(story.steps.count) steps") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(story.steps) { step in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(step.time.prefix(8)).foregroundStyle(.secondary).frame(width: 62, alignment: .leading)
                            Image(systemName: step.stage.symbol)
                                .foregroundStyle(step.stage.isStrong ? story.severity.color : .secondary)
                                .frame(width: 16)
                            Text("\(step.name) \(step.pid)").fontWeight(.medium).frame(width: 150, alignment: .leading)
                                .lineLimit(1)
                            Text(step.detail).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                                .help(step.note)
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .contentShape(Rectangle())
                        .onTapGesture(count: 2) { actions.askAI(step.event) }
                    }
                }
                .padding(.top, 4)
            }
            .font(.system(size: 11))
            let nearby = stories.possiblyRelated(to: story)
            if !nearby.isEmpty {
                Label("Possibly related (within 30 min, no direct link): "
                      + nearby.prefix(3).map(\.title).joined(separator: " · "),
                      systemImage: "link.badge.plus")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            HStack(spacing: 8) {
                Button { actions.openStory(story) } label: { Label("Show Chain", systemImage: "point.3.connected.trianglepath.dotted") }
                    .buttonStyle(.glassProminent)
                    .help("The whole chain, event by event (or double-click the story)")
                Button { actions.askStory(story) } label: { Label("Ask AI", systemImage: "sparkles") }
                    .buttonStyle(.glass)
                Button { actions.showInTimeline(story.firstSeen) } label: {
                    Label("Show in Timeline", systemImage: "clock.arrow.circlepath")
                }
                .buttonStyle(.glass)
                .help("Open Time Travel at this story, with everything else that happened around it")
                if !story.dismissed {
                    Button("Dismiss") { stories.dismiss(story.id) }.buttonStyle(.glass)
                }
                Button("Always Ignore This Chain") { stories.ignoreAlways(story.id) }
                    .buttonStyle(.glass)
                    .help("Never alert again for \(story.originName) with these stages")
                Spacer()
                Button(role: .destructive) { stories.delete(story.id) } label: { Image(systemName: "trash") }
                    .buttonStyle(.glass)
                    .help("Delete this story")
            }
            .controlSize(.small)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.secondary.opacity(0.07)))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 16, bottomLeadingRadius: 16, style: .continuous)
                .fill(story.severity.color)
                .frame(width: 4)
        }
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { actions.openStory(story) }
        .opacity(story.dismissed ? 0.55 : 1)
    }
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
