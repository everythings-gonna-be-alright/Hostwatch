import AppKit
import SwiftUI

/// Show Launch Chain: who started a process, read top-down like a family tree, from launchd to the process itself.
struct LaunchChainView: View {
    let report: LaunchChainReport
    let close: () -> Void
    @StateObject private var copy = CopyState()

    /// Top to bottom: launchd (or the gap before recording), the ancestors oldest first, then the process.
    private var nodes: [Node] {
        var list: [Node] = [report.broken ? .gap : .step(LaunchStep(pid: 1, ppid: 0, path: "/sbin/launchd", args: "",
                                                                    source: .live), origin: report.origin == .launchd)]
        for (i, step) in report.steps.enumerated().reversed() {
            list.append(.step(step, origin: i == report.originIndex))
        }
        list.append(.process(report.process))
        return list
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.top, 30)                         // under the transparent title bar
                .padding(.bottom, 14)
            Divider()
            ScrollView { tree }
            Divider()
            footer
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
        }
        .frame(minWidth: 480, minHeight: 320)
    }

    private var tree: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(nodes.enumerated()), id: \.offset) { i, node in
                NodeRow(node: node, last: i == nodes.count - 1, session: report.session)
            }
            if !report.earlier.isEmpty { earlier }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(nsImage: ProcessIcons.icon(report.process.path))
                .resizable()
                .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text("Who started \(report.process.name)")
                    .font(.title3.weight(.semibold))
                Text(report.summary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            OriginTag(origin: report.origin)
        }
    }

    private var earlier: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Before that, pid \(String(report.process.pid)) ran")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(Array(report.earlier.enumerated()), id: \.offset) { _, step in
                CommandText(step.args.isEmpty ? step.path : step.args, lines: 2)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.quaternary.opacity(0.5)))
        .padding(.leading, 38)
        .padding(.top, 4)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Text("Rebuilt from what Hostwatch recorded, so it works after these processes have exited.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button(copy.done ? "Copied" : "Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(report.text, forType: .string)
                copy.done = true
            }
            Button("Done", action: close)
                .keyboardShortcut(.defaultAction)
        }
        .controlSize(.large)
    }
}

/// "Copy" turns to "Copied" once pressed (no @State macro with the command line tools).
private final class CopyState: ObservableObject {
    @Published var done = false
}

/// One entry in the tree.
enum Node {
    case gap                                      // the chain runs into a parent started before recording
    case step(LaunchStep, origin: Bool)
    case process(LaunchStep)
}

/// A step with its icon on a connecting line, its name, pid and command line.
private struct NodeRow: View {
    let node: Node
    let last: Bool
    let session: String?

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                icon.frame(width: 26, height: 26)
                if !last {
                    Rectangle()
                        .fill(.quaternary)
                        .frame(width: 1.5)
                        .frame(maxHeight: .infinity)
                        .padding(.vertical, 3)
                }
            }
            .frame(width: 26)
            content
                .padding(.bottom, last ? 0 : 14)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var icon: some View {
        switch node {
        case .gap:
            Image(systemName: "questionmark.circle")
                .font(.system(size: 18))
                .foregroundStyle(.tertiary)
        case .step(let step, _), .process(let step):
            if let agent = CodingAgent.of(step.path) {
                AgentBadge(agent: agent, size: 22)
            } else {
                Image(nsImage: ProcessIcons.icon(step.path)).resizable()
            }
        }
    }

    @ViewBuilder private var content: some View {
        switch node {
        case .gap:
            VStack(alignment: .leading, spacing: 2) {
                Text("Not recorded").font(.body.weight(.semibold)).foregroundStyle(.secondary)
                Text("This parent started before Hostwatch was recording, so the chain stops here.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(.top, 4)
        case .step(let step, let origin):
            stepContent(step, origin: origin, highlight: false)
        case .process(let step):
            stepContent(step, origin: false, highlight: true)
        }
    }

    private func stepContent(_ step: LaunchStep, origin: Bool, highlight: Bool) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(step.name)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(highlight ? Color.accentColor : .primary)
                Text("pid \(String(step.pid))")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                if origin { Tag(text: "Origin", color: .accentColor) }
                if highlight { Tag(text: "This event", color: .secondary) }
                Spacer(minLength: 6)
                if !highlight && step.pid != 1 { SourceLabel(source: step.source) }
            }
            .padding(.top, 4)
            if !step.args.isEmpty || step.pid != 1 {
                CommandText(step.args.isEmpty ? step.path : step.args, lines: highlight ? 4 : 2)
            }
        }
    }
}

/// A command line: monospaced, selectable, a few lines at most (the tooltip and Copy keep all of it).
private struct CommandText: View {
    let text: String
    let lines: Int

    init(_ text: String, lines: Int) {
        self.text = text
        self.lines = lines
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11, design: .monospaced))
            .foregroundStyle(.secondary)
            .lineLimit(lines)
            .truncationMode(.middle)
            .textSelection(.enabled)
            .help(text)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Where a step came from, from most to least sure.
private struct SourceLabel: View {
    let source: LaunchStep.Source

    var body: some View {
        let (symbol, text, help): (String, String, String) = switch source {
        case .launch: ("record.circle", "Recorded launch", "Hostwatch saw this process start.")
        case .list: ("list.bullet", "Process list", "From the list of processes Hostwatch records once a minute.")
        case .live: ("dot.radiowaves.left.and.right", "Running now",
                     "Still running. A pid can be reused, so this is the least sure source.")
        }
        Label(text, systemImage: symbol)
            .font(.caption)
            .foregroundStyle(.tertiary)
            .labelStyle(.titleAndIcon)
            .help(help)
    }
}

private struct Tag: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Capsule().fill(color.opacity(0.14)))
    }
}

/// The origin as a tag in the header.
private struct OriginTag: View {
    let origin: ProcessOrigin

    var body: some View {
        let (symbol, text): (String, String) = switch origin {
        case .agent: ("sparkles", "AI agent")
        case .terminal: ("terminal", "Terminal")
        case .app: ("app", "App")
        case .launchd: ("gearshape", "macOS")
        case .scheduled: ("clock", "Scheduled")
        case .ssh: ("network", "Remote login")
        case .other: ("cpu", "Program")
        case .unknown: ("questionmark", "Unknown")
        }
        Label(text, systemImage: symbol)
            .font(.callout.weight(.medium))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(.quaternary.opacity(0.6)))
    }
}

/// "Started by Claude Code": the launch chain in one card, for a question panel. The origin's sentence, the chain as
/// a breadcrumb from the origin down to the program (the middle folded when it's long), and what the program runs.
struct LaunchChainStrip: View {
    let report: LaunchChainReport

    /// Origin first, the program last: at most the origin, the two nearest parents and the program.
    private var crumbs: [LaunchStep?] {
        let ancestors = Array(report.steps.reversed())              // oldest first
        let from = report.originIndex.map { report.steps.count - 1 - $0 } ?? 0
        var shown = Array(ancestors[min(from, ancestors.count)...])
        var out: [LaunchStep?] = []
        if shown.count > 3 { out = [shown.first, nil]; shown = Array(shown.suffix(2)) }   // nil: "…"
        return out + shown.map { Optional($0) } + [report.process]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(report.summary).font(.callout.weight(.medium)).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 4) {
                ForEach(Array(crumbs.enumerated()), id: \.offset) { i, step in
                    if i > 0 { Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(.tertiary) }
                    if let step { crumb(step, last: i == crumbs.count - 1) } else { Text("…").foregroundStyle(.secondary) }
                }
            }
            .lineLimit(1)
            let what = report.process.args.isEmpty ? report.process.path : report.process.args
            Text(what)
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                .help(report.process.path)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.05)))
    }

    private func crumb(_ step: LaunchStep, last: Bool) -> some View {
        HStack(spacing: 4) {
            if let agent = CodingAgent.of(step.path) {
                AgentBadge(agent: agent, size: 14)
            } else {
                Image(nsImage: ProcessIcons.icon(step.path)).resizable().frame(width: 14, height: 14)
            }
            // An agent's binary is named by its version ("2.1.318"): its name says more.
            Text(CodingAgent.of(step.path)?.title ?? step.name)
                .font(.caption.weight(last ? .semibold : .regular)).foregroundStyle(last ? .primary : .secondary)
        }
        .help("\(step.path) (pid \(step.pid))")
    }
}
