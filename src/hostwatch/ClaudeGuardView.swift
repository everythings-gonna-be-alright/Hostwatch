import AppKit
import SwiftUI

extension GuardPrompt {
    var title: String {
        switch tool {
        case "Bash": "Claude Code wants to run a command"
        case "Read", "Grep": "Claude Code wants to read a file"
        case "WebFetch": "Claude Code wants to open a web page"
        default: "Claude Code wants to change a file"
        }
    }
}

/// The floating panel when Claude Code won't ask you itself (it runs with permissions skipped): Block or
/// Allow Once; no answer blocks it.
struct GuardPromptView: View {
    @ObservedObject var claudeGuard: ClaudeGuard

    var body: some View {
        if let prompt = claudeGuard.prompts.first {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .font(.system(size: 30))
                        .foregroundStyle(.orange)
                        .symbolRenderingMode(.hierarchical)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(prompt.title).font(.headline)
                        Text("It " + prompt.reason + ".").font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                ScrollView {
                    Text(prompt.subject)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(maxHeight: 130)
                .fixedSize(horizontal: false, vertical: true)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.1)))
                Text("In \(Self.short(prompt.cwd)). Claude Code is running without asking for permission, so Hostwatch asks instead.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(prompt.deadline.timeIntervalSince(context.date).rounded()))
                        Text("Blocked in \(left) s if you don't answer").font(.caption).foregroundStyle(.secondary).monospacedDigit()
                    }
                    if claudeGuard.prompts.count > 1 {
                        Text("· \(claudeGuard.prompts.count - 1) more waiting").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Allow Once") { claudeGuard.answer(prompt.id, true) }
                    Button("Block") { claudeGuard.answer(prompt.id, false) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(18)
            .frame(width: 520)
        }
    }

    static func short(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }
}

/// Settings ▸ AI: turn the guard on, its state, and the log.
struct ClaudeGuardSection: View {
    @ObservedObject var claudeGuard: ClaudeGuard
    @ObservedObject var ui: SettingsState

    var body: some View {
        Section {
            Toggle("Check Claude Code's actions before they run", isOn: Binding(
                get: { claudeGuard.enabled }, set: { claudeGuard.setEnabled($0) }))
            if claudeGuard.enabled || claudeGuard.status != .off {
                LabeledContent("Status") { statusView }
            }
            LabeledContent {
                HStack(spacing: 8) {
                    Text(summary).foregroundStyle(.secondary).monospacedDigit()
                    Button("Show Log…") { ui.showGuardLog = true }.controlSize(.small)
                }
            } label: {
                Text("Last 24 hours")
            }
        } header: {
            Text("Claude Code guard")
        } footer: {
            Footnote("Adds a hook to Claude Code (~/.claude/settings.json) that hands Hostwatch every command, file "
                     + "change, file read and web fetch before it happens. Dangerous ones (deleting your home folder, a "
                     + "remote shell, sending a secret out, a known malware address) are blocked; risky ones (code "
                     + "downloaded and run, persistence, reading secrets, sudo) need your OK in Claude Code, or in a "
                     + "Hostwatch panel when Claude Code runs without asking. Hostwatch never approves anything itself. "
                     + "When Hostwatch isn't running, the same rules apply without the threat lists.")
        }
    }

    private var summary: String {
        let recent = claudeGuard.log.filter { $0.date > Date().addingTimeInterval(-86400) }
        let blocked = recent.filter { [.blocked, .declinedHere, .noAnswer].contains($0.outcome) }.count
        return "\(claudeGuard.checked) checked in all · \(recent.count - blocked) asked · \(blocked) blocked"
    }

    @ViewBuilder private var statusView: some View {
        switch claudeGuard.status {
        case .off:
            Text("Off").foregroundStyle(.secondary)
        case .active:
            Label("Active", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .missing:
            HStack {
                Label("Removed from Claude Code's settings", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Button("Restore") { claudeGuard.setEnabled(true) }.controlSize(.small)
            }
        case .hooksDisabled:
            Label("Off: Claude Code's settings turn all hooks off (disableAllHooks)", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .failed(let why):
            Label(why, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
        }
    }
}

/// What the guard blocked or asked about, newest first.
struct ClaudeGuardLogView: View {
    @ObservedObject var claudeGuard: ClaudeGuard
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Claude Code guard").font(.title3.weight(.semibold))
                Text("What Hostwatch blocked or asked you about. \(claudeGuard.checked) actions checked in all.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .padding(20)
            Divider()
            if claudeGuard.log.isEmpty {
                ContentUnavailableView("Nothing blocked or asked yet", systemImage: "checkmark.shield",
                                       description: Text("Everyday commands pass without a word."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(claudeGuard.log) { entry in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: Self.symbol(entry.outcome))
                            .foregroundStyle(Self.color(entry.outcome))
                            .frame(width: 18)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(Self.title(entry.outcome)).font(.callout.weight(.semibold))
                                Text(entry.tool).font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Text(entry.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                            }
                            Text(entry.subject).font(.system(size: 11, design: .monospaced)).lineLimit(3).textSelection(.enabled)
                            Text("It \(entry.reason) · in \(GuardPromptView.short(entry.cwd))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 3)
                }
            }
            Divider()
            HStack {
                Button("Clear Log") { claudeGuard.clearLog() }.disabled(claudeGuard.log.isEmpty)
                Spacer()
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 680, height: 520)
    }

    static func title(_ o: GuardLogEntry.Outcome) -> String {
        switch o {
        case .blocked: "Blocked"
        case .asked: "Asked in Claude Code"
        case .allowedHere: "Allowed by you in Hostwatch"
        case .declinedHere: "Blocked by you in Hostwatch"
        case .noAnswer: "Blocked: no answer"
        }
    }

    static func symbol(_ o: GuardLogEntry.Outcome) -> String {
        switch o {
        case .blocked, .declinedHere, .noAnswer: "xmark.octagon.fill"
        case .asked: "questionmark.circle.fill"
        case .allowedHere: "checkmark.circle.fill"
        }
    }

    static func color(_ o: GuardLogEntry.Outcome) -> Color {
        switch o {
        case .blocked, .declinedHere, .noAnswer: .red
        case .asked: .orange
        case .allowedHere: .green
        }
    }
}
