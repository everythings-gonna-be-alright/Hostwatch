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

/// The question when Claude Code won't ask you itself (it runs with permissions skipped), in the style of macOS's
/// permission alerts. Block is the default (Return); Escape blocks too; no answer blocks it.
struct GuardPromptView: View {
    @ObservedObject var claudeGuard: ClaudeGuard

    var body: some View {
        if let prompt = claudeGuard.prompts.first {
            VStack(spacing: 14) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.orange)
                    .symbolRenderingMode(.hierarchical)
                    .accessibilityHidden(true)
                VStack(spacing: 5) {
                    Text(prompt.title).font(.headline).multilineTextAlignment(.center)
                    Text("It " + prompt.reason + ".")
                        .font(.callout).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                }
                ScrollView {
                    Text(prompt.subject)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(maxHeight: 120)
                .fixedSize(horizontal: false, vertical: true)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.05)))
                Text("In \(Self.short(prompt.cwd)). Claude Code runs without asking for permission, so Hostwatch asks.")
                    .font(.caption).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                VStack(spacing: 8) {
                    HStack(spacing: 10) {
                        Button { claudeGuard.answer(prompt.id, true) } label: { Text("Allow Once").frame(maxWidth: .infinity) }
                            .buttonStyle(.glass)
                        Button { claudeGuard.answer(prompt.id, false) } label: { Text("Block").frame(maxWidth: .infinity) }
                            .buttonStyle(.glassProminent)
                            .keyboardShortcut(.defaultAction)
                    }
                    .controlSize(.large)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(prompt.deadline.timeIntervalSince(context.date).rounded()))
                        Text("Blocked in \(left) s if you don't answer"
                             + (claudeGuard.prompts.count > 1 ? " · \(claudeGuard.prompts.count - 1) more waiting" : ""))
                            .font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
                    }
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 22)
            .padding(.top, 26)
            .padding(.bottom, 16)
            .frame(width: 400)
            .onExitCommand { claudeGuard.answer(prompt.id, false) }
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
            if claudeGuard.enabled {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Added to ~/.claude/settings.json. Start a new Claude Code session to load it.")
                    HStack(alignment: .top) {
                        Text("To use it elsewhere, paste this into a project's .claude/settings.json, or into the managed "
                             + "settings (/Library/Application Support/ClaudeCode/managed-settings.json, admin only) so "
                             + "Claude can't remove it:")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button(ui.guardCopied ? "Copied" : "Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(claudeGuard.configFragment, forType: .string)
                            ui.guardCopied = true
                        }
                        .controlSize(.small)
                    }
                    Text(claudeGuard.configFragment)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.05)))
                }
                .font(.callout)
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
            Footnote("Before Claude Code runs a command or touches a file, Hostwatch checks it: dangerous ones are "
                     + "blocked, risky ones need your OK (in Claude Code, or in a Hostwatch panel when Claude Code runs "
                     + "without asking). Hostwatch never approves anything itself.")
        }
    }

    private var summary: String {
        let recent = claudeGuard.log.filter { $0.date > Date().addingTimeInterval(-86400) }
        let blocked = recent.filter { [.blocked, .declinedHere, .noAnswer].contains($0.outcome) }.count
        return "\(recent.count - blocked) asked · \(blocked) blocked"
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
