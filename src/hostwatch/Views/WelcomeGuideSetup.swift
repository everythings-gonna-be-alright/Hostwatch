import SwiftUI

/// Which AI helps: three choices as cards, each saying what it needs and whether that is there. The engine is
/// Settings ▸ AI's own setting, preselected on its default. Only Claude alone needs Claude Code to be chosen:
/// This Mac first still works without it, on the local model.
struct WelcomeAIPage: View {
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var claudeGuard: ClaudeGuard
    let theme: WelcomeTheme
    @ObservedObject private var claude = ClaudeCodeFinder.shared

    private static let choices: [(AIEngine, String, Color, String, String)] = [
        (.onDevice, "lock.laptopcomputer", .teal, "On this Mac only", "Apple's model or your own server. Nothing leaves your Mac."),
        (.hybrid, "arrow.triangle.branch", .indigo, "This Mac first", "This Mac's model first, Claude when it isn't sure."),
        (.claude, "sparkles", .blue, "Claude", "The most thorough. Checks go to Anthropic, secrets removed."),
    ]

    var body: some View {
        WelcomeLayout(theme: theme, title: "Which AI should help?",
                      subtitle: "AI suggests a status for what's new. The decision is always yours.") {
            WelcomeGlowHero(symbol: "sparkles", theme: theme)
        } content: {
            HStack(alignment: .top, spacing: 10) {
                ForEach(Self.choices, id: \.0) { choice in card(choice) }
            }
            statusRow
            WelcomeGroup {
                WelcomeGroupRow(symbol: "wand.and.stars", color: .cyan, title: "Suggest automatically",
                                text: "A status for each new pattern, ready for you to accept.") {
                    Toggle("Suggest automatically", isOn: $classifier.autoClassify).labelsHidden().toggleStyle(.switch)
                }
                if claude.found == true {
                    Divider().padding(.leading, 52)
                    WelcomeGroupRow(symbol: "checkmark.shield.fill", color: .blue, title: "Guard Claude Code",
                                    text: "Checks Claude Code's commands before they run.") {
                        Toggle("Guard Claude Code", isOn: Binding(get: { claudeGuard.enabled }, set: { claudeGuard.setEnabled($0) }))
                            .labelsHidden().toggleStyle(.switch)
                    }
                }
            }
            .padding(.top, 2)
        }
    }

    private func card(_ choice: (AIEngine, String, Color, String, String)) -> some View {
        let (engine, symbol, color, title, text) = choice
        let selected = classifier.engine == engine
        let blocked = engine == .claude && claude.found == false
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        return Button { classifier.engine = engine } label: {
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .top) {
                    if engine == .claude {
                        ClaudeMark(color: .white).padding(5).frame(width: 26, height: 26)
                            .background(ClaudeMark.color.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    } else {
                        WelcomeTile(symbol: symbol, color: color)
                    }
                    Spacer()
                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 17))
                        .foregroundStyle(selected ? AnyShapeStyle(color.gradient) : AnyShapeStyle(Color.primary.opacity(0.25)))
                }
                .padding(.bottom, 6)
                HStack(spacing: 6) {
                    Text(title).font(.headline)
                    if engine == .hybrid {
                        Text("Default").font(.caption2.weight(.semibold)).foregroundStyle(color)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(color.opacity(0.15), in: Capsule())
                    }
                }
                Text(blocked ? "Needs Claude Code, which isn't installed." : text)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .frame(height: 134, alignment: .topLeading)
            .background(selected ? AnyShapeStyle(color.opacity(0.12)) : AnyShapeStyle(.quaternary.opacity(0.5)), in: shape)
            .overlay(shape.strokeBorder(selected ? color.opacity(0.8) : .clear, lineWidth: 1.5))
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .disabled(blocked)
        .opacity(blocked ? 0.5 : 1)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    /// What the choices depend on, in one row of its own under the cards: the local model and Claude Code. Green
    /// when ready, orange when the local model can't be used, grey when Claude Code isn't installed.
    private var statusRow: some View {
        let local = classifier.localStatus
        return HStack(spacing: 10) {
            chip(local.isReady ? "Local model ready" : "Local model unavailable",
                 local.isReady ? "checkmark.circle.fill" : "exclamationmark.circle",
                 local.isReady ? .green : .orange)
                .help(local.label)
            switch claude.found {
            case true?: chip("Claude Code is ready", "checkmark.circle.fill", .green)
            case false?: chip("Claude Code isn't installed", "minus.circle", .secondary)
            case nil: chip("Looking for Claude Code…", "ellipsis.circle", .secondary)
            }
        }
        .font(.caption)
    }

    private func chip(_ text: String, _ symbol: String, _ color: Color) -> some View {
        Label(text, systemImage: symbol)
            .foregroundStyle(color)
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(.quaternary.opacity(0.5), in: Capsule())
    }
}

/// Looks for the `claude` command once, off the main thread: finding it can ask the login shell, which takes
/// seconds. The guide starts it when it opens, so the AI page has the answer before it slides in and nothing on it
/// changes mid-animation.
@MainActor
final class ClaudeCodeFinder: ObservableObject {
    static let shared = ClaudeCodeFinder()
    @Published private(set) var found: Bool?

    func start() {
        guard found == nil else { return }
        Task { found = await Task.detached { ClaudeLocator.path != nil }.value }
    }
}

/// The few settings worth deciding on day one, as System Settings rows. All of them live in Settings too.
struct WelcomeSettingsPage: View {
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var updates: UpdateChecker
    @ObservedObject var model: HUDModel
    let theme: WelcomeTheme
    @StateObject private var loginItem = LoginItem()

    var body: some View {
        WelcomeLayout(theme: theme, title: "A few settings",
                      subtitle: "You can change them later in Settings.") {
            WelcomeSwitchesHero(theme: theme)
        } content: {
            WelcomeGroup {
                WelcomeGroupRow(symbol: "power", color: .blue, title: "Open at login",
                                text: "Hostwatch starts watching when you log in.") {
                    toggle("Open at login", Binding(get: { loginItem.isOn }, set: { loginItem.set($0) }))
                }
                Divider().padding(.leading, 52)
                WelcomeGroupRow(symbol: "exclamationmark.shield.fill", color: .indigo, title: "Check against known threats",
                                text: "Downloads public lists of known threats each day. Nothing about you is sent.") {
                    toggle("Check against known threats", $intel.enabled)
                }
                Divider().padding(.leading, 52)
                WelcomeGroupRow(symbol: "arrow.triangle.2.circlepath", color: .teal, title: "Check for updates",
                                text: "Once a day. It only tells you, it never installs anything.") {
                    toggle("Check for updates", $updates.automatic)
                }
                Divider().padding(.leading, 52)
                WelcomeGroupRow(symbol: "rectangle.on.rectangle", color: .gray, title: "Show the HUD",
                                detail: Text("A small live overlay. Press \(Text("⌃⌥⌘H").fontWeight(.semibold).foregroundStyle(theme.tint)) in any app.")) {
                    toggle("Show the HUD", $model.overlayEnabled)
                }
            }
            if loginItem.needsApproval {
                HStack {
                    Label("macOS asks you to approve it in Login Items.", systemImage: "exclamationmark.circle")
                        .foregroundStyle(.orange)
                    Button("Open Login Items…") { loginItem.openLoginItems() }.buttonStyle(.glass).controlSize(.small)
                }
                .font(.callout)
            }
            if let problem = loginItem.problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.callout)
            }
        }
    }

    private func toggle(_ title: String, _ isOn: Binding<Bool>) -> some View {
        Toggle(title, isOn: isOn).labelsHidden().toggleStyle(.switch)
    }
}
