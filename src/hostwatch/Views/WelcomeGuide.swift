import AppKit
import SwiftUI

/// What the welcome guide reads and changes: the same objects Settings binds, so a choice made here is the setting.
@MainActor
struct WelcomeContext {
    let baseline: BaselineLearner
    let classifier: PatternClassifier
    let claudeGuard: ClaudeGuard
    let intel: ThreatIntel
    let updates: UpdateChecker
    let model: HUDModel
}

/// The welcome guide: seven short pages on the first launch, and from Help ▸ Welcome Guide. Each page is one icon in
/// its own colour, a title and a few lines, centred in the whole window over a soft wash of that colour. The Set Up
/// pages hold the choices that matter on day one (the AI, startup, threat lists, updates, the HUD), applied at once.
struct WelcomeGuideView: View {
    let context: WelcomeContext
    let done: () -> Void
    @StateObject private var state: WelcomePage

    private static let count = WelcomeTheme.pages.count

    init(context: WelcomeContext, start: Int = 0, done: @escaping () -> Void) {
        self.context = context
        self.done = done
        _state = StateObject(wrappedValue: WelcomePage(index: start))
        ClaudeCodeFinder.shared.start()
    }

    private var theme: WelcomeTheme { WelcomeTheme.pages[state.index] }
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Continue slides the next page in from the right, Back from the left. With Reduce Motion, pages fade.
    private var slide: AnyTransition {
        guard !reduceMotion else { return .opacity }
        let ahead: Edge = state.forward ? .trailing : .leading
        let behind: Edge = state.forward ? .leading : .trailing
        return .asymmetric(insertion: .move(edge: ahead).combined(with: .opacity),
                           removal: .move(edge: behind).combined(with: .opacity))
    }

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                page(state.index).id(state.index).transition(slide)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.top, 28)
            HStack {
                Button("Skip", action: done).buttonStyle(.glass).keyboardShortcut(.cancelAction)
                Spacer()
                if state.index > 0 { Button("Back") { state.go(-1) }.buttonStyle(.glass) }
                Group {
                    if state.index < Self.count - 1 {
                        Button("Continue") { state.go(1) }
                    } else {
                        Button("Start Watching", action: done)
                    }
                }
                .buttonStyle(.glassProminent).tint(theme.tint).keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
            .overlay {
                // Centred on the window, whatever the buttons on either side measure.
                HStack(spacing: 7) {
                    ForEach(0..<Self.count, id: \.self) { i in
                        Capsule()
                            .fill(Color.primary.opacity(i == state.index ? 0.7 : 0.18))
                            .frame(width: i == state.index ? 18 : 6, height: 6)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Page \(state.index + 1) of \(Self.count)")
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 22)
        }
        .background {
            // A wash of the page's colour from the top, fading into the window: colour without a single extra shape.
            LinearGradient(colors: [theme.top.opacity(0.22), theme.bottom.opacity(0.06), .clear],
                           startPoint: .top, endPoint: UnitPoint(x: 0.5, y: 0.7))
                .ignoresSafeArea()
        }
        .animation(.spring(duration: 0.45, bounce: 0.12), value: state.index)
        .frame(width: 680, height: 632)   // the 600-point content rect plus the title bar it draws under
    }

    @ViewBuilder private func page(_ i: Int) -> some View {
        let theme = WelcomeTheme.pages[i]
        switch i {
        case 0: MeetPage(theme: theme)
        case 1: TabsPage(theme: theme)
        case 2: DecidePage(theme: theme)
        case 3: LearningPage(baseline: context.baseline, theme: theme)
        case 4: WelcomeAIPage(classifier: context.classifier, claudeGuard: context.claudeGuard, theme: theme)
        case 5: WelcomeSettingsPage(intel: context.intel, updates: context.updates, model: context.model, theme: theme)
        default: StartPage(theme: theme)
        }
    }
}

// MARK: Pages

/// What Hostwatch is, in three lines.
private struct MeetPage: View {
    let theme: WelcomeTheme

    var body: some View {
        WelcomeLayout(theme: theme, title: "Welcome to Hostwatch",
                      subtitle: "A short tour of how it works, and a few choices to make. It takes a minute.") {
            WelcomeWatchHero(theme: theme)
        } content: {
            VStack(alignment: .leading, spacing: 20) {
                WelcomeFeature(symbol: "eye.fill", color: .blue, title: "Sees",
                               text: "Every program that runs, the files it opens and where it connects.")
                WelcomeFeature(symbol: "brain.fill", color: .indigo, title: "Learns",
                               text: "What your Mac usually does, so the ordinary stays quiet.")
                WelcomeFeature(symbol: "bell.badge.fill", color: .teal, title: "Tells you",
                               text: "When something new or risky happens, and can stop it.")
            }
            .fixedSize(horizontal: true, vertical: false)   // as wide as its longest line, so it centres
            Label("All of it stays on this Mac, encrypted.", systemImage: "lock.fill")
                .font(.callout).foregroundStyle(.secondary).padding(.top, 10)
        }
    }
}

/// The five tabs, each in its own colour.
private struct TabsPage: View {
    let theme: WelcomeTheme

    var body: some View {
        WelcomeLayout(theme: theme, title: "Everything in one window",
                      subtitle: "Five tabs, from what happens right now to what it adds up to.") {
            WelcomeWindowHero(theme: theme)
        } content: {
            VStack(alignment: .leading, spacing: 16) {
                WelcomeFeature(symbol: "list.bullet.rectangle.fill", color: .blue, title: "Events",
                               text: "Everything as it happens, live.")
                WelcomeFeature(symbol: "square.stack.3d.up.fill", color: .indigo, title: "Patterns",
                               text: "Repeated activity grouped into habits, each decided once.")
                WelcomeFeature(symbol: "shield.lefthalf.filled", color: .cyan, title: "Protection",
                               text: "What may run, open your secrets or go online.")
                WelcomeFeature(symbol: "point.3.filled.connected.trianglepath.dotted", color: .teal, title: "Stories",
                               text: "Small suspicious steps joined into one alert.")
                WelcomeFeature(symbol: "network", color: .mint, title: "Network",
                               text: "Every server and connection, the new ones first.")
            }
            .fixedSize(horizontal: true, vertical: false)   // as wide as its longest line, so it centres
        }
    }
}

/// The four statuses, then who wins when decisions disagree.
private struct DecidePage: View {
    let theme: WelcomeTheme
    private static let order: [(String, String)] = [
        ("You", "Your choice always comes first."),
        ("Your rules", "Rules made from your choices, for a whole app or folder."),
        ("AI", "Suggestions from Claude or the model on this Mac."),
        ("Automatic", "Apple's own programs and developers you already trust."),
    ]

    var body: some View {
        WelcomeLayout(theme: theme, title: "You decide, once",
                      subtitle: "Each habit gets one of four statuses. Mark it once and it stays that way.") {
            WelcomeStatusHero()
        } content: {
            WelcomeGroup {
                ForEach(Array(Self.order.enumerated()), id: \.offset) { i, step in
                    if i > 0 { Divider().padding(.leading, 52) }
                    HStack(spacing: 12) {
                        Text("\(i + 1)").font(.callout.weight(.bold).monospacedDigit())
                            .foregroundStyle(i == 0 ? .white : theme.bottom)
                            .frame(width: 26, height: 26)
                            .background(i == 0 ? AnyShapeStyle(theme.gradient) : AnyShapeStyle(theme.bottom.opacity(0.15)), in: Circle())
                        VStack(alignment: .leading, spacing: 1) {
                            Text(step.0).fontWeight(.medium)
                            Text(step.1).font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 9)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Who wins when they disagree: you, then your rules, then AI, then automatic")
            .padding(.top, 6)
            Text("When they disagree, the higher one wins.").font(.callout).foregroundStyle(.secondary)
        }
    }
}

/// The learning day: its timeline, what is never learned, and how long it lasts, or Off.
private struct LearningPage: View {
    @ObservedObject var baseline: BaselineLearner
    let theme: WelcomeTheme

    private var length: String {
        let days = baseline.duration / 86_400
        return days <= 1 ? "24 hours" : "\(Int(days.rounded())) days"
    }

    /// Off is 0. Choosing a length after Off starts learning again from now.
    private var choice: Binding<Double> {
        Binding(get: { baseline.isOff ? 0 : baseline.duration }, set: { seconds in
            if seconds == 0 { baseline.turnOff(); return }
            if baseline.isOff { baseline.learnAgain() }
            baseline.setDuration(seconds)
        })
    }

    private func never(_ symbol: String, _ name: String) -> some View {
        HStack(spacing: 7) {
            Image(systemName: symbol).font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
                .frame(width: 22, height: 22).accessibilityHidden(true)
            Text(name)
        }
        .padding(.leading, 6).padding(.trailing, 14).padding(.vertical, 6)
        .background(.quaternary.opacity(0.5), in: Capsule())
    }

    var body: some View {
        WelcomeLayout(theme: theme, title: "The learning day",
                      subtitle: baseline.isOff
                          ? "Learning is off. Every new pattern waits for your decision."
                          : "For the next \(length), Hostwatch learns what your signed apps usually do and marks it Safe for you.") {
            WelcomeLearningHero(theme: theme, off: baseline.isOff)
        } content: {
            Picker("Learning", selection: choice) {
                Text("Off").tag(0.0)
                Text("1 day").tag(24 * 3600.0)
                Text("3 days").tag(3 * 24 * 3600.0)
                Text("7 days").tag(7 * 24 * 3600.0)
            }
            .pickerStyle(.segmented).labelsHidden().controlSize(.large).fixedSize()
            if baseline.isOff {
                Text("You can turn it on again in Settings ▸ Detection.")
                    .font(.callout).foregroundStyle(.secondary).padding(.top, 8)
            } else {
                VStack(spacing: 10) {
                    Text("Never learned. These always wait for you.").font(.callout).foregroundStyle(.secondary)
                    HStack(spacing: 10) {
                        never("terminal.fill", "Shells")
                        never("key.fill", "Your secrets")
                        never("exclamationmark.shield.fill", "Unsigned apps")
                    }
                }
                .padding(.top, 22)
                .accessibilityElement(children: .combine)
            }
        }
    }
}

/// Protection's three modes, starting on Watch.
private struct StartPage: View {
    let theme: WelcomeTheme

    var body: some View {
        WelcomeLayout(theme: theme, title: "Protection, when you're ready",
                      subtitle: "Hostwatch starts in Watch. Once the learning day is over, try Ask in the Protection tab.") {
            WelcomeModesHero(theme: theme)
        } content: {
            VStack(alignment: .leading, spacing: 20) {
                WelcomeFeature(symbol: "eye.fill", color: .blue, title: "Watch",
                               text: "Shows what it would stop, and stops nothing.")
                WelcomeFeature(symbol: "hand.raised.fill", color: .indigo, title: "Ask",
                               text: "Pauses new programs until you decide, with the AI's view first.")
                WelcomeFeature(symbol: "lock.fill", color: .teal, title: "Strict",
                               text: "Only what you allowed can run.")
            }
            .fixedSize(horizontal: true, vertical: false)   // as wide as its longest line, so it centres
        }
    }
}

/// The page shown (no @State macro with the command line tools).
final class WelcomePage: ObservableObject {
    @Published var index: Int
    /// Which way the last turn went, for the slide.
    @Published var forward = true

    func go(_ step: Int) {
        forward = step > 0
        index = min(max(index + step, 0), WelcomeTheme.pages.count - 1)
    }

    init(index: Int = 0) { self.index = min(max(index, 0), WelcomeTheme.pages.count - 1) }
}
