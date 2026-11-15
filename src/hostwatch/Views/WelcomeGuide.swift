import AppKit
import SwiftUI

/// The welcome guide: five short pages on the first launch (Help ▸ Welcome Guide opens it again). What Hostwatch is,
/// the five tabs, how decisions work, the learning day, and Protection. One symbol, a title and a few lines each.
struct WelcomeGuideView: View {
    /// How long the learning day lasts, said on its page ("24 hours", "3 days").
    let learning: String
    let done: () -> Void
    @StateObject private var state = WelcomePage()

    private static let count = 5

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                page(state.index).id(state.index).transition(.opacity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .animation(.easeInOut(duration: 0.2), value: state.index)
            HStack(spacing: 6) {
                ForEach(0..<Self.count, id: \.self) { i in
                    Circle().fill(i == state.index ? Color.primary : Color.primary.opacity(0.2)).frame(width: 6, height: 6)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Page \(state.index + 1) of \(Self.count)")
            .padding(.bottom, 14)
            HStack {
                Button("Skip", action: done).buttonStyle(.glass).keyboardShortcut(.cancelAction)
                Spacer()
                if state.index > 0 { Button("Back") { state.index -= 1 }.buttonStyle(.glass) }
                if state.index < Self.count - 1 {
                    Button("Continue") { state.index += 1 }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
                } else {
                    Button("Start Watching", action: done).buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
                }
            }
            .controlSize(.large)
            .padding(.horizontal, 24)
            .padding(.bottom, 22)
        }
        .frame(width: 560, height: 440)
    }

    @ViewBuilder private func page(_ i: Int) -> some View {
        switch i {
        case 0:
            WelcomeText(symbol: "shield.lefthalf.filled", title: "Hostwatch watches your Mac", lines: [
                "It sees what runs, which files programs open, and where they connect. It learns what's normal here and "
                    + "tells you about what isn't.",
                "Everything stays on this Mac, encrypted.",
            ])
        case 1:
            VStack(spacing: 18) {
                Text("Five tabs").font(.title2.weight(.semibold))
                VStack(alignment: .leading, spacing: 12) {
                    WelcomeTab(symbol: "list.bullet.rectangle", name: "Events", text: "everything as it happens, live.")
                    WelcomeTab(symbol: "square.stack.3d.up", name: "Patterns", text: "the same activity grouped into habits, each one decided once.")
                    WelcomeTab(symbol: "shield.lefthalf.filled", name: "Protection", text: "what may run, open your secrets, or connect.")
                    WelcomeTab(symbol: "point.3.connected.trianglepath.dotted", name: "Stories", text: "small steps joined into one alert when they add up.")
                    WelcomeTab(symbol: "network.badge.shield.half.filled", name: "Network", text: "every domain and connection, new ones first.")
                }
                .frame(maxWidth: 440, alignment: .leading)
            }
            .padding(.horizontal, 40)
        case 2:
            WelcomeText(symbol: "checkmark.seal", title: "You decide, once", lines: [
                "Each habit is a pattern: Safe, New, Suspicious or Dangerous.",
                "Your decisions always win, then your rules, then AI, then what Hostwatch decides by itself. Needs You in "
                    + "Patterns is the short list of what's left.",
            ])
        case 3:
            WelcomeText(symbol: "books.vertical", title: "Today is the learning day", lines: [
                "For the next \(learning) Hostwatch learns what's typical on this Mac. What signed apps do every day is learned "
                    + "for you, so afterwards only a handful of patterns need you.",
                "Shells, your secrets and anything unsigned are never learned. The menu bar icon shows the time left, and "
                    + "Settings changes the length.",
            ])
        default:
            WelcomeText(symbol: "hand.raised", title: "Protection, when you're ready", lines: [
                "Protection starts on Watch: it shows what it would stop and stops nothing. After the learning day, switch to "
                    + "Ask to pause new programs and decide, with the AI's view first.",
                "The HUD, a small live overlay, is in View ▸ Show HUD.",
            ])
        }
    }
}

/// A page: one symbol, a title, a few short lines.
private struct WelcomeText: View {
    let symbol: String
    let title: String
    let lines: [String]

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(.tint)
                .symbolRenderingMode(.hierarchical)
                .frame(height: 56)
                .accessibilityHidden(true)
            Text(title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
            VStack(spacing: 10) {
                ForEach(lines, id: \.self) { line in
                    Text(line).font(.body).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: 440)
        }
        .padding(.horizontal, 40)
        .accessibilityElement(children: .combine)
    }
}

/// One tab on the tabs page: its icon, its name, what it's for.
private struct WelcomeTab: View {
    let symbol: String
    let name: String
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: symbol).font(.system(size: 15, weight: .medium)).foregroundStyle(.tint).frame(width: 24)
            (Text(name + ": ").fontWeight(.semibold) + Text(text).foregroundStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The page shown (no @State macro with the command line tools).
final class WelcomePage: ObservableObject {
    @Published var index = 0
}
