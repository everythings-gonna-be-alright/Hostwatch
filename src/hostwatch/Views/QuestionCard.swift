import AppKit
import SwiftUI

// The parts every question window shares (network connection, program launch, protected file), so the three read as
// one family and the kind is the first thing seen: a band in the kind's colour across the top, the program and what
// it wants, and the four answers in two groups, block and allow.

/// How wide a question is: about as tall as wide with its answers in two rows, not a long strip.
enum QuestionCard {
    static let width: CGFloat = 520
}

/// The top of a question: the kind's symbol on its colour, its name in that colour, and how long is left at the right,
/// over a wash of the colour that fades into the card.
struct QuestionBanner<Trailing: View>: View {
    let kind: EventKind
    let title: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: kind.symbol)
                .font(.system(size: 14, weight: .bold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(kind.color.gradient, in: Circle())
                .shadow(color: kind.color.opacity(0.45), radius: 6, y: 2)
                .accessibilityHidden(true)
            Text(title.uppercased())
                .font(.callout.weight(.medium)).tracking(0.6)
                .foregroundStyle(kind.color)
            Spacer(minLength: 8)
            trailing
        }
        .padding(.horizontal, 22)
        .padding(.top, 18)
        .padding(.bottom, 14)
        .frame(maxWidth: .infinity)
        .background {
            LinearGradient(colors: [kind.color.opacity(0.30), kind.color.opacity(0.08), .clear],
                           startPoint: .top, endPoint: .bottom)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The program's icon and what it wants, centred: the title in bold, a line of detail under it.
struct QuestionSubject<Detail: View>: View {
    let icon: NSImage
    let title: String
    @ViewBuilder var detail: Detail

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(nsImage: icon).resizable().frame(width: 44, height: 44).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.title3.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                detail
            }
            Spacer(minLength: 0)
        }
    }
}

/// The four answers in two groups side by side, with a line between: block on the left, allow on the right, each
/// with once over always. The sides look the same, told apart by place and words alone (symbols crowded them, and
/// red would steer you: it reads as the dangerous choice, when blocking is the safe one). Both Always buttons are the
/// stronger ones, as they decide for good, and alike, so neither side is suggested. Return answers Allow Once, never
/// an Always, so a reflex keypress decides nothing for good.
struct QuestionAnswers: View {
    let alwaysBlock: () -> Void
    let blockOnce: () -> Void
    let allowOnce: () -> Void
    let alwaysAllow: () -> Void
    var blockOnceIsCancel = false
    var help: (alwaysBlock: String, blockOnce: String, allowOnce: String, alwaysAllow: String)

    var body: some View {
        HStack(spacing: 16) {
            VStack(spacing: 8) {
                Button(action: blockOnce) { Text("Block Once").frame(maxWidth: .infinity) }
                    .keyboardShortcut(blockOnceIsCancel ? .cancelAction : nil)
                    .help(help.blockOnce)
                Button(action: alwaysBlock) { Text("Always Block").frame(maxWidth: .infinity) }
                    .buttonStyle(.glassProminent)
                    .help(help.alwaysBlock)
            }
            Divider()
            VStack(spacing: 8) {
                Button(action: allowOnce) { Text("Allow Once").frame(maxWidth: .infinity) }
                    .keyboardShortcut(.defaultAction)
                    .help(help.allowOnce)
                Button(action: alwaysAllow) { Text("Always Allow").frame(maxWidth: .infinity) }
                    .buttonStyle(.glassProminent)
                    .help(help.alwaysAllow)
            }
        }
        .buttonStyle(.glass)
        .fixedSize(horizontal: false, vertical: true)
        .controlSize(.large)
    }
}
