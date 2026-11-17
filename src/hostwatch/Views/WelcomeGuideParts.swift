import SwiftUI

/// Each page's colour pair: its icon's gradient, the soft wash behind the window, and the tint of its switches and
/// Continue button. Calm system colours that read as dependable (blue, indigo, teal, cyan), never the status colours
/// (red, orange, green), which keep their meaning.
struct WelcomeTheme {
    let top: Color
    let bottom: Color
    /// Switches and the Continue button: the page's colour, or blue where the page itself is grey.
    var tint: Color { bottom == Self.grey ? .blue : bottom }
    private static let grey = Color(white: 0.45)

    static let pages: [WelcomeTheme] = [
        WelcomeTheme(top: .cyan, bottom: .blue),
        WelcomeTheme(top: .blue, bottom: .indigo),
        WelcomeTheme(top: .teal, bottom: .blue),
        WelcomeTheme(top: .mint, bottom: .teal),
        WelcomeTheme(top: .cyan, bottom: .indigo),
        WelcomeTheme(top: Color(white: 0.62), bottom: grey),
        WelcomeTheme(top: .blue, bottom: .indigo),
    ]

    var gradient: LinearGradient { LinearGradient(colors: [top, bottom], startPoint: .top, endPoint: .bottom) }
}

/// A page: its picture, the title, an optional line, then the page's content. The picture's box has one height on
/// every page and sits at the top, the rest is centred under it.
struct WelcomeLayout<Hero: View, Content: View>: View {
    let theme: WelcomeTheme
    let title: String
    let subtitle: String?
    let hero: Hero
    let content: Content

    init(theme: WelcomeTheme, title: String, subtitle: String? = nil,
         @ViewBuilder hero: () -> Hero, @ViewBuilder content: () -> Content) {
        self.theme = theme
        self.title = title
        self.subtitle = subtitle
        self.hero = hero()
        self.content = content()
    }

    var body: some View {
        VStack(spacing: 0) {
            hero.frame(height: 130).padding(.top, 8)
            // The words and the page's content sit in the middle of the space left under the picture, so a short
            // page doesn't leave an empty band at the bottom, and the picture stays level from page to page.
            Spacer(minLength: 0)
            Text(title).font(.system(size: 28, weight: .bold)).multilineTextAlignment(.center)
            if let subtitle {
                Text(subtitle).font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true).frame(maxWidth: 520).padding(.top, 8)
            }
            VStack(spacing: 14) { content }.frame(maxWidth: 580).padding(.top, 24)
                .tint(theme.tint)       // switches in the page's colour, not the accent (which can be graphite)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 48)
    }
}

/// Rows in one rounded group with hairlines between them, the way System Settings groups its rows.
struct WelcomeGroup<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

/// A small coloured tile with a white symbol, as System Settings marks its rows.
struct WelcomeTile: View {
    let symbol: String
    let color: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 26, height: 26)
            .background(color.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// A row of a group: tile, title, a line under it, and whatever sits at the trailing edge.
struct WelcomeGroupRow<Trailing: View>: View {
    let symbol: String
    let color: Color
    let title: String
    var text: String? = nil
    /// The line under the title when part of it needs styling (a shortcut in the accent).
    var detail: Text? = nil
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(spacing: 12) {
            WelcomeTile(symbol: symbol, color: color)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                if let line = detail ?? text.map({ Text($0) }) {
                    line.font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            trailing
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

/// A feature line in the style of Apple's welcome sheets: a large coloured symbol, a bold name, one line under it.
struct WelcomeFeature: View {
    let symbol: String
    let color: Color
    let title: String
    let text: String

    var body: some View {
        HStack(spacing: 18) {
            Image(systemName: symbol)
                .font(.system(size: 26, weight: .regular))
                .foregroundStyle(color.gradient)
                .symbolRenderingMode(.monochrome)
                .frame(width: 40)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}
