import SwiftUI

// The welcome guide's pictures, one per page, each drawn for what its page says. They share a height, so the title
// under them never moves, and they are decoration: hidden from VoiceOver, the page's words carry the meaning.

/// Meet: the shield inside rings, keeping watch.
struct WelcomeWatchHero: View {
    let theme: WelcomeTheme

    var body: some View {
        ZStack {
            Circle().strokeBorder(theme.top.opacity(0.14), lineWidth: 1).frame(width: 128, height: 128)
            Circle().strokeBorder(theme.top.opacity(0.26), lineWidth: 1).frame(width: 98, height: 98)
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 30, weight: .medium)).foregroundStyle(.white)
                .frame(width: 68, height: 68)
                .background(theme.gradient, in: Circle())
                .shadow(color: theme.bottom.opacity(0.45), radius: 18, y: 8)
        }
        .accessibilityHidden(true)
    }
}

/// The tabs: a small window with its tab bar, the first tab chosen.
struct WelcomeWindowHero: View {
    let theme: WelcomeTheme

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 4) {
                ForEach(0..<3, id: \.self) { _ in Circle().fill(Color.primary.opacity(0.25)).frame(width: 6, height: 6) }
            }
            HStack(spacing: 3) {
                Capsule().fill(theme.gradient).frame(width: 30, height: 9)
                ForEach(0..<4, id: \.self) { _ in Capsule().fill(Color.primary.opacity(0.14)).frame(width: 22, height: 9) }
            }
            .padding(3)
            .background(Color.primary.opacity(0.06), in: Capsule())
            ForEach([1.0, 0.8, 0.9, 0.6], id: \.self) { w in
                Capsule().fill(Color.primary.opacity(0.1)).frame(width: 128 * w, height: 6)
            }
        }
        .padding(14)
        .frame(width: 168, alignment: .leading)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Color.primary.opacity(0.1)))
        .shadow(color: theme.bottom.opacity(0.25), radius: 18, y: 8)
        .accessibilityHidden(true)
    }
}

/// Deciding: the four statuses, each in its own colour with its name under it. This picture is the page's list of
/// statuses, so VoiceOver reads it.
struct WelcomeStatusHero: View {
    var body: some View {
        HStack(spacing: 22) {
            ForEach([SignatureStatus.safe, .unclassified, .suspicious, .dangerous], id: \.self) { s in
                let color = Color(nsColor: s.nsColor)
                VStack(spacing: 8) {
                    Image(systemName: s.symbol)
                        .font(.system(size: 22, weight: .semibold)).foregroundStyle(.white)
                        .frame(width: 58, height: 58)
                        .background(color.gradient, in: Circle())
                        .shadow(color: color.opacity(0.35), radius: 10, y: 5)
                    Text(s == .unclassified ? "New" : s.title).font(.callout.weight(.medium)).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The learning day: a ring a quarter filled, or empty when learning is off.
struct WelcomeLearningHero: View {
    let theme: WelcomeTheme
    let off: Bool

    var body: some View {
        ZStack {
            Circle().stroke(Color.primary.opacity(0.1), lineWidth: 9)
            Circle().trim(from: 0, to: off ? 0 : 0.28)
                .stroke(theme.gradient, style: StrokeStyle(lineWidth: 9, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Image(systemName: off ? "moon.zzz.fill" : "brain.head.profile.fill")
                .font(.system(size: 34, weight: .medium))
                .foregroundStyle(off ? AnyShapeStyle(Color.secondary) : AnyShapeStyle(theme.gradient))
        }
        .frame(width: 104, height: 104)
        .animation(.easeInOut(duration: 0.3), value: off)
        .accessibilityHidden(true)
    }
}

/// AI: sparkles with a soft glow, no frame.
struct WelcomeGlowHero: View {
    let symbol: String
    let theme: WelcomeTheme

    var body: some View {
        ZStack {
            // A radial fade rather than a blur: a blur spills past the picture's box and gets cut at its edge.
            Circle().fill(RadialGradient(colors: [theme.top.opacity(0.35), .clear], center: .center, startRadius: 0, endRadius: 85))
                .frame(width: 170, height: 170)
            Image(systemName: symbol).font(.system(size: 60, weight: .regular)).foregroundStyle(theme.gradient)
        }
        .accessibilityHidden(true)
    }
}

/// Settings: two switches, one on and one off.
struct WelcomeSwitchesHero: View {
    let theme: WelcomeTheme

    var body: some View {
        VStack(spacing: 10) {
            toggle(on: true)
            toggle(on: false)
        }
        .padding(16)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(Color.primary.opacity(0.1)))
        .accessibilityHidden(true)
    }

    private func toggle(on: Bool) -> some View {
        HStack(spacing: 12) {
            Capsule().fill(Color.primary.opacity(0.14)).frame(width: 54, height: 7)
            ZStack(alignment: on ? .trailing : .leading) {
                Capsule().fill(on ? AnyShapeStyle(theme.gradient) : AnyShapeStyle(Color.primary.opacity(0.15)))
                Circle().fill(.white).padding(2.5).shadow(color: .black.opacity(0.2), radius: 1, y: 1)
            }
            .frame(width: 42, height: 24)
        }
    }
}

/// Protection: Watch, Ask and Strict along a line, Watch chosen.
struct WelcomeModesHero: View {
    let theme: WelcomeTheme

    var body: some View {
        HStack(spacing: 0) {
            mode("eye.fill", current: true)
            Rectangle().fill(Color.primary.opacity(0.15)).frame(width: 26, height: 2)
            mode("hand.raised.fill", current: false)
            Rectangle().fill(Color.primary.opacity(0.15)).frame(width: 26, height: 2)
            mode("lock.fill", current: false)
        }
        .accessibilityHidden(true)
    }

    private func mode(_ symbol: String, current: Bool) -> some View {
        Image(systemName: symbol)
            .font(.system(size: current ? 26 : 20, weight: .medium))
            .foregroundStyle(current ? AnyShapeStyle(.white) : AnyShapeStyle(Color.secondary))
            .frame(width: current ? 72 : 54, height: current ? 72 : 54)
            .background(current ? AnyShapeStyle(theme.gradient) : AnyShapeStyle(Color.primary.opacity(0.07)), in: Circle())
            .shadow(color: current ? theme.bottom.opacity(0.45) : .clear, radius: 16, y: 7)
    }
}

/// Claude's mark, drawn: a burst of rounded rays of uneven length, in Claude's own colour. Used where the guide
/// names Claude or Claude Code, so it is recognised at a glance.
struct ClaudeMark: View {
    static let color = Color(red: 0.85, green: 0.47, blue: 0.34)
    var color: Color = ClaudeMark.color
    private static let rays: [Double] = [1, 0.78, 0.92, 0.7, 0.96, 0.8, 1, 0.74, 0.9, 0.82, 0.97, 0.72]

    var body: some View {
        Canvas { ctx, size in
            let c = CGPoint(x: size.width / 2, y: size.height / 2)
            let r = min(size.width, size.height) / 2
            var path = Path()
            for (i, length) in Self.rays.enumerated() {
                let a = Double(i) / Double(Self.rays.count) * 2 * .pi - .pi / 2
                path.move(to: CGPoint(x: c.x + cos(a) * r * 0.12, y: c.y + sin(a) * r * 0.12))
                path.addLine(to: CGPoint(x: c.x + cos(a) * r * 0.92 * length, y: c.y + sin(a) * r * 0.92 * length))
            }
            ctx.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: r * 0.2, lineCap: .round))
        }
        .accessibilityHidden(true)
    }
}
