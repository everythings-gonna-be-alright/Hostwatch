import SwiftUI

/// The button for asking AI (Classify with AI): a Liquid Glass capsule with a violet light inside. Barely there at
/// rest; on hover it brightens and slowly turns through violet, indigo and magenta; pressed, it glows strongest. The
/// glass is the system's interactive glass, so it answers the pointer as other glass controls do. The light turns
/// only while the pointer is on it (nothing runs at rest), and not at all with Reduce Motion.
struct AIGlowButton: View {
    let title: String
    var systemImage = "sparkles"
    let action: () -> Void
    @StateObject private var hover = AIGlowHover()
    @Environment(\.isEnabled) private var enabled

    var body: some View {
        Button(action: action) {
            Label {
                Text(title)
            } icon: {
                Image(systemName: systemImage)
                    .foregroundStyle(enabled ? AnyShapeStyle(AIGlow.iconGradient) : AnyShapeStyle(.secondary))
            }
        }
        .buttonStyle(AIGlowButtonStyle(hovered: hover.on && enabled))
        .onHover { inside in withAnimation(.easeOut(duration: 0.25)) { hover.on = inside } }
    }
}

/// Whether the pointer is on the button (no @State macro with the command line tools).
final class AIGlowHover: ObservableObject { @Published var on = false }

private struct AIGlowButtonStyle: ButtonStyle {
    let hovered: Bool
    @Environment(\.isEnabled) private var enabled
    @Environment(\.controlSize) private var size

    func makeBody(configuration: Configuration) -> some View {
        let strength: Double = !enabled ? 0 : configuration.isPressed ? 0.6 : hovered ? 0.34 : 0.12
        configuration.label
            .font(size == .small || size == .mini ? .callout : .body)
            .padding(.horizontal, size == .small || size == .mini ? 11 : 14)
            .padding(.vertical, size == .small || size == .mini ? 4 : 6)
            .background {
                AIGlow(strength: strength, moving: hovered || configuration.isPressed).clipShape(Capsule())
            }
            .glassEffect(.regular.interactive(), in: Capsule())
            .opacity(enabled ? 1 : 0.55)
            .animation(.easeOut(duration: 0.18), value: configuration.isPressed)
            .contentShape(Capsule())
    }
}

/// The light inside: a soft turning blend of violet, indigo and magenta.
struct AIGlow: View {
    let strength: Double
    let moving: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    static let colors: [Color] = [Color(red: 0.55, green: 0.36, blue: 1.0), Color(red: 0.36, green: 0.42, blue: 1.0),
                                  Color(red: 0.86, green: 0.38, blue: 0.95), Color(red: 0.55, green: 0.36, blue: 1.0)]
    static let iconGradient = LinearGradient(colors: [Color(red: 0.62, green: 0.42, blue: 1.0), Color(red: 0.92, green: 0.42, blue: 0.9)],
                                             startPoint: .topLeading, endPoint: .bottomTrailing)

    var body: some View {
        TimelineView(.animation(paused: !moving || reduceMotion)) { context in
            let turn = reduceMotion ? 0 : context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 6) / 6 * 360
            AngularGradient(colors: Self.colors, center: .center, angle: .degrees(turn))
                .scaleEffect(1.6)
                .blur(radius: 8)
                .opacity(strength)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}
