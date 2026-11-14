import AppKit
import SwiftUI

/// A collapsed sidebar: the same pages as icons, in a narrow rail. The current page stays highlighted and the
/// badges stay in view, so a collapsed sidebar never hides where you are or what waits for you (a hidden one did).
struct SidebarRail<Items: View>: View {
    let expand: () -> Void
    @ViewBuilder let items: Items

    var body: some View {
        VStack(spacing: 6) {
            HStack {
                SidebarCollapseButton(collapsed: true, action: expand)
                Spacer(minLength: 0)
            }
            .padding(.leading, SidebarMetrics.buttonInset)
            .padding(.bottom, 2)
            items
            Spacer()
        }
        .padding(.top, 10)
        .frame(width: SidebarMetrics.railWidth)
        .frame(maxHeight: .infinity)
        .modifier(SidebarGlass())
    }
}

/// The sidebar as macOS 26 draws its own: a pane of Liquid Glass floating a little inside the window, so what's
/// behind it shows through softly. The rail and the full sidebar share it, one control in two states.
struct SidebarGlass: ViewModifier {
    static let inset: CGFloat = 8
    func body(content: Content) -> some View {
        content
            .background(SidebarMaterial().opacity(0.55))          // the window behind, through the glass
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .padding(Self.inset)
    }
}

/// macOS's own sidebar material, behind the rail and the full sidebar alike: one control in two states.
struct SidebarMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .sidebar
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {}
}

/// The rail's width, and where the collapse button sits from the left edge: the same in the rail and the full
/// sidebar, so the button doesn't move when the sidebar collapses or expands.
enum SidebarMetrics {
    static let railWidth: CGFloat = 52
    static var buttonInset: CGFloat { (railWidth - SidebarCollapseButton.size.width) / 2 }
}

/// One page in the rail: its icon, a small count on the corner when something waits, its name on hover.
struct RailButton: View {
    let symbol: String
    let title: String
    var badge = 0
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .symbolVariant(selected ? .fill : .none)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(selected ? Color.primary : Color.secondary)
                .frame(width: 36, height: 32)
                .background {
                    // The tab bar's selected look, so "you are here" reads the same everywhere.
                    if selected { RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.14)) }
                }
                .overlay(alignment: .topTrailing) {
                    if badge > 0 {
                        Text(badge > 99 ? "99+" : "\(badge)")
                            .font(.system(size: 9, weight: .bold).monospacedDigit())
                            .foregroundStyle(.white)
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(Capsule().fill(Color.accentColor))
                            .offset(x: 4, y: -3)
                    }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(badge > 0 ? "\(title) (\(badge))" : title)
        .accessibilityLabel(badge > 0 ? "\(title), \(badge)" : title)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// The small button that collapses the sidebar to its rail, and expands it again.
struct SidebarCollapseButton: View {
    let collapsed: Bool
    let action: () -> Void
    static let size = CGSize(width: 26, height: 22)

    var body: some View {
        Button(action: action) {
            Image(systemName: "sidebar.leading")
                .font(.system(size: 13, weight: .regular))
                .foregroundStyle(.secondary)
                .frame(width: Self.size.width, height: Self.size.height)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(collapsed ? "Expand the sidebar (⌃⌘S)" : "Collapse the sidebar to icons (⌃⌘S)")
        .accessibilityLabel(collapsed ? "Expand sidebar" : "Collapse sidebar")
    }
}

/// The Protection pages as rail buttons, with the same live badges as the full sidebar.
struct ProtectionRailItems: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor?
    var networkStops: () -> Int
    let page: RulesSegment
    let open: (RulesSegment) -> Void

    var body: some View {
        let _ = protection.revision
        let stops = protection.findings.values.filter { $0.verdict == .block }.count + networkStops()
        RailButton(symbol: "shield.lefthalf.filled", title: "Overview", selected: page == .protectionOverview) { open(.protectionOverview) }
        RailButton(symbol: "lock.doc", title: "Protected Files and Folders", selected: page == .protectedFiles) { open(.protectedFiles) }
        if let firewall { FirewallRailButton(firewall: firewall, page: page, open: open) }
        RailButton(symbol: "exclamationmark.shield", title: "Found", badge: stops, selected: page == .protectionFound) { open(.protectionFound) }
    }
}

private struct FirewallRailButton: View {
    @ObservedObject var firewall: FirewallMonitor
    let page: RulesSegment
    let open: (RulesSegment) -> Void

    var body: some View {
        RailButton(symbol: "network.badge.shield.half.filled", title: "Network Firewall", badge: firewall.prompts.count,
                   selected: page == .firewall) { open(.firewall) }
    }
}
