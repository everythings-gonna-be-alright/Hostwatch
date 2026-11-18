import AppKit
import SwiftUI

/// The window's tab bar: icon and title per tab, counts as small badges. Always with titles: as a toolbar item,
/// a ViewThatFits that once chose the icons-only form kept it (the toolbar offers an item the width it last
/// asked for), so Events, whose toolbar is the fullest, left the titles off for every tab that followed.
/// (The native segmented control drops the icons and puts counts into the titles.)
struct WindowTabBar: View {
    struct Tab: Identifiable {
        let id: Int              // HUDModel.windowTab
        let title: String
        let symbol: String
        var badge: String? = nil
        var badgeTint: Color = .secondary
    }

    let tabs: [Tab]
    @Binding var selection: Int
    /// Told at the click, before the window starts building the new tab (the window veils the old page with it).
    var willSelect: ((Int) -> Void)? = nil
    /// The tab the bar shows as chosen: it moves at once on a click, the window follows a moment later.
    @StateObject private var shown = ShownTab()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        bar(showTitles: true)
    }

    private func bar(showTitles: Bool) -> some View {
        HStack(spacing: 2) {
            ForEach(Array(tabs.enumerated()), id: \.element.id) { i, tab in
                let selected = (shown.id ?? selection) == tab.id
                Button {
                    // The bar first: its new highlight is drawn before the window builds the new tab, which takes
                    // a moment and used to hold the pressed tab still on screen.
                    guard tab.id != selection else { return }
                    shown.id = tab.id
                    willSelect?(tab.id)
                    DispatchQueue.main.async { selection = tab.id; shown.id = nil }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: tab.symbol)
                            .symbolVariant(selected ? .fill : .none)
                            .font(.system(size: 12, weight: .medium))
                        if showTitles {
                            // Never truncated: the toolbar squeezed "Rules" to "R…" when it ran short of room.
                            Text(tab.title).font(.system(size: 12, weight: selected ? .semibold : .regular))
                                .lineLimit(1).fixedSize()
                        }
                        if let badge = tab.badge {
                            Text(badge)
                                .font(.system(size: 10, weight: .semibold).monospacedDigit())
                                .foregroundStyle(.white)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(tab.badgeTint))
                        }
                    }
                    .padding(.horizontal, showTitles ? 10 : 9)
                    // Tall enough that the selected capsule sits as far from the bar's top and bottom as from its
                    // ends: one shape inside the other, with concentric corners.
                    .padding(.vertical, 6.5)
                    // Selected: a raised capsule in the text colour itself, with full-strength text. The accent
                    // colour was used before, and with a graphite accent it looked as dark as the unselected tabs.
                    .foregroundStyle(selected ? Color.primary : Color.secondary)
                    .background {
                        if selected {
                            Capsule().fill(Color.primary.opacity(0.16))
                                .overlay(Capsule().strokeBorder(Color.primary.opacity(0.14), lineWidth: 0.75))
                                .shadow(color: .black.opacity(0.18), radius: 2, y: 1)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(TabPressStyle(still: reduceMotion))
                .help("\(tab.title) (⌘\(i + 1))")
                .accessibilityLabel(tab.title)
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .padding(4)                                           // the same 4 points around the selected capsule
        .fixedSize()                                          // the bar takes the width its titles need
        // No animation on switching: the bar sits in the toolbar, and animating it animated the toolbar's layout
        // while the new tab was being built, which read as a freeze. The press effect is the only motion.
    }
}

/// A tab's press: a soft light under the pointer while it's held. No swelling: drawn by the app, a swell can't spring
/// back while the window builds the new tab, and it looked frozen (the system's glass buttons animate elsewhere).
private struct TabPressStyle: ButtonStyle {
    let still: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background {
                Capsule().fill(Color.primary.opacity(configuration.isPressed ? 0.12 : 0))
            }
            .animation(still ? nil : .easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// A layer in the window's colour over the tabs' content: it covers the old page at the click and fades away once the
/// new one is built, so the build reads as a soft change of page instead of a pause. The fade is Core Animation's,
/// run by the render server: a SwiftUI animation steps on the main thread, which the new tab keeps busy, and stuttered.
/// Only this layer animates: the tabs must not change opacity (that re-attached their tables, see ActivityWindowView).
@MainActor
final class TabVeil: ObservableObject {
    /// Counts covers and reveals: the layer acts on each new value.
    @Published private(set) var step = 0
    private(set) var covered = false

    func cover() { covered = true; step += 1 }

    /// After the new page's first frame: the fade starts on the next turn of the run loop.
    func reveal() {
        guard covered else { return }
        DispatchQueue.main.async { [self] in covered = false; step += 1 }
    }
}

/// The veil's layer. Clicks pass through it.
struct TabVeilLayer: NSViewRepresentable {
    @ObservedObject var veil: TabVeil
    let animated: Bool

    final class VeilView: NSView {
        var lastStep = 0
        override var wantsUpdateLayer: Bool { true }
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
        override func updateLayer() {
            effectiveAppearance.performAsCurrentDrawingAppearance {
                layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
            }
        }
    }

    func makeNSView(context: Context) -> VeilView {
        let view = VeilView()
        view.wantsLayer = true
        view.layer?.opacity = 0
        return view
    }

    /// Both ways are Core Animation fades from wherever the layer is now: in quickly at the click (it keeps playing
    /// while the app builds the new tab), out more slowly once the tab is drawn.
    func updateNSView(_ view: VeilView, context: Context) {
        guard view.lastStep != veil.step, let layer = view.layer else { return }
        view.lastStep = veil.step
        let from = layer.presentation()?.opacity ?? layer.opacity
        let to: Float = veil.covered ? 0.7 : 0
        layer.removeAllAnimations()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        layer.opacity = to
        CATransaction.commit()
        guard animated else { return }
        let fade = CABasicAnimation(keyPath: "opacity")
        fade.fromValue = from
        fade.toValue = to
        fade.duration = veil.covered ? 0.1 : 0.28
        fade.timingFunction = CAMediaTimingFunction(name: veil.covered ? .easeIn : .easeOut)
        layer.add(fade, forKey: "veil")
    }
}

/// WindowTabBar's chosen tab between the click and the window catching up (no @State macro with the command line tools).
final class ShownTab: ObservableObject {
    @Published var id: Int?
}

/// Window-wide sheets and banners.
final class WindowSheetState: ObservableObject {
    @Published var showVulns = false
}

/// Above the window's content when exploited macOS flaws aren't fixed yet: one line, Details, Software
/// Update, and ✕ (it comes back only for a newly listed flaw).
struct VulnerabilityBanner: View {
    @ObservedObject var intel: ThreatIntel
    @ObservedObject var sheets: WindowSheetState
    @AppStorage("vulnBannerDismissed") private var dismissed = ""

    private var unfixed: [ExploitedVuln] {
        intel.recentVulns().filter { if case .likelyFixed = intel.status($0) { return false }; return true }
    }

    var body: some View {
        let open = unfixed
        let key = open.map(\.cve).sorted().joined(separator: ",")
        if intel.vulnerabilitiesEnabled, !open.isEmpty, dismissed != key {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield.fill").font(.title3).foregroundStyle(.orange)
                    .symbolRenderingMode(.hierarchical)
                VStack(alignment: .leading, spacing: 1) {
                    Text(intel.pendingUpdate.map { "\($0) fixes \(open.count) actively exploited \(open.count == 1 ? "flaw" : "flaws")" }
                         ?? "\(open.count) actively exploited macOS \(open.count == 1 ? "flaw" : "flaws") since your last update")
                        .font(.callout.weight(.semibold))
                    Text(Set(open.map(\.component)).sorted().joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Details") { sheets.showVulns = true }.buttonStyle(.glass)
                Button("Software Update") { VulnerabilityList.openSoftwareUpdate() }.buttonStyle(.glassProminent)
                Button { dismissed = key } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Hide until another flaw is listed")
            }
            .controlSize(.small)
            .padding(.horizontal, 14).padding(.vertical, 8)
            .background(Color.orange.opacity(0.08))
        }
    }
}

/// The sheet: actively exploited macOS flaws (CISA), newest first, and whether this Mac is protected.
struct VulnerabilityList: View {
    @ObservedObject var intel: ThreatIntel
    let close: () -> Void

    static func openSoftwareUpdate() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Actively exploited macOS vulnerabilities").font(.title3.weight(.semibold))
                Text("From CISA's Known Exploited Vulnerabilities list · this Mac: \(intel.osVersion)"
                     + (intel.osUpdated.map { ", updated \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""))
                    .font(.callout).foregroundStyle(.secondary)
            }
            .padding(20)
            Divider()
            List(intel.vulns.prefix(60)) { v in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(v.cve).font(.body.monospaced().weight(.semibold)).textSelection(.enabled)
                        Text(v.component).font(.caption.weight(.medium)).padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Capsule().fill(Color.secondary.opacity(0.15)))
                        if v.ransomware {
                            Text("Ransomware").font(.caption.weight(.semibold)).foregroundStyle(.red)
                        }
                        Spacer()
                        Text("added \(v.dateAdded.formatted(date: .abbreviated, time: .omitted))").font(.caption).foregroundStyle(.secondary)
                    }
                    Text(v.description).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 10) {
                        switch intel.status(v) {
                        case .likelyFixed(let date):
                            Label("Likely fixed: macOS was updated \(date.formatted(date: .abbreviated, time: .omitted))",
                                  systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        case .fixedByPendingUpdate(let update):
                            Label("Fixed by the waiting update (\(update))", systemImage: "arrow.down.circle.fill").foregroundStyle(.orange)
                        case .notFixed:
                            Label("Not fixed by your last macOS update", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                        if let advisory = v.advisory, let url = URL(string: advisory) {
                            Link("Apple advisory", destination: url)
                        }
                    }
                    .font(.caption)
                }
                .padding(.vertical, 4)
            }
            Divider()
            HStack {
                Text("CISA doesn't name fixed versions: \"likely fixed\" means macOS was updated after the flaw was listed.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Software Update") { Self.openSoftwareUpdate() }
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 720, height: 560)
    }
}
