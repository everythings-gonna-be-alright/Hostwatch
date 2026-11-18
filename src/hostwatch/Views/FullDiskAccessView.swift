import AppKit
import SwiftUI

/// The Full Disk Access setup window: why Hostwatch needs it, that nothing leaves the Mac, three steps,
/// and a live status that notices the grant by itself (no "quit and try again" guessing).
@MainActor
final class FullDiskAccessSetup: ObservableObject {
    @Published private(set) var granted = Collector.appearsToHaveFullDiskAccess
    @Published private(set) var openedSettings = false
    /// The collector already failed for lack of access (vs. asking before the first start).
    let afterFailure: Bool
    private var timer: Timer?

    /// `previewGranted`: fixed state for rendering previews (no polling).
    init(afterFailure: Bool, previewGranted: Bool? = nil) {
        self.afterFailure = afterFailure
        if let previewGranted { granted = previewGranted; openedSettings = !previewGranted; return }
        #if DEMO
        // HOSTWATCH_DEMO_PAGE=opened: as after Open System Settings, for screenshots.
        openedSettings = ProcessInfo.processInfo.environment["HOSTWATCH_DEMO_PAGE"] == "opened"
        #endif
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let now = Collector.appearsToHaveFullDiskAccess
                if now != self.granted { withAnimation(.snappy) { self.granted = now } }
            }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func openSettings() {
        Collector.openFullDiskAccessSettings()
        withAnimation(.snappy) { openedSettings = true }
    }

    func revealApp() { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }

    /// A build signed ad-hoc (built here) gets a new identity each time: its old list entry stops working.
    var isLocalBuild: Bool {
        SigningCache.shared.cached(Bundle.main.executablePath ?? "")?.adhoc
            ?? (Bundle.main.infoDictionary?["CFBundleIdentifier"] as? String == AppPaths.bundleID)
    }

    /// macOS sometimes applies the grant only to a fresh process.
    func relaunch() {
        let path = Bundle.main.bundlePath
        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", "sleep 1; /usr/bin/open -n \(ResetPlan.quote(path))"]
        try? helper.run()
        NSApp.terminate(nil)
    }
}

/// The window drawn with Liquid Glass: a soft field of colour behind, the app's icon, a large title, what the access
/// lets Hostwatch see as three glass cards in one container, the two steps as one glass bar, and the buttons at the
/// bottom. Icons stay in the text colour, so the glass and the one blue button carry the colour.
struct FullDiskAccessView: View {
    @ObservedObject var setup: FullDiskAccessSetup
    let start: () -> Void
    let close: () -> Void
    var startAnyway: (() -> Void)?

    private var accent: Color { setup.granted ? .teal : .blue }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                header
                reasons.padding(.top, 24)
                steps.padding(.top, 18)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 36)
            .padding(.top, 40)
            footer
        }
        .frame(width: 620, height: 610)
        .background { field }
        .animation(.snappy, value: setup.granted)
    }

    /// Two soft pools of colour the glass refracts, fading into the window.
    private var field: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor)
            RadialGradient(colors: [accent.opacity(0.28), .clear], center: UnitPoint(x: 0.5, y: 0.12),
                           startRadius: 0, endRadius: 300)
            RadialGradient(colors: [Color.cyan.opacity(0.14), .clear], center: UnitPoint(x: 0.1, y: 0.75),
                           startRadius: 0, endRadius: 260)
            RadialGradient(colors: [Color.indigo.opacity(0.14), .clear], center: UnitPoint(x: 0.95, y: 0.7),
                           startRadius: 0, endRadius: 260)
        }
        .ignoresSafeArea()
    }

    // MARK: Header

    private var header: some View {
        VStack(spacing: 0) {
            ZStack(alignment: .bottomTrailing) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath))
                    .resizable()
                    .frame(width: 92, height: 92)
                    .shadow(color: accent.opacity(0.35), radius: 24, y: 10)
                Image(systemName: setup.granted ? "checkmark" : "lock.fill")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(setup.granted ? Color.green : Color.blue, in: Circle())
                    .glassEffect(.regular, in: Circle())
                    .offset(x: 6, y: 4)
                    .contentTransition(.symbolEffect(.replace))
            }
            .accessibilityHidden(true)
            Text(setup.granted ? "Hostwatch is ready" : setup.afterFailure ? "Hostwatch can't see activity yet"
                                                                         : "Let Hostwatch watch over your Mac")
                .font(.system(size: 26, weight: .bold))
                .multilineTextAlignment(.center)
                .padding(.top, 18)
            Text(setup.granted
                 ? "Full Disk Access is on. Start watching whenever you're ready."
                 : "It needs Full Disk Access, which only you can turn on in System Settings.")
                .font(.title3)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 520)
                .padding(.top, 6)
        }
    }

    // MARK: What it sees

    /// One question, three answers, as glass cards side by side; the promise on its own line under them.
    private var reasons: some View {
        VStack(spacing: 12) {
            Text("With Full Disk Access, Hostwatch sees").font(.callout).foregroundStyle(.secondary)
            GlassEffectContainer(spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    ReasonCard(symbol: "terminal", title: "Programs",
                               text: "Every program that starts, and who started it.")
                    ReasonCard(symbol: "key", title: "Password thieves",
                               text: "An unknown program going after your saved passwords.")
                    ReasonCard(symbol: "arrow.clockwise", title: "Startup items",
                               text: "Programs that set themselves to start on their own.")
                }
                .fixedSize(horizontal: false, vertical: true)   // as tall as the tallest card, no taller
            }
            Label("Hostwatch never opens your files itself. It only sees which program does.", systemImage: "lock.fill")
                .font(.callout).foregroundStyle(.secondary).padding(.top, 2)
        }
    }

    // MARK: Steps

    @ViewBuilder private var steps: some View {
        if !setup.granted {
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    StepChip(number: 1, done: setup.openedSettings, title: "Turn it on in Privacy & Security")
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                    StepChip(number: 2, done: false, title: "Come back here")
                    Spacer(minLength: 4)
                    ProgressView().controlSize(.small)
                    Text("Watching for it").font(.callout).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 11)
                .glassEffect(.regular, in: Capsule())
                .accessibilityElement(children: .combine)
                if setup.openedSettings {
                    Text("Turned it on and nothing happens? macOS sometimes needs Hostwatch to reopen.")
                        .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        .transition(.opacity)
                }
                if setup.isLocalBuild {
                    Text("Built Hostwatch yourself? Each build is a new app to macOS. Remove the old entry and add this one.")
                        .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .transition(.opacity.combined(with: .move(edge: .bottom)))
        }
    }

    // MARK: Buttons

    private var footer: some View {
        HStack(spacing: 10) {
            // After System Settings was opened, reopening is the likelier way forward: it takes this place.
            if setup.openedSettings, !setup.granted {
                Button("Quit & Reopen") { setup.relaunch() }
                    .buttonStyle(.glass)
                    .help("macOS sometimes applies Full Disk Access only after Hostwatch reopens")
            } else if let startAnyway, !setup.granted {
                Button("Start Without Access", action: startAnyway)
                    .buttonStyle(.glass)
                    .help("Network activity still works. Processes and files stay invisible")
            }
            Spacer()
            Button(setup.granted ? "Later" : "Not Now", action: close)
                .buttonStyle(.glass)
                .keyboardShortcut(.cancelAction)
            Group {
                if setup.granted {
                    Button("Start Watching", action: start)
                } else {
                    Button("Open System Settings") { setup.openSettings() }
                }
            }
            .buttonStyle(.glassProminent).tint(accent).keyboardShortcut(.defaultAction)
        }
        .controlSize(.large)
        .padding(.horizontal, 24)
        .padding(.bottom, 22)
    }
}

/// One thing the access lets Hostwatch see: a glass card with a symbol in the text colour, a name and one line.
private struct ReasonCard: View {
    let symbol: String
    let title: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 20, weight: .medium))
                .foregroundStyle(.primary)
                .frame(height: 26)
                .accessibilityHidden(true)
            Text(title).font(.headline)
            Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .protectionGlass(18)
        .accessibilityElement(children: .combine)
    }
}

/// A step: its number in a small circle (a check once done) and what to do.
private struct StepChip: View {
    let number: Int
    let done: Bool
    let title: String

    var body: some View {
        HStack(spacing: 8) {
            ZStack {
                Circle().fill(done ? Color.green.opacity(0.22) : Color.primary.opacity(0.12)).frame(width: 22, height: 22)
                if done {
                    Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(.green)
                } else {
                    Text("\(number)").font(.system(size: 11, weight: .bold))
                }
            }
            Text(title).font(.callout)
        }
    }
}
