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

struct FullDiskAccessView: View {
    @ObservedObject var setup: FullDiskAccessSetup
    let start: () -> Void
    let close: () -> Void
    var startAnyway: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 22) {
                header
                reasons
                steps
            }
            .padding(.horizontal, 32)
            .padding(.top, 28)
            .padding(.bottom, 20)
            Divider()
            footer
        }
        .frame(width: 560)
    }

    // MARK: Header

    private var header: some View {
        VStack(spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath))
                    .resizable()
                    .frame(width: 84, height: 84)
                Image(systemName: setup.granted ? "checkmark.circle.fill" : "lock.circle.fill")
                    .font(.system(size: 28))
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, setup.granted ? Color.green : Color.accentColor)
                    .background(Circle().fill(.background).padding(2))
                    .offset(x: 6, y: 4)
                    .contentTransition(.symbolEffect(.replace))
            }
            Text(setup.granted ? "Hostwatch is ready" : setup.afterFailure ? "Hostwatch can't see activity yet"
                                                                         : "Let Hostwatch watch over your Mac")
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(setup.granted
                 ? "Full Disk Access is on. Start watching whenever you're ready."
                 : "To notice suspicious programs, files and connections, Hostwatch needs Full Disk Access. "
                   + "macOS asks you to turn it on yourself in System Settings.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Why

    private var reasons: some View {
        VStack(alignment: .leading, spacing: 12) {
            Reason(symbol: "terminal", tint: .blue, title: "Every program that starts",
                   detail: "Who launched what, with its command line (passwords and tokens masked).")
            Reason(symbol: "doc.badge.gearshape", tint: .orange, title: "Files in sensitive places",
                   detail: "Keychains, SSH keys, browser passwords and login items.")
            Reason(symbol: "lock.laptopcomputer", tint: .green, title: "Stays on this Mac",
                   detail: "Hostwatch watches and never deletes anything. Nothing about your activity leaves this Mac unless you ask AI.")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Steps

    @ViewBuilder private var steps: some View {
        if !setup.granted {
            VStack(alignment: .leading, spacing: 12) {
                StepRow(number: 1, done: setup.openedSettings, title: "Open Privacy & Security ▸ Full Disk Access") {
                    Button("Open System Settings") { setup.openSettings() }
                        .buttonStyle(.glassProminent)
                        .controlSize(.small)
                }
                StepRow(number: 2, done: false, title: "Turn on Hostwatch") {
                    Button("Show in Finder") { setup.revealApp() }
                        .buttonStyle(.glass)
                        .controlSize(.small)
                        .help("Not in the list? Drag Hostwatch from Finder into it, or click + and choose it.")
                }
                StepRow(number: 3, done: false, title: "Come back here: Hostwatch notices by itself") {
                    ProgressView().controlSize(.small)
                }
                if setup.openedSettings {
                    HStack(spacing: 6) {
                        Image(systemName: "questionmark.circle").foregroundStyle(.secondary)
                        Text("Already turned on? macOS sometimes needs Hostwatch to reopen.")
                            .foregroundStyle(.secondary)
                        Button("Quit & Reopen") { setup.relaunch() }.buttonStyle(.link)
                    }
                    .font(.caption)
                    .transition(.opacity)
                }
                if setup.isLocalBuild {
                    Text("Built Hostwatch yourself? Each build is a new app to macOS: remove the old entry and add this one.")
                        .font(.caption).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.secondary.opacity(0.07)))
            .transition(.opacity.combined(with: .move(edge: .bottom)))
        }
    }

    // MARK: Buttons

    private var footer: some View {
        HStack(spacing: 10) {
            if let startAnyway, !setup.granted {
                Button("Start Without Access", action: startAnyway)
                    .buttonStyle(.glass)
                    .help("Network activity still works; processes and files stay invisible")
            }
            Spacer()
            Button(setup.granted ? "Later" : "Not Now", action: close)
                .buttonStyle(.glass)
                .keyboardShortcut(.cancelAction)
            if setup.granted {
                Button("Start Watching", action: start)
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
            } else {
                Button("Open System Settings") { setup.openSettings() }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.large)
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }
}

private struct Reason: View {
    let symbol: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 20))
                .foregroundStyle(tint)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct StepRow<Accessory: View>: View {
    let number: Int
    let done: Bool
    let title: String
    @ViewBuilder let accessory: Accessory

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(done ? Color.green : Color.accentColor).frame(width: 24, height: 24)
                if done {
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                } else {
                    Text("\(number)").font(.system(size: 12, weight: .bold)).foregroundStyle(.white)
                }
            }
            Text(title).font(.callout)
            Spacer(minLength: 8)
            accessory
        }
    }
}
