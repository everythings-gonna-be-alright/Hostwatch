import AppKit
import SwiftUI

/// A new release, in the welcome guide's style: the app's icon, the version and its name, what's new by section,
/// and a way to get it. Opening the release page is all it does: nothing is downloaded or installed by itself.
struct UpdateView: View {
    let release: Release
    let current: String
    let close: () -> Void

    /// "0.18.0 – A welcome tour" reads as the version and its name.
    private var tagline: String? {
        guard let dash = release.name.range(of: " – ") else { return nil }
        return String(release.name[dash.upperBound...])
    }

    private var facts: String {
        var parts = ["You have \(current)"]
        if let date = release.published { parts.append("Released \(date.formatted(date: .abbreviated, time: .omitted))") }
        return parts.joined(separator: " · ")
    }

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                Circle().fill(RadialGradient(colors: [Color.blue.opacity(0.35), .clear], center: .center,
                                             startRadius: 0, endRadius: 80))
                    .frame(width: 160, height: 160)
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 84, height: 84)
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 26)).symbolRenderingMode(.palette).foregroundStyle(.white, .blue)
                    .background(Circle().fill(Color(nsColor: .windowBackgroundColor)).padding(2))
                    .offset(x: 32, y: 32)
            }
            .frame(height: 120)
            .accessibilityHidden(true)
            Text("A new version is ready").font(.system(size: 26, weight: .bold)).padding(.top, 6)
            Text(tagline.map { "Hostwatch \(release.version) · \($0)" } ?? release.name)
                .font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(.top, 6)
            Text(facts).font(.callout).foregroundStyle(.tertiary).padding(.top, 4)
            notes.padding(.top, 20)
            Text("Opens the release page on GitHub. Nothing is installed by itself.")
                .font(.caption).foregroundStyle(.secondary).padding(.top, 12)
            HStack {
                Spacer()
                Button("Later", action: close).buttonStyle(.glass).keyboardShortcut(.cancelAction)
                Button("Open Release Page") { NSWorkspace.shared.open(release.url); close() }
                    .buttonStyle(.glassProminent).tint(.blue).keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
            .padding(.top, 16)
        }
        .padding(.horizontal, 32)
        .padding(.top, 40)
        .padding(.bottom, 22)
        .frame(width: 540, height: 620)
        .background {
            LinearGradient(colors: [Color.cyan.opacity(0.16), Color.blue.opacity(0.04), .clear],
                           startPoint: .top, endPoint: UnitPoint(x: 0.5, y: 0.6))
                .ignoresSafeArea()
        }
    }

    @ViewBuilder private var notes: some View {
        let sections = ReleaseNotes.sections(release.notes)
        if sections.isEmpty {
            Text("No notes for this release.").foregroundStyle(.secondary).frame(maxHeight: .infinity)
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(Array(sections.enumerated()), id: \.offset) { _, section in
                        VStack(alignment: .leading, spacing: 9) {
                            if let title = section.title {
                                Label(title, systemImage: Self.symbol(for: title))
                                    .font(.headline).foregroundStyle(.primary)
                            }
                            ForEach(Array(section.items.enumerated()), id: \.offset) { _, item in
                                HStack(alignment: .firstTextBaseline, spacing: 10) {
                                    Circle().fill(Color.blue.opacity(0.8)).frame(width: 5, height: 5)
                                        .alignmentGuide(.firstTextBaseline) { $0[.bottom] - 1 }
                                    Text(Self.inline(item)).foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(18)
            }
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        }
    }

    /// The changelog's groups, each with its own symbol.
    private static func symbol(for title: String) -> String {
        let t = title.lowercased()
        if t.contains("fix") { return "wrench.and.screwdriver" }
        if t.contains("fast") || t.contains("light") { return "bolt" }
        if t.contains("new") { return "sparkles" }
        return "list.bullet"
    }

    /// Bold leads and code in an item, as the changelog writes them.
    private static func inline(_ markdown: String) -> AttributedString {
        (try? AttributedString(markdown: markdown)) ?? AttributedString(markdown)
    }
}

/// The update window: one at a time, brought forward if it is already open.
@MainActor
enum UpdateWindow {
    private static var window: NSWindow?

    static func show(_ release: Release, current: String) {
        NSApp.activate(ignoringOtherApps: true)
        if let window { window.makeKeyAndOrderFront(nil); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 588),
                              styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.title = "Hostwatch \(release.version) Is Available"
        let close: () -> Void = { [weak window] in window?.close() }
        window.contentView = NSHostingView(rootView: UpdateView(release: release, current: current, close: close))
        window.center()
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { _ in
            MainActor.assumeIsolated { Self.window = nil }
        }
        Self.window = window
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }
}
