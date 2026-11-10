import AppKit
import SwiftUI

/// A connection held in Ask mode, also answerable in the Network tab (its question window closes too).
struct FirewallWaitingRow: View {
    let prompt: FirewallPrompt
    @ObservedObject var firewall: FirewallMonitor

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: prompt.event.proc))
                .resizable().frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(prompt.who).font(.callout.weight(.semibold)).help(prompt.event.proc)
                    Text(prompt.event.extra).font(.system(size: 9, weight: .semibold))
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.18)))
                    Text("\(prompt.destination):\(prompt.event.remotePort)").font(.system(size: 12, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle)
                }
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text("Waiting \(FirewallPromptView.waited(context.date.timeIntervalSince(prompt.since))) · \(prompt.reason)")
                        .font(.caption.monospacedDigit()).foregroundStyle(.orange).lineLimit(1)
                }
            }
            Spacer()
            Button("Block") { firewall.resolve(prompt.id, allow: false) }.buttonStyle(.glass)
            Button("Allow") { firewall.resolve(prompt.id, allow: true) }.buttonStyle(.glassProminent)
        }
        .controlSize(.small)
        .padding(.vertical, 3)
    }
}

/// A question window in the style of macOS's own permission alerts: centered, no title bar, the program's icon,
/// a bold question, two equal buttons (Allow is the default, Escape blocks). Non-activating: answering doesn't
/// bring Hostwatch's other windows forward.
/// A borderless panel that can still take Return and Escape (borderless windows refuse key status by default).
final class GlassPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

@MainActor enum QuestionPanel {
    static let corner: CGFloat = 26

    static func make<V: View>(_ view: V) -> NSPanel {
        // Liquid Glass, as macOS 26's own alerts: no window chrome, the content is a glass card the desktop shows
        // through. The window is clear, so its shadow follows the card's rounded shape.
        let glass = view
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: corner, style: .continuous))
            .ignoresSafeArea()
        let host = NSHostingController(rootView: glass)
        host.sizingOptions = [.preferredContentSize]
        let panel = GlassPanel(contentRect: NSRect(origin: .zero, size: host.view.fittingSize),
                               styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.contentViewController = host
        // Sized before placing, so it's really centered. The content fills the whole frame (it draws under the
        // hidden title bar), so the frame is the content's size; setContentSize would add a title bar's height.
        panel.setFrame(NSRect(origin: .zero, size: host.view.fittingSize), display: false)
        // Growing (Claude's advice coming in) keeps the window where it was centred.
        NotificationCenter.default.addObserver(forName: NSWindow.didResizeNotification, object: panel, queue: .main) { [weak panel] _ in
            MainActor.assumeIsolated {
                guard let panel, let centre = centres[ObjectIdentifier(panel)] else { return }
                let f = panel.frame
                let origin = NSPoint(x: (centre.x - f.width / 2).rounded(), y: (centre.y - f.height / 2).rounded())
                if origin != f.origin { panel.setFrameOrigin(origin) }
                panel.invalidateShadow()                    // the clear window's shadow follows the card's new size
            }
        }
        return panel
    }

    /// In the middle of the screen you're working on; more questions step down and right from there.
    static func show(_ panel: NSPanel, slot: Int) {
        place(panel, slot: slot)
        panel.orderFrontRegardless()
        panel.makeKey()
        // Text can settle to its final height a moment later: centre again once if it did.
        let shown = panel.frame.size
        DispatchQueue.main.async {
            if fitting(panel) != shown { place(panel, slot: slot) }
        }
    }

    private static func fitting(_ panel: NSPanel) -> NSSize {
        guard let view = panel.contentViewController?.view else { return panel.frame.size }
        view.layoutSubtreeIfNeeded()
        return view.fittingSize
    }

    /// Where each question window is centred (kept when it grows).
    private static var centres: [ObjectIdentifier: NSPoint] = [:]

    private static func place(_ panel: NSPanel, slot: Int) {
        let size = fitting(panel)
        let mouse = NSEvent.mouseLocation
        let screen = (NSScreen.screens.first { $0.frame.contains(mouse) } ?? NSScreen.main)?.visibleFrame ?? .zero
        let step = CGFloat(slot % 6)
        centres[ObjectIdentifier(panel)] = NSPoint(x: screen.midX + step * 22, y: screen.midY - step * 22)
        panel.setFrame(NSRect(x: (screen.midX - size.width / 2 + step * 22).rounded(),
                              y: (screen.midY - size.height / 2 - step * 22).rounded(),
                              width: size.width, height: size.height), display: true)
    }
}

/// "curl wants to connect to example.com": the connection waits until you answer; Allow or Block decides the pattern.
struct FirewallPromptView: View {
    @ObservedObject var firewall: FirewallMonitor
    let id: UUID
    /// Who started the program ("python3.12, started by Claude Code"): the launch chain, rebuilt when the question came.
    var chain: LaunchChainReport? = nil

    var body: some View {
        if let prompt = firewall.prompts.first(where: { $0.id == id }) {
            let pattern = prompt.patternKey.split(separator: "|").last.map(String.init) ?? ""
            let gateway = SignatureBuilder.vmGateway(prompt.event.proc)
            VStack(spacing: 14) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: prompt.event.proc))
                    .resizable().frame(width: 64, height: 64)
                    .overlay(alignment: .bottomTrailing) {
                        Image(systemName: "network.badge.shield.half.filled")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.white)
                            .padding(5)
                            .background(Circle().fill(Color.accentColor))
                            .offset(x: 6, y: 4)
                    }
                    .accessibilityHidden(true)
                VStack(spacing: 5) {
                    Text(gateway.map { "A \($0) wants to connect to \(prompt.destination)" }
                         ?? (prompt.who == "Unknown program" ? "An unknown program wants to connect to \(prompt.destination)"
                             : "“\(prompt.event.name)” wants to connect to \(prompt.destination)"))
                        .font(.headline)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("\(prompt.event.extra) · port \(prompt.event.remotePort) · \(prompt.event.remoteHost ?? "")")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Text(gateway.map { "It comes through \(prompt.event.name), from inside its virtual machine; which program made it "
                                   + "can't be seen. Your answer decides \($0)s → \(pattern) from now on." }
                     ?? "Your answer decides \(prompt.event.name) → \(pattern) from now on. The connection waits until you answer.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if let chain, gateway == nil {
                    LaunchChainStrip(report: chain)
                } else {
                    Text(prompt.event.proc)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(prompt.event.proc)
                }
                if let analysis = firewall.advice[prompt.id] {
                    FirewallAdviceView(analysis: analysis)
                } else {
                    // A secondary action, as in macOS alerts ("Show Details", "Learn More"): a borderless,
                    // tinted text button below the message, never competing with Block and Allow.
                    Button { firewall.askClaude(prompt.id) } label: {
                        HStack(spacing: 5) {
                            Text("✱").font(.system(size: 14, weight: .bold))
                            Text("Ask Claude")
                        }
                        .font(.callout.weight(.medium))
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Color.claude)
                    .pointerStyle(.link)
                    .keyboardShortcut("k", modifiers: .command)
                    .help("Claude explains the program, the destination and the risks, and suggests Allow or Block (⌘K)")
                    .accessibilityLabel("Ask Claude about this connection")
                }
                VStack(spacing: 8) {
                    HStack(spacing: 10) {
                        Button { firewall.resolve(prompt.id, allow: false) } label: {
                            Text("Block").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glass)
                        .keyboardShortcut(.cancelAction)
                        Button { firewall.resolve(prompt.id, allow: true) } label: {
                            Text("Allow").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glassProminent)
                        .keyboardShortcut(.defaultAction)
                    }
                    .controlSize(.large)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text("Waiting \(Self.waited(context.date.timeIntervalSince(prompt.since)))")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 22)
            .padding(.top, 26)
            .padding(.bottom, 16)
            .frame(width: firewall.advice[prompt.id] == nil && chain == nil ? 340 : 420)  // room for the chain and the advice
        }
    }

    static func waited(_ s: TimeInterval) -> String {
        let n = Int(s)
        return n < 60 ? "\(n) s" : "\(n / 60) min \(n % 60) s"
    }
}

/// Claude's advice inside a firewall question: verdict and risk, then the answer as it streams in.
struct FirewallAdviceView: View {
    @ObservedObject var analysis: AIAnalysis

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 5) {
                Text("✱").font(.system(size: 12, weight: .bold)).foregroundStyle(Color.claude)
                Text("Claude").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                if let verdict = analysis.verdict {
                    Text(verdict.rawValue.capitalized + (analysis.aiRisk.map { " · risk \($0)" } ?? ""))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Capsule().fill(Self.color(verdict)))
                }
            }
            switch analysis.state {
            case .gathering, .ready:
                ProgressView("Collecting evidence…").controlSize(.small).frame(maxWidth: .infinity, alignment: .leading)
            case .failed(let why):
                Text(why).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            case .asking, .done:
                if body(of: analysis.answer).isEmpty {
                    ProgressView("Asking Claude…").controlSize(.small).frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ScrollView {
                        Text(rendered(body(of: analysis.answer)))
                            .font(.callout)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 220)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.primary.opacity(0.05)))
    }

    /// The answer without its VERDICT / RISK lines (shown as the badge).
    private func body(of answer: String) -> String {
        answer.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { let u = $0.uppercased().replacingOccurrences(of: "*", with: ""); return !u.hasPrefix("VERDICT:") && !u.hasPrefix("RISK:") && !u.hasPrefix("CONFIDENCE:") }
            .joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func rendered(_ markdown: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: markdown, options: options)) ?? AttributedString(markdown)
    }

    static func color(_ v: Verdict) -> Color {
        switch v {
        case .safe: .green
        case .suspicious: .orange
        case .dangerous: .red
        case .unknown: .gray
        }
    }
}

/// Above every tab of the window when the firewall turned itself to Watch: what happened, why, and the way back.
struct FirewallFallbackBanner: View {
    @ObservedObject var firewall: FirewallMonitor
    let openSettings: () -> Void

    var body: some View {
        if let f = firewall.fallback {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill").font(.title3).foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text("The firewall turned itself to Watch").font(.callout.weight(.semibold))
                    Text(Self.reason(f) + " · \(f.at.formatted(date: .omitted, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Button("Firewall Settings", action: openSettings).buttonStyle(.glass)
                Button("Turn \(f.from.short) Back On") { firewall.mode = f.from }.buttonStyle(.glassProminent)
                    .help("Try again: the relay restarts and runs its web check")
                Button { firewall.fallback = nil } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Hide (the firewall stays in Watch)")
            }
            .controlSize(.small)
            .padding(.horizontal, 14).padding(.vertical, 8)
            .background(Color.orange.opacity(0.10))
            .accessibilityElement(children: .contain)
        }
    }

    /// Why, in a sentence: the relay's own reason, or the usual one.
    static func reason(_ f: FirewallMonitor.Fallback) -> String {
        let why = f.why.trimmingCharacters(in: .whitespacesAndNewlines)
        let base = "\(f.from.short) stopped blocking: "
        return base + (why.isEmpty ? "its web check through the relay failed twice, so nothing is blocked now." : why)
    }
}
