import AppKit
import SwiftUI

/// "Checking curl with AI…": what the AI is looking at right now, then "Allowed by AI" for a moment. A small glass
/// notice at the top right, where macOS shows notifications, on every Space and over full-screen apps, whether or not
/// a Hostwatch window is open. It never takes focus or clicks: the program waits, you don't have to.
@MainActor
final class AICheckNotices: ObservableObject {
    struct Item: Identifiable, Equatable {
        enum State: Equatable { case checking, allowed(String) }
        let id: Int
        let name: String
        let path: String
        let what: String
        var state: State
        /// When the check began: the bar fills from here over LiveAICheck.timeLimit.
        var started = Date()
    }

    @Published private(set) var items: [Item] = []
    private var panel: NSPanel?

    /// The programs being checked now (from Protection's paused questions).
    func setChecking(_ asks: [ProtectionAsk]) {
        let allowed = items.filter { if case .allowed = $0.state { return true } else { return false } }
        let checking = asks.map { ask in
            Item(id: ask.id, name: ask.event.name, path: ask.event.proc, what: ask.area == .launches ? "launch" : "file access",
                 state: .checking, started: items.first { $0.id == ask.id }?.started ?? Date())   // the bar keeps its place
        }
        items = checking + allowed.filter { a in !checking.contains { $0.id == a.id } }
        show()
    }

    /// The AI let one go on: say so for a few seconds.
    func allowed(_ ask: ProtectionAsk, note: String) {
        let item = Item(id: ask.id, name: ask.event.name, path: ask.event.proc,
                        what: ask.area == .launches ? "launch" : "file access", state: .allowed(note))
        items.removeAll { $0.id == ask.id }
        items.append(item)
        show()
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.5) { [weak self] in
            self?.items.removeAll { $0.id == ask.id && $0.state != .checking }
            self?.show()
        }
    }

    private func show() {
        guard !items.isEmpty else { panel?.orderOut(nil); return }
        let panel = self.panel ?? Self.makePanel(self)
        self.panel = panel
        panel.setContentSize(panel.contentView?.fittingSize ?? NSSize(width: 320, height: 60))
        if let screen = NSScreen.main?.visibleFrame {
            panel.setFrameTopLeftPoint(NSPoint(x: screen.maxX - panel.frame.width - 12, y: screen.maxY - 12))
        }
        panel.orderFrontRegardless()
    }

    private static func makePanel(_ notices: AICheckNotices) -> NSPanel {
        let host = NSHostingView(rootView: AICheckNoticeView(notices: notices))
        host.sizingOptions = [.intrinsicContentSize]
        let panel = NSPanel(contentRect: NSRect(origin: .zero, size: host.fittingSize),
                            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.contentView = host
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.level = .statusBar
        panel.ignoresMouseEvents = true
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        return panel
    }
}

struct AICheckNoticeView: View {
    @ObservedObject var notices: AICheckNotices

    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            ForEach(notices.items) { item in row(item) }
        }
        .padding(6)
        .animation(.snappy(duration: 0.2), value: notices.items)
    }

    private func row(_ item: AICheckNotices.Item) -> some View {
        HStack(spacing: 10) {
            Image(nsImage: ProcessIcons.icon(item.path)).resizable().frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 1) {
                switch item.state {
                case .checking:
                    Text("Checking \(item.name) with AI").font(.system(size: 12, weight: .semibold))
                    Text("Its \(item.what) waits for a moment").font(.system(size: 11)).foregroundStyle(.secondary)
                case .allowed(let note):
                    Text("\(item.name) allowed by AI").font(.system(size: 12, weight: .semibold))
                    Text(note).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .frame(maxWidth: 240, alignment: .leading)
            Spacer(minLength: 4)
            if item.state == .checking {
                Image(systemName: "sparkles")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.tint)
                    .symbolEffect(.variableColor.iterative.reversing, options: .repeating)
                    .symbolEffect(.pulse, options: .repeating)
            } else {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    .symbolEffect(.bounce, value: item.state)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .overlay(alignment: .bottom) {
            if item.state == .checking { WaitBar(started: item.started).padding(.horizontal, 14).padding(.bottom, 4) }
        }
        .frame(width: 320)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

/// How long the AI may still take: a thin bar filling over LiveAICheck.timeLimit, the time the program waits.
private struct WaitBar: View {
    let started: Date

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30)) { context in
            let done = min(1, max(0, context.date.timeIntervalSince(started) / LiveAICheck.timeLimit))
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.primary.opacity(0.08))
                    Capsule().fill(LinearGradient(colors: [.accentColor.opacity(0.5), .accentColor], startPoint: .leading, endPoint: .trailing))
                        .frame(width: max(4, geo.size.width * done))
                }
            }
            .frame(height: 3)
        }
        .accessibilityHidden(true)
    }
}
