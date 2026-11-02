import AppKit
import SwiftUI
import Testing

final class WidthBox: ObservableObject { @Published var width: CGFloat = 300 }
struct WideView: View {
    @ObservedObject var box: WidthBox
    var body: some View { Color.red.frame(width: box.width, height: 100) }
}

/// The HUD panel keeps its right edge while its content gets wider (resize from the left).
@MainActor @Suite struct HUDPanelResize {
    func rightEdgeAfterWidening(_ options: NSHostingSizingOptions?) async -> (before: CGFloat, after: CGFloat) {
        _ = NSApplication.shared
        let panel = NSPanel(contentRect: NSRect(x: 500, y: 500, width: 300, height: 100),
                            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        let box = WidthBox()
        let host = NSHostingView(rootView: WideView(box: box))
        if let options { host.sizingOptions = options }
        panel.contentView = host
        panel.setFrame(NSRect(x: 500, y: 500, width: 300, height: 100), display: true)
        let before = panel.frame.maxX
        box.width = 420
        for _ in 0..<5 { host.layoutSubtreeIfNeeded(); try? await Task.sleep(nanoseconds: 20_000_000) }
        return (before, panel.frame.maxX)
    }

    @Test func rightEdgeStaysWhenTheContentWidens() async {
        let fixed = await rightEdgeAfterWidening([])                // how the HUD's hosting view is set up
        #expect(fixed.after == fixed.before)
        let auto = await rightEdgeAfterWidening(nil)                // AppKit's default would push it right
        #expect(auto.after > auto.before)
    }
}
