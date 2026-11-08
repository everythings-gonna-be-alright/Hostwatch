import AppKit
import Carbon.HIToolbox
import Combine
import SwiftUI

extension AppDelegate {
    // MARK: Overlay panel

    func setUpPanel() {
        let size = overlaySize()
        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        let hud = NSHostingView(rootView: HUDView(model: model, feed: model.live, stories: stories, collector: collector, signatures: signatures, metrics: metrics, vitals: vitals, intel: intel, actions: actions))
        // The panel's size is set only by `resizeOverlay` (top-right corner fixed). Left to itself the hosting
        // view would resize the panel to its content first, from the bottom-left, so the right edge jumped.
        hud.sizingOptions = []
        panel.contentView = hud
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle, .fullScreenAuxiliary]

        let autosave = "HostwatchOverlay"
        if !panel.setFrameUsingName(autosave), let screen = NSScreen.main {
            let visible = screen.visibleFrame
            panel.setFrameOrigin(NSPoint(x: visible.maxX - panel.frame.width - 14,
                                         y: visible.maxY - panel.frame.height - 14))
        }
        panel.setFrameAutosaveName(autosave)
        resizeOverlay(panel)

        // Click-through by default; "interactive" mode lets you drag it and use its buttons.
        model.$overlayClickThrough
            .sink { [weak panel] clickThrough in
                panel?.ignoresMouseEvents = clickThrough
                panel?.isMovableByWindowBackground = !clickThrough
            }
            .store(in: &cancellables)

        self.panel = panel
        model.$overlayRows.combineLatest(model.$overlayWidth, model.$overlayScale, model.$overlayShowResources)
            .dropFirst()
            .sink { [weak self] _ in
                DispatchQueue.main.async { if let self, let panel = self.panel { self.resizeOverlay(panel) } }
            }
            .store(in: &cancellables)
        model.$overlayEnabled
            .sink { [weak self] _ in DispatchQueue.main.async { self?.refreshOverlayVisibility() } }
            .store(in: &cancellables)
    }

    /// Room for the configured rows at the configured text size, plus header and padding.
    func overlaySize() -> NSSize {
        let s = model.overlayScale
        let rows = CGFloat(model.overlayRows) * (rowHeight(s) + 1)
        return NSSize(width: model.overlayWidth + 2, height: (rows + model.overlayChrome(s)).rounded(.up))
    }

    /// Applies the size while keeping the top-right corner fixed, clamped to the screen.
    func resizeOverlay(_ panel: NSPanel) {
        var size = overlaySize()
        let old = panel.frame
        if let visible = (panel.screen ?? NSScreen.main)?.visibleFrame {
            size.height = min(size.height, visible.height)
            size.width = min(size.width, visible.width)
        }
        let frame = NSRect(x: old.maxX - size.width, y: old.maxY - size.height,
                           width: size.width, height: size.height)
        panel.setFrame(frame, display: true)
    }

    /// Visible when enabled, except while the activity window is full screen.
    func refreshOverlayVisibility() {
        guard let panel else { return }
        if model.overlayEnabled && !activityFullScreen {
            panel.orderFrontRegardless()
        } else {
            panel.orderOut(nil)
        }
        updateUIVisibility()
    }

    /// The event list and HUD redraw only while one of them is visible (not closed, minimised,
    /// hidden or fully covered); the model buffers events meanwhile.
    func updateUIVisibility() {
        func onScreen(_ window: NSWindow?) -> Bool {
            guard let window, window.isVisible else { return false }
            return window.occlusionState.contains(.visible)
        }
        model.uiVisible = onScreen(activityWindow) || onScreen(panel)
    }
}
