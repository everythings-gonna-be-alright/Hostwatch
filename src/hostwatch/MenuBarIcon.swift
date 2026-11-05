import AppKit

/// The menu bar icon: the app icon's mark (the activity list, flagged row brightest, the dots above it joined by a
/// timeline), drawn as a template image so macOS tints it for light and dark menu bars and when it's highlighted.
@MainActor
enum MenuBarIcon {
    static let image: NSImage = {
        // 18 x 18 pt, like system menu bar symbols; drawn in the mark's 24-unit grid.
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: true) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let k: CGFloat = 18.0 / 24.0
            ctx.scaleBy(x: k, y: k)
            // (row centre y, bar length, flagged)
            let rows: [(CGFloat, CGFloat, Bool)] = [(4.9, 9.8, false), (9.4, 13.2, false), (13.9, 11.8, true), (18.4, 7.6, false)]
            func fill(_ path: CGPath, _ alpha: CGFloat) {
                ctx.setFillColor(NSColor.black.withAlphaComponent(alpha).cgColor)
                ctx.addPath(path)
                ctx.fillPath()
            }
            for (y, length, flagged) in rows {
                let r: CGFloat = flagged ? 2.0 : 1.5
                fill(CGPath(ellipseIn: CGRect(x: 4 - r, y: y - r, width: 2 * r, height: 2 * r), transform: nil), flagged ? 1 : 0.55)
                fill(CGPath(roundedRect: CGRect(x: 7.8, y: y - 1.15, width: length + 1.5, height: 2.3), cornerWidth: 1.15,
                            cornerHeight: 1.15, transform: nil), flagged ? 1 : 0.45)
            }
            // The timeline between the first three dots.
            fill(CGPath(roundedRect: CGRect(x: 3.5, y: 6.6, width: 1, height: 1.2), cornerWidth: 0.5, cornerHeight: 0.5, transform: nil), 0.5)
            fill(CGPath(roundedRect: CGRect(x: 3.5, y: 11.1, width: 1, height: 0.7), cornerWidth: 0.5, cornerHeight: 0.5, transform: nil), 0.7)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Hostwatch"
        return image
    }()
}
