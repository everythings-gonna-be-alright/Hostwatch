// Renders assets/AppIcon.icns: a dark HUD panel with activity rows in Hostwatch's event colours
// (cyan process, green connection, orange file) and one flagged row.
// Usage: swift scripts/make-icon.swift   (run from the repo root)
import AppKit

/// Continuous-curvature (superellipse) tile, like Apple's icon shape.
func squircle(_ r: CGRect) -> CGPath {
    let path = CGMutablePath()
    let n: CGFloat = 4, steps = 720
    let a = r.width / 2, b = r.height / 2, cx = r.midX, cy = r.midY
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let c = cos(t), s = sin(t)
        let x = cx + a * (c < 0 ? -1 : 1) * pow(abs(c), 2 / n)
        let y = cy + b * (s < 0 ? -1 : 1) * pow(abs(s), 2 / n)
        i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
    }
    path.closeSubpath()
    return path
}

func render(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext
    let s = CGFloat(px) / 1024           // design in 1024 units
    ctx.scaleBy(x: s, y: s)

    // macOS icon grid: 824×824 body centred in 1024, corner radius ~185.
    let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = squircle(body)

    // Drop shadow.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: NSColor.black.withAlphaComponent(0.45).cgColor)
    ctx.addPath(shape); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
    ctx.restoreGState()

    // Body gradient.
    ctx.saveGState()
    ctx.addPath(shape); ctx.clip()
    let space = CGColorSpaceCreateDeviceRGB()
    let bg = CGGradient(colorsSpace: space, colors: [
        NSColor(srgbRed: 0.16, green: 0.22, blue: 0.40, alpha: 1).cgColor,
        NSColor(srgbRed: 0.03, green: 0.04, blue: 0.10, alpha: 1).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])

    // Subtle top sheen.
    let sheen = CGGradient(colorsSpace: space, colors: [
        NSColor.white.withAlphaComponent(0.16).cgColor, NSColor.white.withAlphaComponent(0).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(sheen, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 600), options: [])

    // Activity rows: dot colour, line length, flagged.
    let cyan = NSColor(srgbRed: 0.25, green: 0.85, blue: 0.95, alpha: 1)
    let green = NSColor(srgbRed: 0.30, green: 0.88, blue: 0.45, alpha: 1)
    let orange = NSColor(srgbRed: 1.00, green: 0.62, blue: 0.20, alpha: 1)
    let red = NSColor(srgbRed: 1.00, green: 0.27, blue: 0.27, alpha: 1)
    let rows: [(NSColor, CGFloat, Bool)] = [
        (cyan, 430, false), (green, 520, false), (orange, 360, false),
        (red, 470, true), (cyan, 300, false),
    ]
    // Frosted glass card holding the rows, with a specular top edge.
    let card = CGRect(x: 150, y: 196, width: 724, height: 632)
    let cardPath = CGPath(roundedRect: card, cornerWidth: 96, cornerHeight: 96, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 40, color: NSColor.black.withAlphaComponent(0.5).cgColor)
    ctx.addPath(cardPath); ctx.setFillColor(NSColor.white.withAlphaComponent(0.07).cgColor); ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addPath(cardPath); ctx.clip()
    let cardSheen = CGGradient(colorsSpace: space, colors: [
        NSColor.white.withAlphaComponent(0.14).cgColor, NSColor.white.withAlphaComponent(0.0).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(cardSheen, start: CGPoint(x: 512, y: card.maxY), end: CGPoint(x: 512, y: card.midY), options: [])
    ctx.restoreGState()
    ctx.addPath(cardPath)
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.22).cgColor)
    ctx.setLineWidth(3); ctx.strokePath()

    let left: CGFloat = 215, rowH: CGFloat = 112
    var y: CGFloat = 742
    for (color, length, flagged) in rows {
        if flagged {
            // Highlight band with a red stripe, like a flagged HUD row.
            let band = CGRect(x: 160, y: y - 44, width: 704, height: 88)
            let bandPath = CGPath(roundedRect: band, cornerWidth: 22, cornerHeight: 22, transform: nil)
            ctx.saveGState()
            ctx.addPath(bandPath); ctx.clip()
            ctx.setFillColor(red.withAlphaComponent(0.22).cgColor); ctx.fill(band)
            ctx.setFillColor(red.cgColor)
            ctx.fill(CGRect(x: 160, y: y - 44, width: 16, height: 88))
            ctx.restoreGState()
        }
        // Glowing dot.
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 26, color: color.withAlphaComponent(0.9).cgColor)
        ctx.setFillColor(color.cgColor)
        ctx.fillEllipse(in: CGRect(x: left, y: y - 26, width: 52, height: 52))
        ctx.restoreGState()
        // Text line.
        let line = CGRect(x: left + 90, y: y - 15, width: length, height: 30)
        ctx.addPath(CGPath(roundedRect: line, cornerWidth: 15, cornerHeight: 15, transform: nil))
        ctx.setFillColor(NSColor.white.withAlphaComponent(flagged ? 0.92 : 0.55).cgColor)
        ctx.fillPath()
        y -= rowH
    }
    ctx.restoreGState()

    // Hairline border.
    ctx.addPath(shape)
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.12).cgColor)
    ctx.setLineWidth(4); ctx.strokePath()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let fm = FileManager.default
let set = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("AppIcon.iconset")
try? fm.removeItem(at: set)
try! fm.createDirectory(at: set, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try! render(base).write(to: set.appendingPathComponent("icon_\(base)x\(base).png"))
    try! render(base * 2).write(to: set.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
try? fm.createDirectory(atPath: "assets", withIntermediateDirectories: true)
try! render(1024).write(to: URL(fileURLWithPath: "assets/AppIcon.png"))
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", set.path, "-o", "assets/AppIcon.icns"]
try! p.run(); p.waitUntilExit()
print(p.terminationStatus == 0 ? "wrote assets/AppIcon.icns" : "iconutil failed")
