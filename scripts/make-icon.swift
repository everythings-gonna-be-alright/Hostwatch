// Renders assets/AppIcon.icns: a near-black tile (the website's look) with the activity list in white: soft
// grey rows, the flagged row in full white, the dots above it joined by a thin timeline (signs connected into a
// story). Monochrome.
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

    // Body: near-black with light from above, like the website.
    ctx.saveGState()
    ctx.addPath(shape); ctx.clip()
    let space = CGColorSpaceCreateDeviceRGB()
    let bg = CGGradient(colorsSpace: space, colors: [
        NSColor(srgbRed: 0.115, green: 0.117, blue: 0.122, alpha: 1).cgColor,
        NSColor(srgbRed: 0.031, green: 0.035, blue: 0.039, alpha: 1).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    // A faint neutral light behind the mark.
    let glow = CGGradient(colorsSpace: space, colors: [
        NSColor.white.withAlphaComponent(0.07).cgColor,
        NSColor.white.withAlphaComponent(0).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: CGPoint(x: 520, y: 500), startRadius: 0,
                           endCenter: CGPoint(x: 520, y: 500), endRadius: 430, options: [])

    // The mark: the original activity list, reduced to white rows. The third row is the flagged one: brighter
    // and with a solid dot; the others are soft grey.
    let rows: [(y: CGFloat, length: CGFloat, flagged: Bool)] = [
        (668, 330, false), (564, 410, false), (460, 380, true), (356, 250, false),
    ]
    // A thin timeline joins the dots from the first row to the flagged one: signs connected into a story.
    for i in 0..<2 {
        let top = rows[i].y - 22 - 10, bottom = rows[i + 1].y + (rows[i + 1].flagged ? 28 : 22) + 10
        ctx.addPath(CGPath(roundedRect: CGRect(x: 300 - 5, y: bottom, width: 10, height: top - bottom),
                           cornerWidth: 5, cornerHeight: 5, transform: nil))
        ctx.setFillColor(NSColor.white.withAlphaComponent(i == 1 ? 0.75 : 0.45).cgColor)
        ctx.fillPath()
    }
    for row in rows {
        let dotR: CGFloat = row.flagged ? 28 : 22
        ctx.setFillColor(NSColor.white.withAlphaComponent(row.flagged ? 1 : 0.5).cgColor)
        ctx.fillEllipse(in: CGRect(x: 300 - dotR, y: row.y - dotR, width: 2 * dotR, height: 2 * dotR))
        let bar = CGRect(x: 370, y: row.y - 15, width: row.length, height: 30)
        ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 15, cornerHeight: 15, transform: nil))
        ctx.setFillColor(NSColor.white.withAlphaComponent(row.flagged ? 1 : 0.32).cgColor)
        ctx.fillPath()
    }

    // Light catching the top edge.
    let edge = CGGradient(colorsSpace: space, colors: [
        NSColor.white.withAlphaComponent(0.10).cgColor, NSColor.white.withAlphaComponent(0).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(edge, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 760), options: [])
    ctx.restoreGState()

    // Hairline border.
    ctx.addPath(shape)
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.14).cgColor)
    ctx.setLineWidth(3); ctx.strokePath()

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
