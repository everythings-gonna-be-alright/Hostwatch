import AppKit
// Renders the square demo film frame by frame and writes raw RGBA to stdout (ffmpeg encodes it).
// Run by build.sh, which explains the arguments. docs/VIDEO.md is the guide to the whole project.
let a = CommandLine.arguments
let footage = a[1], iconPath = a[2], variant = a.count > 3 ? a[3] : "40"
// The 60-second cut tells one story: longer headlines with a second line, cross-fades, and the new app carried from scene to scene.
let connected = variant == "60"
let W: CGFloat = 1080, FPS = 30.0
func load(_ p: String) -> CGImage {
    let s = CGImageSourceCreateWithURL(URL(fileURLWithPath: p) as CFURL, nil)!
    return CGImageSourceCreateImageAtIndex(s, 0, nil)!
}
let fire = load(footage + "/firewall.png"), map = load(footage + "/map-sent.png")
let icon = load(iconPath)
// Only the 60-second cut needs it.
let protection: CGImage? = FileManager.default.fileExists(atPath: footage + "/protection.png") ? load(footage + "/protection.png") : nil
let liveCount = ((try? FileManager.default.contentsOfDirectory(atPath: footage + "/live")) ?? []).filter { $0.hasSuffix(".jpg") }.count
let ctx = CGContext(data: nil, width: 1080, height: 1080, bitsPerComponent: 8, bytesPerRow: 1080 * 4,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.translateBy(x: 0, y: W); ctx.scaleBy(x: 1, y: -1)          // y grows downward from here on
ctx.interpolationQuality = .high
NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: true)

let bg = NSColor(srgbRed: 8/255, green: 9/255, blue: 10/255, alpha: 1)
let red = NSColor(srgbRed: 0.93, green: 0.30, blue: 0.31, alpha: 1)
let green = NSColor(srgbRed: 0.25, green: 0.78, blue: 0.42, alpha: 1)
let amber = NSColor(srgbRed: 0.98, green: 0.72, blue: 0.2, alpha: 1)
let grey = NSColor(white: 0.62, alpha: 1)

func c01(_ x: CGFloat) -> CGFloat { min(1, max(0, x)) }
func prog(_ t: Double, _ start: Double, _ dur: Double) -> CGFloat { c01(CGFloat((t - start) / dur)) }
func ease(_ x: CGFloat) -> CGFloat { x * x * (3 - 2 * x) }
func easeOut(_ x: CGFloat) -> CGFloat { 1 - pow(1 - x, 3) }
func back(_ x: CGFloat) -> CGFloat { let c: CGFloat = 1.70158; return 1 + (c + 1) * pow(x - 1, 3) + c * pow(x - 1, 2) }
func lerp(_ a: CGFloat, _ b: CGFloat, _ p: CGFloat) -> CGFloat { a + (b - a) * p }

func attr(_ s: String, _ size: CGFloat, _ w: NSFont.Weight, _ c: NSColor, center: Bool) -> NSAttributedString {
    let p = NSMutableParagraphStyle(); p.alignment = center ? .center : .left
    return NSAttributedString(string: s, attributes: [.font: NSFont.systemFont(ofSize: size, weight: w), .foregroundColor: c,
                                                      .paragraphStyle: p, .kern: -size * 0.02])
}
func text(_ s: String, _ size: CGFloat, _ w: NSFont.Weight, y: CGFloat, color: NSColor = .white, p: CGFloat = 1) {
    guard p > 0 else { return }
    attr(s, size, w, color.withAlphaComponent(color.alphaComponent * p), center: true)
        .draw(in: NSRect(x: 40, y: y + (1 - easeOut(p)) * 22, width: W - 80, height: 300))
}
func layer(alpha: CGFloat, _ body: () -> Void) {
    guard alpha > 0.001 else { return }
    ctx.saveGState(); ctx.setAlpha(alpha); ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    body()
    ctx.endTransparencyLayer(); ctx.restoreGState()
}
func drawImg(_ i: CGImage, s: CGFloat, ox: CGFloat, oy: CGFloat, clip: CGRect? = nil, alpha: CGFloat = 1) {
    guard alpha > 0.001 else { return }
    ctx.saveGState()
    if let c = clip { ctx.clip(to: CGRect(x: ox + c.minX * s, y: oy + c.minY * s, width: c.width * s, height: c.height * s)) }
    ctx.setAlpha(alpha)
    let w = CGFloat(i.width) * s, h = CGFloat(i.height) * s
    ctx.translateBy(x: ox, y: oy + h); ctx.scaleBy(x: 1, y: -1)
    ctx.draw(i, in: CGRect(x: 0, y: 0, width: w, height: h))
    ctx.restoreGState()
}
func pill(_ s: String, cx: CGFloat, y: CGFloat, size: CGFloat = 31, dot: NSColor? = nil,
          fill: NSColor = NSColor(srgbRed: 0.12, green: 0.125, blue: 0.14, alpha: 0.97), weight: NSFont.Weight = .medium, p: CGFloat) {
    guard p > 0 else { return }
    let str = attr(s, size, weight, .white, center: false), ts = str.size()
    let padX = size * 0.85, dotW: CGFloat = dot == nil ? 0 : size * 0.85
    let w = ts.width + padX * 2 + dotW, h = size * 1.95
    let r = CGRect(x: cx - w / 2, y: y + (1 - back(p)) * 30, width: w, height: h)
    layer(alpha: c01(p * 1.6)) {
        let path = CGPath(roundedRect: r, cornerWidth: h / 2, cornerHeight: h / 2, transform: nil)
        ctx.saveGState(); ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 30, color: NSColor(white: 0, alpha: 0.6).cgColor)
        ctx.addPath(path); ctx.setFillColor(fill.cgColor); ctx.fillPath(); ctx.restoreGState()
        ctx.addPath(path); ctx.setStrokeColor(NSColor(white: 1, alpha: 0.16).cgColor); ctx.setLineWidth(1.5); ctx.strokePath()
        if let d = dot {
            let dd = size * 0.5
            ctx.setFillColor(d.cgColor); ctx.fillEllipse(in: CGRect(x: r.minX + padX, y: r.midY - dd / 2, width: dd, height: dd))
        }
        str.draw(at: NSPoint(x: r.minX + padX + dotW, y: r.minY + (h - ts.height) / 2))
    }
}
func vgrad(_ from: CGFloat, _ to: CGFloat, y0: CGFloat, y1: CGFloat) {
    let g = CGGradient(colorsSpace: nil, colors: [bg.withAlphaComponent(from).cgColor, bg.withAlphaComponent(to).cgColor] as CFArray, locations: [0, 1])!
    ctx.saveGState(); ctx.clip(to: CGRect(x: 0, y: y0, width: W, height: y1 - y0))
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: y0), end: CGPoint(x: 0, y: y1), options: []); ctx.restoreGState()
}
/// The words on top of a scene: a solid band the picture slides under, and a soft fade at the bottom.
func caption(_ title: String, _ long: String? = nil, _ sub: String? = nil, t: Double, bottom: CGFloat = 200) {
    ctx.setFillColor(bg.cgColor); ctx.fill(CGRect(x: 0, y: 0, width: W, height: 212))
    vgrad(1, 0, y0: 212, y1: 290)
    if bottom > 0 { vgrad(0, 0.96, y0: W - bottom, y1: W) }
    if connected, let long, let sub {
        text(long, 60, .semibold, y: 50, p: prog(t, 0.15, 0.5))
        text(sub, 31, .regular, y: 142, color: grey, p: prog(t, 0.45, 0.5))
    } else {
        text(title, 66, .semibold, y: 82, p: prog(t, 0.15, 0.5))
    }
}
func glow() {
    let g = CGGradient(colorsSpace: nil, colors: [NSColor(white: 1, alpha: 0.075).cgColor, NSColor(white: 1, alpha: 0).cgColor] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(g, startCenter: CGPoint(x: 540, y: 420), startRadius: 0, endCenter: CGPoint(x: 540, y: 420), endRadius: 640, options: [])
}
func iconAt(y: CGFloat, size: CGFloat, p: CGFloat) {
    let s = size * lerp(0.6, 1, back(p))
    drawImg(icon, s: s / CGFloat(icon.width), ox: 540 - s / 2, oy: y + (size - s) / 2, alpha: c01(p * 2))
}

// MARK: Scenes (t is seconds inside the scene)

func intro(_ t: Double) {
    glow()
    iconAt(y: 250, size: 270, p: prog(t, 0.05, 0.6))
    text("Hostwatch", 88, .bold, y: 548, p: prog(t, 0.35, 0.5))
    text("Security that understands your Mac", 42, .regular, y: 672, color: grey, p: prog(t, 0.8, 0.5))
}
func outro(_ t: Double) {
    glow()
    iconAt(y: 230, size: 250, p: prog(t, 0.05, 0.6))
    text("Hostwatch", 88, .bold, y: 512, p: prog(t, 0.3, 0.5))
    pill("Free  ·  macOS 26 or later", cx: 540, y: 665, size: 34, dot: green, p: prog(t, 0.8, 0.45))
    text("hostwatch.tech", 42, .semibold, y: 800, p: prog(t, 1.2, 0.5))
}
func live(_ t: Double, _ d: Double) {
    let n = min(liveCount, max(1, Int(t * FPS) + 1))
    let f = load(String(format: "%@/live/%04d.jpg", footage, n))
    let p = ease(prog(t, 0, d)), s = lerp(0.84, 1.0, p)
    drawImg(f, s: s, ox: lerp(34, -6, p), oy: 250)
    caption("Watches every app", "It watches every app", "Every program, file and connection, live", t: t, bottom: 260)
    pill("Green is normal", cx: 330, y: 950, size: 36, dot: green, p: prog(t, 1.6, 0.45))
    pill("New gets a closer look", cx: 720, y: 950, size: 36, dot: amber, p: prog(t, 3.3, 0.45))
}
func card(_ r: CGRect, radius: CGFloat = 30, fill: NSColor = NSColor(white: 1, alpha: 0.06), stroke: NSColor = NSColor(white: 1, alpha: 0.13)) {
    let p = CGPath(roundedRect: r, cornerWidth: radius, cornerHeight: radius, transform: nil)
    ctx.addPath(p); ctx.setFillColor(fill.cgColor); ctx.fillPath()
    ctx.addPath(p); ctx.setStrokeColor(stroke.cgColor); ctx.setLineWidth(2); ctx.strokePath()
}
func ltext(_ s: String, _ size: CGFloat, _ w: NSFont.Weight, x: CGFloat, cy: CGFloat, color: NSColor = .white) {
    let a = attr(s, size, w, color, center: false); a.draw(at: NSPoint(x: x, y: cy - a.size().height / 2))
}
func symbol(_ name: String, size: CGFloat, cx: CGFloat, cy: CGFloat, color: NSColor = .white) {
    let cfg = NSImage.SymbolConfiguration(pointSize: size, weight: .semibold).applying(.init(paletteColors: [color]))
    guard let im = NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(cfg) else { return }
    let z = im.size
    im.draw(in: NSRect(x: cx - z.width / 2, y: cy - z.height / 2, width: z.width, height: z.height), from: .zero,
            operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
}
/// The attack as a picture: the app, then three plain steps that appear one at a time, then the verdict.
func storyScene(_ t: Double) {
    caption("One app goes rogue", "Here is what it really did", "Small signs, joined into one story", t: t, bottom: 0)
    let head = connected ? prog(t, 0, 0.35) : prog(t, 0.2, 0.5), danger = prog(t, 5.0, 0.5)
    let ys: [CGFloat] = [560, 720, 880], times: [Double] = [1.2, 2.5, 3.8]
    let steps = [("shield.slash.fill", "Skipped Apple's safety check"), ("key.fill", "Read your browser logins"), ("globe", "Called an unknown server")]
    var end: CGFloat = 440
    for i in 0..<3 { end = lerp(end, ys[i], ease(prog(t, times[i] - 0.5, 0.5))) }
    if end > 441 {
        ctx.setStrokeColor(NSColor(white: 1, alpha: 0.22).cgColor); ctx.setLineWidth(5); ctx.setLineCap(.round)
        ctx.move(to: CGPoint(x: 168, y: 440)); ctx.addLine(to: CGPoint(x: 168, y: end)); ctx.strokePath()
    }
    layer(alpha: head) {
        let r = CGRect(x: 90, y: 290 + (connected ? 0 : (1 - easeOut(head)) * 30), width: 900, height: 150)
        card(r, radius: 38)
        if danger > 0 { card(r, radius: 38, fill: red.withAlphaComponent(0.2 * danger), stroke: red.withAlphaComponent(danger)) }
        card(CGRect(x: r.minX + 32, y: r.midY - 46, width: 92, height: 92), radius: 22, fill: NSColor(white: 1, alpha: 0.12), stroke: .clear)
        symbol("externaldrive.fill", size: 40, cx: r.minX + 78, cy: r.midY)
        ltext("CleanMyDisk", 48, .semibold, x: r.minX + 152, cy: r.midY)
    }
    pill("Dangerous", cx: 835, y: 333, size: 32, fill: red, weight: .bold, p: danger)
    for i in 0..<3 {
        let p = prog(t, times[i], 0.45)
        guard p > 0 else { continue }
        let k = 46 * back(p)
        ctx.setFillColor(red.cgColor); ctx.fillEllipse(in: CGRect(x: 168 - k, y: ys[i] - k, width: k * 2, height: k * 2))
        layer(alpha: c01(p * 1.5)) {
            symbol(steps[i].0, size: 34, cx: 168, cy: ys[i])
            let dx = (1 - easeOut(p)) * 50
            card(CGRect(x: 245 + dx, y: ys[i] - 56, width: 745, height: 112))
            ltext(steps[i].1, 41, .medium, x: 282 + dx, cy: ys[i])
        }
    }
}
func cursor(x: CGFloat, y: CGFloat, alpha: CGFloat) {
    let pts: [(CGFloat, CGFloat)] = [(0, 0), (0, 17), (4.5, 13), (7.5, 20), (10, 19), (7, 12), (13, 12)]
    let k: CGFloat = 3.2, path = CGMutablePath()
    path.move(to: CGPoint(x: x, y: y))
    for q in pts.dropFirst() { path.addLine(to: CGPoint(x: x + q.0 * k, y: y + q.1 * k)) }
    path.closeSubpath()
    layer(alpha: alpha) {
        ctx.saveGState(); ctx.setShadow(offset: CGSize(width: 0, height: -4), blur: 10, color: NSColor(white: 0, alpha: 0.7).cgColor)
        ctx.addPath(path); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath(); ctx.restoreGState()
        ctx.addPath(path); ctx.setStrokeColor(NSColor.black.cgColor); ctx.setLineWidth(2.5); ctx.setLineJoin(.round); ctx.strokePath()
    }
}
func firewall(_ t: Double) {
    let pop = prog(t, 0.1, 0.5), done = prog(t, 3.9, 0.4)
    let s = 0.92 * lerp(0.9, 1, back(pop)) * lerp(1, 0.96, ease(done))
    let w = 932 * s, h = 874 * s, ox = 540 - w / 2, oy = 652 - h / 2
    drawImg(fire, s: s, ox: ox, oy: oy, alpha: c01(pop * 1.5) * lerp(1, 0.3, ease(done)))
    let bx = ox + 273 * s, by = oy + 718 * s
    let press = prog(t, 3.3, 0.1) * (1 - prog(t, 3.45, 0.25))
    if press > 0 {
        ctx.addPath(CGPath(roundedRect: CGRect(x: ox + 90 * s, y: oy + 690 * s, width: 366 * s, height: 56 * s), cornerWidth: 26, cornerHeight: 26, transform: nil))
        ctx.setFillColor(NSColor(white: 1, alpha: 0.3 * press).cgColor); ctx.fillPath()
    }
    let ring = prog(t, 3.3, 0.5)
    if ring > 0, ring < 1 {
        ctx.setStrokeColor(NSColor(white: 1, alpha: 0.7 * (1 - ring)).cgColor); ctx.setLineWidth(4)
        let r = lerp(12, 80, easeOut(ring)); ctx.strokeEllipse(in: CGRect(x: bx - r, y: by - r, width: r * 2, height: r * 2))
    }
    caption("New connection? You decide", "Anything else new waits", "Nothing unknown connects without your OK", t: t, bottom: 0)
    let m = ease(prog(t, 1.9, 1.2))
    cursor(x: lerp(930, bx - 4, m), y: lerp(1040, by - 2, m) + (press > 0 ? 3 : 0), alpha: prog(t, 1.7, 0.25) * (1 - prog(t, 4.0, 0.3)))
    pill("Blocked", cx: 540, y: 590, size: 68, dot: .white, fill: red, weight: .bold, p: prog(t, 3.95, 0.45))
}
func mapScene(_ t: Double) {
    let p = ease(prog(t, 1.2, 2.0)), z = lerp(0.6, 1.2, p)
    let fx = lerp(900, 860, p), fy = lerp(560, 400, p), ox = 540 - fx * z, oy = lerp(640, 640, p) - fy * z
    drawImg(map, s: z, ox: ox, oy: oy)
    func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: ox + x * z, y: oy + y * z) }
    // Dots of data travel from the app along its line and stop at the blocked destination.
    let path: [(CGFloat, CGFloat)] = [(657, 512), (680, 480), (694, 400), (706, 310), (722, 287), (850, 287), (1033, 287)]
    var lens: [CGFloat] = [0]
    for i in 1..<path.count { lens.append(lens[i - 1] + hypot(path[i].0 - path[i - 1].0, path[i].1 - path[i - 1].1)) }
    let on = prog(t, 3.3, 0.3)
    if on > 0 {
        for k in 0..<4 {
            let u = CGFloat(((t - 3.3) / 1.1 + Double(k) / 4).truncatingRemainder(dividingBy: 1)) * lens.last!
            let i = max(1, lens.firstIndex { $0 >= u } ?? path.count - 1), q = (u - lens[i - 1]) / (lens[i] - lens[i - 1])
            let c = pt(lerp(path[i - 1].0, path[i].0, q), lerp(path[i - 1].1, path[i].1, q))
            let fadeEnd = 1 - c01((u / lens.last! - 0.9) * 10)
            ctx.setFillColor(red.withAlphaComponent(0.35 * on * fadeEnd).cgColor); ctx.fillEllipse(in: CGRect(x: c.x - 15, y: c.y - 15, width: 30, height: 30))
            ctx.setFillColor(NSColor(white: 1, alpha: on * fadeEnd).cgColor); ctx.fillEllipse(in: CGRect(x: c.x - 6.5, y: c.y - 6.5, width: 13, height: 13))
        }
        let pulse = CGFloat(((t - 3.3) / 1.1).truncatingRemainder(dividingBy: 1)), grow = 26 * pulse
        let a = pt(1033, 262), b = pt(1292, 312)
        ctx.addPath(CGPath(roundedRect: CGRect(x: a.x - grow, y: a.y - grow, width: b.x - a.x + grow * 2, height: b.y - a.y + grow * 2),
                           cornerWidth: 14 + grow, cornerHeight: 14 + grow, transform: nil))
        ctx.setStrokeColor(red.withAlphaComponent(0.8 * (1 - pulse) * on).cgColor); ctx.setLineWidth(4); ctx.strokePath()
    }
    caption("See where your data goes", "Its connection is blocked", "The map shows where your data tried to go", t: t, bottom: 160)
    pill("Stopped here", cx: 870, y: 575, size: 40, dot: red, weight: .semibold, p: prog(t, 3.9, 0.4))
}
/// Watching an app as a picture: a one-minute ring fills, then the two numbers that matter.
/// In the connected cut the new app's tile arrives from the scene before and its icon leaves for the story's header.
func watchScene(_ t: Double, _ d: Double) {
    caption("Not sure about an app?", "Not sure about the new one?", "Watch it closely for one minute", t: t, bottom: 0)
    let o = connected ? 0.3 : 0.0
    let arrive = connected ? ease(prog(t, 0.1, 0.9)) : 1, leave = connected ? ease(prog(t, d - 1.1, 0.7)) : 0
    let inn = connected ? arrive : prog(t, 0.2, 0.5), run = ease(prog(t, 0.9 + o, 2.6)), done = prog(t, 3.5 + o, 0.4)
    let c = CGPoint(x: 540, y: 530 + (connected ? 0 : (1 - easeOut(inn)) * 30)), r: CGFloat = 175
    layer(alpha: inn * (1 - leave)) {
        ctx.setLineWidth(20); ctx.setLineCap(.round)
        ctx.setStrokeColor(NSColor(white: 1, alpha: 0.1).cgColor); ctx.strokeEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
        if run > 0 {
            ctx.setStrokeColor((amber.blended(withFraction: done, of: red) ?? red).cgColor)
            ctx.addArc(center: c, radius: r, startAngle: -.pi / 2, endAngle: -.pi / 2 + 2 * .pi * max(0.001, run), clockwise: false); ctx.strokePath()
        }
        text("\(Int((60 * run).rounded())) s", 60, .semibold, y: c.y + 4)
        text("CleanMyDisk", 44, .semibold, y: c.y + 215)
    }
    if arrive < 1 {
        layer(alpha: 1 - arrive) {
            let tile = CGRect(x: 440, y: 430, width: 200, height: 200)
            card(tile, radius: 46, fill: NSColor(white: 1, alpha: 0.07))
            card(tile, radius: 46, fill: amber.withAlphaComponent(0.1), stroke: amber.withAlphaComponent(0.8))
        }
    }
    layer(alpha: connected ? 1 : inn) {
        symbol("externaldrive.fill", size: lerp(lerp(76, 58, arrive), 40, leave),
               cx: lerp(540, 168, leave), cy: lerp(lerp(530, c.y - 42, arrive), 365, leave))
    }
    pill("5 red flags", cx: 335, y: 875, size: 46, dot: red, weight: .semibold, p: prog(t, 3.7 + o, 0.45) * (1 - leave))
    pill("6 warnings", cx: 750, y: 875, size: 46, dot: amber, weight: .semibold, p: prog(t, 4.5 + o, 0.45) * (1 - leave))
}
/// Everyday apps get a green tick one by one. The last one is new and gets a question mark.
/// In the connected cut the new app's tile then moves to the middle, where the next scene picks it up.
func learnScene(_ t: Double, _ d: Double) {
    caption("Learns what's normal", "And learns what's normal", "Trusted apps stay quiet in the background", t: t, bottom: 0)
    let leave = connected ? ease(prog(t, d - 1.2, 0.75)) : 0
    let apps = ["safari.fill", "envelope.fill", "music.note", "terminal.fill", "photo.fill", "message.fill", "calendar", "externaldrive.fill"]
    for (i, name) in apps.enumerated() {
        let p = prog(t, 0.3 + Double(i) * 0.08, 0.45)
        guard p > 0 else { continue }
        let last = i == apps.count - 1, tint = last ? amber : green, gone = last ? 0 : leave
        let x = 80 + CGFloat(i % 4) * 240, y = 310 + CGFloat(i / 4) * 250 + (1 - easeOut(p)) * 30
        let r = CGRect(x: last ? lerp(x, 440, leave) : x, y: last ? lerp(y, 430, leave) : y, width: 200, height: 200)
        let mark = prog(t, last ? 4.2 : 1.3 + Double(i) * 0.36, 0.4)
        layer(alpha: p * (1 - gone)) {
            card(r, radius: 46, fill: NSColor(white: 1, alpha: 0.07))
            if mark > 0 { card(r, radius: 46, fill: tint.withAlphaComponent(0.1 * mark), stroke: tint.withAlphaComponent(0.8 * mark)) }
            symbol(name, size: 76, cx: r.midX, cy: r.midY, color: NSColor(white: 1, alpha: 0.92))
        }
        if mark > 0 {
            layer(alpha: 1 - leave) {
                let k = 32 * back(mark), c = CGPoint(x: r.maxX - 14, y: r.minY + 14)
                ctx.setFillColor(tint.cgColor); ctx.fillEllipse(in: CGRect(x: c.x - k, y: c.y - k, width: k * 2, height: k * 2))
                layer(alpha: c01(mark * 1.5)) { symbol(last ? "questionmark" : "checkmark", size: 26, cx: c.x, cy: c.y, color: last ? .black : .white) }
            }
        }
    }
    pill("7 trusted", cx: 335, y: 870, size: 44, dot: green, weight: .semibold, p: prog(t, 3.9, 0.4) * (1 - leave))
    pill("1 new", cx: 740, y: 870, size: 44, dot: amber, weight: .semibold, p: prog(t, 4.5, 0.4) * (1 - leave))
}
/// The real Protection tab: the whole overview, then a push in to the Network card and its Off / Watch / Ask / Strict switch.
func protectScene(_ t: Double) {
    guard let im = protection else { return }
    let p = ease(prog(t, 1.6, 1.6)), z = lerp(0.53, 1.2, p)
    let ox = 540 - lerp(1644, 2317, p) * z, oy = 650 - lerp(760, 800, p) * z
    drawImg(im, s: z, ox: ox, oy: oy)
    let on = prog(t, 3.4, 0.3)
    if on > 0 {
        let pulse = CGFloat(((t - 3.4) / 1.1).truncatingRemainder(dividingBy: 1)), grow = 22 * pulse
        let r = CGRect(x: ox + 2021 * z - grow, y: oy + 559 * z - grow, width: 510 * z + grow * 2, height: 56 * z + grow * 2)
        ctx.addPath(CGPath(roundedRect: r, cornerWidth: min(18 + grow, r.height / 2), cornerHeight: min(18 + grow, r.height / 2), transform: nil))
        ctx.setStrokeColor(green.withAlphaComponent(0.9 * (1 - pulse) * on).cgColor); ctx.setLineWidth(4); ctx.strokePath()
    }
    caption("You choose how strict", "You choose how strict", "Only watch, ask first, or block the unknown", t: t, bottom: 200)
    if !connected { pill("Watch, Ask or Strict", cx: 540, y: 940, size: 40, dot: green, weight: .semibold, p: prog(t, 3.8, 0.4)) }
}
/// The Claude Code guard as a picture: a dangerous command is typed and stopped before it runs.
func guardScene(_ t: Double) {
    caption("Guards your AI agent", "It guards your AI agent too", "Risky Claude Code commands are checked first", t: t, bottom: 0)
    let inn = prog(t, 0.2, 0.5), blocked = prog(t, 3.4, 0.4), typing = prog(t, 1.0, 1.6)
    let r = CGRect(x: 80, y: 330 + (1 - easeOut(inn)) * 30, width: 920, height: 320)
    layer(alpha: inn) {
        card(r, radius: 38)
        if blocked > 0 { card(r, radius: 38, fill: red.withAlphaComponent(0.14 * blocked), stroke: red.withAlphaComponent(blocked)) }
        for i in 0..<3 {
            ctx.setFillColor(NSColor(white: 1, alpha: 0.22).cgColor)
            ctx.fillEllipse(in: CGRect(x: r.minX + 36 + CGFloat(i) * 34, y: r.minY + 34, width: 20, height: 20))
        }
        ltext("Claude Code", 30, .medium, x: r.minX + 160, cy: r.minY + 44, color: grey)
        let cmd = "rm -rf ~/Documents"
        let shown = "$ " + String(cmd.prefix(Int(CGFloat(cmd.count) * typing)))
        let line = NSAttributedString(string: shown, attributes: [.font: NSFont.monospacedSystemFont(ofSize: 54, weight: .medium), .foregroundColor: NSColor.white])
        let at = NSPoint(x: r.minX + 56, y: r.minY + 150)
        line.draw(at: at)
        if (typing > 0 && typing < 1) || Int(t * 2.5) % 2 == 0 {
            ctx.setFillColor(NSColor(white: 1, alpha: 0.8).cgColor)
            ctx.fill(CGRect(x: at.x + line.size().width + 8, y: at.y + 6, width: 26, height: 56))
        }
    }
    pill("Blocked before it ran", cx: 540, y: 745, size: 50, dot: .white, fill: red, weight: .bold, p: prog(t, 3.5, 0.45))
}
/// Privacy as a picture: a Mac with a lock on it.
func privacyScene(_ t: Double) {
    caption("Stays on your Mac", "And it all stays on your Mac", "Private and encrypted", t: t, bottom: 0)
    let p = prog(t, 0.2, 0.5), l = prog(t, 0.9, 0.45), cy = 610 + (1 - easeOut(p)) * 30
    layer(alpha: p) { symbol("laptopcomputer", size: 300, cx: 540, cy: cy, color: NSColor(white: 1, alpha: 0.9)) }
    if l > 0 {
        let k = 70 * back(l)
        ctx.setFillColor(green.cgColor); ctx.fillEllipse(in: CGRect(x: 540 - k, y: cy - 30 - k, width: k * 2, height: k * 2))
        layer(alpha: c01(l * 1.5)) { symbol("lock.fill", size: 56, cx: 540, cy: cy - 30) }
    }
}

// MARK: Timeline

typealias Scene = (Double, (Double, Double) -> Void)
let short: [Scene] = [
    (3.0, { t, _ in intro(t) }), (6.0, live), (7.0, { t, _ in storyScene(t) }), (6.0, { t, _ in firewall(t) }),
    (6.0, { t, _ in mapScene(t) }), (6.5, watchScene), (5.5, { t, _ in outro(t) }),
]
// One story: it watches, learns, meets a new app, watches it closely, shows what it did, blocks it, then the rest.
// Lengths include the 0.4 s each scene shares with the next, so they add up to 64 for a 60-second film.
let long: [Scene] = [
    (3.2, { t, _ in intro(t) }), (6.0, live), (6.6, learnScene), (6.6, watchScene), (7.6, { t, _ in storyScene(t) }),
    (6.4, { t, _ in mapScene(t) }), (6.4, { t, _ in firewall(t) }), (6.2, { t, _ in protectScene(t) }),
    (6.2, { t, _ in guardScene(t) }), (3.4, { t, _ in privacyScene(t) }), (5.4, { t, _ in outro(t) }),
]
let scenes = connected ? long : short
let overlap = connected ? 0.4 : 0.0
var starts: [Double] = [], clock = 0.0
for sc in scenes { starts.append(clock); clock += sc.0 - overlap }
let total = clock + overlap
let out = FileHandle.standardOutput
for f in 0..<Int((total * FPS).rounded()) {
    let now = Double(f) / FPS
    ctx.setFillColor(bg.cgColor); ctx.fill(CGRect(x: 0, y: 0, width: W, height: W))
    for (i, sc) in scenes.enumerated() {
        let t = now - starts[i]
        guard t >= 0, t < sc.0 else { continue }
        let first = i == 0, last = i == scenes.count - 1
        // Connected: a scene fades in over the one before it. Otherwise each scene dips to the background.
        let fadeIn = connected && !first ? overlap : 0.3, fadeOut = last ? 0.4 : (connected ? overlap : 0.28)
        let env = ease(prog(t, 0, fadeIn)) * (1 - ease(prog(t, sc.0 - fadeOut, fadeOut)))
        autoreleasepool { layer(alpha: env) { sc.1(t, sc.0) } }
    }
    if connected {
        ctx.setFillColor(NSColor(white: 1, alpha: 0.22).cgColor)
        ctx.fill(CGRect(x: 0, y: W - 6, width: W * CGFloat(now / total), height: 6))
    }
    out.write(Data(bytes: ctx.data!, count: 1080 * 1080 * 4))
}
FileHandle.standardError.write("frames done, \(total) s\n".data(using: .utf8)!)
