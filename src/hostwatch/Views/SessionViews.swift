import SwiftUI

// Coding-agent sessions in the views: the maker's mark, a session's facts line (as `claude --resume` lists them),
// and the sessions replayed from a Time Travel window.

/// The agent's maker, as a small mark drawn here (no bitmaps): Anthropic's slanted A, OpenAI's six-petal knot,
/// Google's four-colour G, Cursor's cube. 15 pt, legible at a glance next to a row.
struct AgentBadge: View {
    let agent: CodingAgent
    var size: CGFloat = 15

    var body: some View {
        Group {
            switch agent {
            case .claude: AnthropicMark()
            case .codex: OpenAIMark()
            case .gemini: GoogleMark()
            case .cursor: CursorMark()
            }
        }
        .frame(width: size, height: size)
        .help(agent.title)
        .accessibilityLabel(agent.title)
    }
}

/// Anthropic: a rounded terracotta tile with the slanted, cross-bar-less A.
private struct AnthropicMark: View {
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, h = geo.size.height
            ZStack {
                RoundedRectangle(cornerRadius: w * 0.24, style: .continuous).fill(Color(red: 0.85, green: 0.47, blue: 0.34))
                // Anthropic's logomark (the published 24-unit outline), drawn at 62 % of the box.
                Path { p in
                    let s = w * 0.62 / 24, ox = (w - 24 * s) / 2, oy = (h - 24 * s) / 2
                    func pt(_ x: Double, _ y: Double) -> CGPoint { CGPoint(x: ox + x * s, y: oy + y * s) }
                    p.move(to: pt(17.3041, 3.541)); p.addLine(to: pt(13.6323, 3.541)); p.addLine(to: pt(20.3283, 20.459))
                    p.addLine(to: pt(24, 20.459)); p.closeSubpath()
                    p.move(to: pt(6.6959, 3.541)); p.addLine(to: pt(0, 20.459)); p.addLine(to: pt(3.7442, 20.459))
                    p.addLine(to: pt(5.1135, 16.9063)); p.addLine(to: pt(12.1187, 16.9063)); p.addLine(to: pt(13.488, 20.4591))
                    p.addLine(to: pt(17.2322, 20.4591)); p.addLine(to: pt(10.5363, 3.5409)); p.closeSubpath()
                    p.move(to: pt(6.3247, 13.7641)); p.addLine(to: pt(8.6161, 7.8185)); p.addLine(to: pt(10.9075, 13.7641)); p.closeSubpath()
                }
                .fill(Color.white, style: FillStyle(eoFill: true))
            }
        }
    }
}

/// OpenAI: the knot of six petals around a hollow centre, white on black.
private struct OpenAIMark: View {
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, c = CGPoint(x: w / 2, y: w / 2)
            ZStack {
                RoundedRectangle(cornerRadius: w * 0.24, style: .continuous).fill(Color.black)
                ForEach(0..<6, id: \.self) { i in
                    Capsule()
                        .fill(Color.white)
                        .frame(width: w * 0.17, height: w * 0.46)
                        .offset(y: -w * 0.19)
                        .rotationEffect(.degrees(Double(i) * 60), anchor: .center)
                        .position(c)
                }
                Circle().fill(Color.black).frame(width: w * 0.22, height: w * 0.22).position(c)
            }
        }
    }
}

/// Google: the G in its four colours on white.
private struct GoogleMark: View {
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, c = CGPoint(x: w / 2, y: w / 2), r = w * 0.32, line = w * 0.17
            ZStack {
                RoundedRectangle(cornerRadius: w * 0.24, style: .continuous).fill(Color.white)
                    .overlay(RoundedRectangle(cornerRadius: w * 0.24, style: .continuous).strokeBorder(Color.black.opacity(0.12), lineWidth: 0.5))
                arc(c, r, from: 45, to: 135, Color(red: 0.26, green: 0.52, blue: 0.96), line)     // blue: right, lower
                arc(c, r, from: 135, to: 225, Color(red: 0.20, green: 0.66, blue: 0.33), line)    // green: bottom
                arc(c, r, from: 225, to: 315, Color(red: 0.98, green: 0.74, blue: 0.02), line)    // yellow: left
                arc(c, r, from: 315, to: 400, Color(red: 0.92, green: 0.26, blue: 0.21), line)    // red: top
                Rectangle().fill(Color(red: 0.26, green: 0.52, blue: 0.96))
                    .frame(width: r + line / 2, height: line).position(x: c.x + (r + line / 2) / 2, y: c.y)
            }
        }
    }

    private func arc(_ c: CGPoint, _ r: CGFloat, from: Double, to: Double, _ color: Color, _ line: CGFloat) -> some View {
        Path { p in p.addArc(center: c, radius: r, startAngle: .degrees(from), endAngle: .degrees(to), clockwise: false) }
            .stroke(color, style: StrokeStyle(lineWidth: line, lineCap: .butt))
    }
}

/// Cursor: a cube seen from above, white on black.
private struct CursorMark: View {
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            ZStack {
                RoundedRectangle(cornerRadius: w * 0.24, style: .continuous).fill(Color.black)
                Path { p in
                    let top = CGPoint(x: w * 0.5, y: w * 0.18), left = CGPoint(x: w * 0.2, y: w * 0.36)
                    let right = CGPoint(x: w * 0.8, y: w * 0.36), bottom = CGPoint(x: w * 0.5, y: w * 0.84)
                    let mid = CGPoint(x: w * 0.5, y: w * 0.56), lb = CGPoint(x: w * 0.2, y: w * 0.66), rb = CGPoint(x: w * 0.8, y: w * 0.66)
                    p.move(to: top); p.addLine(to: right); p.addLine(to: rb); p.addLine(to: bottom); p.addLine(to: lb); p.addLine(to: left); p.closeSubpath()
                    p.move(to: left); p.addLine(to: mid); p.addLine(to: right)
                    p.move(to: mid); p.addLine(to: bottom)
                }
                .stroke(Color.white, lineWidth: max(1, w * 0.08))
            }
        }
    }
}

extension CodingAgent {
    /// The maker's tint, for text next to the mark.
    var tint: Color {
        switch self {
        case .claude: Color(red: 0.85, green: 0.47, blue: 0.34)
        case .codex: Color(white: 0.2)
        case .gemini: Color(red: 0.26, green: 0.52, blue: 0.96)
        case .cursor: Color(white: 0.35)
        }
    }
}

extension AgentSession {
    /// "ProcessHUD · main · 12 min · 340 events · 5 conn", the way `claude --resume` lists a session.
    var facts: String { facts(withEvents: true) }

    /// For a group row, whose count capsule already says how many events are listed.
    var groupFacts: String { facts(withEvents: false) }

    private func facts(withEvents: Bool) -> String {
        var parts: [String] = []
        if !project.isEmpty { parts.append(project) }
        if !branch.isEmpty { parts.append(branch) }
        let minutes = Int(duration / 60)
        parts.append(isLive ? (minutes < 60 ? "\(minutes) min" : "\(minutes / 60) h \(minutes % 60) min")
                     : "ended " + RelativeDateTimeFormatter.short.localizedString(for: ended ?? lastSeen, relativeTo: Date()))
        if withEvents { parts.append("\(events.formatted()) events") }
        if connections > 0 { parts.append("\(connections) conn") }
        return parts.joined(separator: " · ")
    }

    var tooltip: String {
        var lines = ["\(agent.title), pid \(id)" + (cwd.isEmpty ? "" : " · \(cwd)"),
                     "Started \(started.formatted(date: .abbreviated, time: .shortened))"
                     + (ended.map { ", ended \($0.formatted(date: .omitted, time: .shortened))" } ?? ""),
                     "\(pids.count) processes · \(launches) launches · \(files) file opens · \(connections) connections"]
        if !firstPrompt.isEmpty, firstPrompt != topic { lines.append("First prompt: \(firstPrompt)") }
        if !sessionID.isEmpty { lines.append("Claude session \(sessionID)") }
        return lines.joined(separator: "\n")
    }
}

extension RelativeDateTimeFormatter {
    static let short: RelativeDateTimeFormatter = { let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; return f }()
}

/// Sessions replayed from the Time Travel window, once per window (not on every redraw).
@MainActor
final class ReplayedSessions: ObservableObject {
    private var key: (Int, Int)?
    private var cached: [AgentSession] = []

    func sessions(for travel: TimeTravel, named: [AgentSession]) -> [AgentSession] {
        let key = (travel.revision, travel.listed.count)
        if key.0 != self.key?.0 || key.1 != self.key?.1 {
            cached = AgentSessions.replay(travel.listed, named: named)
            self.key = key
        }
        return cached
    }
}
