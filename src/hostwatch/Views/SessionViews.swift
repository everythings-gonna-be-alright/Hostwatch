import SwiftUI

// Coding-agent sessions in the views: the maker's mark, a session's facts line (as `claude --resume` lists them),
// and the sessions replayed from a Time Travel window.

/// A small, plain mark for the agent's maker: a letter in its tint. No logos.
struct AgentBadge: View {
    let agent: CodingAgent

    var body: some View {
        Text(agent.mark)
            .font(.system(size: 9, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: 15, height: 15)
            .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(agent.tint))
            .help(agent.title)
            .accessibilityLabel(agent.title)
    }
}

extension CodingAgent {
    /// One or two letters: who makes the agent.
    var mark: String {
        switch self {
        case .claude: "A"       // Anthropic
        case .codex: "O"        // OpenAI
        case .gemini: "G"       // Google
        case .cursor: "Cu"
        }
    }

    var tint: Color {
        switch self {
        case .claude: Color(red: 0.85, green: 0.47, blue: 0.34)
        case .codex: Color(red: 0.06, green: 0.64, blue: 0.50)
        case .gemini: Color(red: 0.26, green: 0.52, blue: 0.96)
        case .cursor: Color(white: 0.35)
        }
    }
}

extension AgentSession {
    /// "ProcessHUD · main · 12 min · 340 events · 5 conn", the way `claude --resume` lists a session.
    var facts: String {
        var parts: [String] = []
        if !project.isEmpty { parts.append(project) }
        if !branch.isEmpty { parts.append(branch) }
        let minutes = Int(duration / 60)
        parts.append(isLive ? (minutes < 60 ? "\(minutes) min" : "\(minutes / 60) h \(minutes % 60) min")
                     : "ended " + RelativeDateTimeFormatter.short.localizedString(for: ended ?? lastSeen, relativeTo: Date()))
        parts.append("\(events.formatted()) events")
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
