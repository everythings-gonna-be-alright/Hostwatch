import SwiftUI

/// Above the Events list: one chip per coding-agent session (Claude Code and the like), live ones first. Click a
/// chip to see only that session's events (its whole process tree); right-click for its patterns.
struct SessionStrip: View {
    @ObservedObject var sessions: AgentSessions
    @ObservedObject var model: HUDModel
    /// Opens the Patterns tab scoped to these keys.
    let showPatterns: (String, Set<String>) -> Void

    var body: some View {
        let listed = sessions.sessions
        if !listed.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    Image(systemName: "sparkles.rectangle.stack").foregroundStyle(.secondary)
                        .help("Coding-agent sessions: each is the agent and every process it started")
                    ForEach(listed) { s in
                        SessionChip(session: s, selected: model.onlySession == s.id) {
                            model.onlySession = model.onlySession == s.id ? nil : s.id
                        } patterns: {
                            showPatterns("Session: \(s.name)", s.keys)
                        }
                    }
                    if model.onlySession != nil {
                        Button("Show All Events") { model.onlySession = nil }.buttonStyle(.link).font(.system(size: 11))
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 6)
            }
            Divider()
        }
    }
}

private struct SessionChip: View {
    let session: AgentSession
    let selected: Bool
    let toggle: () -> Void
    let patterns: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack(spacing: 6) {
                Circle().fill(session.isLive ? Color.green : Color.secondary.opacity(0.5)).frame(width: 6, height: 6)
                Text(session.name).fontWeight(.semibold)
                Text(detail).foregroundStyle(.secondary).monospacedDigit()
                if session.newPatterns > 0 {
                    Text("\(session.newPatterns) New").foregroundStyle(Color.accentColor).monospacedDigit()
                }
            }
            .font(.system(size: 11))
            .padding(.horizontal, 9).padding(.vertical, 3)
            .background(Capsule().fill(selected ? Color.accentColor.opacity(0.16) : Color.primary.opacity(0.05)))
            .overlay(Capsule().strokeBorder(selected ? Color.accentColor.opacity(0.35) : Color.clear, lineWidth: 0.5))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .opacity(session.isLive ? 1 : 0.7)
        .help(help)
        .contextMenu {
            Button("Show Only This Session", action: toggle)
            Button("Show Its Patterns…", action: patterns).disabled(session.keys.isEmpty)
        }
    }

    private var detail: String {
        let minutes = Int(session.duration / 60)
        let age = minutes < 60 ? "\(minutes) min" : "\(minutes / 60) h \(minutes % 60) min"
        return "\(session.isLive ? age : "ended") · \(session.events.formatted()) events · \(session.connections) conn"
    }

    private var help: String {
        var lines = ["\(session.agent.title), pid \(session.id)" + (session.cwd.isEmpty ? "" : " · \(session.cwd)"),
                     "Started \(session.started.formatted(date: .omitted, time: .shortened))"
                     + (session.ended.map { ", ended \($0.formatted(date: .omitted, time: .shortened))" } ?? ""),
                     "\(session.pids.count) processes · \(session.launches) launches · \(session.files) file opens · \(session.connections) connections"]
        if !session.sessionID.isEmpty { lines.append("Claude session \(session.sessionID)") }
        lines.append("Click: only this session's events · Right-click: its patterns")
        return lines.joined(separator: "\n")
    }
}
