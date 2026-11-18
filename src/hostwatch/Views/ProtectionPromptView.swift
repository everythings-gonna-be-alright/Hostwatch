import AppKit
import SwiftUI

/// "curl wants to run": a launch or file access the collector holds, with the time it will wait. macOS gives
/// Endpoint Security a few seconds, so the panel says what happens if you don't answer.
struct ProtectionPromptView: View {
    let ask: ProtectionAsk
    let chain: LaunchChainReport
    /// The protected card's or your place's name ("SSH keys", "contracts").
    var place: String? = nil
    /// Paused the Ctrl+Z way, from your shell: say how to bring it back after Allow.
    var fgHint = false
    let waiting: Int
    let respond: (ProtectionMonitor.PromptAnswer) -> Void
    let expired: () -> Void

    private var title: String {
        let name = ask.event.name
        if ask.area == .launches { return "\(name) wants to run" }
        return "\(name) wants to \(ask.event.extra.contains("w") ? "change" : "read") \(place ?? "a protected file")"
    }

    private var detail: String {
        ask.area == .launches ? (ask.event.args.isEmpty ? ask.event.target : ask.event.args) : ask.event.target
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            QuestionKindLabel(kind: ask.area == .launches ? .exec : .file,
                              title: ask.area == .launches ? "Program launch" : "Protected file")
            HStack(alignment: .top, spacing: 12) {
                Image(nsImage: ProcessIcons.icon(ask.event.proc)).resizable().frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.headline)
                    Text(ask.reason).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let left = max(0, Int(ask.deadline.timeIntervalSince(context.date).rounded(.up)))
                    // Paused by Hostwatch: it goes on without an answer, as Hold does. Held by Endpoint Security: blocked.
                    Label(ask.reactive ? "Continues in \(left) s" : "Blocks in \(left) s", systemImage: "timer")
                        .font(.callout.monospacedDigit()).foregroundStyle(.orange)
                }
            }
            if let verdict = ask.aiVerdict {
                AIConclusion(verdict: verdict, limit: ask.aiLimit)
            } else if let note = ask.aiNote {
                Label(note, systemImage: "sparkles")                     // no answer, or no model: one quiet line
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if fgHint {
                Label("Your shell shows it as stopped. After Allow it goes on in the background: type fg in your terminal to bring it back.",
                      systemImage: "terminal")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if ask.reactive {
                Text(ask.area == .launches ? "It started and is paused until you answer."
                     : "It opened the file and is paused until you answer. Block stops it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            LaunchChainStrip(report: chain)
            if ask.area == .files {
                Text(detail)
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
            }
            HStack {
                if waiting > 1 { Text("\(waiting - 1) more waiting").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                // Two pairs, the same choice on each side: once (this time only) or always (decides the pattern).
                Button("Always Block") { respond(.block) }.buttonStyle(.glass)
                    .help("Stop it, and mark its pattern Dangerous: it's stopped every time")
                Button("Block Once") { respond(.blockOnce) }.buttonStyle(.glass)
                    .help("Stop it this time. Next time you're asked again")
                Divider().frame(height: 18)
                Button("Allow Once") { respond(.allowOnce) }.buttonStyle(.glass)
                    .help("Let it go on this time. Next time you're asked again")
                Button("Always Allow") { respond(.alwaysAllow) }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
                    .help("Let it go on, and mark its pattern Safe")
            }
            .controlSize(.large)
        }
        .padding(22)
        .frame(width: 600)
        .task(id: ask.id) {
            let wait = ask.deadline.timeIntervalSinceNow
            if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
            if !Task.isCancelled { expired() }
        }
    }
}

/// The AI's conclusion, as a card the eye finds: the verdict as a headline in its colour, the confidence, the reason,
/// and, when the case is yours whatever the AI says, why.
private struct AIConclusion: View {
    let verdict: LocalVerdict
    let limit: String?

    private var headline: String {
        switch verdict.verdict {
        case .safe: "AI thinks it's safe"
        case .suspicious: "AI thinks it's suspicious"
        case .dangerous: "AI thinks it's dangerous"
        case .unknown: "AI isn't sure"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles").foregroundStyle(verdict.verdict.color)
                Text(headline).font(.headline).foregroundStyle(verdict.verdict.color)
                Text("\(verdict.confidence.rawValue.capitalized) confidence")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(Capsule().fill(Color.primary.opacity(0.08)))
                Spacer(minLength: 0)
            }
            if !verdict.reason.isEmpty {
                Text(verdict.reason).font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            if let limit {
                Label("Yours to decide: \(limit).", systemImage: "hand.raised")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(verdict.verdict.color.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(verdict.verdict.color.opacity(0.30), lineWidth: 0.5))
        .accessibilityElement(children: .combine)
    }
}
