import AppKit
import SwiftUI

/// "curl wants to run": a launch or file access the collector holds, with the time it will wait. macOS gives
/// Endpoint Security a few seconds, so the panel says what happens if you don't answer.
struct ProtectionPromptView: View {
    let ask: ProtectionAsk
    let chain: LaunchChainReport
    /// The protected card's or your place's name ("SSH keys", "contracts").
    var place: String? = nil
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
            HStack(alignment: .top, spacing: 12) {
                Image(nsImage: ProcessIcons.icon(ask.event.proc)).resizable().frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.headline)
                    Text(ask.reason).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let left = max(0, Int(ask.deadline.timeIntervalSince(context.date).rounded(.up)))
                    Label("Blocks in \(left) s", systemImage: "timer")
                        .font(.callout.monospacedDigit()).foregroundStyle(.orange)
                }
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
                Button("Block") { respond(.block) }.buttonStyle(.glass)
                Button("Allow Once") { respond(.allowOnce) }.buttonStyle(.glass)
                Button("Always Allow") { respond(.alwaysAllow) }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
        }
        .padding(22)
        .frame(width: 520)
        .task(id: ask.id) {
            let wait = ask.deadline.timeIntervalSinceNow
            if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
            if !Task.isCancelled { expired() }
        }
    }
}
