import AppKit
import SwiftUI

// MARK: - Panel

struct HeldView: View {
    @ObservedObject var hold: ProcessHold
    var askAI: (ActivityEvent) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Hostwatch paused \(hold.held.count == 1 ? "a process" : "\(hold.held.count) processes")",
                  systemImage: "pause.circle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.orange)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                VStack(spacing: 10) {
                    ForEach(hold.held) { HeldRow(held: $0, hold: hold, now: context.date, askAI: askAI) }
                }
            }
            Text("Frozen until you answer. If you don't, it will \(hold.timeoutAction == .resume ? "continue" : "be killed").")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(width: 520, alignment: .leading)
    }
}

private struct HeldRow: View {
    let held: HeldProcess
    let hold: ProcessHold
    let now: Date
    let askAI: (ActivityEvent) -> Void

    var body: some View {
        let left = max(0, Int(held.deadline.timeIntervalSince(now).rounded(.up)))
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("\(held.name)").font(.system(size: 13, weight: .semibold))
                Text("pid \(held.pid)").foregroundStyle(.secondary).monospacedDigit()
                Spacer()
                Text("\(left) s").monospacedDigit().foregroundStyle(left <= 10 ? .orange : .secondary)
            }
            Text(held.reason).font(.system(size: 12))
            Group {
                if !held.event.parent.isEmpty { Text("started by \(held.event.parent)") }
                if !held.event.args.isEmpty { Text(held.event.args).lineLimit(2) }
                else if held.event.kind != .exec { Text("\(held.event.kind.rawValue): \(held.event.target)").lineLimit(2) }
            }
            .font(.system(size: 11, design: .monospaced))
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            HStack {
                Button("Allow") { hold.allow(held) }.buttonStyle(.glassProminent)
                Button("Always Allow") { hold.alwaysAllow(held) }.buttonStyle(.glass)
                    .help("Allow and mark this pattern Safe: it won't be held again")
                Button("Kill", role: .destructive) { hold.kill(held) }.buttonStyle(.glass)
                Spacer()
                Button { askAI(held.event) } label: { Label("Ask AI", systemImage: "sparkles") }.buttonStyle(.glass)
            }
            .controlSize(.small)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.secondary.opacity(0.08)))
    }
}
