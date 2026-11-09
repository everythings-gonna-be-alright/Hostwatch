import SwiftUI

/// Classify with AI, live: the pattern being asked right now, then every pattern of the run with its state, newest
/// change first. The answers land as they come (one at a time from the local model, a batch at once from Claude).
struct ClassifyLiveView: View {
    @ObservedObject var live: ClassifyLive
    @ObservedObject var classifier: PatternClassifier

    private var ordered: [ClassifyLive.Step] { live.steps.sorted { $0.since > $1.since } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if let now = live.asking {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Asking \(askedBy(now)) about").font(.caption).foregroundStyle(.secondary)
                        Text("\(now.program) → \(now.pattern)").font(.system(size: 12, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.accentColor.opacity(0.1)))
            }
            if live.steps.isEmpty {
                Text("Nothing classified yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 80)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(ordered) { step in row(step); Divider() }
                    }
                }
                .frame(height: 340)
            }
        }
        .padding(16)
        .frame(width: 560)
    }

    private var header: some View {
        let settled = live.count { if case .done = $0 { return true } else { return false } }
        let left = live.count { if case .left = $0 { return true } else { return false } }
        let open = live.count { switch $0 { case .waiting, .asking: return true; default: return false } }
        return VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(classifier.bulk == nil ? "Last Classify with AI" : "Classifying with AI").font(.headline)
                Spacer()
                if let run = classifier.bulk {
                    Text("\(run.done) of \(run.total)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
            Text(live.engineText).font(.caption).foregroundStyle(.secondary)
            Text("\(settled) answered · \(left) left for you · \(open) to go").font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private func askedBy(_ step: ClassifyLive.Step) -> String {
        if case .asking(let who) = step.state { return who }
        return "AI"
    }

    private func row(_ step: ClassifyLive.Step) -> some View {
        HStack(alignment: .top, spacing: 8) {
            KindTile(kind: step.kind)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(step.program).fontWeight(.medium)
                    Text(step.pattern).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).help(step.pattern)
                }
                if let detail = detail(step.state) {
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            Spacer(minLength: 8)
            badge(step.state)
        }
        .padding(.vertical, 6)
    }

    private func detail(_ state: ClassifyLive.Step.State) -> String? {
        switch state {
        case .waiting(let what): "Waiting for \(what)"
        case .asking(let who): "Asking \(who)…"
        case .done(_, let by, let reason): reason.isEmpty ? "by \(by)" : "\(by): \(reason)"
        case .left(let why): why
        case .failed(let why): why
        }
    }

    @ViewBuilder private func badge(_ state: ClassifyLive.Step.State) -> some View {
        switch state {
        case .waiting: Image(systemName: "clock").foregroundStyle(.tertiary)
        case .asking: ProgressView().controlSize(.mini)
        case .done(let status, _, _): StatusPill(status: status)
        case .left: Label("For you", systemImage: "person.fill.questionmark").font(.caption).foregroundStyle(.secondary)
        case .failed: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
    }
}

/// After a run: reopens its live list (hidden until something was classified).
struct LastRunButton: View {
    @ObservedObject var live: ClassifyLive
    let open: () -> Void

    var body: some View {
        if !live.steps.isEmpty {
            Button(action: open) { Image(systemName: "list.bullet.rectangle") }
                .buttonStyle(.glass)
                .help("What the last Classify with AI did, pattern by pattern")
        }
    }
}
