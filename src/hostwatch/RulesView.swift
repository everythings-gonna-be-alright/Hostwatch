import SwiftUI

/// Rules tab: proposals from Claude (checked locally) and the rules you approved.
struct RulesView: View {
    @ObservedObject var book: RuleBook
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier

    var body: some View {
        let _ = signatures.revision
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if !book.proposals.isEmpty {
                        section("Proposals") {
                            ForEach(book.proposals) { ProposalCard(proposal: $0, book: book) }
                        }
                    }
                    section("Your rules (\(book.activeCount) active)") {
                        if book.rules.isEmpty {
                            Text("No rules yet. Mark a few patterns Safe or Suspicious yourself, then ask Claude to suggest rules.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(book.rules) { RuleRow(rule: $0, book: book, matches: matches($0)) }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack {
                Text(book.message.isEmpty ? "Rules apply after you approve them; your own markings always win." : book.message)
                    .lineLimit(1)
                Spacer()
                Text("\(book.yourDecisions.count) of your decisions to learn from").monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Text("Rules learned from your decisions: Claude proposes, Hostwatch checks each one against everything you decided, you approve.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            if book.running {
                ProgressView().controlSize(.small)
                Button("Cancel") { book.cancel() }.buttonStyle(.glass)
            } else {
                Button { book.suggest() } label: { Label("Suggest Rules with Claude", systemImage: "sparkles") }
                    .buttonStyle(.glassProminent)
                    .disabled(classifier.engine == .onDevice || book.yourDecisions.count < 2)
                    .help(classifier.engine == .onDevice
                          ? "Needs Claude: rule learning is beyond the on-device model (Detection ▸ AI Engine)."
                          : "Sends your decisions (patterns you marked, secrets masked) to Claude for rule proposals.")
            }
        }
        .controlSize(.small)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 13, weight: .semibold))
            content()
        }
    }

    private func matches(_ rule: LearnedRule) -> Int {
        signatures.allEntries.filter { $0.source == "rule" && $0.note == rule.name && rule.matches($0) }.count
    }
}

private struct ActionPill: View {
    let status: SignatureStatus
    var body: some View { StatusPill(status: status) }
}

private struct ProposalCard: View {
    let proposal: RuleProposal
    let book: RuleBook

    var body: some View {
        let r = proposal.rule, e = proposal.evaluation
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ActionPill(status: r.action)
                Text(r.name).font(.system(size: 13, weight: .semibold))
                Spacer()
            }
            Text(r.matcherText).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            if !r.rationale.isEmpty { Text(r.rationale).font(.system(size: 12)).foregroundStyle(.secondary) }
            HStack(spacing: 14) {
                Label("\(e.agreeing.count) of your decisions", systemImage: "checkmark.circle")
                Label("\(e.newPatterns) new pattern\(e.newPatterns == 1 ? "" : "s")", systemImage: "square.stack.3d.up")
                if e.newHighRisk > 0 { Label("\(e.newHighRisk) high-risk", systemImage: "flame").foregroundStyle(.orange) }
            }
            .font(.system(size: 11))
            ForEach(e.warnings, id: \.self) { Label($0, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                .font(.system(size: 11))
            ForEach(e.problems, id: \.self) { Label($0, systemImage: "xmark.octagon").foregroundStyle(.red) }
                .font(.system(size: 11))
            HStack {
                Button("Approve") { book.approve(proposal) }
                    .buttonStyle(.glassProminent)
                    .disabled(!e.approvable)
                    .help(e.approvable ? "Apply this rule from now on" : "Fix the problems above first; it can't be approved")
                Button("Reject") { book.reject(proposal) }.buttonStyle(.glass)
            }
            .controlSize(.small)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.secondary.opacity(0.07)))
    }
}

private struct RuleRow: View {
    let rule: LearnedRule
    let book: RuleBook
    let matches: Int

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ActionPill(status: rule.action)
            VStack(alignment: .leading, spacing: 3) {
                Text(rule.name).fontWeight(.semibold)
                Text(rule.matcherText).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                if let why = rule.pausedReason {
                    Label("Paused: \(why)", systemImage: "pause.circle").foregroundStyle(.orange).font(.system(size: 11))
                } else {
                    Label("Check passes · classifies \(matches) pattern\(matches == 1 ? "" : "s")", systemImage: "checkmark.seal")
                        .foregroundStyle(.green).font(.system(size: 11))
                }
            }
            Spacer()
            Button(rule.isActive ? "Pause" : "Resume") { book.pause(rule, rule.isActive) }.buttonStyle(.glass)
            Button(role: .destructive) { book.delete(rule) } label: { Image(systemName: "trash") }.buttonStyle(.glass)
        }
        .controlSize(.small)
        .font(.system(size: 12))
        .padding(.vertical, 4)
    }
}
