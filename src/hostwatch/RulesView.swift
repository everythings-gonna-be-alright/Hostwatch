import SwiftUI

/// Rules tab: automatic decisions in one place. The baseline (rules per signer, learned in the first
/// hour, and what needs your review), then Claude's proposals, then the rules you approved.
struct RulesView: View {
    @ObservedObject var book: RuleBook
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var baseline: BaselineLearner
    /// Opens Patterns filtered to an app.
    var showPatterns: (String) -> Void = { _ in }
    /// Opens Patterns showing exactly these patterns.
    var showKeys: (String, [String]) -> Void = { _, _ in }

    var body: some View {
        let _ = signatures.revision
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    baselineSection
                    if let review = baseline.report?.review, !review.isEmpty { reviewSection(review) }
                    yourRulesSection
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack {
                Text(footer).lineLimit(1)
                Spacer()
                Text("\(book.yourDecisions.count) of your decisions to learn from").monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    private var footer: String {
        if !baseline.message.isEmpty { return baseline.message }
        if !book.message.isEmpty { return book.message }
        return "Your own markings always win over any rule."
    }

    // MARK: Baseline

    private var baselineSection: some View {
        section("Baseline", subtitle: "From code signatures, on this Mac, no AI") {
            HStack(spacing: 10) {
                Image(systemName: baseline.phase == .done ? "checkmark.shield" : "hourglass")
                    .foregroundStyle(baseline.phase == .done ? .green : .secondary)
                Text(baseline.statusText).font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button { Task { await baseline.buildNow() } } label: {
                    Label(baseline.running ? "Updating…" : "Update Baseline", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.glass)
                .disabled(baseline.running)
                .help("Sort New patterns again by code signature and add rules for trusted apps. Local, no AI.")
                Menu {
                    Button("Remove All Baseline Rules", role: .destructive) { baseline.undo() }
                } label: { Image(systemName: "ellipsis") }
                    .menuStyle(.button).buttonStyle(.glass).fixedSize()
                    .disabled(baseline.rules.isEmpty)
                    .help("Remove every baseline rule; what they trusted goes back to New")
            }
            .controlSize(.small)
            Text("One rule per app (its developer's signature must match), plus one for macOS itself. A rule trusts the app's "
                 + "normal-risk activity, now and later. Never high-risk, unsigned or downloaded code; credentials, login "
                 + "items and other sensitive places stay for you unless you trusted the app yourself.")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !baseline.rules.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(baseline.rules.enumerated()), id: \.element.id) { i, rule in
                        if i > 0 { Divider() }
                        BaselineRuleRow(rule: rule, count: baseline.patternCount(rule), baseline: baseline, showKeys: showKeys)
                    }
                }
                .padding(.horizontal, 12)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.secondary.opacity(0.06)))
            }
        }
    }

    private func reviewSection(_ review: [BaselineReport.Group]) -> some View {
        let count = review.reduce(0) { $0 + $1.keys.count }
        let brew = review.filter(\.homebrew)
        return section("Needs your review", subtitle: "\(review.count) app\(review.count == 1 ? "" : "s") · \(count) pattern\(count == 1 ? "" : "s")") {
            Text("Not trusted automatically. Trust an app you know (a rule is added for it), mark it Suspicious, "
                 + "or Dismiss to hide it here; dismissed patterns stay New.")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !brew.isEmpty, !SigningCache.shared.trustHomebrew {
                HStack(spacing: 10) {
                    Image(systemName: "mug").foregroundStyle(.brown)
                    Text("\(brew.count) Homebrew tool\(brew.count == 1 ? "" : "s") (\(brew.map(\.app).prefix(4).joined(separator: ", "))"
                         + "\(brew.count > 4 ? "…" : "")). Homebrew signs what it builds ad-hoc, so they can't be checked by developer.")
                        .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Trust Homebrew Tools") { Task { await baseline.trustHomebrew() } }
                        .buttonStyle(.glass)
                        .help("Trust programs installed by Homebrew (with its install receipt). Also in Settings ▸ Detection.")
                }
                .controlSize(.small)
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.brown.opacity(0.08)))
            }
            VStack(spacing: 0) {
                ForEach(Array(review.enumerated()), id: \.element.id) { i, g in
                    if i > 0 { Divider() }
                    ReviewRow(group: g, baseline: baseline, showKeys: showKeys)
                }
            }
            .padding(.horizontal, 12)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.orange.opacity(0.05)))
        }
    }

    // MARK: Your rules

    private var yourRulesSection: some View {
        section("Your rules", subtitle: "\(book.activeCount) active · learned from your decisions") {
            HStack(spacing: 10) {
                Text("Claude proposes rules from the patterns you marked yourself; Hostwatch checks each one; you approve.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Spacer()
                if book.running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { book.cancel() }.buttonStyle(.glass)
                } else {
                    Button { book.suggest() } label: { Label("Suggest Rules from My Decisions", systemImage: "sparkles") }
                        .buttonStyle(.glass)
                        .disabled(classifier.engine == .onDevice || book.yourDecisions.count < 2)
                        .help(classifier.engine == .onDevice
                              ? "Needs Claude: rule learning is beyond the on-device model (Settings ▸ AI)."
                              : "Sends your decisions (patterns you marked, secrets masked) to Claude for rule proposals.")
                }
            }
            .controlSize(.small)
            ForEach(book.proposals) { ProposalCard(proposal: $0, book: book) }
            if book.rules.isEmpty && book.proposals.isEmpty {
                Text("No rules yet. Mark a few patterns Safe or Suspicious yourself, then ask for suggestions.")
                    .font(.system(size: 12)).foregroundStyle(.tertiary)
            }
            ForEach(book.rules) { RuleRow(rule: $0, book: book, matches: matches($0)) }
        }
    }

    private func section<Content: View>(_ title: String, subtitle: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(.system(size: 15, weight: .semibold))
                Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
            }
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

private struct BaselineRuleRow: View {
    let rule: BaselineRule
    let count: Int
    let baseline: BaselineLearner
    let showKeys: (String, [String]) -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: rule.id == "system" ? "apple.logo" : rule.id == "homebrew" ? "mug" : "app.badge.checkmark")
                .frame(width: 18)
                .foregroundStyle(rule.paused ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.green))
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(rule.name).fontWeight(.semibold)
                    if rule.approvedByYou {
                        Text("Trusted by you")
                            .font(.system(size: 10, weight: .semibold))
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .foregroundStyle(.blue)
                            .background(Capsule().fill(Color.blue.opacity(0.14)))
                    }
                }
                Text(rule.paused ? "\(rule.signer) · paused, its patterns are New again"
                                 : "\(rule.signer) · trusts \(count) pattern\(count == 1 ? "" : "s")")
                    .font(.system(size: 11)).foregroundStyle(rule.paused ? .orange : .secondary)
            }
            Spacer()
            Button("Show") { showKeys(rule.name, baseline.keys(rule)) }.buttonStyle(.glass)
                .disabled(count == 0)
                .help("Open exactly the patterns this rule trusts in Patterns")
            Button(rule.paused ? "Resume" : "Pause") { baseline.setPaused(rule, !rule.paused) }.buttonStyle(.glass)
            Button(role: .destructive) { baseline.delete(rule) } label: { Image(systemName: "trash") }.buttonStyle(.glass)
                .help("Delete this rule; its patterns become New. Update Baseline may create it again: pause it to keep it off.")
        }
        .controlSize(.small)
        .font(.system(size: 12))
        .padding(.vertical, 8)
        .opacity(rule.paused ? 0.7 : 1)
    }
}

private final class ExpandState: ObservableObject { @Published var open = false }

private struct ReviewRow: View {
    let group: BaselineReport.Group
    let baseline: BaselineLearner
    let showKeys: (String, [String]) -> Void
    @StateObject private var expand = ExpandState()
    private var anyCode: Bool { baseline.runsAnyCode(group) }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: group.homebrew ? "mug" : "questionmark.app")
                .frame(width: 18)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(group.app).fontWeight(.semibold)
                    Button {
                        withAnimation(.snappy(duration: 0.2)) { expand.open.toggle() }
                    } label: {
                        HStack(spacing: 3) {
                            Text("\(group.keys.count) pattern\(group.keys.count == 1 ? "" : "s")").monospacedDigit()
                            Image(systemName: "chevron.right")
                                .font(.system(size: 9, weight: .semibold))
                                .rotationEffect(.degrees(expand.open ? 90 : 0))
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .help(expand.open ? "Hide the patterns" : "Show the patterns here")
                }
                ForEach(group.reasons.prefix(4), id: \.self) { reason in
                    Text("· " + reason).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
                if group.reasons.count > 4 {
                    Text("· and \(group.reasons.count - 4) more").font(.system(size: 11)).foregroundStyle(.tertiary)
                }
                if expand.open {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(baseline.entries(group)) { e in ReviewPatternLine(entry: e) }
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.secondary.opacity(0.07)))
                    .padding(.vertical, 3)
                }
                if anyCode {
                    Label("Runs any script it's given: trusting it would trust a virus's script too. Dismiss keeps it New.",
                          systemImage: "info.circle")
                        .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            if !anyCode {
                Button("Trust") { Task { await baseline.trustApp(group) } }.buttonStyle(.glass)
                    .help("Your decision: mark these Safe; a signed app also gets a baseline rule (Trusted by you)")
            }
            Button("Dismiss") { baseline.dismiss(group) }.buttonStyle(.glass)
                .help("Hide it here; its patterns stay New")
            Menu {
                Button("Show in Patterns") { showKeys(group.app, group.keys) }
                Button("Mark Suspicious") { baseline.markSuspicious(group) }
            } label: { Image(systemName: "ellipsis") }
                .menuStyle(.button).buttonStyle(.glass).fixedSize()
                .help("Show in Patterns, or Mark Suspicious")
        }
        .controlSize(.small)
        .font(.system(size: 12))
        .padding(.vertical, 8)
    }
}

/// One pattern in an expanded review row: what kind, who, what, and how risky.
private struct ReviewPatternLine: View {
    let entry: SignatureEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: entry.kind == .exec ? "terminal" : entry.kind == .net ? "network" : "doc")
                .font(.system(size: 10)).foregroundStyle(.secondary).frame(width: 14)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.pattern).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).lineLimit(2)
                Text("\((entry.process as NSString).lastPathComponent) · seen \(entry.count)× · last \(entry.lastSeen.formatted(.relative(presentation: .named)))"
                     + (entry.note.map { " · \($0)" } ?? ""))
                    .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            if entry.risk == .high {
                Text("High risk").font(.system(size: 10, weight: .semibold)).foregroundStyle(.orange)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Capsule().fill(Color.orange.opacity(0.14)))
            }
        }
        .help(entry.process)
    }
}
