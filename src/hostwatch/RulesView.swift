import SwiftUI

/// Rules tab, three views of one idea: every pattern is decided by you, a rule, the baseline (code
/// signatures) or an AI suggestion you accepted. *Needs You* is what's still New, *Rules* is what decides
/// automatically, *Decided* shows who decided what (AI apart from you).
enum RulesSegment: Int, CaseIterable { case needsYou, rules, decided }

final class RulesTabState: ObservableObject {
    @Published var segment: RulesSegment = .needsYou
    var chosen = false
}

struct RulesView: View {
    @ObservedObject var book: RuleBook
    @ObservedObject var signatures: SignatureStore
    @ObservedObject var classifier: PatternClassifier
    @ObservedObject var baseline: BaselineLearner
    @ObservedObject var tab: RulesTabState
    /// Opens Patterns filtered to an app.
    var showPatterns: (String) -> Void = { _ in }
    /// Opens Patterns showing exactly these patterns.
    var showKeys: (String, [String]) -> Void = { _, _ in }

    private var review: [BaselineReport.Group] { baseline.report?.review ?? [] }
    private var waiting: Int { review.count + book.proposals.count }

    var body: some View {
        let _ = signatures.revision
        VStack(spacing: 0) {
            Picker("", selection: Binding(get: { tab.segment }, set: { tab.segment = $0; tab.chosen = true })) {
                Text(waiting > 0 ? "Needs You  \(waiting)" : "Needs You").tag(RulesSegment.needsYou)
                Text("Rules  \(baseline.rules.filter { !$0.paused }.count + book.activeCount)").tag(RulesSegment.rules)
                Text("Decisions").tag(RulesSegment.decided)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .padding(.vertical, 10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    switch tab.segment {
                    case .needsYou: needsYou
                    case .rules: baselineSection; learnedSection
                    case .decided: DecidedView(signatures: signatures, showKeys: showKeys)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack {
                Text(footer).lineLimit(1)
                Spacer()
                Text("\(book.yourDecisions.count) of your decisions").monospacedDigit()
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .onAppear {
            if !tab.chosen { tab.segment = waiting > 0 ? .needsYou : .rules }
        }
    }

    private var footer: String {
        if !baseline.message.isEmpty { return baseline.message }
        if !classifier.lastMessage.isEmpty { return classifier.lastMessage }
        if !book.message.isEmpty { return book.message }
        return "Your own decisions always win over any rule or AI."
    }

    // MARK: Needs You

    @ViewBuilder private var needsYou: some View {
        let count = review.reduce(0) { $0 + $1.keys.count }
        section("Needs You", subtitle: review.isEmpty ? "" : "\(review.count) app\(review.count == 1 ? "" : "s") · \(count) pattern\(count == 1 ? "" : "s")") {
            HStack(spacing: 10) {
                Text("New patterns, by app. Trust an app you know (a rule is added for it), accept the AI's "
                     + "suggestion, or Dismiss to hide it here (its patterns stay New). Interpreters and shells "
                     + "like python or bash aren't listed: they run any script, so they can't be trusted.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Spacer()
                if classifier.running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { classifier.cancel() }.buttonStyle(.glass)
                } else {
                    Button { classifier.classifyNow() } label: { Label("Ask AI for Suggestions", systemImage: "sparkles") }
                        .buttonStyle(.glass)
                        .disabled(review.isEmpty)
                        .help("AI suggests a status for up to \(classifier.batchSize) New patterns (\(classifier.engine.title)). "
                              + "Nothing changes until you accept.")
                }
            }
            .controlSize(.small)
        }
        if book.running {
            RuleProgressCard(book: book)
        } else if let result = book.lastResult {
            HStack(spacing: 8) {
                Image(systemName: book.proposals.isEmpty ? "info.circle" : "checkmark.circle.fill")
                    .foregroundStyle(book.proposals.isEmpty ? Color.secondary : Color.green)
                Text("Suggest Rules: " + result).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button { book.lastResult = nil } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).foregroundStyle(.secondary).help("Close")
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.secondary.opacity(0.07)))
        }
        if !book.proposals.isEmpty {
            section("Rule proposals", subtitle: "from Claude, checked by Hostwatch") {
                ForEach(book.proposals) { ProposalCard(proposal: $0, book: book) }
            }
        }
        if review.isEmpty && book.proposals.isEmpty && !book.running {
            VStack(spacing: 8) {
                Image(systemName: "checkmark.circle").font(.system(size: 34)).foregroundStyle(.green)
                Text("Nothing needs you").font(.headline)
                Text("\(signatures.allEntries.count - signatures.count(.unclassified)) patterns are decided. "
                     + "New ones appear here.")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 40)
        } else if !review.isEmpty {
            VStack(spacing: 0) {
                ForEach(Array(review.enumerated()), id: \.element.id) { i, g in
                    if i > 0 { Divider() }
                    ReviewRow(group: g, baseline: baseline, signatures: signatures, showKeys: showKeys)
                }
            }
            .padding(.horizontal, 12)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.orange.opacity(0.05)))
        }
    }

    // MARK: Rules

    private var baselineSection: some View {
        section("Baseline rules", subtitle: "from code signatures, on this Mac, no AI") {
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
            Text("One rule per app (its developer's signature must match), plus one for macOS services. A rule "
                 + "trusts the app's normal-risk activity, now and later. Never high-risk, unsigned or downloaded "
                 + "code, interpreters or shells; sensitive places only for apps you trusted yourself.")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !baseline.rules.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(baseline.rules.enumerated()), id: \.element.id) { i, rule in
                        if i > 0 { Divider() }
                        BaselineRuleRow(rule: rule, baseline: baseline, signatures: signatures, showKeys: showKeys)
                    }
                }
                .padding(.horizontal, 12)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.secondary.opacity(0.06)))
            }
        }
    }

    private var learnedSection: some View {
        section("Learned rules", subtitle: "\(book.activeCount) active · from your decisions") {
            HStack(spacing: 10) {
                Text("Claude turns patterns you marked yourself into rules; Hostwatch checks each one (never a "
                     + "blanket trust of python, bash or node); you approve it in Needs You.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Spacer()
                if book.running {
                    ProgressView().controlSize(.small)
                    Text("Claude is working… proposals appear in Needs You").font(.system(size: 12)).foregroundStyle(.secondary)
                    Button("Cancel") { book.cancel() }.buttonStyle(.glass)
                } else {
                    Button { book.suggest(); tab.segment = .needsYou } label: { Label("Suggest Rules…", systemImage: "sparkles") }
                        .buttonStyle(.glass)
                        .disabled(classifier.engine == .onDevice || book.yourDecisions.count < 2)
                        .help(classifier.engine == .onDevice
                              ? "Needs Claude: rule learning is beyond the on-device model (Settings ▸ AI)."
                              : "Sends your decisions (patterns you marked, secrets masked) to Claude for rule proposals.")
                }
            }
            .controlSize(.small)
            if book.rules.isEmpty {
                let mine = book.yourDecisions.count
                Text(mine >= 2
                     ? "No learned rules yet. You've decided \(mine) patterns yourself: Suggest Rules… can turn them into a few "
                       + "rules that also cover new ones."
                     : "No learned rules yet. Mark at least two patterns Safe or Suspicious yourself, then ask for suggestions.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if classifier.engine == .onDevice {
                    Text("Suggest Rules needs Claude: choose an engine with Claude in Settings ▸ AI.")
                        .font(.system(size: 12)).foregroundStyle(.orange)
                }
            }
            ForEach(book.rules) { RuleRow(rule: $0, book: book, signatures: signatures, keys: matchingKeys($0), showKeys: showKeys) }
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

    private func matchingKeys(_ rule: LearnedRule) -> [String] {
        signatures.allEntries.filter { $0.source == "rule" && $0.note == rule.name && rule.matches($0) }.map(\.id)
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
    let signatures: SignatureStore
    let keys: [String]
    let showKeys: (String, [String]) -> Void
    @StateObject private var expand = ExpandState()
    private var matches: Int { keys.count }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ActionPill(status: rule.action)
            VStack(alignment: .leading, spacing: 3) {
                Text(rule.name).fontWeight(.semibold)
                Text(rule.matcherText).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                if let why = rule.pausedReason {
                    Label("Paused: \(why)", systemImage: "pause.circle").foregroundStyle(.orange).font(.system(size: 11))
                } else {
                    HStack(spacing: 6) {
                        Label("Check passes", systemImage: "checkmark.seal").foregroundStyle(.green)
                        PatternsToggle(count: matches, expand: expand)
                    }
                    .font(.system(size: 11))
                }
                if expand.open {
                    InlinePatterns(keys: keys, signatures: signatures) { showKeys(rule.name, keys) }
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
    let baseline: BaselineLearner
    let signatures: SignatureStore
    let showKeys: (String, [String]) -> Void
    @StateObject private var expand = ExpandState()

    var body: some View {
        let keys = baseline.keys(rule)
        let count = keys.count
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: rule.id == "system" ? "apple.logo" : "app.badge.checkmark")
                .frame(width: 18)
                .padding(.top, 1)
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
                if rule.paused {
                    Text("\(rule.signer) · paused, its patterns are New again")
                        .font(.system(size: 11)).foregroundStyle(.orange)
                } else {
                    HStack(spacing: 6) {
                        Text("\(rule.signer) · trusts").foregroundStyle(.secondary)
                        PatternsToggle(count: count, expand: expand)
                    }
                    .font(.system(size: 11))
                }
                if expand.open {
                    InlinePatterns(keys: keys, signatures: signatures) { showKeys(rule.name, keys) }
                }
            }
            Spacer()
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

/// "12 patterns ›": shows or hides the row's patterns in place.
private struct PatternsToggle: View {
    let count: Int
    @ObservedObject var expand: ExpandState

    var body: some View {
        Button {
            withAnimation(.snappy(duration: 0.2)) { expand.open.toggle() }
        } label: {
            HStack(spacing: 3) {
                Text("\(count) pattern\(count == 1 ? "" : "s")").monospacedDigit()
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .rotationEffect(.degrees(expand.open ? 90 : 0))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .font(.system(size: 11)).foregroundStyle(.secondary)
        .disabled(count == 0)
        .help(expand.open ? "Hide the patterns" : "Show the patterns here")
    }
}

/// A row's patterns, listed in place (high risk first, then most recent).
private struct InlinePatterns: View {
    let entries: [SignatureEntry]
    let openAll: () -> Void
    static let limit = 40

    init(keys: [String], signatures: SignatureStore, openAll: @escaping () -> Void) {
        entries = keys.compactMap { signatures.entry($0) }
            .sorted { $0.risk != $1.risk ? $0.risk > $1.risk : $0.lastSeen > $1.lastSeen }
        self.openAll = openAll
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(entries.prefix(Self.limit)) { ReviewPatternLine(entry: $0) }
            HStack(spacing: 6) {
                if entries.count > Self.limit {
                    Text("and \(entries.count - Self.limit) more").foregroundStyle(.tertiary)
                }
                Button("Open in Patterns", action: openAll)
                    .buttonStyle(.link)
            }
            .font(.system(size: 11))
            .padding(.top, 2)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.secondary.opacity(0.07)))
        .padding(.vertical, 3)
    }
}

private struct ReviewRow: View {
    let group: BaselineReport.Group
    let baseline: BaselineLearner
    let signatures: SignatureStore
    let showKeys: (String, [String]) -> Void
    @StateObject private var expand = ExpandState()

    /// "Safe ×3, Suspicious ×1 · on-device AI", or nil when there's no suggestion.
    private var suggestionText: String? {
        let entries = baseline.entries(group)
        let suggestions = entries.compactMap(\.suggestion)
        guard !suggestions.isEmpty else { return nil }
        let byStatus = Dictionary(grouping: suggestions, by: \.status)
        let parts = [SignatureStatus.dangerous, .suspicious, .safe].compactMap { s in
            byStatus[s].map { "\(s.title)\($0.count > 1 || entries.count > 1 ? " ×\($0.count)" : "")" }
        }
        let engines = Set(suggestions.map(\.engineName)).sorted().joined(separator: " and ")
        let missing = entries.count - suggestions.count
        return parts.joined(separator: ", ") + " · \(engines)" + (missing > 0 ? " · \(missing) without a suggestion" : "")
    }
    private var anyCode: Bool { baseline.runsAnyCode(group) }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "questionmark.app")
                .frame(width: 18)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(group.app).fontWeight(.semibold)
                    PatternsToggle(count: group.keys.count, expand: expand)
                }
                ForEach(group.reasons.prefix(4), id: \.self) { reason in
                    Text("· " + reason).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                }
                if group.reasons.count > 4 {
                    Text("· and \(group.reasons.count - 4) more").font(.system(size: 11)).foregroundStyle(.tertiary)
                }
                if let text = suggestionText {
                    HStack(spacing: 4) {
                        Image(systemName: text.contains("Claude") ? "asterisk" : "apple.intelligence")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(text.contains("Claude") ? Color.claude : Color.secondary)
                        Text("AI suggests: " + text).foregroundStyle(.secondary)
                    }
                    .font(.system(size: 11)).lineLimit(1)
                }
                if expand.open {
                    InlinePatterns(keys: group.keys, signatures: signatures) { showKeys(group.app, group.keys) }
                }
            }
            Spacer()
            if suggestionText != nil {
                Button("Accept") { Task { await baseline.acceptSuggestions(group) } }.buttonStyle(.glass)
                    .help("Your decision: apply the AI's suggestions to these patterns")
            }
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
            if let sug = entry.suggestion {
                HStack(spacing: 3) {
                    Image(systemName: sug.source == "claude" ? "asterisk" : "apple.intelligence")
                        .foregroundStyle(sug.source == "claude" ? Color.claude : Color.secondary)
                    Text(sug.status.title)
                }
                .font(.system(size: 10, weight: .semibold))
                .help("Suggested by \(sug.engineName)" + (sug.note.map { ": \($0)" } ?? ""))
            }
            if entry.risk == .high {
                Text("High risk").font(.system(size: 10, weight: .semibold)).foregroundStyle(.orange)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Capsule().fill(Color.orange.opacity(0.14)))
            }
        }
        .help(entry.process)
    }
}

/// Who decided what: you, AI, your rules, the baseline. Grouped by app; AI and your decisions can be undone.
private struct DecidedView: View {
    @ObservedObject var signatures: SignatureStore
    let showKeys: (String, [String]) -> Void

    struct Group: Identifiable {
        let app: String
        var keys: [String]
        var statuses: [SignatureStatus: Int]
        var id: String { app }
    }

    enum Who: String, CaseIterable {
        case ai = "Patterns AI decided", you = "Patterns you decided", rules = "Patterns decided by learned rules",
             baseline = "Patterns decided by baseline rules"

        var detail: String {
            switch self {
            case .ai: return "one by one: on-device AI or Claude, accepted by you or automatically"
            case .you: return "one by one, each covers only itself (and apps you trusted)"
            case .rules: return "rules learned from your decisions"
            case .baseline: return "code signatures, no AI"
            }
        }
        var symbol: String {
            switch self { case .ai: return "asterisk"; case .you: return "person.fill"; case .rules: return "checklist"; case .baseline: return "checkmark.shield" }
        }
        var tint: Color {
            switch self { case .ai: return .claude; case .you: return .blue; case .rules: return .teal; case .baseline: return .green }
        }

        static func of(_ e: SignatureEntry) -> Who? {
            guard e.status != .unclassified else { return nil }
            switch e.source {
            case "claude", "on-device": return .ai
            case "you": return .you
            case "rule": return .rules
            case "baseline": return .baseline
            default: return nil   // "auto": routine activity, decided locally
            }
        }
    }

    var body: some View {
        let _ = signatures.revision
        let groups = grouped()
        VStack(alignment: .leading, spacing: 22) {
            ForEach(Who.allCases, id: \.self) { who in
                let list = groups[who] ?? []
                let total = list.reduce(0) { $0 + $1.keys.count }
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Label { Text(who.rawValue) } icon: { Image(systemName: who.symbol).foregroundStyle(who.tint) }
                            .font(.system(size: 15, weight: .semibold))
                        Text("\(total) pattern\(total == 1 ? "" : "s") · \(who.detail)").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    if list.isEmpty {
                        Text("None.").font(.system(size: 12)).foregroundStyle(.tertiary)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(list.prefix(who == .baseline ? 12 : 50).enumerated()), id: \.element.id) { i, g in
                                if i > 0 { Divider() }
                                DecidedRow(group: g, who: who, signatures: signatures, showKeys: showKeys)
                            }
                            if list.count > (who == .baseline ? 12 : 50) {
                                Text("and \(list.count - (who == .baseline ? 12 : 50)) more apps: see Patterns, Decided By column")
                                    .font(.system(size: 11)).foregroundStyle(.tertiary).padding(.vertical, 6)
                            }
                        }
                        .padding(.horizontal, 12)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(who.tint.opacity(0.05)))
                    }
                }
            }
        }
    }

    private func grouped() -> [Who: [Group]] {
        var out: [Who: [String: Group]] = [:]
        for e in signatures.allEntries {
            guard let who = Who.of(e) else { continue }
            let path = SignatureStore.subjectPath(e)
            let app = BaselinePolicy.appName(path.isEmpty ? e.process : path)
            var g = out[who]?[app] ?? Group(app: app, keys: [], statuses: [:])
            g.keys.append(e.id)
            g.statuses[e.status, default: 0] += 1
            out[who, default: [:]][app] = g
        }
        return out.mapValues { $0.values.sorted { $0.keys.count != $1.keys.count ? $0.keys.count > $1.keys.count : $0.app < $1.app } }
    }
}

private struct DecidedRow: View {
    let group: DecidedView.Group
    let who: DecidedView.Who
    let signatures: SignatureStore
    let showKeys: (String, [String]) -> Void
    @StateObject private var expand = ExpandState()

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(group.app).fontWeight(.semibold)
                    Text([SignatureStatus.dangerous, .suspicious, .safe].compactMap { s in
                        group.statuses[s].map { "\($0) \(s.title.lowercased())" } }.joined(separator: " · "))
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    PatternsToggle(count: group.keys.count, expand: expand)
                }
                if expand.open {
                    InlinePatterns(keys: group.keys, signatures: signatures) {
                        showKeys("\(group.app) · \(who.rawValue.lowercased())", group.keys)
                    }
                }
            }
            Spacer()
            if who == .ai || who == .you {
                Button("Undo") { signatures.set(.unclassified, keys: group.keys) }.buttonStyle(.glass)
                    .help("Put these \(group.keys.count) patterns back to New (they appear in Needs You)")
            }
        }
        .controlSize(.small)
        .font(.system(size: 12))
        .padding(.vertical, 6)
    }
}

/// "Claude is suggesting rules from your 214 decisions… 0:12" with Cancel, while Suggest Rules runs.
private struct RuleProgressCard: View {
    @ObservedObject var book: RuleBook

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            ProgressView().controlSize(.regular)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text("Claude is suggesting rules from your \(book.sentDecisions) decisions…")
                        .font(.system(size: 13, weight: .semibold))
                    if let start = book.startedAt {
                        TimelineView(.periodic(from: start, by: 1)) { context in
                            let s = max(0, Int(context.date.timeIntervalSince(start)))
                            Text(String(format: "%d:%02d", s / 60, s % 60))
                                .font(.system(size: 12).monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                }
                Text("Proposals appear here when it's done, usually in 10–30 seconds. Only patterns you decided "
                     + "are sent, with secrets masked.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Cancel") { book.cancel() }.buttonStyle(.glass).controlSize(.small)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.accentColor.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.accentColor.opacity(0.25)))
    }
}
