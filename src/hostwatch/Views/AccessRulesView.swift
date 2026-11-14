import AppKit
import SwiftUI

/// Protection ▸ Allow and Block: your own rules, a folder or file, or a network destination, for one program or any
/// program. Two glass sections, each with its rules and Add Rule. The form says why a rule can't be added.
struct AccessRulesView: View {
    @ObservedObject var protection: ProtectionMonitor
    @StateObject private var form = AccessRuleForm()

    var body: some View {
        GlassEffectContainer(spacing: 12) {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Allow and Block").font(.headline)
                    Text("Your own rules come before everything automatic: patterns, AI and threat lists. The most specific "
                         + "rule wins (one program over any program, a deeper folder over its parent), and Block when two are "
                         + "equally specific. Block acts in Ask and Strict and shows as \u{201C}would block\u{201D} in Watch.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                section(.files, title: "Files and folders", symbol: "folder",
                        empty: "No rules yet. Block a folder for every program, or allow one program into a protected place.")
                section(.network, title: "Network", symbol: "network",
                        empty: "No rules yet. Block a domain for every program, or always allow one program to a server.")
            }
        }
    }

    private func section(_ kind: AccessRule.Kind, title: String, symbol: String, empty: String) -> some View {
        let rules = protection.accessRules.filter { $0.kind == kind }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(title, systemImage: symbol).font(.subheadline.weight(.semibold))
                Spacer()
                Button { form.start(kind) } label: { Label("Add Rule…", systemImage: "plus") }
                    .buttonStyle(.glass).controlSize(.small)
            }
            if form.kind == kind { AccessRuleEditor(form: form, protection: protection) }
            if rules.isEmpty && form.kind != kind {
                Text(empty).font(.callout).foregroundStyle(.secondary)
            }
            ForEach(rules) { rule in row(rule) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .protectionGlass(16)
    }

    private func row(_ rule: AccessRule) -> some View {
        HStack(spacing: 10) {
            Image(systemName: rule.action == .allow ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(rule.action == .allow ? Color.green : Color.red)
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.kind == .files ? AccessRules.display(rule.target) : rule.target)
                    .font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Text("\(rule.action == .allow ? "Allow" : "Block") · \(rule.programName)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { rule.on }, set: { on in update(rule.id) { $0.on = on } }))
                .labelsHidden().toggleStyle(.switch).controlSize(.small)
            Button { protection.accessRules.removeAll { $0.id == rule.id } } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove this rule")
        }
        .opacity(rule.on ? 1 : 0.55)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(rule.sentence)
    }

    private func update(_ id: String, _ change: (inout AccessRule) -> Void) {
        if let i = protection.accessRules.firstIndex(where: { $0.id == id }) { change(&protection.accessRules[i]) }
    }
}

/// The rule being written (no @State macro with the command line tools).
@MainActor
final class AccessRuleForm: ObservableObject {
    @Published var kind: AccessRule.Kind?
    @Published var action: AccessRule.Action = .block
    @Published var target = ""
    @Published var program: String?

    func start(_ kind: AccessRule.Kind) {
        self.kind = kind
        action = .block
        target = ""
        program = nil
    }

    var rule: AccessRule? {
        guard let kind else { return nil }
        return AccessRule(kind: kind, target: target.trimmingCharacters(in: .whitespaces), program: program, action: action)
    }
}

private struct AccessRuleEditor: View {
    @ObservedObject var form: AccessRuleForm
    @ObservedObject var protection: ProtectionMonitor

    private var problem: String? {
        guard let rule = form.rule else { return nil }
        let sensitive = ProtectedGroup.all.flatMap { $0.prefixes(home: NSHomeDirectory()) }
        return AccessRules.refusal(rule, sensitive: sensitive)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Action", selection: $form.action) {
                Text("Block").tag(AccessRule.Action.block)
                Text("Allow").tag(AccessRule.Action.allow)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            HStack {
                TextField(form.kind == .files ? "/Users/you/Documents/contracts" : "example.com or 203.0.113.9", text: $form.target)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                if form.kind == .files {
                    Button("Choose…") { chooseTarget() }.controlSize(.small)
                }
            }
            HStack(spacing: 8) {
                Text("For").foregroundStyle(.secondary)
                Menu(form.program.map { AccessRule(kind: .files, target: "", program: $0, action: .block).programName } ?? "Any program") {
                    Button("Any program") { form.program = nil }
                    Button("Choose a Program…") { chooseProgram() }
                }
                .fixedSize()
                Spacer()
                Button("Cancel") { form.kind = nil }.controlSize(.small)
                Button("Add Rule") {
                    if let rule = form.rule { protection.accessRules.append(rule) }
                    form.kind = nil
                }
                .buttonStyle(.glassProminent).controlSize(.small)
                .disabled(problem != nil)
            }
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.4)))
    }

    private func chooseTarget() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose the folder or file this rule is about."
        if panel.runModal() == .OK, let url = panel.url { form.target = url.standardizedFileURL.path }
    }

    private func chooseProgram() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.treatsFilePackagesAsDirectories = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.message = "Choose an app, or a command-line program. An app covers every program inside it."
        if panel.runModal() == .OK, let url = panel.url { form.program = url.standardizedFileURL.path }
    }
}
