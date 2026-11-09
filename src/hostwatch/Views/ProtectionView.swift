import AppKit
import SwiftUI

/// Rules ▸ Protection: a mode per area, the protected-files cards, and what the rehearsal found, to decide before
/// anything is stopped. source: docs/adr/0011-protection.md
struct ProtectionView: View {
    @ObservedObject var protection: ProtectionMonitor
    /// Marks patterns: Allow (Safe) or Block (Dangerous), as everywhere else.
    let mark: ([String], SignatureStatus) -> Void

    private static let limit = 40
    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .abbreviated; f.dateTimeStyle = .named; return f
    }()

    var body: some View {
        let _ = protection.revision
        VStack(alignment: .leading, spacing: 22) {
            modes
            files
            findings
        }
    }

    // MARK: Modes

    private var modes: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Protection").font(.headline)
                Spacer()
                if protection.paused, let until = protection.pausedUntil {
                    Text("Paused until \(until.formatted(date: .omitted, time: .shortened))").foregroundStyle(.orange)
                    Button("Resume") { protection.resume() }
                } else {
                    Button("Pause for 15 Minutes") { protection.pause(minutes: 15) }
                }
            }
            ForEach(ProtectionArea.allCases, id: \.self) { area in modeRow(area) }
            Text(protection.enforcer.text + " Watching since \(protection.since.formatted(date: .abbreviated, time: .omitted)).")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.45)))
    }

    private func modeRow(_ area: ProtectionArea) -> some View {
        HStack(spacing: 10) {
            KindTile(kind: area == .launches ? .exec : .file)
            Text(area.title).fontWeight(.medium).frame(width: 80, alignment: .leading)
            Picker(area.title, selection: Binding(get: { protection.mode(area) }, set: { protection.setMode($0, for: area) })) {
                ForEach(ProtectionMode.allCases, id: \.self) { mode in
                    Text(mode.short).tag(mode)
                        .selectionDisabled(mode.enforces && !protection.enforcer.canEnforce)
                }
            }
            .labelsHidden()
            .fixedSize()
            .help(ProtectionMode.allCases.map(\.title).joined(separator: "\n"))
            Text(todayText(area)).foregroundStyle(.secondary).monospacedDigit()
            Spacer()
        }
    }

    private func todayText(_ area: ProtectionArea) -> String {
        guard protection.mode(area) != .off else { return "" }
        let stop = protection.count(area, .block), ask = protection.count(area, .ask)
        let verb = protection.mode(area).enforces && protection.enforcer.canEnforce ? "stopped" : "would stop"
        return "Today: \(verb) \(stop) · would ask \(ask)"
    }

    // MARK: Protected files

    private var files: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Protected files").font(.headline)
            Text("Programs that aren't expected in these places are asked about, or blocked. Allow one by marking its "
                 + "pattern Safe, here or in Patterns.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(ProtectedGroup.all) { group in card(group) }
        }
    }

    private func card(_ group: ProtectedGroup) -> some View {
        let setting = protection.groups[group.id] ?? ProtectedGroupSetting()
        let hits = protection.findings(group: group.id).reduce(0) { $0 + $1.count }
        return HStack(spacing: 10) {
            Image(systemName: group.symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.title).fontWeight(.medium)
                Text("Expected: \(group.expected)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if hits > 0 { Text("\(hits)×").foregroundStyle(.secondary).monospacedDigit().help("Found by the rehearsal") }
            Picker("Others", selection: Binding(get: { setting.others }, set: { v in
                var s = setting; s.others = v; protection.groups[group.id] = s
            })) {
                Text("Others: Ask").tag(ProtectionVerdict.ask)
                Text("Others: Block").tag(ProtectionVerdict.block)
            }
            .labelsHidden().fixedSize().disabled(!setting.on)
            Toggle("", isOn: Binding(get: { setting.on }, set: { on in
                var s = setting; s.on = on; protection.groups[group.id] = s
            }))
            .labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.quaternary.opacity(0.35)))
    }

    // MARK: Findings

    private var findings: some View {
        let all = protection.findings.values.sorted {
            ($0.verdict == .block ? 0 : 1, -$0.count) < ($1.verdict == .block ? 0 : 1, -$1.count)
        }
        return VStack(alignment: .leading, spacing: 8) {
            Text("What protection found").font(.headline)
            if all.isEmpty {
                Text("Nothing yet. What would be stopped or asked about appears here, so you can decide first.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Allow marks the pattern Safe. Block marks it Dangerous. Either way it leaves this list.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(all.prefix(Self.limit)) { f in finding(f) }
                if all.count > Self.limit {
                    Text("and \(all.count - Self.limit) more").font(.caption).foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func finding(_ f: ProtectionFinding) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: ProcessIcons.icon(f.program)).resizable().frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(f.name).fontWeight(.semibold)
                    Text(f.enforced ? "Stopped" : f.verdict == .block ? "Would stop" : "Would ask")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(f.verdict == .block ? Color.red : Color.orange)
                    Text("\(f.count)× · \(Self.relative.localizedString(for: f.lastSeen, relativeTo: Date()))")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Text(f.pattern).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).help(f.pattern)
                Text(f.reason).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Allow") { mark([f.patternKey], .safe) }
            Button("Block") { mark([f.patternKey], .dangerous) }
            Button { protection.forget([f.id]) } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless).help("Remove from this list without deciding")
        }
        .controlSize(.small)
        .padding(.vertical, 4)
    }
}
