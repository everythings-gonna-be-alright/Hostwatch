import AppKit
import SwiftUI

/// Rules ▸ Protection ▸ Overview: the state at a glance (a shield, a sentence, the pause), a card per area with its
/// four modes in view and today's numbers, then how protection acts and where to go next. Built like a System
/// Settings pane: one decision per card, the explanation next to the control it explains.
struct ProtectionOverview: View {
    @ObservedObject var protection: ProtectionMonitor
    var firewall: FirewallMonitor? = nil
    let go: (RulesSegment) -> Void

    var body: some View {
        let _ = protection.revision
        VStack(alignment: .leading, spacing: 18) {
            header
            HStack(alignment: .top, spacing: 14) {
                ForEach(ProtectionArea.allCases, id: \.self) { area in AreaCard(protection: protection, area: area, go: go) }
                if let firewall { FirewallCard(firewall: firewall, go: go) }
            }
            .fixedSize(horizontal: false, vertical: true)         // both cards as tall as the taller one
            details
        }
    }

    // MARK: Header

    private enum State { case off, rehearsing, protecting, paused }

    private var state: State {
        if protection.paused { return .paused }
        let modes = ProtectionArea.allCases.map(protection.mode)
        let net = firewall?.mode ?? .off
        if modes.contains(where: \.enforces) || net == .ask || net == .strict { return .protecting }
        return modes.contains(where: { $0 != .off }) || net == .watch ? .rehearsing : .off
    }

    private var tint: Color {
        switch state {
        case .off: .secondary
        case .rehearsing: .purple
        case .protecting: .green
        case .paused: .orange
        }
    }

    private var title: String {
        switch state {
        case .off: "Protection is off"
        case .rehearsing: "Rehearsing"
        case .protecting: "Protecting"
        case .paused: "Paused until \(protection.pausedUntil?.formatted(date: .omitted, time: .shortened) ?? "")"
        }
    }

    private var sentence: String {
        let stopped = ProtectionArea.allCases.reduce(0) { $0 + protection.count($1, .block) }
        switch state {
        case .off: return "Nothing is checked. Turn on Watch to see what protection would stop, without stopping anything."
        case .rehearsing:
            return "Nothing is stopped. Today \(stopped) would have been. Decide those in Found, then turn on Ask."
        case .protecting: return "Today \(stopped) stopped. What isn't decided yet is asked about or watched, as each area says."
        case .paused: return "Nothing is checked or stopped until then, rehearsal included."
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: state == .paused ? "pause.circle.fill" : state == .off ? "shield.slash" : "checkmark.shield.fill")
                .font(.system(size: 34, weight: .medium))
                .foregroundStyle(tint)
                .symbolRenderingMode(.hierarchical)
                .frame(width: 44)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.title2.weight(.semibold))
                Text(sentence).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            if protection.paused {
                Button("Resume") { protection.resume() }.buttonStyle(.glassProminent)
            } else if state != .off {
                Button("Pause for 15 Minutes") { protection.pause(minutes: 15) }.buttonStyle(.glass)
            }
        }
        .controlSize(.large)
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(tint.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(tint.opacity(0.25), lineWidth: 0.5))
    }

    // MARK: Details

    private var details: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label {
                Text(protection.enforcer.text).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "info.circle")
            }
            .foregroundStyle(.secondary)
            Divider()
            let cards = ProtectedGroup.all.filter { (protection.groups[$0.id] ?? ProtectedGroupSetting()).on }.count
            let yours = protection.customPlaces.filter(\.on).count
            link("lock.doc", "Protected Files and Folders",
                 "\(cards) of \(ProtectedGroup.all.count) groups on" + (yours > 0 ? ", \(yours) of yours" : ""), .protectedFiles)
            link("exclamationmark.shield", "Found", "\(protection.findings.count) to review", .protectionFound)
            Text("Watching since \(protection.since.formatted(date: .abbreviated, time: .omitted))")
                .font(.caption).foregroundStyle(.tertiary)
        }
        .font(.callout)
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.35)))
    }

    private func link(_ symbol: String, _ title: String, _ detail: String, _ page: RulesSegment) -> some View {
        Button { go(page) } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                Text(detail).foregroundStyle(.secondary).monospacedDigit()
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Launches or Files: the four modes as a segmented control, what the chosen one does, and today's numbers.
private struct AreaCard: View {
    @ObservedObject var protection: ProtectionMonitor
    let area: ProtectionArea
    let go: (RulesSegment) -> Void

    private var mode: ProtectionMode { protection.mode(area) }

    /// The chosen mode in one sentence, in this area's words.
    private var explanation: String {
        switch (area, mode) {
        case (.launches, .off): "Launches aren't checked."
        case (.launches, .watch): "Nothing is stopped. Launches that would be are marked in Events."
        case (.launches, .ask): "Stops launches you blocked. Pauses new ones and asks you."
        case (.launches, .strict): "Stops every launch nobody allowed."
        case (.files, .off): "Protected places aren't checked."
        case (.files, .watch): "Nothing is stopped. Programs that would be are marked in Events."
        case (.files, .ask): "Stops programs you blocked. Pauses unexpected ones and asks you."
        case (.files, .strict): "Stops every program not expected in a protected place."
        }
    }

    var body: some View {
        let findings = protection.findings.values.filter { $0.area == area }.count
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                KindTile(kind: area == .launches ? .exec : .file)
                Text(area.title).font(.headline)
            }
            Picker(area.title, selection: Binding(get: { mode }, set: { protection.setMode($0, for: area) })) {
                ForEach(ProtectionMode.allCases, id: \.self) { Text($0.short).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(explanation).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minHeight: 34, alignment: .topLeading)
            if area == .launches, mode == .strict {
                Label("Builds and scripts nobody decided yet are stopped too.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
            if mode != .off {
                HStack(spacing: 24) {
                    number(protection.count(area, .block), mode.enforces ? "stopped today" : "would stop today",
                           tint: protection.count(area, .block) > 0 ? .red : .primary)
                    number(protection.count(area, .ask), mode == .watch ? "would ask today" : "asked today", tint: .primary)
                }
            }
            if findings > 0 {
                Button { go(.protectionFound) } label: {
                    Text("Review \(findings) in Found").font(.callout)
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold))
                }
                .buttonStyle(.link)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.quaternary.opacity(0.4)))
    }

    private func number(_ n: Int, _ label: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(n.formatted()).font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit().foregroundStyle(tint)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Network: the firewall's four modes, in the same card as Launches and Files, with what the chosen one does.
private struct FirewallCard: View {
    @ObservedObject var firewall: FirewallMonitor
    let go: (RulesSegment) -> Void

    private var explanation: String {
        switch firewall.mode {
        case .off: "Connections aren't judged."
        case .watch: "Nothing is blocked. Connections that would be are listed in Network."
        case .ask: "Blocks what you blocked. A new connection waits for your answer."
        case .strict: "Only what's allowed connects."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                KindTile(kind: .net)
                Text("Network").font(.headline)
            }
            Picker("Network", selection: $firewall.mode) {
                ForEach(FirewallMode.allCases, id: \.self) { Text($0.short).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(explanation).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minHeight: 34, alignment: .topLeading)
            if firewall.mode == .ask || firewall.mode == .strict {
                VStack(alignment: .leading, spacing: 1) {
                    Text(firewall.blockedCount.formatted())
                        .font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit()
                        .foregroundStyle(firewall.blockedCount > 0 ? Color.red : Color.primary)
                    Text("blocked since Hostwatch started").font(.caption).foregroundStyle(.secondary)
                }
            }
            Button { go(.firewall) } label: {
                Text("Firewall settings and status").font(.callout)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold))
            }
            .buttonStyle(.link)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.quaternary.opacity(0.4)))
    }
}
