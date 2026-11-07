import SwiftUI

// MARK: - Views

/// A tag on the launch row: "🔥 380% · 2.1 GB · 12 min" while heavy, "ended · peak 240%" after (tinted,
/// like a Finder tag, not a solid pill).
struct VitalBadgeView: View {
    let badge: ProcessVitals.Badge
    var compact = false

    var body: some View {
        switch badge {
        case .heavy(let cpu, let mem, let running, let cpuHeavy, _):
            Label {
                Text(compact ? (cpuHeavy ? "\(Int(cpu))%" : ProcessVitals.memory(mem))
                     : [cpuHeavy ? "\(Int(cpu))% CPU" : nil, ProcessVitals.memory(mem),
                        running > 0 ? ProcessVitals.duration(running) : nil].compactMap { $0 }.joined(separator: " · "))
                    .monospacedDigit()
            } icon: {
                Image(systemName: cpuHeavy ? "flame.fill" : "memorychip.fill").symbolRenderingMode(.hierarchical)
            }
            .labelStyle(.titleAndIcon)
            .font(.system(size: compact ? 10 : 11, weight: .medium))
            .foregroundStyle(Color.orange)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(Color.orange.opacity(0.14)))
            .overlay(Capsule().strokeBorder(Color.orange.opacity(0.35), lineWidth: 0.5))
            .accessibilityLabel("Running heavy: \(Int(cpu)) percent CPU, \(ProcessVitals.memory(mem)) memory")
            .help("Still running and using a lot: \(Int(cpu))% of one CPU core on average over 30 s, "
                  + "\(ProcessVitals.memory(mem)) of memory" + (running > 0 ? ", running for \(ProcessVitals.duration(running))" : ""))
        case .ended(let peakCPU, let peakMem, let ago):
            Label {
                Text(compact ? "ended" : "Ended \(ProcessVitals.duration(ago)) ago · peak \(Int(peakCPU))% · \(ProcessVitals.memory(peakMem))")
                    .monospacedDigit()
            } icon: {
                Image(systemName: "checkmark.circle")
            }
            .labelStyle(.titleAndIcon)
            .font(.system(size: compact ? 10 : 11))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(Capsule().fill(Color.secondary.opacity(0.10)))
        }
    }
}

/// Collapsed or expanded, shared by live and Time Travel.
final class HeavyStripState: ObservableObject {
    @Published var collapsed = false
}

/// Above the events: processes started while watching that run heavy, live or at the playhead. A tinted
/// banner with one row per process (app icon, CPU gauge, memory, running time) and a ⋯ menu.
struct HeavyStrip: View {
    let context: HeavyContext
    @ObservedObject var state: HeavyStripState
    let onlyThese: Bool
    let toggleOnlyThese: () -> Void
    let actions: HUDActions

    var body: some View {
        let heavy = context.entries.sorted { $0.cpu > $1.cpu }
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "flame.fill")
                    .font(.system(size: 16))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text(context.live ? "Still running heavy" : "Running heavy at \(context.at.formatted(date: .omitted, time: .standard))")
                        .font(.headline)
                    Text("\(heavy.count) process\(heavy.count == 1 ? "" : "es") started while Hostwatch was watching")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                if state.collapsed {
                    // One line: the busiest names, so collapsing never hides that something is there.
                    Text(heavy.prefix(3).map { "\($0.name) \($0.cpuHeavy ? "\(Int($0.cpu))%" : ProcessVitals.memory($0.mem))" }
                        .joined(separator: "  ·  "))
                        .font(.callout.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 8)
                Toggle(isOn: Binding(get: { onlyThese }, set: { _ in toggleOnlyThese() })) {
                    Label("Only These", systemImage: "line.3.horizontal.decrease")
                }
                .toggleStyle(.button)
                .buttonStyle(.glass)
                .help(onlyThese ? "Show all events again" : "Show only these processes' events")
                Button {
                    withAnimation(.snappy) { state.collapsed.toggle() }
                } label: {
                    Image(systemName: "chevron.down").rotationEffect(.degrees(state.collapsed ? -90 : 0))
                }
                .buttonStyle(.glass)
                .help(state.collapsed ? "Show details" : "Collapse")
            }
            .controlSize(.small)
            if !state.collapsed {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                    ForEach(heavy.prefix(5)) { h in HeavyRow(h: h, context: context, actions: actions) }
                }
                if heavy.count > 5 {
                    Text("and \(heavy.count - 5) more").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(14)
        // Content, not a control: a tinted grouped background (Liquid Glass is for the control layer).
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.orange.opacity(0.07)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.orange.opacity(0.22), lineWidth: 0.5))
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

private struct HeavyRow: View {
    let h: HeavyProcess
    let context: HeavyContext
    let actions: HUDActions

    private var event: ActivityEvent { context.events(h.pid) ?? h.launchEvent }

    var body: some View {
        GridRow(alignment: .center) {
            HStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: h.path))
                    .resizable().frame(width: 20, height: 20)
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 6) {
                        Text(h.name).font(.body.weight(.semibold))
                        if h.untrusted {
                            Text("Untrusted").font(.caption2.weight(.semibold)).foregroundStyle(.red)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Color.red.opacity(0.12)))
                                .help("Unsigned, ad-hoc, quarantined or from a download/temp folder")
                        }
                    }
                    Text("pid " + String(h.pid) + (h.parent.isEmpty ? "" : " · from " + (h.parent as NSString).lastPathComponent))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            // One full core is a quarter of the gauge: 400% fills it.
            Gauge(value: min(h.cpu, 400), in: 0...400) { EmptyView() }
                .gaugeStyle(.accessoryLinearCapacity)
                .tint(h.cpuHeavy ? Color.orange : Color.secondary)
                .frame(width: 90)
                .help("\(Int(h.cpu))% of one CPU core (400% fills the bar)")
            Text("\(Int(h.cpu))%").font(.callout.monospacedDigit()).foregroundStyle(h.cpuHeavy ? .primary : .secondary)
                .gridColumnAlignment(.trailing)
            Label(ProcessVitals.memory(h.mem), systemImage: "memorychip")
                .font(.callout.monospacedDigit()).foregroundStyle(h.memHeavy ? .primary : .secondary)
            Text(context.running(h) > 0 ? ProcessVitals.duration(context.running(h)) : "")
                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Button { actions.askAI(event) } label: { Image(systemName: "sparkles") }
                    .buttonStyle(.borderless)
                    .help("Ask AI about \(h.name)")
                Menu {
                    Button("Ask AI About \(h.name)…") { actions.askAI(event) }
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: h.path)]) }
                    Button("Copy Path") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(h.path, forType: .string)
                    }
                } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.button).buttonStyle(.borderless).menuIndicator(.hidden).fixedSize()
            }
            .gridColumnAlignment(.trailing)
        }
    }
}
