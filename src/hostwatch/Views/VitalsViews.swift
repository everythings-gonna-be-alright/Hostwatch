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
    /// Heavy pids already shown: the card says it once, then Running Now's flame carries it, so a process heavy
    /// for hours doesn't hold 50 points above the list. A pid that calms down and turns heavy again shows again.
    @Published var folded: Set<Int> = []

    func fold(_ pids: Set<Int>, current: Set<Int>) { folded = folded.intersection(current).union(pids) }
}

/// Above the events: processes started while watching that run heavy, live or at the playhead. A tinted
/// banner with one row per process (app icon, CPU gauge, memory, running time) and a ⋯ menu.
struct HeavyStrip: View {
    let context: HeavyContext
    @ObservedObject var state: HeavyStripState
    let onlyThese: Bool
    let toggleOnlyThese: () -> Void
    let actions: HUDActions
    var fold: (() -> Void)? = nil

    /// What is heavy, in words: "Hostwatch is using a lot of CPU and memory", "3 processes are using a lot of CPU".
    /// "using a lot of CPU and memory" (at 14:02 in Time Travel).
    private func doing(_ heavy: [HeavyProcess]) -> String {
        let cpu = heavy.contains(where: \.cpuHeavy), mem = heavy.contains(where: \.memHeavy)
        let what = cpu && mem ? "CPU and memory" : cpu ? "CPU" : "memory"
        return "using a lot of \(what)" + (context.live ? "" : " at \(context.at.formatted(date: .omitted, time: .shortened))")
    }

    private func title(_ heavy: [HeavyProcess]) -> String { "\(heavy.count) processes are " + doing(heavy) }

    var body: some View {
        let heavy = context.entries.sorted { $0.cpu > $1.cpu }
        let single = heavy.count == 1 ? heavy.first : nil
        VStack(alignment: .leading, spacing: 8) {
            // One line: for a single process everything it needs, for several the summary (rows when opened).
            HStack(spacing: 8) {
                if single == nil {
                    Button {
                        withAnimation(.snappy(duration: 0.2)) { state.collapsed.toggle() }
                    } label: {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(state.collapsed ? 0 : 90))
                            .frame(width: 14, height: 14)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(state.collapsed ? "Show the processes" : "Hide the processes")
                }
                Image(systemName: "flame.fill").foregroundStyle(.orange).symbolRenderingMode(.hierarchical)
                if let h = single {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: h.path)).resizable().frame(width: 16, height: 16)
                    Text(h.name).font(.system(size: 12, weight: .semibold)).lineLimit(1)
                    if h.untrusted { UntrustedTag() }
                    Text("is " + doing(heavy)).font(.system(size: 12)).lineLimit(1)
                    Text("·").foregroundStyle(.tertiary)
                    HeavyMetrics(h: h, context: context)
                } else {
                    Text(title(heavy)).font(.system(size: 12, weight: .semibold)).lineLimit(1)
                    if state.collapsed {
                        Text(heavy.prefix(3).map(\.name).joined(separator: ", ") + (heavy.count > 3 ? "…" : ""))
                            .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                Spacer(minLength: 12)
                if let h = single { HeavyActions(h: h, context: context, actions: actions) }
                Toggle(isOn: Binding(get: { onlyThese }, set: { _ in toggleOnlyThese() })) {
                    Label(onlyThese ? "Show All Events" : "Show Only These", systemImage: "line.3.horizontal.decrease")
                }
                .toggleStyle(.button)
                .buttonStyle(.glass)
                .buttonBorderShape(.capsule)
                .controlSize(.small)
                .help(onlyThese ? "Show all events again" : "Show only these processes' events")
                if let fold {
                    Button(action: fold) {
                        Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                            .frame(width: 16, height: 16).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help("Hide. Running Now keeps showing it with a flame.")
                }
            }
            .help(context.live ? "Started while Hostwatch was watching, and still running" : "")
            if single == nil, !state.collapsed {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    ForEach(heavy.prefix(5)) { h in HeavyRow(h: h, context: context, actions: actions) }
                }
                .padding(.leading, 22)
                if heavy.count > 5 {
                    Text("and \(heavy.count - 5) more").font(.caption).foregroundStyle(.secondary).padding(.leading, 22)
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        // Content, not a control: a neutral grouped background, colour only where something is heavy.
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.quaternary.opacity(0.45)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

private struct UntrustedTag: View {
    var body: some View {
        Text("Untrusted").font(.system(size: 10, weight: .semibold)).foregroundStyle(.red)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Capsule().fill(Color.red.opacity(0.12)))
            .overlay(Capsule().strokeBorder(Color.red.opacity(0.35), lineWidth: 0.5))
            .help("Unsigned, ad-hoc, quarantined or from a download or temp folder")
    }
}

/// "CPU ▬▬ 96% · Memory 10 GB · for 6 min", the heavy measure in orange.
private struct HeavyMetrics: View {
    let h: HeavyProcess
    let context: HeavyContext

    var body: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Text("CPU").foregroundStyle(.secondary)
                // One full core is a quarter of the bar: 400% fills it.
                Gauge(value: min(h.cpu, 400), in: 0...400) { EmptyView() }
                    .gaugeStyle(.accessoryLinearCapacity)
                    .tint(h.cpuHeavy ? Color.orange : Color.secondary)
                    .frame(width: 70)
                Text("\(Int(h.cpu))%").monospacedDigit().foregroundStyle(h.cpuHeavy ? .orange : .primary)
            }
            .help("\(Int(h.cpu))% of one CPU core, averaged over 30 seconds (400% fills the bar)")
            HStack(spacing: 4) {
                Text("Memory").foregroundStyle(.secondary)
                Text(ProcessVitals.memory(h.mem)).monospacedDigit().foregroundStyle(h.memHeavy ? .orange : .primary)
            }
            if context.running(h) > 0 {
                Text("for " + ProcessVitals.duration(context.running(h))).monospacedDigit().foregroundStyle(.secondary)
            }
        }
        .font(.system(size: 12))
        .lineLimit(1)
        .fixedSize()
    }
}

/// Ask AI…, with the other actions on its arrow: one split button instead of a button and a separate ⋯ menu.
private struct HeavyActions: View {
    let h: HeavyProcess
    let context: HeavyContext
    let actions: HUDActions

    private var event: ActivityEvent { context.events(h.pid) ?? h.launchEvent }

    var body: some View {
        Menu {
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: h.path)]) }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(h.path, forType: .string)
            }
        } label: {
            Label("Ask AI…", systemImage: "sparkles")
        } primaryAction: {
            actions.askAI(event)
        }
        .menuStyle(.button)
        .buttonStyle(.glass)
        .buttonBorderShape(.capsule)
        .controlSize(.small)
        .fixedSize()
        .help("Ask AI whether \(h.name) should be doing this. The arrow has Show in Finder and Copy Path.")
    }
}

private struct HeavyRow: View {
    let h: HeavyProcess
    let context: HeavyContext
    let actions: HUDActions

    var body: some View {
        GridRow(alignment: .center) {
            HStack(spacing: 8) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: h.path)).resizable().frame(width: 16, height: 16)
                Text(h.name).font(.system(size: 12, weight: .semibold))
                if h.untrusted { UntrustedTag() }
                Text("pid \(h.pid)" + (h.parent.isEmpty ? "" : " · started by " + (h.parent as NSString).lastPathComponent))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            HeavyMetrics(h: h, context: context)
            HeavyActions(h: h, context: context, actions: actions).gridColumnAlignment(.trailing)
        }
    }
}
