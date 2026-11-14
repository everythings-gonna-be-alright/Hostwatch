import SwiftUI

/// A segmented switch whose segments show an icon beside their text. SwiftUI's segmented picker on macOS draws a
/// label's title alone and drops its icon, so Events / Running Now and the grouping switches are built from buttons,
/// like the Show filter beside them. The selected segment is raised in the text colour, as the selected tab is, so
/// it reads with any accent colour. Compact: icons alone, the title on hover.
struct IconSegments<Value: Hashable>: View {
    struct Item {
        let value: Value
        let title: String
        let symbol: String
        var help: String? = nil
    }

    @Binding var selection: Value
    let items: [Item]
    var compact = false

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                let selected = selection == item.value
                Button { selection = item.value } label: {
                    HStack(spacing: 5) {
                        Image(systemName: item.symbol)
                            .symbolVariant(selected ? .fill : .none)
                            .font(.system(size: 11, weight: .medium))
                        if !compact {
                            Text(item.title).font(.system(size: 12, weight: selected ? .semibold : .regular))
                                .lineLimit(1).fixedSize()
                        }
                    }
                    .padding(.horizontal, compact ? 8 : 10).padding(.vertical, 4)
                    .foregroundStyle(selected ? Color.primary : Color.secondary)
                    .background {
                        if selected {
                            Capsule().fill(Color.primary.opacity(0.16))
                                .overlay(Capsule().strokeBorder(Color.primary.opacity(0.12), lineWidth: 0.5))
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .help(item.help ?? item.title)
                .accessibilityLabel(item.title)
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .padding(2)
        .background(Capsule().fill(Color.primary.opacity(0.06)))
        .fixedSize()
    }
}

extension IconSegments where Value == EventGrouping {
    /// No Groups · By Process · By AI Session, on Events and Patterns alike.
    init(grouping: Binding<EventGrouping>, compact: Bool = false) {
        self.init(selection: grouping, items: EventGrouping.allCases.map { .init(value: $0, title: $0.title, symbol: $0.symbol) },
                  compact: compact)
    }
}
