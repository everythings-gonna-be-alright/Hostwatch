import AppKit
import SwiftUI

/// Pills, tags and marks for the AppKit event list, drawn once per look and reused as images.
/// source: docs/adr/0010-appkit-event-list.md
@MainActor
final class BadgeImages {
    static let shared = BadgeImages()

    private var cache: [String: NSImage] = [:]
    private var symbols: [String: NSImage] = [:]
    private var appearance = ""

    /// The image for `key` in the current appearance, rendering `make()` the first time.
    func image<V: View>(_ key: String, _ make: () -> V) -> NSImage {
        let dark = NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        let look = dark ? "dark" : "light"
        if look != appearance { cache.removeAll(); appearance = look }
        if cache.count > 2000 { cache.removeAll() }      // badge texts vary: never let the cache grow without end
        if let hit = cache[key] { return hit }
        let renderer = ImageRenderer(content: make().environment(\.colorScheme, dark ? .dark : .light))
        renderer.scale = NSScreen.main?.backingScaleFactor ?? 2
        let image = renderer.nsImage ?? NSImage(size: .zero)
        cache[key] = image
        return image
    }

    /// An SF Symbol at a size and weight (tinting is the image view's).
    func symbol(_ name: String, size: CGFloat, weight: NSFont.Weight = .regular) -> NSImage {
        let key = "\(name)|\(size)|\(weight.rawValue)"
        if let hit = symbols[key] { return hit }
        let config = NSImage.SymbolConfiguration(pointSize: size, weight: weight)
        let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(config)
            ?? NSImage(size: .zero)
        symbols[key] = image
        return image
    }

    func statusPill(_ status: SignatureStatus) -> NSImage { image("status:\(status.rawValue)") { StatusPill(status: status) } }
    func knownBadPill() -> NSImage { image("knownbad") { KnownBadPill() } }
    func knownBadTag(_ detail: String) -> NSImage { image("knownbadtag") { KnownBadTag(detail: detail) } }
    func vital(_ badge: ProcessVitals.Badge) -> NSImage { image("vital:\(badge)") { VitalBadgeView(badge: badge) } }
    func fileMode(_ mode: String) -> NSImage { image("mode:\(mode)") { FileModeIcon(mode: mode) } }
    func proto(_ proto: String) -> NSImage { image("proto:\(proto)") { ProtocolTag(proto: proto) } }
    func agent(_ agent: CodingAgent, size: CGFloat, tinted: Bool = false) -> NSImage {
        image("agent:\(agent):\(size):\(tinted)") { AgentBadge(agent: agent, size: size, tinted: tinted) }
    }
    func kindTile(_ kind: EventKind) -> NSImage { image("kindtile:\(kind.rawValue)") { KindTile(kind: kind) } }
    func capsule(count: Int, noun: String) -> NSImage { image("count:\(count):\(noun)") { CountCapsule(count: count, noun: noun) } }
    func plainMark() -> NSImage {
        image("plainmark") { RoundedRectangle(cornerRadius: 4, style: .continuous).fill(.quaternary).frame(width: 16, height: 16) }
    }
}

/// One cell: up to three images, then a label. Views are kept and hidden rather than made per row.
final class EventCellView: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("event")
    private let stack = NSStackView()
    private let icons = (0..<3).map { _ in NSImageView() }
    private let label = NSTextField(labelWithString: "")

    override init(frame: NSRect) {
        super.init(frame: frame)
        clipsToBounds = true                             // a column too narrow cuts its content, never the next column's
        stack.orientation = .horizontal
        stack.spacing = 5
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        for icon in icons {
            icon.imageScaling = .scaleNone
            icon.setContentHuggingPriority(.required, for: .horizontal)
            icon.setContentCompressionResistancePriority(.required, for: .horizontal)
            stack.addArrangedSubview(icon)
        }
        label.lineBreakMode = .byTruncatingTail
        label.usesSingleLineMode = true
        label.maximumNumberOfLines = 1
        label.cell?.truncatesLastVisibleLine = true
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        stack.addArrangedSubview(label)
        addSubview(stack)
        // The right edge gives way first: when the images don't fit, a required right edge broke the left one,
        // so the row slid left and a marker overlapped the status pill.
        let trailing = stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -2)
        trailing.priority = .defaultHigh
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            trailing,
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
        textField = label
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    struct Icon {
        var image: NSImage
        var tint: NSColor? = nil
        var toolTip: String? = nil
    }

    func set(icons: [Icon] = [], text: String? = nil, color: NSColor = .labelColor, font: NSFont,
             truncation: NSLineBreakMode = .byTruncatingTail, toolTip: String? = nil) {
        for (i, view) in self.icons.enumerated() {
            if i < icons.count {
                view.image = icons[i].image
                view.contentTintColor = icons[i].tint
                view.toolTip = icons[i].toolTip
                view.isHidden = false
            } else {
                view.isHidden = true
            }
        }
        label.isHidden = text == nil
        // One line per row: a multi-line command (a shell script) drew shifted up and clipped, so its line breaks
        // show as ⏎ (the tooltip keeps the whole text).
        label.stringValue = (text ?? "").contains(where: \.isNewline)
            ? (text ?? "").split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }.joined(separator: " ⏎ ")
            : text ?? ""
        label.textColor = color
        label.font = font
        label.lineBreakMode = truncation
        label.toolTip = toolTip
        self.toolTip = nil
    }
}

/// A plain row whose selection is Liquid Glass, as the window's tab bar (DESIGN.md: selection, not the accent colour:
/// the system's accent fill isn't Liquid Glass, and with a graphite accent it was grey). The text keeps its colours.
final class GlassRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("glassrow")
    /// The selection: real Liquid Glass behind the row's cells, as the tab bar's lens, a little larger than a stripe.
    private var lens: NSGlassEffectView?

    override var isSelected: Bool {
        didSet { if isSelected != oldValue { updateLens() } }
    }

    private func updateLens() {
        guard isSelected else { lens?.removeFromSuperview(); lens = nil; return }
        guard lens == nil else { return }
        let glass = NSGlassEffectView(frame: bounds.insetBy(dx: 6, dy: -1))
        glass.cornerRadius = 8
        glass.autoresizingMask = [.width, .height]
        addSubview(glass, positioned: .below, relativeTo: nil)
        lens = glass
    }

    override func layout() {
        super.layout()
        lens?.frame = bounds.insetBy(dx: 6, dy: -1)
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        if !isSelected { lens?.removeFromSuperview(); lens = nil }
    }

    /// The glass is the selection: nothing drawn.
    override func drawSelection(in dirtyRect: NSRect) {}

    override var interiorBackgroundStyle: NSView.BackgroundStyle { .normal }

    /// Nothing of its own: the table draws the ground and the stripes under the rows (OutlineView.drawBackground). A
    /// row view fills itself with the table's ground colour and hid the stripes.
    override func drawBackground(in dirtyRect: NSRect) {}
}

/// A group row: the band itself, with the same SwiftUI band the other lists draw, laid across the row past the
/// disclosure triangle. Group rows are few, so hosting SwiftUI here costs nothing noticeable.
final class GroupRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("grouprow")
    private let host = NSHostingView(rootView: AnyView(EmptyView()))

    override init(frame: NSRect) {
        super.init(frame: frame)
        host.translatesAutoresizingMaskIntoConstraints = false
        addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 22),   // past the triangle
            host.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -22),
            host.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    /// A soft rounded tile on the clear table, like the map's tiles, so a group reads as one block.
    override func drawBackground(in dirtyRect: NSRect) {
        let tile = bounds.insetBy(dx: 6, dy: 2)
        NSColor.labelColor.withAlphaComponent(0.06).setFill()
        NSBezierPath(roundedRect: tile, xRadius: 10, yRadius: 10).fill()
    }

    func set(_ item: EventItem, links: [BandLink]) {
        // A program group shows the program's icon (an AI session its maker's mark, the catch-all nothing).
        let icon = item.agent == nil && !item.isCatchAll ? ProcessIcons.icon(item.event.proc) : nil
        host.rootView = AnyView(GroupBand(title: item.groupTitle, facts: item.groupSubtitle, agent: item.agent, icon: icon,
                                          dimmed: item.isCatchAll, links: links, status: item.status,
                                          count: item.children?.count ?? 0, noun: "event"))
        toolTip = item.groupTitle
    }

}

/// A menu item that runs a closure.
final class ClosureMenuItem: NSMenuItem {
    private var handler: () -> Void = {}

    /// `symbol`: a small SF Symbol before the title, as macOS's own menus show.
    convenience init(_ title: String, symbol: String? = nil, enabled: Bool = true, _ handler: @escaping () -> Void) {
        self.init(title: title, action: #selector(run), keyEquivalent: "")
        self.handler = handler
        self.target = self
        self.isEnabled = enabled
        if let symbol { image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
    }

    @objc private func run() { handler() }
}

extension NSMenu {
    /// A disabled line of text, like SwiftUI's `Text` in a menu.
    func addLabel(_ text: String) {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        addItem(item)
    }

    func addSubmenu(_ title: String, symbol: String? = nil, _ fill: (NSMenu) -> Void) {
        let sub = NSMenu(title: title)
        sub.autoenablesItems = false
        fill(sub)
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        if let symbol { item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
        item.submenu = sub
        addItem(item)
    }
}
