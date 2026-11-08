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
    func agent(_ agent: CodingAgent, size: CGFloat) -> NSImage { image("agent:\(agent):\(size)") { AgentBadge(agent: agent, size: size) } }
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
        label.cell?.truncatesLastVisibleLine = true
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        stack.addArrangedSubview(label)
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -2),
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
        label.stringValue = text ?? ""
        label.textColor = color
        label.font = font
        label.lineBreakMode = truncation
        label.toolTip = toolTip
        self.toolTip = nil
    }
}

/// A group row: the whole row is one cell (AppKit's group-row style draws the band behind it).
final class GroupCellView: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("group")
    private let mark = NSImageView()
    private let title = NSTextField(labelWithString: "")
    private let facts = NSTextField(labelWithString: "")
    private let status = NSImageView()
    private let count = NSImageView()

    override init(frame: NSRect) {
        super.init(frame: frame)
        let stack = NSStackView(views: [mark, title, facts, NSView(), status, count])
        stack.orientation = .horizontal
        stack.spacing = 8
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        for v in [mark, status, count] {
            v.imageScaling = .scaleNone
            v.setContentHuggingPriority(.required, for: .horizontal)
            v.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        title.font = .systemFont(ofSize: 13, weight: .semibold)
        title.lineBreakMode = .byTruncatingTail
        title.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        facts.font = .systemFont(ofSize: 12)
        facts.textColor = .secondaryLabelColor
        facts.lineBreakMode = .byTruncatingTail
        facts.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -10),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
        textField = title
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func set(_ item: EventItem) {
        let badges = BadgeImages.shared
        mark.image = item.agent.map { badges.agent($0, size: 16) } ?? badges.plainMark()
        title.stringValue = item.groupTitle
        title.textColor = item.isCatchAll ? .secondaryLabelColor : .labelColor
        facts.stringValue = item.groupSubtitle
        facts.isHidden = item.groupSubtitle.isEmpty
        status.image = badges.statusPill(item.status)
        status.toolTip = "The most serious status among these events"
        count.image = badges.capsule(count: item.children?.count ?? 0, noun: "event")
        toolTip = item.groupTitle
    }
}

/// A menu item that runs a closure.
final class ClosureMenuItem: NSMenuItem {
    private var handler: () -> Void = {}

    convenience init(_ title: String, enabled: Bool = true, _ handler: @escaping () -> Void) {
        self.init(title: title, action: #selector(run), keyEquivalent: "")
        self.handler = handler
        self.target = self
        self.isEnabled = enabled
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

    func addSubmenu(_ title: String, _ fill: (NSMenu) -> Void) {
        let sub = NSMenu(title: title)
        sub.autoenablesItems = false
        fill(sub)
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.submenu = sub
        addItem(item)
    }
}
