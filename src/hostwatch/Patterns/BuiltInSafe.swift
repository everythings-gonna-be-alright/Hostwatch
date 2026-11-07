import Foundation

// MARK: - Built-in safe patterns

/// macOS's own behaviour, the same on every Mac and impossible to fake: decided as routine (Safe) out of the box.
/// Only exact patterns, and when a parent is named it must be that program on the sealed, read-only system
/// volume (a copy elsewhere doesn't count). Signing still applies on top (a swapped binary is high-risk), and
/// stories ignore automatic decisions, so a chain through one of these still alerts.
enum BuiltInSafe {
    struct Item {
        let kind: EventKind
        /// The exact program that must start it (exec) or do it (file); nil: any program.
        let parent: String?
        /// Glob over the pattern text.
        let pattern: String
        let reason: String
    }

    static let items: [Item] = [
        Item(kind: .file, parent: nil, pattern: "r ~/.CFUserTextEncoding",
             reason: "macOS: every app reads its text-encoding preference"),
        Item(kind: .exec, parent: "/usr/sbin/networksetup",
             pattern: "/bin/sh -c ‹/bin/cp /Library/Preferences/SystemConfiguration/preferences.plist *",
             reason: "macOS: networksetup backs up the network settings"),
        Item(kind: .exec, parent: nil, pattern: "/bin/bash /usr/libexec/tmp_cleaner",
             reason: "macOS: its own temporary-files clean-up script"),
        Item(kind: .exec, parent: nil, pattern: "/bin/sh /usr/libexec/tmp_cleaner",
             reason: "macOS: its own temporary-files clean-up script"),
        Item(kind: .exec, parent: "/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer",
             pattern: "/usr/sbin/screencapture *com.apple.screenshot.launcher*",
             reason: "macOS: a screenshot you took (⇧⌘3, ⇧⌘4, ⇧⌘5)"),
    ]

    /// Why this is macOS's own ordinary behaviour, or nil.
    static func reason(kind: EventKind, parent: String, pattern: String) -> String? {
        items.first { item in
            item.kind == kind && Glob.match(item.pattern, pattern)
                && (item.parent.map { $0 == parent && SignatureBuilder.isSealedSystem(parent) } ?? true)
        }?.reason
    }
}
