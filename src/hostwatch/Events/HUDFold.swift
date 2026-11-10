import Foundation

/// The overlay's rows: the same program doing the same kind of thing with the same status, folded into one row with a
/// count and a summary ("read 12 files in Shortcuts.app"). Anything with a badge (threat list, beacon, new domain,
/// first sighting, heavy, would-stop) keeps its own row, so an exception never hides inside a fold.
enum HUDFold {
    struct Item: Identifiable {
        let events: [ActivityEvent]                  // newest first
        var id: UUID { events[0].id }
        var event: ActivityEvent { events[0] }
        var count: Int { events.count }
        var folded: Bool { events.count > 1 }
    }

    /// Events fold only within this many seconds of their row's newest event: a burst, not the whole minute.
    static let window: Double = 5

    /// `events` newest first. `key` gives the fold key, nil for an event that must keep its own row.
    static func fold(_ events: [ActivityEvent], limit: Int, key: (ActivityEvent) -> String?) -> [Item] {
        var items: [Item] = []
        var open: [String: Int] = [:]               // fold key → index in items
        for e in events {
            if let k = key(e), let i = open[k], seconds(items[i].event) - seconds(e) <= window {
                items[i] = Item(events: items[i].events + [e])
                continue
            }
            if items.count == limit { break }
            if let k = key(e) { open[k] = items.count }
            items.append(Item(events: [e]))
        }
        return items
    }

    /// When it happened, in seconds: the recorded stamp, else the clock time of the day ("04:58:30.123456").
    static func seconds(_ e: ActivityEvent) -> Double {
        if e.ts > 0 { return e.ts }
        let parts = e.time.split(separator: ":")
        guard parts.count == 3, let h = Double(parts[0]), let m = Double(parts[1]), let s = Double(parts[2]) else { return 0 }
        return h * 3600 + m * 60 + s
    }

    /// A single row's detail in words: "x.plist in Preferences", "wrote x.plist in …/Caches", "started by zsh".
    /// Connections keep their destination, which is the fact there.
    static func detail(_ e: ActivityEvent) -> String {
        switch e.kind {
        case .file:
            let name = (e.target as NSString).lastPathComponent
            let folder = place([e.target]).map { " in \($0)" } ?? ""
            return (e.extra.contains("w") ? "wrote " : "") + (name.isEmpty ? e.target : name) + folder
        case .exec:
            let parent = (e.parent as NSString).lastPathComponent
            return parent.isEmpty ? "started" : "started by \(parent)"
        case .net:
            return e.detail
        }
    }

    /// What a folded row says, in plain words.
    static func summary(_ events: [ActivityEvent]) -> String {
        guard let first = events.first else { return "" }
        let n = events.count
        switch first.kind {
        case .file:
            let modes = Set(events.map(\.extra))
            let verb = modes.allSatisfy { $0 == "r" } ? "read" : modes.allSatisfy { !$0.contains("r") } ? "wrote" : "opened"
            let unique = Set(events.map(\.target)).count
            return "\(verb) \(unique) file\(unique == 1 ? "" : "s")" + place(events.map(\.target)).map { " in \($0)" }.orEmpty
        case .exec:
            let names = unique(events.map { ($0.target as NSString).lastPathComponent })
            return "started \(n) program\(n == 1 ? "" : "s"): " + names.prefix(3).joined(separator: ", ") + (names.count > 3 ? "…" : "")
        case .net:
            let hosts = unique(events.map { $0.host.isEmpty ? ($0.remoteHost ?? "?") : $0.host })
            return "\(n) connection\(n == 1 ? "" : "s"): " + hosts.prefix(2).joined(separator: ", ") + (hosts.count > 2 ? "…" : "")
        }
    }

    /// Where files are, as a person would say it: the app bundle they're in, or the last folders they share.
    static func place(_ paths: [String]) -> String? {
        let dirs = paths.map { ($0 as NSString).deletingLastPathComponent }
        guard var common = dirs.first else { return nil }
        for d in dirs.dropFirst() {
            while !(d == common || d.hasPrefix(common.hasSuffix("/") ? common : common + "/")) && common.count > 1 {
                common = (common as NSString).deletingLastPathComponent
            }
        }
        if let r = common.range(of: ".app", options: .backwards) {
            return ((String(common[..<r.upperBound]) as NSString).lastPathComponent)
        }
        let home = AppPaths.userHome
        if common == home { return "the home folder" }
        if common == "/" || common.isEmpty { return nil }
        let short = common.hasPrefix(home) ? "~" + common.dropFirst(home.count) : common
        // The last two folders say where: "~/Library/Preferences", "…/Contents/Resources".
        let parts = short.split(separator: "/")
        let limit = short.hasPrefix("~") ? 3 : 2
        return parts.count > limit ? "…/" + parts.suffix(2).joined(separator: "/") : short
    }

    private static func unique(_ items: [String]) -> [String] {
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
