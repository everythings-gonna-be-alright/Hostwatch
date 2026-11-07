import Foundation

/// Where Hostwatch keeps its data.
enum AppPaths {
    static let name = "Hostwatch"
    static let bundleID = "local.hostwatch.app"

    private static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
    /// ~/Library/Application Support/Hostwatch: patterns, stories, domains, signing facts, token.
    /// In demo mode everything lives in the demo folder instead.
    static var support: URL {
        #if DEMO
        if let root = Demo.root { return root.appendingPathComponent("support", isDirectory: true) }
        #endif
        return home.appendingPathComponent("Library/Application Support/\(name)", isDirectory: true)
    }
    /// ~/Library/Logs/Hostwatch: collector log and the History folder.
    static var logs: URL {
        #if DEMO
        if let root = Demo.root { return root.appendingPathComponent("logs", isDirectory: true) }
        #endif
        return home.appendingPathComponent("Library/Logs/\(name)", isDirectory: true)
    }
    /// The user's home folder as paths are shown and judged (the demo's made-up user in demo mode).
    static var userHome: String {
        #if DEMO
        if Demo.active { return Demo.home }
        #endif
        return FileManager.default.homeDirectoryForCurrentUser.path
    }
    /// Running as the demo (only possible in the demo build).
    static var isDemo: Bool {
        #if DEMO
        return Demo.active
        #else
        return false
        #endif
    }
}
