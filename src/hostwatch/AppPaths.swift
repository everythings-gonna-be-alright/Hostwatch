import Foundation

/// Where Hostwatch keeps its data.
enum AppPaths {
    static let name = "Hostwatch"
    static let bundleID = "local.hostwatch.app"

    private static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
    /// ~/Library/Application Support/Hostwatch: patterns, stories, domains, signing facts, token.
    /// In demo mode everything lives in the demo folder instead.
    static var support: URL {
        Demo.root.map { $0.appendingPathComponent("support", isDirectory: true) }
            ?? home.appendingPathComponent("Library/Application Support/\(name)", isDirectory: true)
    }
    /// ~/Library/Logs/Hostwatch: collector log and the History folder.
    static var logs: URL {
        Demo.root.map { $0.appendingPathComponent("logs", isDirectory: true) }
            ?? home.appendingPathComponent("Library/Logs/\(name)", isDirectory: true)
    }
    /// The user's home folder as paths are shown and judged (the demo's made-up user in demo mode).
    static var userHome: String { Demo.root != nil ? Demo.home : FileManager.default.homeDirectoryForCurrentUser.path }
}
