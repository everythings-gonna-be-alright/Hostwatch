import Foundation

/// Where Hostwatch keeps its data.
enum AppPaths {
    static let name = "Hostwatch"
    static let bundleID = "local.hostwatch.app"

    private static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
    /// ~/Library/Application Support/Hostwatch: patterns, stories, domains, signing facts, token.
    static var support: URL { home.appendingPathComponent("Library/Application Support/\(name)", isDirectory: true) }
    /// ~/Library/Logs/Hostwatch: collector log and the History folder.
    static var logs: URL { home.appendingPathComponent("Library/Logs/\(name)", isDirectory: true) }
}
