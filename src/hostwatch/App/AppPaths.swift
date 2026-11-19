import Foundation

/// Where Hostwatch keeps its data.
enum AppPaths {
    static let name = "Hostwatch"
    static let bundleID = "tech.hostwatch.app"
    /// The identifier up to 0.13.0 (`local.`): its settings and keychain items are carried over on first launch.
    static let oldBundleID = "local.hostwatch.app"

    /// The collector with the Endpoint Security entitlement, in its own bundle inside the app (ADR 0018): the app keeps the
    /// signature it always had (its keychain identity, and so its data key), and only the root collector is entitled.
    static let collectorBundleID = "tech.hostwatch.collector"
    static let collectorHelper = "Contents/Library/Helpers/Hostwatch Collector.app"

    /// The entitled collector inside `app`, when this build has one.
    static func entitledCollector(in app: URL) -> String? {
        let path = app.appendingPathComponent(collectorHelper + "/Contents/MacOS/Hostwatch").path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    /// The app around this process: itself, or the app holding the collector's helper bundle.
    static var outerApp: URL { outerApp(ofBundle: Bundle.main.bundlePath) }

    static func outerApp(ofBundle path: String) -> URL {
        if let r = path.range(of: "/" + collectorHelper) { return URL(fileURLWithPath: String(path[..<r.lowerBound])) }
        return URL(fileURLWithPath: path)
    }

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
    /// An environment override that changes what the app trusts (another collector socket, signing database or
    /// own bundle, signing rules off): read only in debug and demo builds. In the shipped app any program running
    /// as you could relaunch Hostwatch with one set, so there they don't exist.
    static func developerOverride(_ key: String) -> String? {
        #if DEBUG || DEMO
        return ProcessInfo.processInfo.environment[key]
        #else
        return nil
        #endif
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
