import Foundation

/// A rule from the short-lived separate Allow and Block list, kept only so saved rules can be read and moved: file
/// rules into the places' exceptions (ProtectionMonitor.moveFileRulesIntoPlaces), network rules into destinations
/// (Destinations.from). source: docs/adr/0015-your-allow-and-block-rules.md
struct AccessRule: Codable, Identifiable, Equatable, Sendable {
    enum Kind: String, Codable, Sendable { case files, network }
    enum Action: String, Codable, Sendable { case allow, block }

    var id = UUID().uuidString
    var kind: Kind
    var target: String
    var program: String?
    var action: Action
    var on = true
}

/// Matching shared by places and destinations: paths covering paths, and an app covering its programs.
enum AccessRules {
    /// The path itself or anything inside it. "/var" and "/private/var" are the same place on macOS.
    static func covers(_ target: String, _ path: String) -> Bool {
        for t in variants(target) {
            for p in variants(path) where p == t || p.hasPrefix(t.hasSuffix("/") ? t : t + "/") { return true }
        }
        return false
    }

    private static func variants(_ path: String) -> [String] {
        path.hasPrefix("/private/") ? [path, String(path.dropFirst(8))] : [path, "/private" + path]
    }

    /// The program named: the binary itself, or anything inside the app bundle it names.
    static func runs(_ rule: String?, _ program: String) -> Bool {
        guard let rule else { return true }
        return program == rule || program.hasPrefix(rule.hasSuffix("/") ? rule : rule + "/")
    }

    /// "~/Documents/contracts" for paths in your home.
    static func display(_ path: String, home: String = NSHomeDirectory()) -> String {
        path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }
}
