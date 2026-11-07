import Foundation

/// 0.13.0 changed the bundle identifier (`local.hostwatch.app` → `tech.hostwatch.app`). macOS keys settings, the
/// keychain and privacy grants by it, so the first launch carries over what it can: the settings domain is copied,
/// the data key's keychain item is re-stored under the new identity (one keychain dialog), and Full Disk Access
/// has to be granted again (the app notices and shows its setup window).
enum Migration {
    static let markerKey = "migratedFromBundleID"
    /// Set when this launch moved settings over: the keychain item is re-stored under the new identity too.
    nonisolated(unsafe) private(set) static var changedIdentity = false

    /// Runs before anything reads `UserDefaults.standard`.
    static func run(defaults: UserDefaults = .standard, old: String = AppPaths.oldBundleID) {
        guard defaults.string(forKey: markerKey) == nil else { return }
        guard let oldValues = UserDefaults(suiteName: old)?.persistentDomain(forName: old), !oldValues.isEmpty else {
            defaults.set("none", forKey: markerKey)
            return
        }
        copy(oldValues, into: defaults)
        defaults.set(old, forKey: markerKey)
        changedIdentity = true
    }

    /// Every setting of the old domain the new one doesn't have yet.
    static func copy(_ values: [String: Any], into defaults: UserDefaults) {
        for (key, value) in values where key != markerKey && defaults.object(forKey: key) == nil {
            defaults.set(value, forKey: key)
        }
    }
}
