import Foundation

/// Package guard in the collector (ADR 0024, layer 3): the app's compact copy of the malicious-package lists, and the
/// check a held launch gets when it installs a package. Answered here, with no round trip: a lookup is a binary
/// search, far inside macOS's deadline.
final class PackageHold: @unchecked Sendable {     // every field is read and written under `lock`
    private let lock = NSLock()
    private var listed = ListedPackages()
    private var enforcing = false

    /// `{"packages": {"enforce": true, "lists": {…}}}` from the app. `lists` is left out when only the mode changed.
    func configure(_ d: [String: Any]) {
        let lists = (d["lists"] as? [String: Any]).map(ListedPackages.init(payload:))
        lock.lock()
        enforcing = d["enforce"] as? Bool ?? false
        if let lists { listed = lists }
        let summary = "\(enforcing ? "stopping" : "not stopping") installs, \(listed.count) listed packages"
        lock.unlock()
        Agent.log("packages: \(summary)")
    }

    /// Whether launches must be held for packages, and their environment read.
    var isEnforcing: Bool { lock.lock(); defer { lock.unlock() }; return enforcing && !listed.isEmpty }

    /// The first target on the lists, with the record that lists it.
    func listedTarget(_ targets: [InstallTarget]) -> (InstallTarget, MalwareRecord)? {
        guard !targets.isEmpty else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard enforcing else { return nil }
        for t in targets { if let r = listed.record(for: t.package) { return (t, r) } }
        return nil
    }
}
