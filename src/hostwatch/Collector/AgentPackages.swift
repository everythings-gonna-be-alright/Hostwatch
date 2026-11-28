import Foundation

/// Package guard in the collector (ADR 0024, layers 3 and 4): the app's compact copy of the malicious-package lists,
/// the processes install scripts started (contained), and the checks the holds and the firewall relay ask. Answered
/// here, with no round trip: a lookup is a binary search or a dictionary read, far inside macOS's deadline.
final class PackageHold: @unchecked Sendable {     // every field is read and written under `lock`
    enum Mode: String { case off, watch, ask, strict }

    /// Who a contained process is running for. `runner`: the npx/uvx process itself, which needs your registry
    /// login: only what it starts is contained.
    struct Contained: Equatable, Sendable {
        var target: InstallTarget
        var runner = false
    }

    private let lock = NSLock()
    private var listed = ListedPackages()
    private var mode = Mode.off
    private var readPaths: [String] = []
    private var writePaths: [String] = []
    private var extraHosts: [String] = []
    private var known: [String: Set<String>] = [:]
    private var contained: [Int: Contained] = [:]
    private var reported: [String: TimeInterval] = [:]

    /// `{"packages": {"mode": "ask", "lists": {…}, "contain": {"read": […], "write": […], "hosts": […]},
    /// "known": {"npm": […]}}` from the app. Parts left out keep what they were.
    func configure(_ d: [String: Any]) {
        let lists = (d["lists"] as? [String: Any]).map(ListedPackages.init(payload:))
        let contain = d["contain"] as? [String: Any]
        let knownIn = d["known"] as? [String: [String]]
        lock.lock()
        mode = Mode(rawValue: d["mode"] as? String ?? "") ?? (d["enforce"] as? Bool == true ? .ask : .off)
        if let lists { listed = lists }
        if let contain {
            readPaths = contain["read"] as? [String] ?? []
            writePaths = contain["write"] as? [String] ?? []
            extraHosts = contain["hosts"] as? [String] ?? []
        }
        if let knownIn { known = knownIn.mapValues(Set.init) }
        if mode == .off { contained = [:] }
        let summary = "\(mode.rawValue), \(listed.count) listed packages, \(readPaths.count + writePaths.count) contained places"
        lock.unlock()
        Agent.log("packages: \(summary)")
    }

    /// Launches are held and their environment read: containment needs to see every install script, in Watch too
    /// (answered at once there).
    var isActive: Bool { lock.lock(); defer { lock.unlock() }; return mode != .off }
    /// Listed packages and contained actions are denied, not only reported.
    var isEnforcing: Bool { lock.lock(); defer { lock.unlock() }; return mode == .ask || mode == .strict }
    /// The places the open hold must see for containment.
    var prefixes: [String] { lock.lock(); defer { lock.unlock() }; return mode == .off ? [] : readPaths + writePaths }

    /// The first target on the lists, with the record that lists it (Ask and Strict only).
    func listedTarget(_ targets: [InstallTarget]) -> (InstallTarget, MalwareRecord)? {
        guard !targets.isEmpty else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard mode == .ask || mode == .strict else { return nil }
        for t in targets { if let r = listed.record(for: t.package) { return (t, r) } }
        return nil
    }

    // MARK: Which processes are contained

    /// Every held launch: an install script, a package run at once, or a child of a contained process is
    /// contained. Anything else that reuses a pid isn't. Returns what this process is contained as.
    @discardableResult
    func noteLaunch(pid: Int, ppid: Int, installs: [InstallTarget]) -> Contained? {
        lock.lock(); defer { lock.unlock() }
        guard mode != .off else { return nil }
        var c: Contained?
        if let s = installs.first(where: { $0.how == .script }) { c = Contained(target: s) }
        else if let parent = contained[ppid] { c = Contained(target: parent.target) }
        else if let run = installs.first(where: { $0.how == .run }) { c = Contained(target: run, runner: true) }
        contained[pid] = c
        if contained.count > 20_000 { contained = [:] }    // something is wrong: forget rather than grow
        return c
    }

    /// A fork keeps its parent's containment (node's workers, a shell's subshells).
    func forked(parent: Int, child: Int) {
        lock.lock(); defer { lock.unlock() }
        if let c = contained[parent] { contained[child] = Contained(target: c.target) }
    }

    func exited(_ pid: Int) {
        lock.lock(); contained[pid] = nil; lock.unlock()
    }

    /// The contained process this pid is, nil when it isn't (a runner isn't: only what it starts).
    func contained(_ pid: Int) -> Contained? {
        lock.lock(); defer { lock.unlock() }
        guard let c = contained[pid], !c.runner else { return nil }
        return c
    }

    // MARK: The checks

    struct Finding: Sendable {
        var contained: Contained
        var violation: InstallContainment.Violation
        var target: String          // the file, the program or the host
        var why: String
        var enforced: Bool
    }

    /// A contained process opening a secret or writing a startup place.
    func checkOpen(pid: Int, file: String, mode fileMode: String) -> Finding? {
        lock.lock(); defer { lock.unlock() }
        guard mode != .off, let c = contained[pid], !c.runner,
              let v = InstallContainment.open(file, mode: fileMode, read: readPaths, write: writePaths) else { return nil }
        return Finding(contained: c, violation: v, target: file,
                       why: v == .read ? "read a secret" : "write a place that starts code later", enforced: enforcing)
    }

    /// A contained process starting an AI CLI, a secret scanner or a persistence tool.
    func checkLaunch(_ c: Contained?, path: String, args: [String]) -> Finding? {
        guard let c, !c.runner, let (name, why) = InstallContainment.blockedLaunch(path: path, args: args) else { return nil }
        lock.lock(); defer { lock.unlock() }
        return Finding(contained: c, violation: .launch, target: name, why: "start \(why)", enforced: enforcing)
    }

    /// A contained process connecting anywhere but a registry or a native build's download host.
    func checkConnect(pid: Int, host: String) -> Finding? {
        lock.lock(); defer { lock.unlock() }
        guard mode != .off, let c = contained[pid], !c.runner,
              !InstallContainment.hostAllowed(host, extra: extraHosts) else { return nil }
        return Finding(contained: c, violation: .connect, target: host.isEmpty ? "an unnamed address" : host,
                       why: "connect outside the package registries", enforced: enforcing)
    }

    /// A named install whose name looks like a well-known package's: refused in Strict, reported in every mode.
    func checkLookalike(_ installs: [InstallTarget]) -> (InstallTarget, String, Bool)? {
        lock.lock(); defer { lock.unlock() }
        guard mode != .off else { return nil }
        for t in installs where t.how != .script {
            if let like = PackageNames.lookalike(t.package.name, t.package.ecosystem, known: known[t.package.ecosystem.osv] ?? []) {
                return (t, like, mode == .strict)
            }
        }
        return nil
    }

    /// Reported once a minute per process, action and target: a script retrying in a loop is one line.
    func shouldReport(_ key: String, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let t = reported[key], now - t < 60 { return false }
        reported[key] = now
        if reported.count > 2000 { reported = reported.filter { now - $0.value < 60 } }
        return true
    }

    private var enforcing: Bool { mode == .ask || mode == .strict }
}

// MARK: In the holds

extension AgentGuard {
    /// The package guard's say on a held launch or open: false to deny, true to allow outright, nil to go on to the
    /// other rules. Every launch passes here while packages are guarded: it also keeps the contained set right.
    func packageDecision(_ r: HoldRequest) -> Bool? {
        switch r.what {
        case .exec:
            let c = packages.noteLaunch(pid: r.pid, ppid: r.ppid, installs: r.installs)
            if let (target, record) = packages.listedTarget(r.installs) {
                sendPackage("guard_package", r, target, ["malware": .str(record.id)])
                return false
            }
            if let f = packages.checkLaunch(c, path: r.path, args: r.argv) {
                reportContained(f, r)
                if f.enforced { return false }
            }
            let named = r.installs.filter { $0.how != .script }
            if let (target, like, refuse) = packages.checkLookalike(named) {
                if packages.shouldReport("look\0\(target.package.key)") {
                    sendPackage("guard_contain", r, target, ["tried": .str("lookalike"), "target": .str(like),
                                                            "why": .str("looks like \(like)"), "enforced": .bool(refuse)])
                }
                if refuse { return false }
            }
            for t in named where packages.shouldReport("inst\0\(r.pid)\0\(t.package.key)") {
                sendPackage("guard_install", r, t, [:])
            }
            return nil
        case .open:
            guard let f = packages.checkOpen(pid: r.pid, file: r.file, mode: r.mode) else { return nil }
            reportContained(f, r)
            return f.enforced ? false : nil
        }
    }

    func reportContained(_ f: PackageHold.Finding, _ r: HoldRequest) {
        guard packages.shouldReport("\(f.violation.rawValue)\0\(f.contained.target.package.key)\0\(f.target)") else { return }
        sendPackage("guard_contain", r, f.contained.target, ["tried": .str(f.violation.rawValue), "target": .str(f.target),
                                                             "why": .str(f.why), "enforced": .bool(f.enforced)])
    }

    /// A connection through the firewall's relay from a contained process (nil: not contained, or allowed).
    func packageConnect(pid: Int, program: String, host: String) -> PackageHold.Finding? {
        guard let f = packages.checkConnect(pid: pid, host: host) else { return nil }
        let r = HoldRequest(what: .exec, path: program, pid: pid, ppid: 0, uid: 0, seconds: 0)
        reportContained(f, r)
        return f
    }

    func sendPackage(_ kind: String, _ r: HoldRequest, _ t: InstallTarget, _ extra: [String: JValue]) {
        send(currentDecider, Self.line(kind, r, extra.merging([
            "ecosystem": .str(t.package.ecosystem.osv), "package": .str(t.package.name), "version": .str(t.package.version),
            "how": .str(t.how.rawValue), "detail": .str(t.detail)]) { a, _ in a }))
    }
}
