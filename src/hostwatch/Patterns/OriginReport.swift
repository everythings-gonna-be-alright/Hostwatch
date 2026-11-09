import Foundation

/// Where a process came from: its nearest meaningful ancestor, shells and wrappers skipped. Used by
/// `--origin-report` to measure whether "a familiar pattern from a new kind of origin" would be worth flagging.
enum ProcessOrigin: String, CaseIterable, Sendable {
    case agent = "AI agent"
    case terminal = "terminal"
    case app = "app"
    case launchd = "launchd"
    case scheduled = "scheduled"
    case ssh = "ssh"
    case other = "other program"
    case unknown = "unknown"

    /// Programs that only pass a command on: the origin is whoever started them.
    static let passThrough: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "env", "xargs",
                                           "nohup", "timeout", "time", "login", "sudo", "su", "caffeinate", "script",
                                           "arch", "exec", "nice", "tmux", "screen"]

    static func passesThrough(_ path: String) -> Bool {
        passThrough.contains((path as NSString).lastPathComponent.lowercased())
    }

    /// The origin of the first ancestor that isn't a pass-through. `ancestors` runs parent first, then its parent…;
    /// `brokenAt` says the chain ended because a launch wasn't recorded (else it reached launchd or pid 1).
    static func classify(ancestors: [String], brokenAt: Bool) -> ProcessOrigin {
        for path in ancestors {
            if CodingAgent.of(path) != nil { return .agent }
            if passesThrough(path) { continue }
            return of(path)
        }
        return brokenAt ? .unknown : .launchd
    }

    /// One non-pass-through program's kind.
    static func of(_ path: String) -> ProcessOrigin {
        let name = (path as NSString).lastPathComponent
        if CodingAgent.of(path) != nil { return .agent }
        if path == "/sbin/launchd" || name == "launchd" { return .launchd }
        if ["cron", "periodic", "atrun", "anacron"].contains(name) { return .scheduled }
        if name == "sshd" || name == "sshd-session" { return .ssh }
        let terminals = ["/Terminal.app/", "/iTerm.app/", "/Ghostty.app/", "/Warp.app/", "/Alacritty.app/", "/kitty.app/",
                         "/WezTerm.app/"]
        if terminals.contains(where: path.contains) { return .terminal }
        if path.contains(".app/") { return .app }
        return .other
    }

    /// The programs worth an origin: where the program alone says little about intent.
    static func isToolLike(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent.lowercased()
        return SignatureBuilder.interpreters.contains(name) || SignatureBuilder.isLolbin(path)
            || SignatureBuilder.isPlainTool(path) || SignatureBuilder.watchedTools.contains(name)
            || SignatureBuilder.adminTools.contains((path as NSString).lastPathComponent)
    }
}

// MARK: - Report

/// `--origin-report [history folder]`: over the recorded history, how many kinds of origin each tool pattern has,
/// and what a "new kind of origin reopens a pattern" rule would have done (read-only). One pass in time order, state
/// per pattern, so a long history costs little memory.
func runOriginReport(_ folder: String?) -> Never {
    SigningCache.shared.live = false
    SigningCache.shared.trustInstalledAppsInMemory()
    let dir = folder ?? HistoryRecorder.defaultDirectory.path
    guard FileManager.default.fileExists(atPath: dir) else { print("no history in \(dir)"); exit(1) }
    // The last few days only (a week of history takes long): learn on the first day, check the rest.
    let env = ProcessInfo.processInfo.environment
    let windowDays = Double(env["HOURS"] ?? "").map { $0 / 24 } ?? Double(env["DAYS"] ?? "") ?? 3
    let learnDays = Double(env["LEARN_DAYS"] ?? "") ?? windowDays / 3
    let since = Date().addingTimeInterval(-windowDays * 86_400)
    let top = Int(ProcessInfo.processInfo.environment["REPORT_TOP"] ?? "") ?? 15
    let all = ProcessOrigin.allCases
    func bit(_ o: ProcessOrigin) -> UInt8 { 1 << UInt8(all.firstIndex(of: o)!) }

    struct Launch { var ppid: Int; var path: String; var parent: String }
    struct Pattern { var seen: UInt8 = 0; var known: UInt8 = 0; var flagged = false }
    struct Hit { var key: String; var origin: ProcessOrigin; var known: UInt8; var at: Double }

    var launches: [Int: Launch] = [:]            // the latest recorded launch for each pid
    var patterns: [String: Pattern] = [:]
    var originCount: [ProcessOrigin: Int] = [:]
    var hitsByOrigin: [ProcessOrigin: Int] = [:]
    var recent: [Hit] = []                       // the latest flags only
    var hitCount = 0
    var total = 0, toolEvents = 0
    var first = 0.0, last = 0.0
    let decoder = JSONDecoder()

    func chain(ppid: Int, firstParent: String) -> (paths: [String], broken: Bool) {
        var paths: [String] = firstParent.isEmpty ? [] : [firstParent]
        var next = ppid, steps = 0
        while next > 1, steps < 30 {
            guard let up = launches[next] else { return (paths, true) }      // a launch before recording began
            if paths.last != up.path { paths.append(up.path) }
            next = up.ppid; steps += 1
        }
        return (paths, false)
    }

    HistoryFiles.forEachLine(path: dir, since: since) { line in autoreleasepool {
        // A command-line loop has no run loop to drain Foundation's temporaries: without a pool per line they pile
        // up (13 GB of footprint over a week of history).
        // The time is read from the line itself: the decoder doesn't fill `ts` (the app does that on its own path),
        // and a line outside the window is skipped before the costly decode.
        guard let at = HistoryArchive.timestamp(line)?.timeIntervalSince1970, at >= since.timeIntervalSince1970,
              var e = try? decoder.decode(ActivityEvent.self, from: line) else { return }
        e.ts = at
        total += 1
        if e.kind == .exec { launches[e.pid] = Launch(ppid: e.ppid, path: e.target, parent: e.parent) }
        let subject = e.kind == .exec ? e.target : e.proc
        guard !e.signatureKey.isEmpty, ProcessOrigin.isToolLike(subject) else { return }
        toolEvents += 1
        if first == 0 { first = e.ts }
        last = max(last, e.ts)
        // A launch's origin starts at its parent; a file or connection's at the acting process's own parent.
        let start: (parent: String, ppid: Int)
        if e.kind == .exec { start = (e.parent, launches[e.ppid]?.ppid ?? 0) }
        else if let own = launches[e.pid] { start = (own.parent, own.ppid) }
        else { start = (e.parent, 0) }
        let c = chain(ppid: start.ppid, firstParent: start.parent)
        let origin = ProcessOrigin.classify(ancestors: c.paths, brokenAt: c.broken)
        originCount[origin, default: 0] += 1

        var p = patterns[e.signatureKey] ?? Pattern()
        let b = bit(origin)
        let isNewPattern = p.seen == 0
        p.seen |= b
        if e.ts < first + learnDays * 86_400 || isNewPattern {
            p.known |= b                                     // learning, or a pattern seen for the first time
        } else if p.known & b == 0 {
            hitCount += 1
            hitsByOrigin[origin, default: 0] += 1
            p.flagged = true
            recent.append(Hit(key: e.signatureKey, origin: origin, known: p.known, at: e.ts))
            if recent.count > top * 4 { recent.removeFirst(recent.count - top * 2) }
            p.known |= b                                     // flagged once per new kind
        }
        patterns[e.signatureKey] = p
    } }
    guard toolEvents > 0 else { print("no tool events"); exit(0) }
    let days = max(1.0 / 1440, (last - first) / 86_400)
    func names(_ mask: UInt8) -> String { all.filter { mask & bit($0) != 0 }.map(\.rawValue).joined(separator: "+") }

    func span(_ d: Double) -> String { d < 1 ? String(format: "%.0f min", d * 1440) : String(format: "%.1f days", d) }
    print("\(total) events over \(span(days)), \(toolEvents) by interpreters and tools")
    var spread: [Int: Int] = [:]
    for p in patterns.values { spread[min(p.seen.nonzeroBitCount, 4), default: 0] += 1 }
    print("\n\(patterns.count) tool patterns, by how many kinds of origin they were seen from:")
    for n in 1...4 { print("  \(n == 4 ? "4+" : String(n)): \(spread[n] ?? 0)") }
    print("\nevents by origin:")
    for (o, n) in originCount.sorted(by: { $0.value > $1.value }) { print(String(format: "  %9d  %@", n, o.rawValue)) }

    let saved = SignatureStore.readSaved(from: AppPaths.support)
    let status = Dictionary((saved?.entries ?? []).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
    let flagged = patterns.filter(\.value.flagged).map(\.key)
    let safe = flagged.filter { status[$0]?.status == .safe }
    let byYou = safe.filter { ["you", "rule"].contains(status[$0]?.source ?? "") }
    let afterDays = max(1.0 / 1440, days - learnDays)
    print("\nrule: learn \(span(learnDays)), then flag a known pattern seen from a new kind of origin")
    print("  \(hitCount) flags over \(span(afterDays)) (\(String(format: "%.1f", Double(hitCount) / afterDays)) a day) on \(flagged.count) patterns")
    print("  \(safe.count) of those patterns are Safe today and would be reopened (\(byYou.count) decided by you or a rule)")
    print("  new origin was: " + hitsByOrigin.sorted { $0.value > $1.value }.map { "\($0.key.rawValue) \($0.value)" }.joined(separator: ", "))

    print("\nlatest flags:")
    let fmt = DateFormatter(); fmt.dateFormat = "MMM d HH:mm"
    for h in recent.suffix(top).reversed() {
        let s = status[h.key].map { " [\($0.status.title)\($0.source.map { ", \($0)" } ?? "")]" } ?? ""
        let parts = h.key.split(separator: "|", maxSplits: 2).map(String.init)
        let what = parts.count == 3 ? "\(parts[1]) · \(parts[2])" : h.key
        print("  \(fmt.string(from: Date(timeIntervalSince1970: h.at)))  \(names(h.known)) → \(h.origin.rawValue)\(s)  \(what.prefix(110))")
    }
    exit(0)
}
