import Darwin
import Foundation

// The collector's side of the firewall (Ask and Strict modes). pf sends your programs' new connections to the
// relay; for each one the relay asks the app (a "fw_ask" line; the app answers with "fw_answer"); the answer is
// remembered for a while per program and destination. Fail-safes: the redirect is removed when the mode goes
// off, when the collector stops, by a watchdog if the collector dies, and if the web check through the relay
// fails twice. Rules never survive a reboot (pf anchors live in memory).

/// What the app answered for a destination, until when.
struct FirewallAnswer: Sendable { var pass: Bool; var until: TimeInterval }

final class AgentFirewall: @unchecked Sendable {
    static let port: UInt16 = 46_110
    static let canaryURL = "https://www.apple.com/library/test/success.html"
    static let canaryHost = "www.apple.com"

    enum Mode: String { case off, ask, strict }

    private let agent: Agent
    private let lock = NSLock()
    private var mode = Mode.off
    private var relay: FirewallRelay?
    private var loaded: PFRedirect.Loaded?
    private weak var decider: AgentClient?
    private var nextAsk = 0
    /// Waiting questions by destination key: one question per program and destination, however many flows.
    private var waiting: [String: (id: Int, done: DispatchSemaphore, waiters: Int)] = [:]
    private var answers: [String: FirewallAnswer] = [:]
    private var canaryUntil: TimeInterval = 0
    private var healthRunning = false
    private(set) var state = "off"
    /// Turning the redirect on (tests replace it: no pf without root).
    var turnOn: ((AgentFirewall) -> Void)?

    init(agent: Agent) { self.agent = agent }

    static func key(_ f: RelayFlow) -> String {
        "\(f.program.isEmpty ? f.name : f.program)|\(f.tcp ? "TCP" : "UDP")|\(f.host.isEmpty ? (f.original?.address ?? "") : f.host)|\(f.original?.port ?? 0)"
    }

    // MARK: Configuration from the app

    /// {"firewall": {"mode": "off|ask|strict", "flush": true}} from the app's main connection.
    func configure(_ cfg: [String: Any], from client: AgentClient) {
        let wanted = Mode(rawValue: cfg["mode"] as? String ?? "") ?? .off
        lock.lock()
        decider = client
        if cfg["flush"] as? Bool == true { answers = [:] }
        let previous = mode
        mode = wanted
        // Leaving Ask: connections waiting for you are decided by the new mode (they read it when woken).
        let release = wanted != .ask && previous == .ask ? waiting : [:]
        if !release.isEmpty { waiting = [:] }
        lock.unlock()
        for (_, e) in release { for _ in 0..<max(e.waiters, 1) { e.done.signal() } }
        guard wanted != previous else { return }
        if wanted == .off { disable(reason: "") } else if previous == .off { (turnOn ?? { $0.enable() })(self) } else { status("on") }
    }

    /// {"fw_answer": {"id": 3, "key": "…", "pass": true, "ttl": 120}}
    func answer(_ a: [String: Any]) {
        guard let key = a["key"] as? String else { return }
        let pass = a["pass"] as? Bool ?? false
        let ttl = (a["ttl"] as? NSNumber)?.doubleValue ?? 60
        lock.lock()
        answers[key] = FirewallAnswer(pass: pass, until: now + ttl)
        // Answers expire; forget expired ones instead of keeping one per connection ever answered.
        if answers.count > 2000 { let t = now; answers = answers.filter { $0.value.until > t } }
        let entry = waiting.removeValue(forKey: key)
        lock.unlock()
        if let entry { for _ in 0..<max(entry.waiters, 1) { entry.done.signal() } }
    }

    /// The app's connection closed: whatever was waiting gets the mode's default.
    func clientGone(_ client: AgentClient) {
        lock.lock()
        let wasDecider = decider === client
        if wasDecider { decider = nil }
        let all = wasDecider ? waiting : [:]
        if wasDecider { waiting = [:] }
        lock.unlock()
        for (_, e) in all { for _ in 0..<max(e.waiters, 1) { e.done.signal() } }
    }

    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    // MARK: Turning it on and off

    fileprivate func enable() {
        if relay == nil {
            let r = FirewallRelay(port: Self.port)
            r.decide = { [weak self] flow in self?.decide(flow) ?? .pass }
            r.onEnd = { [weak self] flow in self?.report(flow) }
            let sockets = agent.recentSockets
            r.recentOwner = { tcp, port in sockets.owner(tcp: tcp, port: port, wait: 0.15) }
            do { try r.start() } catch {
                Agent.logError("firewall relay: \(error)")
                status("failed", "The relay couldn't start: \(error)")
                return
            }
            for _ in 0..<50 where !r.ready { usleep(20_000) }
            guard r.ready else { status("failed", "The relay couldn't listen on port \(Self.port)."); return }
            relay = r
        }
        let mdns = getpwnam("_mdnsresponder")?.pointee.pw_uid ?? 65
        let (l, problem) = PFRedirect.load(PFRedirect.rules(port: Self.port, exemptUIDs: [0, mdns]), failsafe: .whenGone(getpid()))
        guard let l else {
            Agent.logError("firewall: pf refused the rules: \(problem)")
            status("failed", "pf refused the rules.")
            return
        }
        lock.lock(); loaded = l; lock.unlock()
        Agent.log("firewall: redirect on (relay port \(Self.port))")
        status("on")
        startHealthCheck()
    }

    /// Removes the redirect. The relay keeps running so connections already through it finish normally.
    func disable(reason: String) {
        lock.lock()
        let l = loaded
        loaded = nil
        if !reason.isEmpty { mode = .off }
        let all = waiting
        waiting = [:]
        lock.unlock()
        for (_, e) in all { for _ in 0..<max(e.waiters, 1) { e.done.signal() } }
        if let l { PFRedirect.unload(l); Agent.log("firewall: redirect off\(reason.isEmpty ? "" : " (\(reason))")") }
        status(reason.isEmpty ? "off" : "failed", reason)
    }

    private var isOn: Bool { lock.lock(); defer { lock.unlock() }; return loaded != nil }

    /// Every 30 s the web through the relay, as the unprivileged user `nobody`; two failures in a row turn the
    /// redirect off, so a broken relay can't leave you without network.
    private func startHealthCheck() {
        lock.lock()
        guard !healthRunning else { lock.unlock(); return }
        healthRunning = true
        lock.unlock()
        Thread.detachNewThread { [self] in
            var failures = 0
            while !agent.wait(30) {
                guard isOn else { failures = 0; continue }
                lock.lock(); canaryUntil = now + 10; lock.unlock()
                let out = runOurs("/usr/bin/sudo", ["-n", "-u", "nobody", "/usr/bin/curl", "-s", "-m", "8", "-o", "/dev/null",
                                                    "-w", "%{http_code}", Self.canaryURL])
                lock.lock(); canaryUntil = 0; lock.unlock()
                let ok = out.hasPrefix("2") || out.hasPrefix("3")
                failures = ok ? 0 : failures + 1
                if failures >= 2 {
                    Agent.logError("firewall: web check through the relay failed twice; turning the redirect off")
                    disable(reason: "The web check through the relay failed twice, so the firewall turned itself off.")
                    failures = 0
                }
            }
            lock.lock(); healthRunning = false; lock.unlock()
        }
    }

    /// Runs a check as part of Hostwatch's own process tree, so its activity is never reported or judged.
    private func runOurs(_ path: String, _ args: [String]) -> String {
        guard let child = try? Spawned.start(path, args) else { return "" }
        agent.addToOurTree(Int(child.pid))                   // sudo; the curl it starts joins through its exec event
        var data = Data()
        if let fd = child.stdout {
            var buf = [UInt8](repeating: 0, count: 4096)
            while true { let n = read(fd, &buf, buf.count); if n <= 0 { break }; data.append(contentsOf: buf[0..<n]) }
        }
        child.wait()
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: Deciding

    /// Called by the relay for every new flow (on that flow's own thread).
    func decide(_ flow: RelayFlow) -> FirewallRelay.Decision {
        let key = Self.key(flow)
        lock.lock()
        let mode = self.mode
        if flow.program == "/usr/bin/curl", flow.host == Self.canaryHost, now < canaryUntil { lock.unlock(); return .pass }
        if agent.isOurs(Int(flow.pid)) { lock.unlock(); return .pass }                 // Hostwatch itself
        if let a = answers[key], a.until > now { lock.unlock(); return a.pass ? .pass : .block }
        guard mode != .off, let client = decider else { lock.unlock(); return mode == .strict ? .block : .pass }
        let entry: (id: Int, done: DispatchSemaphore, waiters: Int)
        var isNew = false
        if var e = waiting[key] {
            e.waiters += 1; waiting[key] = e; entry = e
        } else {
            nextAsk += 1
            entry = (nextAsk, DispatchSemaphore(value: 0), 1)
            waiting[key] = entry
            isNew = true
        }
        lock.unlock()
        if isNew { ask(entry.id, key: key, flow: flow, client: client) }
        // Ask: the connection waits as long as it takes you to answer (switching modes or the app going away
        // also ends the wait). Strict: only the app's quick answer.
        _ = entry.done.wait(timeout: .now() + (mode == .ask ? 24 * 3600 : 5))
        lock.lock()
        defer { lock.unlock() }
        if let a = answers[key], a.until > now { return a.pass ? .pass : .block }
        if waiting[key]?.id == entry.id { waiting[key] = nil }
        // No answer: switched off or to Watch → pass; Strict → blocked; Ask without the app → pass.
        switch self.mode {
        case .strict: return .block
        case .off: return .pass
        case .ask: return decider == nil ? .pass : .block
        }
    }

    private func ask(_ id: Int, key: String, flow: RelayFlow, client: AgentClient) {
        guard let dst = flow.original else { return }
        let target = dst.isV6 ? "[\(dst.address)]:\(dst.port)" : "\(dst.address):\(dst.port)"
        var ev = AgentEvent([("kind", .str("fw_ask")), ("id", .int(id)), ("key", .str(key)), ("time", .str(Agent.nowHMS())),
                             ("pid", .int(Int(flow.pid))), ("ppid", .int(agent.pidParent(Int(flow.pid)))),
                             ("name", .str(Self.name(flow))),
                             ("proc", .str(flow.program)), ("target", .str(target)), ("extra", .str(flow.tcp ? "TCP" : "UDP"))])
        if !flow.host.isEmpty { ev.set("host", .str(flow.host)); ev.set("host_src", .str("dns")) }
        else if let (host, source) = agent.resolveHosts([dst.address], budget: 0.2)[dst.address] {
            ev.set("host", .str(host)); ev.set("host_src", .str(source))
        }
        client.lock.lock()
        let ok = client.send(ev.jsonLine())
        client.lock.unlock()
        if !ok { clientGone(client) }
    }

    /// A finished flow the other sources may have missed (UDP above all) becomes an ordinary net event.
    private func report(_ flow: RelayFlow) {
        guard flow.pid > 0, let dst = flow.original, !agent.isOurs(Int(flow.pid)) else { return }
        let target = dst.isV6 ? "[\(dst.address)]:\(dst.port)" : "\(dst.address):\(dst.port)"
        // The program found when it connected: by the end of the flow a short-lived one has usually quit.
        agent.publishConnection(pid: Int(flow.pid), remote: target, proto: flow.tcp ? "TCP" : "UDP", nameHint: flow.name,
                                host: flow.host, budget: 0.2, blocked: flow.blocked, path: flow.program)
    }

    static func name(_ f: RelayFlow) -> String {
        let base = Agent.base(f.program)
        return !base.isEmpty ? base : !f.name.isEmpty ? f.name : "?"
    }

    private func status(_ state: String, _ detail: String = "") {
        lock.lock(); self.state = state; let client = decider; lock.unlock()
        guard let client else { return }
        let ev = AgentEvent([("kind", .str("fw_status")), ("state", .str(state)), ("detail", .str(detail))])
        client.lock.lock(); _ = client.send(ev.jsonLine()); client.lock.unlock()
    }

    /// The collector is stopping: remove the redirect now.
    func shutdown() {
        lock.lock(); let l = loaded; loaded = nil; lock.unlock()
        if let l { PFRedirect.unload(l) }
        relay?.stop()
    }
}
