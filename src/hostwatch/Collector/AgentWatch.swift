import Darwin
import Foundation

/// What the collector sends about a watch: {"kind":"watch","id":…,"state":"recording|done|failed","profile":{…}}.
struct WatchMessage: Codable, Sendable {
    var kind = "watch"
    var id: String
    var state: String
    var detail = ""
    var profile: BehaviorProfile?

    static let encoder = JSONEncoder()          // dates as numbers: exact
    static let decoder = JSONDecoder()

    func line() -> Data { ((try? Self.encoder.encode(self)) ?? Data()) + Data("\n".utf8) }
}

/// The collector's side of Watch Closely: a second eslogger with the watch's event types, kept to the watched
/// process tree (lines are checked for its pids before they're parsed), summarised by a BehaviorRecorder and sent
/// to the app every 2 s. One watch at a time; it ends at its time limit, when you stop it, when every watched
/// process has exited, or when the app goes away.
final class AgentWatch: @unchecked Sendable {
    static let maxSeconds: Double = 300
    static let maxEvents = 2_000_000

    private let agent: Agent
    private let lock = NSLock()
    private var session: Session?

    final class Session: @unchecked Sendable {
        let id: String
        let recorder: BehaviorRecorder
        weak var client: AgentClient?
        var child: Spawned?
        let started = ProcessInfo.processInfo.systemUptime
        var stopped = false
        var why = ""
        init(id: String, recorder: BehaviorRecorder, client: AgentClient?) {
            self.id = id; self.recorder = recorder; self.client = client
        }
    }

    init(agent: Agent) { self.agent = agent }

    /// The event types this macOS's eslogger knows, of the ones a watch wants.
    static let supportedEvents: [String] = {
        let out = (try? Spawned.run("/usr/bin/eslogger", ["--list-events"])) ?? Data()
        let known = Set(String(decoding: out, as: UTF8.self).split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) })
        return known.isEmpty ? ["exec", "fork", "exit", "open"] : BehaviorRecorder.events.filter(known.contains)
    }()

    // MARK: From the app

    /// {"watch": {"id": "…", "pid": 123, "seconds": 60}} starts one; {"watch": {"id": "…", "stop": true}} stops it.
    func handle(_ cfg: [String: Any], from client: AgentClient) {
        let id = cfg["id"] as? String ?? UUID().uuidString
        if cfg["stop"] as? Bool == true { stop(id: id, why: "stopped"); return }
        let pid = Agent.intValue(cfg["pid"])
        let seconds = min(Self.maxSeconds, max(10, (cfg["seconds"] as? NSNumber)?.doubleValue ?? 60))
        start(id: id, pid: pid, seconds: seconds, client: client)
    }

    func clientGone(_ client: AgentClient) {
        lock.lock(); let s = session; lock.unlock()
        if let s, s.client == nil || s.client === client { stop(id: s.id, why: "the app went away") }
    }

    /// A network connection the collector reported: part of the profile when it's the tree's.
    func noteConnection(_ ev: AgentEvent) {
        lock.lock(); let s = session; lock.unlock()
        guard let s else { return }
        lock.lock()
        s.recorder.addConnection(pid: ev.int("pid"), proto: ev.string("extra"), remote: ev.string("target"), host: ev.string("host"))
        lock.unlock()
    }

    // MARK: Recording

    func start(id: String, pid: Int, seconds: Double, client: AgentClient?) {
        if let old = currentID { stop(id: old, why: "replaced by a new watch") }
        let path = ProcessList.path(pid)
        guard pid > 0, !path.isEmpty, kill(pid_t(pid), 0) == 0 || errno == EPERM else {
            send(WatchMessage(id: id, state: "failed", detail: "That process isn't running any more."), to: client)
            return
        }
        agent.netLock.lock(); let args = agent.pidArgs[pid] ?? ""; agent.netLock.unlock()
        let recorder = BehaviorRecorder(pid: pid, name: Agent.base(path), path: path, args: args,
                                        ppid: ProcessList.parent(pid), limit: seconds, home: Self.homeOfClient())
        recorder.adopt(BehaviorRecorder.descendants(of: pid))         // helpers it already runs
        let s = Session(id: id, recorder: recorder, client: client)
        let child: Spawned
        do {
            child = try Spawned.start("/usr/bin/eslogger", Self.supportedEvents)
        } catch {
            send(WatchMessage(id: id, state: "failed", detail: "Endpoint Security couldn't start: \(error)"), to: client)
            return
        }
        s.child = child
        agent.ignore(Int(child.pid))
        lock.lock(); session = s; lock.unlock()
        Agent.log("watch \(id): pid \(pid) (\(path)) for \(Int(seconds)) s, \(Self.supportedEvents.count) event types")
        Thread.detachNewThread { [self] in read(s, child) }
        Thread.detachNewThread { [self] in report(s, limit: seconds) }
    }

    private var currentID: String? { lock.lock(); defer { lock.unlock() }; return session?.id }

    func stop(id: String, why: String) {
        lock.lock()
        guard let s = session, s.id == id, !s.stopped else { lock.unlock(); return }
        s.stopped = true
        s.why = why
        lock.unlock()
        s.child?.terminate()
    }

    /// eslogger's lines: only those that mention a pid of the tree are parsed.
    private func read(_ s: Session, _ child: Spawned) {
        let reader = LineReader(fd: child.stdout!)
        var markers: [Data] = []
        var treeSize = 0
        reader.forEach { line in
            lock.lock()
            if s.stopped { lock.unlock(); return false }
            if s.recorder.tree.count != treeSize { markers = s.recorder.markers; treeSize = s.recorder.tree.count }
            lock.unlock()
            guard markers.contains(where: { line.range(of: $0) != nil }),
                  let raw = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return true }
            lock.lock()
            s.recorder.add(raw)
            let tooMany = s.recorder.profile.events >= Self.maxEvents
            lock.unlock()
            if tooMany { stop(id: s.id, why: "event limit reached") }
            return true
        }
        child.wait()
        agent.unignore(Int(child.pid))
    }

    /// Every 2 s the profile so far; at the end the final one.
    private func report(_ s: Session, limit: Double) {
        var exitedSince: TimeInterval?
        while true {
            let done = agent.wait(2)
            let elapsed = ProcessInfo.processInfo.systemUptime - s.started
            lock.lock()
            s.recorder.tick(seconds: elapsed)
            if s.recorder.allExited {
                exitedSince = exitedSince ?? elapsed
            }
            let stopped = s.stopped
            lock.unlock()
            var why = ""
            if done { why = "the collector stopped" }
            else if stopped { lock.lock(); why = s.why; lock.unlock() }
            else if elapsed >= limit { why = "time limit" }
            else if let t = exitedSince, elapsed - t >= 1 { why = "the process exited" }
            if !why.isEmpty {
                stop(id: s.id, why: why)
                lock.lock()
                s.recorder.finish(why)
                let profile = s.recorder.profile
                if session === s { session = nil }
                lock.unlock()
                send(WatchMessage(id: s.id, state: "done", detail: why, profile: profile), to: s.client)
                Agent.log("watch \(s.id): done (\(why)), \(profile.events) events")
                return
            }
            lock.lock(); let profile = s.recorder.profile; lock.unlock()
            send(WatchMessage(id: s.id, state: "recording", profile: profile), to: s.client)
        }
    }

    private func send(_ m: WatchMessage, to client: AgentClient?) {
        guard let client else { return }
        client.lock.lock()
        let ok = client.send(m.line())
        client.lock.unlock()
        if !ok { agent.dropClient(client) }
    }

    /// The home folder of the user who ran the app (for ~ in paths): the console user.
    static func homeOfClient() -> String {
        var uid: uid_t = 0
        if let s = SCConsoleUser.uid() { uid = s }
        if uid != 0, let pw = getpwuid(uid) { return String(cString: pw.pointee.pw_dir) }
        return ProcessInfo.processInfo.environment["SUDO_USER"].flatMap { getpwnam($0) }.map { String(cString: $0.pointee.pw_dir) }
            ?? NSHomeDirectory()
    }

    // MARK: Test tool

    static let testFlag = "--watch-test"

    /// `sudo Hostwatch --watch-test <pid> [seconds]`: records a process for a while (30 s by default) and prints what
    /// the window would show: highlights, then the evidence the AI gets. Network isn't included (that needs the
    /// collector's connection sources).
    static func runTest(_ args: [String]) -> Never {
        setvbuf(stdout, nil, _IOLBF, 0)
        guard geteuid() == 0 else { print("Run it with sudo:  sudo '\(CommandLine.arguments[0])' \(testFlag) <pid> [seconds]"); exit(1) }
        guard let pid = args.first.flatMap(Int.init) else { print("Usage: \(testFlag) <pid> [seconds]"); exit(1) }
        let seconds = args.dropFirst().first.flatMap(Double.init).map { max(5, min($0, maxSeconds)) } ?? 30
        let path = ProcessList.path(pid)
        guard !path.isEmpty else { print("No process \(pid)."); exit(1) }
        let recorder = BehaviorRecorder(pid: pid, name: Agent.base(path), path: path, ppid: ProcessList.parent(pid),
                                        limit: seconds, home: homeOfClient())
        recorder.adopt(BehaviorRecorder.descendants(of: pid))
        print("Watching \(Agent.base(path)) (pid \(pid)) and \(recorder.tree.count - 1) process(es) it already runs, for "
              + "\(Int(seconds)) s with \(supportedEvents.count) event types…")
        guard let child = try? Spawned.start("/usr/bin/eslogger", supportedEvents) else { print("eslogger didn't start."); exit(1) }
        let lock = NSLock()
        var parsed = 0, skipped = 0
        var ignored: [String: Int] = [:]                    // matched a pid but weren't the tree's own events
        Thread.detachNewThread {
            let reader = LineReader(fd: child.stdout!)
            while let line = reader.next() {
                lock.lock()
                let markers = recorder.markers
                lock.unlock()
                guard markers.contains(where: { line.range(of: $0) != nil }),
                      let raw = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { skipped += 1; continue }
                lock.lock()
                let before = recorder.profile.events
                recorder.add(raw)
                parsed += 1
                if recorder.profile.events == before {
                    let type = (raw["event"] as? [String: Any])?.keys.first ?? "?"
                    let caller = raw["process"] as? [String: Any]
                    ignored["\(type) by \(Agent.base(Agent.exe(caller))) (\(Agent.pid(caller)))", default: 0] += 1
                }
                lock.unlock()
            }
        }
        let start = Date()
        while Date().timeIntervalSince(start) < seconds {
            sleep(1)
            lock.lock(); let done = recorder.allExited; lock.unlock()
            if done { sleep(1); break }
        }
        child.terminate()
        lock.lock()
        recorder.tick(seconds: Date().timeIntervalSince(start))
        recorder.finish(recorder.allExited ? "the process exited" : "time limit")
        let profile = recorder.profile
        lock.unlock()
        print("Lines: \(parsed) parsed for the tree, \(skipped) skipped (other processes). Events: \(profile.events).")
        if !ignored.isEmpty {
            print("Mentioned the tree but done by others (not counted): "
                  + ignored.sorted { $0.value > $1.value }.prefix(8).map { "\($0.key) ×\($0.value)" }.joined(separator: ", "))
        }
        print("\nHighlights:")
        for h in profile.highlights() { print("  [\(h.level)] \(h.text)") }
        print("\n" + profile.evidence())
        exit(0)
    }
}

/// The logged-in (console) user.
enum SCConsoleUser {
    static func uid() -> uid_t? {
        var st = stat()
        guard stat("/dev/console", &st) == 0 else { return nil }
        return st.st_uid
    }
}
