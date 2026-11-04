import AppKit
import Foundation

// Claude Code guard: a PreToolUse hook (`Hostwatch --claude-hook`) hands every Bash command, file write, read
// and web fetch to Hostwatch before it happens. Dangerous → blocked; risky → you're asked (in Claude Code, or in
// a Hostwatch panel when Claude Code won't ask); everything else → Claude Code's normal permissions. Hostwatch
// never answers "allow", so it can only make Claude Code stricter.

/// The app's answer to the hook.
struct GuardReply: Codable, Equatable, Sendable {
    enum Decision: String, Codable, Sendable { case none, ask, deny }
    var decision: Decision
    var reason: String = ""

    static let none = GuardReply(decision: .none)

    /// What the hook prints: nothing (normal permissions) or Claude Code's PreToolUse decision.
    var hookOutput: Data? {
        guard decision != .none else { return nil }
        let out: [String: Any] = ["hookSpecificOutput": [
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.rawValue,
            "permissionDecisionReason": reason,
        ]]
        return try? JSONSerialization.data(withJSONObject: out)
    }
}

/// One tool call, as the hook receives it.
struct GuardRequest: Sendable {
    var tool: String
    var input: [String: any Sendable]
    var cwd: String
    var mode: String
    var session: String

    init?(json: Data) {
        guard let obj = (try? JSONSerialization.jsonObject(with: json)) as? [String: Any],
              let tool = obj["tool_name"] as? String else { return nil }
        self.tool = tool
        input = (obj["tool_input"] as? [String: Any] ?? [:]).compactMapValues { Self.sendable($0) }
        cwd = obj["cwd"] as? String ?? ""
        mode = obj["permission_mode"] as? String ?? "default"
        session = obj["session_id"] as? String ?? ""
    }

    private static func sendable(_ v: Any) -> (any Sendable)? {
        switch v {
        case let s as String: s
        case let n as NSNumber: n.doubleValue
        case let a as [[String: Any]]: a.map { $0.compactMapValues { $0 as? String } }
        default: nil
        }
    }

    /// What the call is about, for the panel and the log: the command, the file or the URL.
    var subject: String {
        for key in ["command", "file_path", "notebook_path", "url", "path"] {
            if let s = input[key] as? String, !s.isEmpty { return s }
        }
        return tool
    }

    /// Claude Code won't show its own prompt in these modes, so "ask" would mean "run".
    var claudeWontAsk: Bool { ["bypassPermissions", "dontAsk"].contains(mode) }
}

enum ClaudeHook {
    static let flag = "--claude-hook"
    /// Seconds the hook may take (Claude Code cancels it after this, set in the hook's settings).
    static let timeout = 90
    /// How long Hostwatch's panel waits for you before it blocks the call.
    static let confirmSeconds: TimeInterval = 60

    static var socketPath: String { AppPaths.support.appendingPathComponent("guard/claude.sock").path }

    /// The decision for a verdict. `confirm` asks you in Hostwatch (nil when Hostwatch isn't running).
    static func reply(_ v: GuardVerdict, request: GuardRequest, confirm: ((String) -> Bool?)?) -> GuardReply {
        switch v.level {
        case .ok:
            return .none
        case .deny:
            return GuardReply(decision: .deny, reason: "Hostwatch blocked this: it \(v.summary). If it's really needed, "
                              + "ask the user to run it themselves.")
        case .ask:
            guard request.claudeWontAsk else { return GuardReply(decision: .ask, reason: "Hostwatch: this \(v.summary).") }
            switch confirm?(v.summary) {
            case true?: return .none
            case false?: return GuardReply(decision: .deny, reason: "The user declined this in Hostwatch: it \(v.summary).")
            case nil:
                return GuardReply(decision: .deny, reason: "Hostwatch couldn't ask the user (Claude Code isn't asking in this "
                                  + "mode and Hostwatch didn't get an answer): it \(v.summary). Ask the user to run it themselves.")
            }
        }
    }

    /// `Hostwatch --claude-hook`: reads the call from stdin, asks the running app (or judges it here with the
    /// built-in rules when the app isn't running), prints the decision. Always exits 0: a broken hook mustn't
    /// break Claude Code, and blocking is said in JSON.
    static func run() -> Never {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard let request = GuardRequest(json: input) else { exit(0) }
        let reply = askApp(input) ?? Self.reply(CommandGuard().assess(tool: request.tool, input: request.input, cwd: request.cwd),
                                               request: request, confirm: nil)
        if let out = reply.hookOutput { FileHandle.standardOutput.write(out) }
        exit(0)
    }

    /// The running app's reply over its socket; nil if it isn't running or doesn't answer in time.
    static func askApp(_ input: Data, path: String = socketPath) -> GuardReply? {
        guard let fd = UnixSocket.connect(path) else { return nil }
        defer { close(fd) }
        var timeout = timeval(tv_sec: Int(confirmSeconds) + 20, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var line = input.filter { $0 != 0x0A }
        line.append(0x0A)
        guard UnixSocket.send(fd, line), let answer = UnixSocket.readLine(fd, limit: 64_000) else { return nil }
        return try? JSONDecoder().decode(GuardReply.self, from: answer)
    }
}

enum UnixSocket {
    static func connect(_ path: String) -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { close(fd); return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in raw.copyBytes(from: bytes); raw[bytes.count] = 0 }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard ok == 0 else { close(fd); return nil }
        return fd
    }

    static func send(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = Darwin.send(fd, raw.baseAddress! + sent, raw.count - sent, 0)
                if n <= 0 { if n < 0 && errno == EINTR { continue }; return false }
                sent += n
            }
            return true
        }
    }

    /// One line (without the newline), or nil on timeout, close or overflow.
    static func readLine(_ fd: Int32, limit: Int) -> Data? {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 16_384)
        while buffer.count <= limit {
            let n = recv(fd, &chunk, chunk.count, 0)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return nil }
            buffer.append(contentsOf: chunk[0..<n])
            if let nl = buffer.firstIndex(of: 0x0A) { return buffer[buffer.startIndex..<nl] }
        }
        return nil
    }
}

// MARK: - Claude Code's settings file

/// Adds and removes Hostwatch's hook in Claude Code's user settings (~/.claude/settings.json), leaving
/// everything else as it is.
enum ClaudeSettingsFile {
    static var defaultURL: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude/settings.json") }
    static let matcher = CommandGuard.tools.joined(separator: "|")

    static func command(executable: String) -> String {
        "'" + executable.replacingOccurrences(of: "'", with: "'\\''") + "' " + ClaudeHook.flag
    }

    enum Problem: Error, Equatable { case unreadable(String) }

    static func read(_ url: URL) throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        guard let data = FileManager.default.contents(atPath: url.path),
              let obj = (data.isEmpty ? [:] : try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw Problem.unreadable("\(url.path) isn't valid JSON, so Hostwatch won't change it")
        }
        return obj
    }

    /// Our hook's command line, if installed.
    static func installedCommand(in json: [String: Any]) -> String? {
        let groups = (json["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]] ?? []
        for group in groups {
            for hook in group["hooks"] as? [[String: Any]] ?? [] {
                if let c = hook["command"] as? String, c.contains(ClaudeHook.flag) { return c }
            }
        }
        return nil
    }

    static func hooksDisabled(in json: [String: Any]) -> Bool { json["disableAllHooks"] as? Bool == true }

    static func adding(_ command: String, to json: [String: Any]) -> [String: Any] {
        var json = removing(from: json)
        var hooks = json["hooks"] as? [String: Any] ?? [:]
        var groups = hooks["PreToolUse"] as? [[String: Any]] ?? []
        groups.append(["matcher": matcher,
                       "hooks": [["type": "command", "command": command, "timeout": ClaudeHook.timeout]]])
        hooks["PreToolUse"] = groups
        json["hooks"] = hooks
        return json
    }

    static func removing(from json: [String: Any]) -> [String: Any] {
        var json = json
        guard var hooks = json["hooks"] as? [String: Any], let groups = hooks["PreToolUse"] as? [[String: Any]] else { return json }
        let kept: [[String: Any]] = groups.compactMap { group in
            var group = group
            let list = (group["hooks"] as? [[String: Any]] ?? []).filter { !(($0["command"] as? String ?? "").contains(ClaudeHook.flag)) }
            if list.isEmpty, group["hooks"] != nil { return nil }
            group["hooks"] = list
            return group
        }
        if kept.isEmpty { hooks.removeValue(forKey: "PreToolUse") } else { hooks["PreToolUse"] = kept }
        if hooks.isEmpty { json.removeValue(forKey: "hooks") } else { json["hooks"] = hooks }
        return json
    }

    /// Writes atomically; the first time, keeps the original next to it (settings.json.before-hostwatch).
    static func write(_ json: [String: Any], to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let backup = url.appendingPathExtension("before-hostwatch")
        if FileManager.default.fileExists(atPath: url.path), !FileManager.default.fileExists(atPath: backup.path) {
            try? FileManager.default.copyItem(at: url, to: backup)
        }
        var data = try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        data.append(0x0A)
        try data.write(to: url, options: .atomic)
    }
}

// MARK: - The app's side

/// A call Hostwatch is asking you about (Claude Code won't ask in its current mode).
struct GuardPrompt: Identifiable {
    let id = UUID()
    let tool: String
    let subject: String
    let reason: String
    let cwd: String
    let deadline: Date
    let answer: (Bool?) -> Void
}

struct GuardLogEntry: Codable, Identifiable, Equatable {
    enum Outcome: String, Codable { case blocked, asked, allowedHere, declinedHere, noAnswer }
    var id = UUID()
    var date: Date
    var tool: String
    var subject: String
    var reason: String
    var cwd: String
    var outcome: Outcome
}

@MainActor
final class ClaudeGuard: ObservableObject {
    enum Status: Equatable {
        case off, active, missing, hooksDisabled, failed(String)
    }

    @Published private(set) var enabled: Bool
    @Published private(set) var status: Status = .off
    @Published private(set) var log: [GuardLogEntry] = []
    @Published private(set) var checked = 0
    @Published private(set) var prompts: [GuardPrompt] = []

    /// Host or IP → why it's known-bad (the threat lists).
    var listed: (String) -> String? = { _ in nil }
    /// Called when prompts appear or go (the app shows or hides the panel).
    var onPromptsChange: (() -> Void)?

    let settingsURL: URL
    let executable: String
    let socketPath: String
    private let defaults: UserDefaults
    private let logURL: URL
    private var server: Int32 = -1
    private var timer: Timer?
    static let maxLog = 300

    init(settingsURL: URL = ClaudeSettingsFile.defaultURL, executable: String = Bundle.main.executablePath ?? CommandLine.arguments[0],
         defaults: UserDefaults = .standard, logURL: URL = AppPaths.support.appendingPathComponent("claude-guard.json"),
         socketPath: String = ClaudeHook.socketPath) {
        self.settingsURL = settingsURL
        self.socketPath = socketPath
        self.executable = executable
        self.defaults = defaults
        self.logURL = logURL
        enabled = defaults.bool(forKey: "claudeGuard")
        if let data = try? Data(contentsOf: logURL), let saved = try? JSONDecoder.iso.decode(Saved.self, from: data) {
            log = saved.log; checked = saved.checked
        }
    }

    private struct Saved: Codable { var log: [GuardLogEntry]; var checked: Int }

    var hookCommand: String { ClaudeSettingsFile.command(executable: executable) }

    // MARK: Installing

    func setEnabled(_ on: Bool) {
        do {
            let json = try ClaudeSettingsFile.read(settingsURL)
            let updated = on ? ClaudeSettingsFile.adding(hookCommand, to: json) : ClaudeSettingsFile.removing(from: json)
            try ClaudeSettingsFile.write(updated, to: settingsURL)
            enabled = on
            defaults.set(on, forKey: "claudeGuard")
            refreshStatus()
        } catch {
            status = .failed((error as? ClaudeSettingsFile.Problem).map { if case .unreadable(let s) = $0 { s } else { "" } }
                             ?? error.localizedDescription)
        }
    }

    /// Whether the hook is still in Claude Code's settings; keeps its path current if the app moved.
    func refreshStatus() {
        guard enabled else { status = .off; return }
        guard let json = try? ClaudeSettingsFile.read(settingsURL) else {
            status = .failed("\(settingsURL.path) isn't valid JSON"); return
        }
        guard let installed = ClaudeSettingsFile.installedCommand(in: json) else { status = .missing; return }
        if installed != hookCommand, FileManager.default.isExecutableFile(atPath: executable) {
            try? ClaudeSettingsFile.write(ClaudeSettingsFile.adding(hookCommand, to: json), to: settingsURL)
        }
        status = ClaudeSettingsFile.hooksDisabled(in: json) ? .hooksDisabled : .active
    }

    // MARK: Serving the hook

    func start() {
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshStatus() }
        }
        do {
            server = try AgentSocket.create(path: socketPath, clientUID: nil)
        } catch {
            NSLog("Hostwatch: Claude guard socket: \(error)")
            return
        }
        let fd = server
        Thread.detachNewThread { [weak self] in self?.accept(fd) }
    }

    nonisolated private func accept(_ server: Int32) {
        while true {
            let fd = Darwin.accept(server, nil, nil)
            if fd < 0 { if errno == EINTR || errno == EAGAIN { continue }; return }
            // Only this user's processes (the socket is 0600 in our folder; checked again here).
            guard let peer = AgentSocket.peer(fd), peer.uid == getuid() else { close(fd); continue }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            Thread.detachNewThread { [weak self] in self?.serve(fd) }
        }
    }

    nonisolated private func serve(_ fd: Int32) {
        defer { close(fd) }
        guard let line = UnixSocket.readLine(fd, limit: 4_000_000), let request = GuardRequest(json: line) else { return }
        let done = DispatchSemaphore(value: 0)
        let box = ReplyBox()
        DispatchQueue.main.async { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { done.signal(); return }
                self.handle(request) { reply in box.reply = reply; done.signal() }
            }
        }
        _ = done.wait(timeout: .now() + ClaudeHook.confirmSeconds + 10)
        let reply = box.reply ?? GuardReply(decision: .deny, reason: "Hostwatch didn't answer in time.")
        guard var data = try? JSONEncoder().encode(reply) else { return }
        data.append(0x0A)
        _ = UnixSocket.send(fd, data)
    }

    private final class ReplyBox: @unchecked Sendable { var reply: GuardReply? }

    /// Judges a call and answers through `reply` (at once, or after you answer the panel).
    func handle(_ request: GuardRequest, reply: @escaping (GuardReply) -> Void) {
        let verdict = CommandGuard(listed: listed).assess(tool: request.tool, input: request.input, cwd: request.cwd)
        checked += 1
        switch verdict.level {
        case .ok:
            reply(.none)
            if checked % 25 == 0 { save() }
        case .deny:
            record(request, verdict, .blocked)
            reply(ClaudeHook.reply(verdict, request: request, confirm: nil))
        case .ask where !request.claudeWontAsk:
            record(request, verdict, .asked)
            reply(ClaudeHook.reply(verdict, request: request, confirm: nil))
        case .ask:
            let prompt = GuardPrompt(tool: request.tool, subject: request.subject, reason: verdict.summary, cwd: request.cwd,
                                     deadline: Date().addingTimeInterval(ClaudeHook.confirmSeconds)) { [weak self] answer in
                guard let self else { return }
                self.record(request, verdict, answer == true ? .allowedHere : answer == false ? .declinedHere : .noAnswer)
                reply(ClaudeHook.reply(verdict, request: request, confirm: { _ in answer }))
            }
            prompts.append(prompt)
            onPromptsChange?()
            DispatchQueue.main.asyncAfter(deadline: .now() + ClaudeHook.confirmSeconds) { [weak self] in
                self?.answer(prompt.id, nil)
            }
        }
    }

    /// Your answer in the panel (nil: no answer in time).
    func answer(_ id: UUID, _ allow: Bool?) {
        guard let i = prompts.firstIndex(where: { $0.id == id }) else { return }
        let prompt = prompts.remove(at: i)
        prompt.answer(allow)
        onPromptsChange?()
    }

    private func record(_ request: GuardRequest, _ verdict: GuardVerdict, _ outcome: GuardLogEntry.Outcome) {
        let entry = GuardLogEntry(date: Date(), tool: request.tool,
                                  subject: String(Secrets.mask(request.subject, marker: Secrets.historyMarker).prefix(2_000)),
                                  reason: verdict.summary, cwd: request.cwd, outcome: outcome)
        log.insert(entry, at: 0)
        if log.count > Self.maxLog { log.removeLast(log.count - Self.maxLog) }
        save()
    }

    func clearLog() { log = []; checked = 0; save() }

    /// Blocked or asked in the last 24 hours.
    var recentCount: Int { log.filter { $0.date > Date().addingTimeInterval(-86400) }.count }
    var recentBlocked: Int { log.filter { $0.date > Date().addingTimeInterval(-86400) && $0.outcome == .blocked }.count }

    private func save() {
        guard let data = try? JSONEncoder.iso.encode(Saved(log: log, checked: checked)) else { return }
        try? FileManager.default.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: logURL, options: .atomic)
        chmod(logURL.path, 0o600)
    }
}

private extension JSONDecoder {
    static let iso: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}

private extension JSONEncoder {
    static let iso: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }()
}
