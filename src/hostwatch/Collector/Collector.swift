import AppKit
import Darwin
import Foundation

/// Starts and stops the root collector (`Hostwatch --collector`, built into this binary).
/// Elevation goes through the standard macOS admin prompt.
@MainActor
final class Collector: ObservableObject {
    enum State: Equatable {
        case stopped
        case starting
        case running(pid: Int32)
        case failed(String)
        case needsFullDiskAccess
    }

    @Published private(set) var state: State = .stopped

    @Published var startAtLaunch: Bool {
        didSet { UserDefaults.standard.set(startAtLaunch, forKey: "startCollectorAtLaunch") }
    }

    let logURL: URL
    /// The collector as a background service (Developer ID builds): registered and approved once.
    let daemon = CollectorDaemon()
    var usesDaemon: Bool { daemon.available }
    /// The service is registered but waits for your approval in Login Items (the app shows how).
    var onNeedsApproval: (() -> Void)?
    private var approvalWatch: Timer?
    private let tokenURL: URL
    private(set) var token = ""
    private var monitor: Timer?
    private var logOffset: UInt64 = 0

    /// Called when eslogger is refused for lack of Full Disk Access.
    var onNeedsFullDiskAccess: (() -> Void)?

    init() {
        let fm = FileManager.default
        let support = AppPaths.support
        let logs = AppPaths.logs
        try? fm.createDirectory(at: support, withIntermediateDirectories: true)
        try? fm.createDirectory(at: logs, withIntermediateDirectories: true)
        tokenURL = support.appendingPathComponent("collector.token")
        logURL = logs.appendingPathComponent("agent.log")
        startAtLaunch = UserDefaults.standard.object(forKey: "startCollectorAtLaunch") as? Bool ?? true
    }

    var isRunning: Bool {
        if usesDaemon { return daemon.isEnabled }
        if case .running = state { return true }
        return false
    }

    var statusText: String {
        if usesDaemon, state != .needsFullDiskAccess {
            if case .failed = state {} else { return daemon.statusText }
        }
        switch state {
        case .stopped: return "Collector stopped"
        case .starting: return "Collector starting…"
        case .running(let pid): return "Collector running (PID \(pid))"
        case .failed: return "Collector failed — see log"
        case .needsFullDiskAccess: return "Collector needs Full Disk Access"
        }
    }

    static let jobLabel = "local.hostwatch.collector"


    // MARK: Start

    func start() {
        if usesDaemon { startService(); return }
        guard !isRunning, state != .starting else { return }
        let executable = Bundle.main.executablePath ?? CommandLine.arguments[0]
        do {
            token = Self.randomToken()
            try writeToken(token)
        } catch {
            state = .failed("Cannot write token file: \(error.localizedDescription)")
            return
        }

        // Run as a launchd job whose program is this app's own binary (collector-launcher
        // mode). launchd jobs are their own TCC "responsible process", so eslogger is
        // checked against Hostwatch.app's Full Disk Access grant. A plain
        // `do shell script … with administrator privileges` would make macOS's auth
        // helper responsible instead, and the grant would never apply.
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        let plist: [String: Any] = [
            "Label": Self.jobLabel,
            "ProgramArguments": [
                executable, collectorLauncherFlag,
                executable, collectorFlag,
                "--owner-pid", String(getpid()),
                "--token-file", tokenURL.path,
                "--socket", CollectorSocket.path,
            ],
            "RunAtLoad": true,
            "KeepAlive": false,
            "ProcessType": "Interactive",
            "StandardOutPath": logURL.path,
            "StandardErrorPath": logURL.path,
        ]
        let plistURL = FileManager.default.temporaryDirectory.appendingPathComponent("\(Self.jobLabel).plist")
        do {
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try data.write(to: plistURL, options: .atomic)
        } catch {
            state = .failed("Cannot write launchd job: \(error.localizedDescription)")
            return
        }

        // Copy the job into a fresh root-owned directory, (re)load it, print the launcher PID.
        let job = "system/\(Self.jobLabel)"
        let command = """
        launchctl bootout \(job) >/dev/null 2>&1; \
        D=$(mktemp -d /private/tmp/hostwatch.XXXXXX) && \
        cp \(sh(plistURL.path)) "$D/job.plist" && chown root:wheel "$D/job.plist" && chmod 644 "$D/job.plist" && \
        launchctl bootstrap system "$D/job.plist" && sleep 1 && \
        launchctl print \(job) | awk '$1=="pid" && $2=="=" {print $3; exit}'
        """
        let appleScript = """
        do shell script "\(appleScriptEscape(command))" with administrator privileges \
        with prompt "Hostwatch needs administrator access to start its Endpoint Security collector."
        """

        logOffset = (try? FileManager.default.attributesOfItem(atPath: logURL.path)[.size] as? NSNumber)?.uint64Value ?? 0
        state = .starting
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Self.runOsascript(appleScript)
            DispatchQueue.main.async { self.finishStart(result) }
        }
    }

    private func finishStart(_ result: Result<String, Error>) {
        switch result {
        case .success(let output):
            guard let pid = Int32(output.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 else {
                // Job loaded but already exited: explain why from the log.
                evaluateExit()
                return
            }
            state = .running(pid: pid)
            startMonitoring()
        case .failure(let error):
            let message = error.localizedDescription
            // -128 = user pressed Cancel in the password dialog.
            state = message.contains("-128") ? .stopped : .failed(message)
        }
    }

    // MARK: The background service

    /// Registers the service (one admin password, then approval in Login Items, once). Once it runs, the app
    /// connects to its socket by itself; its log says if Full Disk Access is missing.
    private func startService() {
        daemon.refresh()
        if daemon.status == .notRegistered || daemon.status == .notFound {
            logOffset = (try? FileManager.default.attributesOfItem(atPath: CollectorDaemon.logURL.path)[.size] as? NSNumber)?.uint64Value ?? 0
            daemon.register()
            if let problem = daemon.problem {
                state = problem == "cancelled" ? .stopped : .failed(problem)
                return
            }
        }
        watchService()
    }

    /// Follows the service's state: approval given, or the service failing for lack of Full Disk Access.
    private func watchService() {
        approvalWatch?.invalidate()
        if daemon.needsApproval { onNeedsApproval?() }
        state = daemon.isEnabled ? .running(pid: 0) : .starting
        var checks = 0
        approvalWatch = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.daemon.refresh()
                checks += 1
                if self.daemon.isEnabled {
                    if case .running = self.state {} else { self.state = .running(pid: 0) }
                    // A few seconds in: did it fail for lack of Full Disk Access?
                    if checks % 3 == 0, self.serviceLogSinceStart().contains("ERR_NOT_PERMITTED") {
                        self.state = .needsFullDiskAccess
                        self.onNeedsFullDiskAccess?()
                        self.approvalWatch?.invalidate()
                    }
                    if checks >= 30 { self.approvalWatch?.invalidate() }
                } else if self.daemon.status == .notRegistered {
                    self.state = .stopped
                    self.approvalWatch?.invalidate()
                }
            }
        }
    }

    private func serviceLogSinceStart() -> String {
        guard let handle = try? FileHandle(forReadingFrom: CollectorDaemon.logURL) else { return "" }
        defer { try? handle.close() }
        try? handle.seek(toOffset: logOffset)
        return String(decoding: handle.readDataToEndOfFile(), as: UTF8.self)
    }

    /// Removes the service (an admin password): the collector stops and won't start at boot.
    func stopService() {
        approvalWatch?.invalidate()
        daemon.unregister()
        state = daemon.isEnabled ? .running(pid: 0) : .stopped
    }

    // MARK: Stop

    /// Stops a collector this app started. Uses the shutdown token over the
    /// existing connection; the agent also exits on its own when the app quits.
    func stop(via model: HUDModel, completion: (() -> Void)? = nil) {
        if usesDaemon { stopService(); completion?(); return }
        guard isRunning else { completion?(); return }
        let sent = model.sendShutdown(token: token) { completion?() }
        if !sent {
            // Not connected yet: fall back to an admin-prompted kill.
            if case .running(let pid) = state {
                _ = pid
                let script = "do shell script \"launchctl bootout system/\(Self.jobLabel)\" with administrator privileges"
                DispatchQueue.global().async { _ = Self.runOsascript(script) }
            }
        }
        state = .stopped
        monitor?.invalidate()
    }

    // MARK: Monitoring

    private func startMonitoring() {
        monitor?.invalidate()
        monitor = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkAlive() }
        }
    }

    private func checkAlive() {
        guard case .running(let pid) = state else { monitor?.invalidate(); return }
        // Root-owned process: kill(pid, 0) gives EPERM while it is alive.
        if kill(pid, 0) == 0 || errno == EPERM { return }
        monitor?.invalidate()
        evaluateExit()
    }

    private func evaluateExit() {
        let output = logSinceStart()
        if output.contains("ERR_NOT_PERMITTED") || output.contains("Full Disk Access") {
            state = .needsFullDiskAccess
            onNeedsFullDiskAccess?()
        } else {
            let tail = output.split(separator: "\n").suffix(6).joined(separator: "\n")
            state = .failed(tail.isEmpty ? "Collector exited without output." : tail)
        }
    }

    /// Log text written since the most recent start.
    private func logSinceStart() -> String {
        guard let handle = try? FileHandle(forReadingFrom: logURL) else { return "" }
        defer { try? handle.close() }
        try? handle.seek(toOffset: logOffset)
        return String(decoding: handle.readDataToEndOfFile(), as: UTF8.self)
    }

    /// Best-effort check: without Full Disk Access these TCC-protected
    /// locations are unreadable. A false "true" just means the collector
    /// reports the problem after the password prompt instead of before it.
    static var appearsToHaveFullDiskAccess: Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let probes = ["\(home)/Library/Safari", "\(home)/Library/Mail",
                      "/Library/Application Support/com.apple.TCC/TCC.db"]
        for path in probes where FileManager.default.fileExists(atPath: path) {
            let fd = open(path, O_RDONLY)
            if fd < 0 { if errno == EPERM || errno == EACCES { return false } else { continue } }
            close(fd)
            if path.hasSuffix(".db") { return true }
            if (try? FileManager.default.contentsOfDirectory(atPath: path)) == nil { return false }
            return true
        }
        return true
    }

    func openLog() {
        if usesDaemon, FileManager.default.isReadableFile(atPath: CollectorDaemon.logURL.path) {
            NSWorkspace.shared.open(CollectorDaemon.logURL); return
        }
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        NSWorkspace.shared.open(logURL)
    }

    static func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: Helpers

    private func writeToken(_ token: String) throws {
        let fm = FileManager.default
        try? fm.removeItem(at: tokenURL)
        guard fm.createFile(atPath: tokenURL.path, contents: Data(token.utf8),
                            attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private static func randomToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    nonisolated private static func runOsascript(_ source: String) -> Result<String, Error> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", source]
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        do {
            try process.run()
        } catch {
            return .failure(error)
        }
        let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let errorText = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        if process.terminationStatus == 0 { return .success(output) }
        return .failure(NSError(domain: "Hostwatch", code: Int(process.terminationStatus),
                                userInfo: [NSLocalizedDescriptionKey: errorText.trimmingCharacters(in: .whitespacesAndNewlines)]))
    }
}

/// POSIX single-quote a shell word.
private func sh(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

private func appleScriptEscape(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
}
