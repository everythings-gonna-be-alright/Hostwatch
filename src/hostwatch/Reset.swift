import AppKit
import Foundation

/// "Reset Hostwatch…": erase what you choose, then start again like a fresh install.
///
/// Files are removed by a small helper after this process has exited, so no store writes its data back
/// while quitting. Settings are removed here (through UserDefaults, which owns them) right before exiting.
struct ResetPlan: Equatable {
    /// Patterns, stories, domains, your rules, signing facts, the MCP token, and the baseline.
    var data = true
    /// Window, HUD, detection, AI, exclusions and history settings.
    var settings = true
    /// Recorded events and resource history, and the collector log.
    var history = true

    var isEmpty: Bool { !data && !settings && !history }

    /// UserDefaults keys that belong to the baseline (they go with the data, not the settings).
    static let baselineKeys = ["baselineStartedAt", "baselineWavesDone", "baselineReport2", "baselineRules2",
                               "baselineRules", "baselineReport"]

    /// The shell script the helper runs: waits for `pid` to exit, removes files, reopens the app.
    static func script(_ plan: ResetPlan, pid: Int32, support: URL, logs: URL, historyDir: URL, app: URL) -> String {
        var lines = ["while /bin/kill -0 \(pid) 2>/dev/null; do /bin/sleep 0.2; done"]
        if plan.data { lines.append("/bin/rm -rf \(quote(support.path))") }
        if plan.history {
            // A custom history folder may hold other files: only Hostwatch's own.
            lines.append("/usr/bin/find \(quote(historyDir.path)) -maxdepth 1 -type f \\( -name 'activity-*' -o -name 'metrics-*' \\) -delete 2>/dev/null")
            lines.append("/bin/rm -rf \(quote(logs.path))")
        }
        lines.append("/usr/bin/open -n \(quote(app.path))")
        return lines.joined(separator: "\n")
    }

    static func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// Removes the chosen settings from `defaults` (all of them, the baseline's, or all but the baseline's).
    func clearDefaults(_ defaults: UserDefaults, domain: String) {
        switch (settings, data) {
        case (true, true):
            defaults.removePersistentDomain(forName: domain)
        case (true, false):
            // Includes global keys, but removing those from this app's defaults does nothing.
            for key in defaults.dictionaryRepresentation().keys where !Self.baselineKeys.contains(key) {
                defaults.removeObject(forKey: key)
            }
        case (false, true):
            Self.baselineKeys.forEach(defaults.removeObject(forKey:))
        case (false, false):
            break
        }
        defaults.synchronize()
    }
}

@MainActor
enum Reset {
    /// Stops the collector, clears settings, hands file removal to a helper and exits; the helper reopens the app.
    static func run(_ plan: ResetPlan, collector: Collector, model: HUDModel, historyDir: URL) {
        guard !plan.isEmpty else { return }
        let finish = {
            let script = ResetPlan.script(plan, pid: getpid(), support: AppPaths.support, logs: AppPaths.logs,
                                          historyDir: historyDir, app: Bundle.main.bundleURL)
            let helper = Process()
            helper.executableURL = URL(fileURLWithPath: "/bin/sh")
            helper.arguments = ["-c", script]
            helper.standardInput = FileHandle.nullDevice
            helper.standardOutput = FileHandle.nullDevice
            helper.standardError = FileHandle.nullDevice
            do { try helper.run() } catch {
                let alert = NSAlert()
                alert.messageText = "Couldn't reset Hostwatch"
                alert.informativeText = error.localizedDescription
                alert.runModal()
                return
            }
            plan.clearDefaults(.standard, domain: AppPaths.bundleID)
            exit(0)   // not terminate(): quitting normally would save the stores again
        }
        if collector.isRunning {
            var done = false
            let once = { if !done { done = true; finish() } }
            collector.stop(via: model) { DispatchQueue.main.async(execute: once) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: once)   // don't wait forever
        } else {
            finish()
        }
    }
}
