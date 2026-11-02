import Foundation
import Testing
@testable import Hostwatch

/// Reset Hostwatch…: erases only what you chose, and only Hostwatch's own files.
@Suite struct ResetHostwatch {
    let fm = FileManager.default

    func dir(_ root: URL, _ name: String, files: [String]) throws -> URL {
        let d = root.appendingPathComponent(name)
        try fm.createDirectory(at: d, withIntermediateDirectories: true)
        for f in files { try Data("x".utf8).write(to: d.appendingPathComponent(f)) }
        return d
    }

    func run(_ plan: ResetPlan) throws -> (support: URL, logs: URL, custom: URL) {
        let root = fm.temporaryDirectory.appendingPathComponent("hw-reset-\(UUID().uuidString)")
        let support = try dir(root, "Application Support/Hostwatch", files: ["signatures-v2.json", "collector.token"])
        let logs = try dir(root, "Logs/Hostwatch", files: ["agent.log"])
        let custom = try dir(root, "My History", files: ["activity-20261101.jsonl.gz", "metrics-20261101.jsonl", "notes.txt"])
        let script = ResetPlan.script(plan, pid: 99_999_999, support: support, logs: logs, historyDir: custom,
                                      app: root.appendingPathComponent("NoSuch.app"))
            .replacingOccurrences(of: "/usr/bin/open -n", with: "/usr/bin/true")   // don't launch anything
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", script]
        try p.run()
        p.waitUntilExit()
        return (support, logs, custom)
    }

    @Test func everythingLeavesOnlyYourOwnFiles() throws {
        let (support, logs, custom) = try run(ResetPlan())
        #expect(!fm.fileExists(atPath: support.path) && !fm.fileExists(atPath: logs.path))
        #expect(try fm.contentsOfDirectory(atPath: custom.path) == ["notes.txt"])   // a custom folder keeps other files
    }

    @Test func keepHistory() throws {
        let (support, logs, custom) = try run(ResetPlan(data: true, settings: false, history: false))
        #expect(!fm.fileExists(atPath: support.path))
        #expect(fm.fileExists(atPath: logs.appendingPathComponent("agent.log").path))
        #expect(try fm.contentsOfDirectory(atPath: custom.path).count == 3)
    }

    @Test func pathsWithQuotesAreSafe() {
        #expect(ResetPlan.quote("/a/it's here") == "'/a/it'\\''s here'")
    }

    @Test(arguments: [(true, false), (false, true)])
    func settingsAndBaselineAreSeparate(_ settings: Bool, _ data: Bool) {
        let d = scratchDefaults("hw-reset")
        d.set(true, forKey: "overlayEnabled")
        d.set(3, forKey: "baselineWavesDone")
        ResetPlan(data: data, settings: settings, history: false).clearDefaults(d, domain: "unused")
        #expect((d.object(forKey: "overlayEnabled") == nil) == settings)
        #expect((d.object(forKey: "baselineWavesDone") == nil) == data)
    }
}
