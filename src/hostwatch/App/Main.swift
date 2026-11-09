import AppKit
import Foundation

@main
enum Entry {
    static func main() {
        let args = CommandLine.arguments
        #if DEMO
        Demo.configure(args)                                 // --demo <folder>: made-up data (demo build only)
        #endif
        // Claude Code's PreToolUse hook: first, and before anything else loads (it runs for every tool call).
        if args.count > 1, args[1] == ClaudeHook.flag { ClaudeHook.run() }
        Migration.run()                                      // settings from the old bundle identifier, before any read
        if args.contains(FirewallProbe.flag) { FirewallProbe.run() }
        if let i = args.firstIndex(of: FirewallRelayTest.flag) { FirewallRelayTest.run(Array(args[(i + 1)...])) }
        if let i = args.firstIndex(of: AgentWatch.testFlag) { AgentWatch.runTest(Array(args[(i + 1)...])) }
        if args.contains("--mcp") { MCPServer().run() }      // read-only MCP server for Claude Code
        if args.contains("--suggest-rules") { runRuleSuggestionDryRun() }
        if args.contains("--triage-benchmark") { runTriageBenchmark() }   // local models against your decisions
        if let i = args.firstIndex(of: "--signature-report"), i + 1 < args.count {
            runSignatureReport(args[i + 1])
        }
        if let i = args.firstIndex(of: "--export-history") {
            runExportHistory(i + 1 < args.count ? args[i + 1] : nil)
        }
        if let i = args.firstIndex(of: "--regroup-report") {
            runRegroupReport(i + 1 < args.count ? args[i + 1] : nil)
        }
        if let i = args.firstIndex(of: "--origin-report") {
            runOriginReport(i + 1 < args.count ? args[i + 1] : nil)
        }
        if let i = args.firstIndex(of: "--signing-check"), i + 1 < args.count {
            runSigningCheck(Array(args[(i + 1)...]))
        }
        if let i = args.firstIndex(of: "--story-replay"), i + 1 < args.count {
            MainActor.assumeIsolated { runStoryReplay(args[i + 1]) }
        }
        if args.contains("--metrics-probe") { runMetricsProbe() }
        if let i = args.firstIndex(of: "--compress-history"), i + 1 < args.count {
            runCompressHistory(args[i + 1])
        }
        if let i = args.firstIndex(of: "--time-travel-probe") {
            runTimeTravelProbe(i + 1 < args.count ? args[i + 1] : nil)
        }
        // The collector itself (root, started by the launcher below): the flag comes first.
        if args.count > 1, args[1] == collectorFlag { runCollectorAgent(Array(args.dropFirst(2))) }
        if let i = args.firstIndex(of: collectorLauncherFlag) {
            runCollectorLauncher(Array(args[(i + 1)...]))
        }
        // Plain AppKit lifecycle: a SwiftUI App needs a scene, and its only one (an empty Settings
        // window) was shown on every launch/reopen.
        MainActor.assumeIsolated {
            let app = NSApplication.shared
            app.delegate = appDelegate
            app.mainMenu = appDelegate.makeMainMenu()
            app.run()
        }
    }

    @MainActor private static let appDelegate = AppDelegate()
}
