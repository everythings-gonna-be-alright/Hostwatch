import Foundation
import Testing

/// The dependency direction, enforced without splitting the package into modules (ADR 0008): the collector and the
/// logic never import UI frameworks, the collector never reaches into the app's engines, and files stay one concept
/// each (under the size that made the old Signatures.swift and Views.swift expensive to work in).
@Suite struct CodebaseStructure {
    static let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("src/hostwatch")

    static func files() throws -> [(name: String, text: String)] {
        try FileManager.default.contentsOfDirectory(atPath: sources.path).filter { $0.hasSuffix(".swift") }.sorted()
            .map { ($0, try String(contentsOf: sources.appendingPathComponent($0), encoding: .utf8)) }
    }

    /// The root collector: its own process, no AppKit or SwiftUI, and none of the app's engines.
    @Test func collectorImportsNoUI() throws {
        let appEngines = ["SignatureStore", "StoryEngine", "HUDModel", "AppDelegate", "NSWorkspace", "NSAlert"]
        for (name, text) in try Self.files() where name.hasPrefix("Agent") || name == "CollectorLauncher.swift" {
            #expect(!text.contains("import SwiftUI") && !text.contains("import AppKit"), "\(name) imports a UI framework")
            for engine in appEngines { #expect(!text.contains(engine), "\(name) reaches into \(engine)") }
        }
    }

    /// What decides (patterns, rules, stories' scoring, history) has no SwiftUI in it: it must stay testable as values.
    @Test func logicFilesHaveNoSwiftUI() throws {
        let logic = ["PatternBuilder", "PatternModel", "PatternStore", "Rules", "Baseline", "HistoryStream",
                     "HistoryFiles", "HistoryArchive", "Firewall", "Secrets", "Signing", "CommandGuard", "MCPServer"]
        for (name, text) in try Self.files() where logic.contains(String(name.dropLast(6))) {
            #expect(!text.contains("import SwiftUI"), "\(name) imports SwiftUI")
            #expect(!text.contains("struct ") || !text.contains(": View {"), "\(name) declares a View")
        }
    }

    /// No file grows back into a grab bag: 1,000 lines is the alarm (the target is ~700).
    @Test func filesStaySmall() throws {
        for (name, text) in try Self.files() {
            let lines = text.split(separator: "\n", omittingEmptySubsequences: false).count
            #expect(lines <= 1000, "\(name) has \(lines) lines: split it along its MARK sections")
        }
    }
}
