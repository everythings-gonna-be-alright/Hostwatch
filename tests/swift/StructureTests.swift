import Foundation
import Testing

/// The dependency direction, enforced without splitting the package into modules (ADR 0008): the collector and the
/// logic never import UI frameworks, the collector never reaches into the app's engines, every file is in an area
/// folder, and files stay one concept each (under the size that made the old Signatures.swift expensive to work in).
@Suite struct CodebaseStructure {
    static let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("src/hostwatch")

    /// The area folders, as `docs/ARCHITECTURE.md` lists them.
    static let areas = ["App", "Events", "Patterns", "Detection", "Firewall", "History", "Collector", "AI", "Views"]

    /// (folder, file name, text) for every Swift file, one folder deep.
    static func files() throws -> [(area: String, name: String, text: String)] {
        let fm = FileManager.default
        var out: [(String, String, String)] = []
        for entry in try fm.contentsOfDirectory(atPath: sources.path).sorted() {
            let url = sources.appendingPathComponent(entry)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                for name in try fm.contentsOfDirectory(atPath: url.path).sorted() where name.hasSuffix(".swift") {
                    out.append((entry, name, try String(contentsOf: url.appendingPathComponent(name), encoding: .utf8)))
                }
            } else if entry.hasSuffix(".swift") {
                out.append(("", entry, try String(contentsOf: url, encoding: .utf8)))
            }
        }
        return out
    }

    @Test func everyFileIsInAnAreaFolder() throws {
        for f in try Self.files() {
            #expect(Self.areas.contains(f.area), "\(f.name) is in \"\(f.area)\": put it in one of \(Self.areas)")
        }
    }

    /// The root collector: its own process, no AppKit or SwiftUI, and none of the app's engines.
    @Test func collectorImportsNoUI() throws {
        let appEngines = ["SignatureStore", "StoryEngine", "HUDModel", "AppDelegate", "NSWorkspace", "NSAlert"]
        for f in try Self.files() where f.area == "Collector" && f.name != "Collector.swift" {
            #expect(!f.text.contains("import SwiftUI") && !f.text.contains("import AppKit"), "\(f.name) imports a UI framework")
            for engine in appEngines { #expect(!f.text.contains(engine), "\(f.name) reaches into \(engine)") }
        }
    }

    /// What decides (patterns, detection, history, the firewall) has no SwiftUI in it: it must stay testable as
    /// values. Views live in Views/ (or are named …View.swift next to their engine).
    @Test func logicFoldersHaveNoSwiftUI() throws {
        for f in try Self.files() where ["Patterns", "Detection", "Firewall", "History", "Collector"].contains(f.area)
                && !f.name.hasSuffix("View.swift") {
            #expect(!f.text.contains("import SwiftUI"), "\(f.area)/\(f.name) imports SwiftUI")
            #expect(!f.text.contains(": View {"), "\(f.area)/\(f.name) declares a View")
        }
    }

    /// No file grows back into a grab bag: 1,000 lines is the alarm (the target is ~700).
    @Test func filesStaySmall() throws {
        for f in try Self.files() {
            let lines = f.text.split(separator: "\n", omittingEmptySubsequences: false).count
            #expect(lines <= 1000, "\(f.area)/\(f.name) has \(lines) lines: split it along its MARK sections")
        }
    }
}
