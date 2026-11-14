import Foundation
import Testing

/// The machine-checkable rules of docs/DESIGN.md, so they hold for every new view. Each failure says which rule and
/// where.
@Suite struct DesignRules {
    /// The app's views and settings: what people see.
    static func uiFiles() throws -> [(name: String, text: String)] {
        try CodebaseStructure.files().filter { ["Views", "App", "AI"].contains($0.area) }.map { ($0.name, $0.text) }
    }

    /// DESIGN.md §1: an action is a button. Blue link text means "go somewhere".
    @Test func actionsAreButtonsNotLinks() throws {
        for f in try Self.uiFiles() {
            #expect(!f.text.contains(".buttonStyle(.link)"), "\(f.name): use .buttonStyle(.glass).controlSize(.small) for an action (DESIGN.md §1)")
        }
    }

    /// DESIGN.md §6: no semicolons in anything a person reads (Text, Button, Label, Toggle, help, Footnote, and the
    /// pieces joined to them).
    @Test func noSemicolonsOnScreen() throws {
        let call = try Regex(#"(Text|Button|Label|Toggle|help|Footnote)\("[^"\n]*;[^"\n]*""#)
        let piece = try Regex(#"(?m)^\s*\+ "[^"\n]*;[^"\n]*""#)
        for f in try Self.uiFiles() where f.name != "AskAI.swift" {          // AskAI.swift holds prompts for the model
            #expect(f.text.firstMatch(of: call) == nil, "\(f.name): a semicolon in on-screen text (DESIGN.md §6)")
            #expect(f.text.firstMatch(of: piece) == nil, "\(f.name): a semicolon in on-screen text (DESIGN.md §6)")
        }
    }

    /// DESIGN.md §1: a segmented switch that needs icons uses IconSegments: the system one drops them on macOS.
    @Test func segmentedPickersDontPromiseIcons() throws {
        for f in try Self.uiFiles() {
            let lines = f.text.split(separator: "\n", omittingEmptySubsequences: false)
            for (i, line) in lines.enumerated() where line.contains(".pickerStyle(.segmented)") {
                let before = lines[max(0, i - 12)..<i].joined(separator: "\n")
                #expect(!before.contains("labelStyle(.titleAndIcon)"), "\(f.name): segmented pickers show no icons, use IconSegments (DESIGN.md §1)")
            }
        }
    }
}
