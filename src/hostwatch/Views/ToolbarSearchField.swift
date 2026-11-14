import AppKit
import SwiftUI

/// The window's search field, as a toolbar item placed by hand: `.searchable` belongs to the whole window and can't
/// be left out of one tab (Protection has nothing to search) without rebuilding every kept tab. An AppKit search
/// field keeps the native look and behaviour: the clear button, Esc to clear, ⌘F to focus (Edit ▸ Find).
struct ToolbarSearchField: NSViewRepresentable {
    @Binding var text: String
    let prompt: String

    /// The field on screen, for Edit ▸ Find. Only one window has it.
    nonisolated(unsafe) static weak var current: NSSearchField?

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.sendsSearchStringImmediately = true
        field.target = context.coordinator
        field.action = #selector(Coordinator.changed(_:))
        field.placeholderString = prompt
        field.setAccessibilityLabel("Search")
        Self.current = field
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.text = $text
        if field.stringValue != text { field.stringValue = text }
        if field.placeholderString != prompt { field.placeholderString = prompt }
        Self.current = field
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }

        @objc func changed(_ sender: NSSearchField) {
            if text.wrappedValue != sender.stringValue { text.wrappedValue = sender.stringValue }
        }
    }
}
