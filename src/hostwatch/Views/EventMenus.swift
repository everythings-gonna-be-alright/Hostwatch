import AppKit
import SwiftUI

/// Right-click menus of the Events list (an AppKit table: its menus are NSMenus).
extension ActivityWindowView {
    func eventMenu(_ item: EventItem) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        if item.isGroup { fillGroupMenu(menu, item) } else { fillRowMenu(menu, item.event) }
        return menu
    }

    private func fillRowMenu(_ menu: NSMenu, _ event: ActivityEvent) {
        if traveling && travel.showingSearch && event.ts > 0 {
            menu.addItem(ClosureMenuItem("Show in Timeline") { travel.reveal(event) })
            menu.addItem(.separator())
        }
        menu.addItem(ClosureMenuItem("Ask AI: Is This Dangerous?…") { actions.askAI(event) })
        menu.addItem(ClosureMenuItem("Watch \(event.name) Closely…") { actions.watch(event) })
        menu.addItem(.separator())
        menu.addLabel("Pattern: \(event.signatureProcess) → \(event.signaturePattern)")
        for status in SignatureStatus.allCases {
            menu.addItem(ClosureMenuItem("Mark Pattern \(status.title)") { signatures.set(status, keys: [event.signatureKey]) })
        }
        menu.addSubmenu("Mark All \(event.kind.title) From This Process") { sub in
            for status in SignatureStatus.allCases {
                let allowed = !(status == .safe && !SignatureStore.canTrustWholeProcess(event.signatureProcess))
                sub.addItem(ClosureMenuItem(status == .unclassified ? "Clear Rule" : status.title, enabled: allowed) {
                    signatures.setProcessRule(status, kind: event.kind, process: event.signatureProcess)
                })
            }
        }
        menu.addSubmenu("Exclude") { sub in
            for (title, pattern) in event.exclusionSuggestions {
                sub.addItem(ClosureMenuItem(title) { model.addExclusion(pattern) })
            }
            sub.addItem(.separator())
            sub.addItem(ClosureMenuItem("Edit Exclusions…") { actions.openExclusions() })
        }
        menu.addItem(.separator())
        menu.addItem(ClosureMenuItem("Copy Detail") { Self.copyToPasteboard(event.target) })
        menu.addItem(ClosureMenuItem("Copy Process Path", enabled: !event.proc.isEmpty) { Self.copyToPasteboard(event.proc) })
        if event.kind == .file || event.kind == .exec {
            menu.addItem(ClosureMenuItem("Reveal in Finder") {
                NSWorkspace.shared.selectFile(event.target, inFileViewerRootedAtPath: "")
            })
        }
    }

    private func fillGroupMenu(_ menu: NSMenu, _ item: EventItem) {
        if let session = shownSessions.first(where: { $0.topic == item.groupTitle }) {
            let only = model.onlySession == session.id
            menu.addItem(ClosureMenuItem(only ? "Show All Sessions" : "Show Only This Session") {
                model.onlySession = only ? nil : session.id
                model.onlySessionPids = only ? nil : session.pids
            })
            menu.addItem(ClosureMenuItem("Show Its Patterns…", enabled: !session.keys.isEmpty) {
                signatures.search = ""
                signatures.scope = .init(title: "Session: \(session.name)", keys: session.keys)
                model.windowTab = 1
            })
            if !session.sessionID.isEmpty {
                menu.addItem(ClosureMenuItem("Copy Claude Session ID") { Self.copyToPasteboard(session.sessionID) })
            }
        } else {
            menu.addItem(ClosureMenuItem("Show Only \(item.groupTitle)") { model.searchText = item.groupTitle })
        }
    }

    /// The links in an AI session's band: the same two actions as its menu, one click away.
    func groupLinks(_ item: EventItem) -> [BandLink] {
        guard let session = shownSessions.first(where: { $0.topic == item.groupTitle }) else { return [] }
        let only = model.onlySession == session.id
        var links = [BandLink(title: only ? "All sessions" : "Only this session") {
            model.onlySession = only ? nil : session.id
            model.onlySessionPids = only ? nil : session.pids
        }]
        if !session.keys.isEmpty {
            links.append(BandLink(title: "Patterns") {
                signatures.search = ""
                signatures.scope = .init(title: "Session: \(session.name)", keys: session.keys)
                model.windowTab = 1
            })
        }
        return links
    }

    static func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
