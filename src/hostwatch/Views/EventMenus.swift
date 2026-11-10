import AppKit
import SwiftUI

/// Right-click menus of the Events list (an AppKit table: its menus are NSMenus).
extension ActivityWindowView {
    func eventMenu(_ items: [EventItem]) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        if items.count > 1 {
            fillSelectionMenu(menu, items.map(\.event))
        } else if let item = items.first {
            if item.isGroup { fillGroupMenu(menu, item) } else { fillRowMenu(menu, item.event) }
        }
        return menu
    }

    /// Several events selected: decide all their patterns at once, copy them all.
    private func fillSelectionMenu(_ menu: NSMenu, _ events: [ActivityEvent]) {
        let keys = Array(Set(events.map(\.signatureKey).filter { !$0.isEmpty })).sorted()
        let noun = keys.count == 1 ? "Pattern" : "\(keys.count) Patterns"
        menu.addLabel("\(events.count) events · \(keys.count) pattern\(keys.count == 1 ? "" : "s")")
        for status in SignatureStatus.allCases {
            menu.addItem(ClosureMenuItem("Mark \(noun) \(status.title)", enabled: !keys.isEmpty) {
                signatures.set(status, keys: keys)
            })
        }
        addClassifyMenu(menu, keys: keys)
        menu.addItem(.separator())
        menu.addItem(ClosureMenuItem("Copy Details") { Self.copyToPasteboard(events.map(\.target).joined(separator: "\n")) })
        let paths = Array(Set(events.map(\.proc).filter { !$0.isEmpty })).sorted()
        menu.addItem(ClosureMenuItem(paths.count > 1 ? "Copy \(paths.count) Process Paths" : "Copy Process Path",
                                     enabled: !paths.isEmpty) { Self.copyToPasteboard(paths.joined(separator: "\n")) })
    }

    private func fillRowMenu(_ menu: NSMenu, _ event: ActivityEvent) {
        if traveling && travel.showingSearch && event.ts > 0 {
            menu.addItem(ClosureMenuItem("Show in Timeline") { travel.reveal(event) })
            menu.addItem(.separator())
        }
        menu.addItem(ClosureMenuItem("Ask AI: Is This Dangerous?…") { actions.askAI(event) })
        menu.addItem(ClosureMenuItem("Watch \(event.name) Closely…") { actions.watch(event) })
        menu.addItem(ClosureMenuItem("Show Launch Chain…") { actions.showLaunchChain(event) })
        menu.addItem(.separator())
        menu.addLabel("Pattern: \(event.signatureProcess) → \(event.signaturePattern)")
        for status in SignatureStatus.allCases {
            menu.addItem(ClosureMenuItem("Mark Pattern \(status.title)") { signatures.set(status, keys: [event.signatureKey]) })
        }
        addClassifyMenu(menu, keys: [event.signatureKey])
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
        menu.addItem(.separator())
        addClassifyMenu(menu, keys: (item.children ?? []).map(\.event.signatureKey))
    }

    /// Classify with AI for exactly these patterns: the verdicts applied, or kept as suggestions. Only New ones count.
    private func addClassifyMenu(_ menu: NSMenu, keys: [String]) {
        let only = Set(keys.filter { !$0.isEmpty })
        let n = classifier.undecided(in: only), unasked = classifier.classifiable(in: only).count
        let busy = classifier.bulk != nil || classifier.running
        let item = NSMenuItem(title: n == 0 ? "Classify with AI (nothing New)" : "Classify \(n) New Pattern\(n == 1 ? "" : "s") with AI",
                              action: nil, keyEquivalent: "")
        let sub = NSMenu()
        sub.addItem(ClosureMenuItem("Apply the Verdicts") { classifier.classifyAll(apply: true, only: only) })
        sub.addItem(ClosureMenuItem("Suggest Only, I’ll Decide", enabled: unasked > 0) { classifier.classifyAll(apply: false, only: only) })
        item.submenu = sub
        item.isEnabled = n > 0 && !busy
        menu.addItem(item)
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
