import AppKit
import SwiftUI

/// Launch and file protection: the rehearsal on the live feed, the collector's Endpoint Security questions, and the
/// panel that asks you. source: docs/adr/0011-protection.md
extension AppDelegate {
    func setUpProtection() {
        model.protection = protection
        protection.onConfigChange = { [weak self] in
            guard let self else { return }
            self.model.guardConfig = self.protection.collectorConfig()
        }
        protection.answer = { [weak self] id, allow, ttl in self?.model.sendGuardAnswer(id: id, allow: allow, ttl: ttl) }
        protection.markPattern = { [weak self] key, status in
            self?.signatures.set(status, keys: [key], note: status == .safe ? "allowed in Protection" : "blocked in Protection")
        }
        protection.onPromptsChange = { [weak self] in self?.refreshProtectionPanels() }
        model.onGuardStatus = { [weak self] state, detail in self?.protection.enforcerStatus(state, detail) }
        model.onGuardAsk = { [weak self] obj in
            guard let self, let ask = Self.protectionAsk(obj) else { return }
            self.protection.handleAsk(ask, status: self.signatures.status(for: ask.event))
        }
        model.onGuardBlock = { [weak self] obj in
            guard let self, let ask = Self.protectionAsk(obj) else { return }
            self.protection.collectorBlocked(ask.event, area: ask.area, reason: obj["reason"] as? String ?? "stopped")
        }
        model.guardConfig = protection.collectorConfig()
    }

    /// A collector line about a held (or stopped) launch or file access, as an event the patterns understand.
    static func protectionAsk(_ obj: [String: Any]) -> ProtectionAsk? {
        func str(_ k: String) -> String { obj[k] as? String ?? "" }
        func int(_ k: String) -> Int { (obj[k] as? NSNumber)?.intValue ?? 0 }
        let path = str("path")
        guard !path.isEmpty else { return nil }
        let name = (path as NSString).lastPathComponent
        let time = Date().formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute().second())
        let event: ActivityEvent
        let area: ProtectionArea
        if str("what") == "open" {
            event = ActivityEvent(kind: .file, time: time, pid: int("pid"), ppid: int("ppid"), name: name, proc: path,
                                  target: str("file"), extra: str("mode").isEmpty ? "r" : str("mode"), parent: str("parent"))
            area = .files
        } else {
            event = ActivityEvent(kind: .exec, time: time, pid: int("pid"), ppid: int("ppid"), name: name, proc: path,
                                  target: path, extra: "", parent: str("parent"), args: str("args"))
            area = .launches
        }
        let seconds = (obj["deadline"] as? NSNumber)?.doubleValue ?? 10
        return ProtectionAsk(id: int("id"), event: event, area: area, reason: "", group: nil,
                             deadline: Date().addingTimeInterval(seconds))
    }

    /// One glass question panel at a time, like the firewall's: a launch waits only a few seconds.
    func refreshProtectionPanels() {
        protectionPanel?.orderOut(nil)
        protectionPanel = nil
        guard let ask = protection.prompts.first else { return }
        let chain = launchChainReport(for: ask.event)
        let panel = QuestionPanel.make(ProtectionPromptView(ask: ask, chain: chain, waiting: protection.prompts.count) { [weak self] choice in
            self?.protection.respond(ask.id, choice)
        } expired: { [weak self] in
            self?.protection.expire(ask.id)
        })
        protectionPanel = panel
        QuestionPanel.show(panel, slot: 0)
        NSSound(named: "Tink")?.play()
    }
}
