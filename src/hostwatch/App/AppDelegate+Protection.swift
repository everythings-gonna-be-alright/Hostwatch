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
            self.firewall.rulesChanged()                     // a network rule may have changed what passes
        }
        protection.answer = { [weak self] id, allow, ttl in self?.model.sendGuardAnswer(id: id, allow: allow, ttl: ttl) }
        protection.waiting = { [weak self] id in self?.model.sendGuardWait(id: id) }
        model.onGuardLate = { [weak self] id, pid in self?.protection.collectorLate(id: id, pid: pid) }
        protection.markPattern = { [weak self] key, status in
            self?.signatures.set(status, keys: [key], note: status == .safe ? "allowed in Protection" : "blocked in Protection")
        }
        protection.onPromptsChange = { [weak self] in
            self?.refreshProtectionPanels()
            self?.refreshFirewallPanels()               // a held connection question may be next
        }
        // The collector holds programs invisibly to your shell when it runs as the root service.
        protection.engine.remote = ReactiveEnforcer.Remote(
            hold: { [weak self] pid in
                guard let self, self.collector.usesDaemon, self.model.connected else { return false }
                self.model.sendHold(pid: Int(pid))
                return true
            },
            release: { [weak self] pid, stop in self?.model.sendRelease(pid: Int(pid), stop: stop) })
        model.onHoldResult = { [weak self] pid, method in self?.protection.engine.holdResult(pid: pid, method: method) }
        protection.engine.onMethodKnown = { [weak self] _ in self?.refreshProtectionPanels() }
        protection.onLaunchAnswered = { [weak self] event, allowed in
            self?.firewall.launchAnswered(pid: event.pid, name: event.name, allowed: allowed)
        }
        protection.aiCheck = { [weak self] event in await self?.checkWithAI(event) }
        protection.onAIAllowed = { [weak self] ask, note in self?.aiNotices.allowed(ask, note: note) }
        firewall.networkDecision = { [weak self] f in self?.protection.networkDecision(host: f.host, ip: f.ip, program: f.program) }
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

    /// A paused program, as the AI sees it: the fast model you chose (on-device, or your own server), the pattern
    /// with its context, the rule in LiveAICheck. Nil when no fast model is ready: then you are asked straight away.
    func checkWithAI(_ event: ActivityEvent) async -> LiveAICheck.Outcome? {
        let model = LocalModelChoice.model()
        guard model.status().isReady, let entry = signatures.entry(event.signatureKey) else { return nil }
        let context = classifier.context?(entry)
        let warned = !TriagePrompt.warningSigns(entry, context: context).isEmpty
        let verdict = try? await model.triage(TriagePrompt.pattern(entry, context: context))
        return LiveAICheck.outcome(verdict: verdict, risk: entry.risk, warned: warned,
                                   refusal: SignatureBuilder.aiSafeRefusal(entry))
    }

    /// One glass question panel at a time, like the firewall's: a launch waits only a few seconds. What the AI is
    /// still checking isn't a question yet: it shows as a notice.
    func refreshProtectionPanels() {
        aiNotices.setChecking(protection.prompts.filter(\.checking))
        protectionPanel?.orderOut(nil)
        protectionPanel = nil
        guard let ask = protection.prompts.first(where: { !$0.checking }) else { return }
        let chain = launchChainReport(for: ask.event)
        let place = ask.group.flatMap { protection.placeTitle(group: $0) }
        // Paused the way the shell sees, from an interactive shell: after Allow, it goes on in the background.
        let shells: Set<String> = ["zsh", "bash", "fish", "sh", "dash", "ksh", "tcsh", "csh", "nu"]
        let fromShell = shells.contains((ask.event.parent as NSString).lastPathComponent)
        let fgHint = fromShell && protection.engine.pausedTheShellWay(ask.event.pid)
        let panel = QuestionPanel.make(ProtectionPromptView(ask: ask, chain: chain, place: place, fgHint: fgHint,
                                                            waiting: protection.prompts.filter { !$0.checking }.count) { [weak self] choice in
            self?.protection.respond(ask.id, choice)
        } expired: { [weak self] in
            self?.protection.expire(ask.id)
        })
        protectionPanel = panel
        QuestionPanel.show(panel, slot: 0)
        if protectionPanelAskID != ask.id { NSSound(named: "Tink")?.play() }
        protectionPanelAskID = ask.id
    }
}
