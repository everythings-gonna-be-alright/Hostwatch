import AppKit

/// The background collector must be this copy's: macOS keeps one registration for the app's identifier, and the copy
/// that registered it last owns it. Opening another copy (an older one in Downloads) left this app talking to that
/// copy's collector, without Endpoint Security, its launches paused after they start. Replacing the app in place
/// needs none of this: the service follows the bundle at its path.
extension AppDelegate {
    func setUpCollectorCopyCheck() {
        model.onCollectorHello = { [weak self] hello in self?.collectorSaidHello(hello) }
    }

    private func collectorSaidHello(_ hello: [String: Any]?) {
        guard collector.usesDaemon, !collectorCopyAsked else { return }
        collectorHelloAt = hello == nil ? collectorHelloAt : Date()
        // Silence: an older collector. Right after the app was replaced in place, the old one keeps running until it
        // notices (within 30 s) and restarts as this version: ask only if it's still the old one a minute later.
        if hello == nil {
            let asked = Date()
            DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self] in
                guard let self, self.model.connected, (self.collectorHelloAt ?? .distantPast) < asked else { return }
                self.askToUseThisCopy(Self.collectorCopyProblem(mine: "", theirs: nil, version: nil) ?? "")
            }
            return
        }
        let mine = Bundle.main.bundleURL.standardizedFileURL.path
        let theirs = (hello?["app"] as? String).map { URL(fileURLWithPath: $0).standardizedFileURL.path }
        guard let mismatch = Self.collectorCopyProblem(mine: mine, theirs: theirs, version: hello?["version"] as? String) else { return }
        askToUseThisCopy(mismatch)
    }

    /// One plain question: what's better now, what has to happen, what it costs. Where the old part lives only when
    /// it's another copy (you may want to delete it).
    private func askToUseThisCopy(_ note: String) {
        guard !collectorCopyAsked else { return }
        collectorCopyAsked = true
        let alert = NSAlert()
        alert.messageText = "Finish updating Hostwatch"
        alert.informativeText = "This version protects your Mac with a better technology from Apple: programs are checked "
            + "before they start, not stopped right after.\n\nThe part of Hostwatch that works in the background is still "
            + "the old one, so it needs to be replaced. It takes a moment, and macOS asks for your password twice."
            + (note.isEmpty ? "" : "\n\n" + note)
        alert.addButton(withTitle: "Replace Now")
        alert.addButton(withTitle: "Later")
        NSApp.activate()
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        collector.daemon.reregister()
    }

    /// Whether the background part must be replaced: nil when it's this copy's, otherwise a note for the question
    /// ("" for one from an older version, where it lives for another copy). `theirs` is nil for a collector from
    /// before 0.19 (it says nothing about itself). Pure.
    nonisolated static func collectorCopyProblem(mine: String, theirs: String?, version: String?) -> String? {
        guard let theirs else { return "" }
        guard theirs != mine else { return nil }
        let home = NSHomeDirectory()
        let shown = theirs.hasPrefix(home + "/") ? "~" + theirs.dropFirst(home.count) : theirs
        return "The old one belongs to the copy of Hostwatch in \((shown as NSString).deletingLastPathComponent). "
            + "You can delete that copy afterwards."
    }
}
