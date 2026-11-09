import Foundation
import Testing
@testable import Hostwatch

/// Launch and file protection decide like the firewall: your decision, then risk, then macOS's own programs.
@Suite struct ProtectionDecisions {
    let home = NSHomeDirectory()

    func filePattern(_ path: String, mode: String = "r", actor: String) -> (String, PatternRisk) {
        let (pattern, risk, _) = SignatureBuilder.fileTarget(path, mode: mode, actor: actor)
        return (pattern, risk)
    }

    @Test func launchesFollowThePatternThenRisk() {
        #expect(ProtectionPolicy.decideLaunch(target: "/tmp/x", status: .dangerous, risk: .normal, riskReason: "").verdict == .block)
        #expect(ProtectionPolicy.decideLaunch(target: "/tmp/x", status: .safe, risk: .high, riskReason: "").verdict == .allow)
        #expect(ProtectionPolicy.decideLaunch(target: "/tmp/x", status: .unclassified, risk: .high, riskReason: "unsigned").verdict == .block)
        #expect(ProtectionPolicy.decideLaunch(target: "/usr/libexec/xpcproxy", status: .unclassified, risk: .normal,
                                              riskReason: "").verdict == .allow)
        // curl is macOS's, but it runs what it's told: judged by its pattern, so a new one is asked about.
        #expect(ProtectionPolicy.decideLaunch(target: "/usr/bin/curl", status: .unclassified, risk: .normal,
                                              riskReason: "").verdict == .ask)
        #expect(ProtectionPolicy.decideLaunch(target: "/Apps/H", status: .dangerous, risk: .high, riskReason: "",
                                              hostwatch: "/Apps/H").verdict == .allow)
    }

    @Test func sshKeysAskForStrangersOnly() {
        let (stranger, sRisk) = filePattern(home + "/.ssh/id_ed25519", actor: "/Applications/Slack.app/Contents/MacOS/Slack")
        let d = ProtectionPolicy.decideFile(pattern: stranger, status: .unclassified, risk: sRisk, settings: [:])
        #expect(d?.verdict == .ask && d?.group == "ssh")
        let (own, oRisk) = filePattern(home + "/.ssh/id_ed25519", actor: "/usr/bin/ssh")
        #expect(ProtectionPolicy.decideFile(pattern: own, status: .unclassified, risk: oRisk, settings: [:])?.verdict == .allow)
        // You allowed Slack (marked its pattern Safe): it passes.
        #expect(ProtectionPolicy.decideFile(pattern: stranger, status: .safe, risk: sRisk, settings: [:])?.verdict == .allow)
    }

    @Test func aCardTurnedOffOrSetToBlock() {
        let (p, r) = filePattern(home + "/.ssh/id_ed25519", actor: "/tmp/evil")
        #expect(ProtectionPolicy.decideFile(pattern: p, status: .unclassified, risk: r,
                                            settings: ["ssh": .init(on: false)]) == nil)
        #expect(ProtectionPolicy.decideFile(pattern: p, status: .unclassified, risk: r,
                                            settings: ["ssh": .init(on: true, others: .block)])?.verdict == .block)
    }

    @Test func ordinaryFilesAndAutostartReadsAreNotProtected() {
        let (doc, r1) = filePattern(home + "/Documents/notes.txt", actor: "/tmp/evil")
        #expect(ProtectionPolicy.decideFile(pattern: doc, status: .unclassified, risk: r1, settings: [:]) == nil)
        let (read, r2) = filePattern(home + "/Library/LaunchAgents/x.plist", mode: "r", actor: "/tmp/evil")
        #expect(ProtectionPolicy.decideFile(pattern: read, status: .unclassified, risk: r2, settings: [:]) == nil)
        let (write, r3) = filePattern(home + "/Library/LaunchAgents/x.plist", mode: "w", actor: "/tmp/evil")
        #expect(ProtectionPolicy.decideFile(pattern: write, status: .unclassified, risk: r3, settings: [:])?.group == "autostart")
    }

    @Test func strictTurnsQuestionsIntoBlocks() {
        #expect(ProtectionPolicy.effective(.ask, mode: .strict) == .block)
        #expect(ProtectionPolicy.effective(.ask, mode: .watch) == .ask)
        #expect(ProtectionPolicy.effective(.block, mode: .off) == nil)
    }

    @Test func labels() {
        #expect(ProtectionPolicy.label(of: "r ~/.ssh/*  [SSH keys]") == "SSH keys")
        #expect(ProtectionPolicy.label(of: "r *  [ordinary files]") == nil)
        #expect(ProtectionPolicy.label(of: "/usr/bin/curl") == nil)
    }

    @Test func groupsCoverEverySensitiveLabel() {
        for (_, label) in SignatureBuilder.sensitive { #expect(ProtectedGroup.group(forLabel: label) != nil, "\(label)") }
        #expect(ProtectedGroup.group(id: "ssh")!.prefixes(home: "/Users/me").contains("/Users/me/.ssh"))
    }
}

/// The rehearsal: Watch marks what would be stopped, counts the rest, and forgets what you decided.
@MainActor @Suite struct ProtectionRehearsal {
    func monitor() -> ProtectionMonitor {
        let suite = "protection-test-\(UUID().uuidString)"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json")
        return ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!, fileURL: url)
    }

    func launch(_ target: String, parent: String = "/bin/zsh") -> ActivityEvent {
        ActivityEvent(kind: .exec, time: "12:00:00", pid: 10, ppid: 9, name: (target as NSString).lastPathComponent,
                      proc: target, target: target, extra: "", parent: parent)
    }

    @Test func watchMarksWhatWouldBeStopped() {
        let m = monitor()
        var e = launch("/tmp/dropper")
        m.consider(&e, status: .dangerous)
        #expect(e.protection == .wouldBlock && m.count(.launches, .block) == 1)
        #expect(m.findings.count == 1)
        m.decided(patternKeys: [e.signatureKey])
        #expect(m.findings.isEmpty)
    }

    @Test func questionsAreCountedNotMarked() {
        let m = monitor()
        var e = launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)
        #expect(e.protection == .none && m.count(.launches, .ask) == 1)
    }

    @Test func offAndPausedDoNothing() {
        let m = monitor()
        m.launchMode = .off
        var e = launch("/tmp/dropper")
        m.consider(&e, status: .dangerous)
        #expect(e.protection == .none && m.findings.isEmpty)
        m.launchMode = .watch
        m.pause(minutes: 15)
        m.consider(&e, status: .dangerous)
        #expect(e.protection == .none && m.stateWord == "Protection paused")
    }

    @Test func theCollectorGetsOnlyCardsThatAreOn() {
        let m = monitor()
        m.groups = ["ssh": .init(on: false)]
        let ids = (m.collectorConfig(home: "/Users/me")["groups"] as? [[String: Any]])?.compactMap { $0["id"] as? String } ?? []
        #expect(!ids.contains("ssh") && ids.contains("keychain"))
    }
}

/// Folders and files you protect yourself.
@MainActor @Suite struct ProtectionCustomPlaces {
    let folder = CustomPlace(path: "/Users/me/Projects/secret", isFolder: true)

    @Test func insideTheFolderStrangersAreAsked() {
        let d = ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secret/plan.md", actor: "/Applications/Slack.app/Contents/MacOS/Slack",
                                              status: .unclassified, places: [folder])
        #expect(d?.verdict == .ask && d?.group == folder.groupID)
        #expect(ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secretive/x", actor: "/tmp/x",
                                              status: .unclassified, places: [folder]) == nil)
    }

    @Test func macOSAndYourDecisionsPass() {
        #expect(ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secret/a", actor: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
                                              status: .unclassified, places: [folder])?.verdict == .allow)
        #expect(ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secret/a", actor: "/usr/bin/curl",
                                              status: .unclassified, places: [folder])?.verdict == .ask)
        #expect(ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secret/a", actor: "/tmp/x",
                                              status: .safe, places: [folder])?.verdict == .allow)
        var off = folder; off.on = false
        #expect(ProtectionPolicy.decideCustom(path: "/Users/me/Projects/secret/a", actor: "/tmp/x",
                                              status: .unclassified, places: [off]) == nil)
    }

    @Test func aSingleFileAndThePrivateAlias() {
        let file = CustomPlace(path: "/private/etc/hosts", isFolder: false)
        #expect(file.covers("/etc/hosts") && file.covers("/private/etc/hosts") && !file.covers("/etc/hosts.bak"))
    }

    @Test func addingAndRemovingPlaces() {
        let suite = "custom-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent(suite))
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(suite, isDirectory: true)
        m.addPlaces([dir, dir])
        #expect(m.customPlaces.count == 1 && m.customPlaces[0].isFolder)
        let ids = (m.collectorConfig(home: "/Users/me")["groups"] as? [[String: Any]])?.compactMap { $0["id"] as? String } ?? []
        #expect(ids.contains(m.customPlaces[0].groupID))
        m.removePlace(m.customPlaces[0].id)
        #expect(m.customPlaces.isEmpty)
    }
}

/// Ask and Strict without Endpoint Security: stop what's blocked, pause what's asked about, never root's processes.
@MainActor @Suite struct ProtectionReactive {
    final class Signals { var sent: [(Int32, Int32)] = [] }

    func monitor(uid: uid_t = getuid(), path: String = "/tmp/dropper") -> (ProtectionMonitor, Signals) {
        let suite = "reactive-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent(suite))
        let signals = Signals()
        m.engine.signal = { pid, sig in signals.sent.append((pid, sig)); return 0 }
        m.engine.inspect = { _ in ProcessFacts(uid: uid, path: path) }
        m.engine.startWatchdog = { _, _ in nil }
        return (m, signals)
    }

    func launch(_ target: String = "/tmp/dropper") -> ActivityEvent {
        ActivityEvent(kind: .exec, time: "12:00:00", pid: 4242, ppid: 9, name: "dropper", proc: target, target: target,
                      extra: "", parent: "/bin/zsh")
    }

    @Test func strictStopsWhatIsBlocked() {
        let (m, s) = monitor()
        m.launchMode = .strict
        var e = launch()
        m.consider(&e, status: .dangerous)
        #expect(s.sent.map(\.1) == [SIGKILL] && e.protection == .blocked)
        #expect(m.findings.values.first?.enforced == true)
    }

    @Test func askPausesThenYourAnswerDecides() {
        let (m, s) = monitor(path: "/usr/bin/curl")
        m.launchMode = .ask
        var e = launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)            // curl runs what it's told: a new one is asked about
        #expect(s.sent.map(\.1) == [SIGSTOP] && m.prompts.count == 1 && m.prompts[0].reactive)
        m.respond(m.prompts[0].id, .block)
        #expect(s.sent.map(\.1) == [SIGSTOP, SIGKILL] && m.prompts.isEmpty)
    }

    @Test func noAnswerLetsItGoOn() {
        let (m, s) = monitor(path: "/usr/bin/curl")
        m.launchMode = .ask
        var e = launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)
        #expect(m.prompts.count == 1)
        m.expire(m.prompts[0].id)
        #expect(s.sent.map(\.1) == [SIGSTOP, SIGCONT] && m.prompts.isEmpty)
    }

    @Test func rootsProcessesAreNeverTouched() {
        let (m, s) = monitor(uid: 0)
        m.launchMode = .strict
        var e = launch()
        m.consider(&e, status: .dangerous)
        #expect(s.sent.isEmpty && e.protection == .wouldBlock)
        #expect(m.findings.values.first?.enforced == false)
    }

    @Test func turningTheModeDownReleasesThePaused() {
        let (m, s) = monitor(path: "/usr/bin/curl")
        m.launchMode = .ask
        var e = launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)
        m.launchMode = .watch
        #expect(s.sent.map(\.1) == [SIGSTOP, SIGCONT] && m.prompts.isEmpty)
    }
}
