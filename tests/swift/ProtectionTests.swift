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
        #expect(e.protection == .none && m.state(network: .off).word == "Protection paused")
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

/// The Overview's charts: hour by hour, the last 24 hours, every hour present.
@MainActor @Suite struct ProtectionHourly {
    @Test func countsLandInTheirHour() {
        let suite = "hourly-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent(suite))
        var stop = ActivityEvent(kind: .exec, time: "1", pid: 1, ppid: 1, name: "d", proc: "/tmp/d", target: "/tmp/d", extra: "", parent: "/bin/zsh")
        m.consider(&stop, status: .dangerous)
        var ask = ActivityEvent(kind: .exec, time: "1", pid: 1, ppid: 1, name: "curl", proc: "/usr/bin/curl", target: "/usr/bin/curl", extra: "", parent: "/bin/zsh")
        m.consider(&ask, status: .unclassified)
        let day = ProtectionTimeline.buckets(m.hourly, area: .launches, range: .day)
        #expect(day.count == 24 && day.last?.block == 1 && day.last?.ask == 1)
        #expect(day.dropLast().allSatisfy { $0.total == 0 })
        #expect(ProtectionTimeline.buckets(m.hourly, area: .files, range: .day).allSatisfy { $0.total == 0 })
        let week = ProtectionTimeline.buckets(m.hourly, area: .launches, range: .week)
        #expect(week.count == 7 && week.last?.block == 1 && week.last?.ask == 1)
    }
}

/// The overview's header and the window's subtitle: one state, and the firewall counts.
@Suite struct ProtectionStates {
    @Test func everythingOffIsOff() {
        #expect(ProtectionState(paused: false, modes: [.off, .off], network: .off) == .off)
        #expect(ProtectionState.off.word == nil)
    }

    @Test func watchingAnywhereIsRehearsal() {
        #expect(ProtectionState(paused: false, modes: [.watch, .off], network: .off) == .rehearsing)
        #expect(ProtectionState(paused: false, modes: [.off, .off], network: .watch) == .rehearsing)
    }

    @Test func networkOnAskIsProtectingEvenWhenLaunchesOnlyWatch() {
        let s = ProtectionState(paused: false, modes: [.watch, .watch], network: .ask)
        #expect(s == .protecting && s.word == "Protecting")
        #expect(ProtectionState(paused: false, modes: [.strict, .off], network: .off) == .protecting)
    }

    @Test func pauseWinsOverEverything() {
        #expect(ProtectionState(paused: true, modes: [.strict, .ask], network: .strict) == .paused)
    }
}

/// The Overview's charts as data: every bucket present, the right bucket for each count, one shared scale.
@Suite struct ProtectionTimelines {
    var calendar: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "Europe/Kyiv")!; return c }
    let now = Date(timeIntervalSince1970: 1_794_000_000)        // a fixed moment, so day edges are known

    @Test func dayIs24HoursEndingNowWeekIs7DaysEndingToday() {
        let day = ProtectionTimeline.empty(.day, now: now, calendar: calendar)
        #expect(day.count == 24 && day.last!.start <= now && now.timeIntervalSince(day.last!.start) < 3600)
        let week = ProtectionTimeline.empty(.week, now: now, calendar: calendar)
        #expect(week.count == 7 && week.last!.start == calendar.startOfDay(for: now))
        #expect(calendar.dateComponents([.day], from: week.first!.start, to: week.last!.start).day == 6)
        let month = ProtectionTimeline.empty(.month, now: now, calendar: calendar)
        #expect(month.count == 30 && month.last!.start == calendar.startOfDay(for: now))
        #expect(ProtectionTimeline.Range.month.phrase == "the last 30 days")
    }

    @Test func countsLandInTheirBucketAndOldOnesAreLeftOut() {
        let hour = Int(now.timeIntervalSince1970 / 3600)
        let hourly = [
            ProtectionMonitor.HourCount(hour: hour, area: .launches, block: 2, ask: 1),
            ProtectionMonitor.HourCount(hour: hour - 30, area: .launches, block: 1, ask: 0),      // yesterday: week only
            ProtectionMonitor.HourCount(hour: hour - 10 * 24, area: .launches, block: 9, ask: 9),  // too old for day and week
            ProtectionMonitor.HourCount(hour: hour, area: .files, block: 5, ask: 5),               // another area
        ]
        let day = ProtectionTimeline.buckets(hourly, area: .launches, range: .day, now: now, calendar: calendar)
        #expect(day.reduce(0) { $0 + $1.block } == 2 && day.reduce(0) { $0 + $1.ask } == 1)
        let week = ProtectionTimeline.buckets(hourly, area: .launches, range: .week, now: now, calendar: calendar)
        #expect(week.reduce(0) { $0 + $1.block } == 3)
        // ten days ago: only the month sees it
        let month = ProtectionTimeline.buckets(hourly, area: .launches, range: .month, now: now, calendar: calendar)
        #expect(month.reduce(0) { $0 + $1.block } == 12)
    }

    @Test func networkBucketsByFirstSeenAndTheScaleIsShared() {
        let seen = [(now, blocked: true), (now.addingTimeInterval(-7200), blocked: false), (now.addingTimeInterval(-86_400 * 3), blocked: true)]
        let day = ProtectionTimeline.buckets(firstSeen: seen, range: .day, now: now, calendar: calendar)
        #expect(day.reduce(0) { $0 + $1.block } == 1 && day.reduce(0) { $0 + $1.ask } == 1)
        let week = ProtectionTimeline.buckets(firstSeen: seen, range: .week, now: now, calendar: calendar)
        #expect(week.reduce(0) { $0 + $1.block } == 2)
        #expect(ProtectionTimeline.sharedMax([day]) == 1 && ProtectionTimeline.sharedMax([day, week]) == 2)   // the week puts two on one day
        #expect(ProtectionTimeline.sharedMax([[], []]) == 1)       // never a zero-height scale
        #expect([3, 6, 7, 11, 23, 140, 1000].map(ProtectionTimeline.tidy) == [3, 10, 10, 20, 25, 200, 1000])
    }
}

/// A paused program checked by AI first: only a sure Safe lets it go on, this time, and never for what is yours to
/// decide. The question still comes for everything else, with what the AI said.
@MainActor @Suite struct ProtectionAIChecks {
    func verdict(_ v: Verdict, _ c: LocalVerdict.Confidence) -> LocalVerdict { .init(verdict: v, confidence: c, reason: "ordinary") }

    @Test func onlyASureSafeAllows() {
        #expect(LiveAICheck.outcome(verdict: verdict(.safe, .high), risk: .normal, warned: false, refusal: nil) == .allow("ordinary"))
        #expect(LiveAICheck.outcome(verdict: verdict(.safe, .medium), risk: .normal, warned: false, refusal: nil) != .allow("ordinary"))
        #expect(LiveAICheck.outcome(verdict: verdict(.suspicious, .high), risk: .normal, warned: false, refusal: nil) != .allow("ordinary"))
        #expect(LiveAICheck.outcome(verdict: nil, risk: .normal, warned: false, refusal: nil) == .ask("The AI didn't answer in time."))
    }

    @Test func shellsSensitiveFilesHighRiskAndWarningsStayYours() {
        let sure = verdict(.safe, .high)
        for case .ask(let note, _, _) in [
            LiveAICheck.outcome(verdict: sure, risk: .normal, warned: false, refusal: "python runs whatever it is told"),
            LiveAICheck.outcome(verdict: sure, risk: .high, warned: false, refusal: nil),
            LiveAICheck.outcome(verdict: sure, risk: .normal, warned: true, refusal: nil),
        ] { #expect(note.contains("Not allowed by AI alone")) }
    }

    @Test func onByDefaultAndCanBeTurnedOff() {
        let d = UserDefaults(suiteName: "aicheck-\(UUID().uuidString)")!
        #expect(LiveAICheck.enabled(d))
        d.set(false, forKey: LiveAICheck.settingKey)
        #expect(!LiveAICheck.enabled(d))
    }

    func paused(_ outcome: LiveAICheck.Outcome?) async -> (ProtectionMonitor, ProtectionReactive.Signals, [String]) {
        let (m, s) = ProtectionReactive().monitor(path: "/usr/bin/curl")
        m.launchMode = .ask
        var allowed: [String] = []
        m.aiCheck = { _ in outcome }
        m.onAIAllowed = { ask, _ in allowed.append(ask.event.name) }
        var e = ProtectionReactive().launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)
        #expect(m.prompts.first?.checking == true)           // a notice, not yet a question
        for _ in 0..<50 where m.prompts.first?.checking == true { try? await Task.sleep(for: .milliseconds(20)) }
        return (m, s, allowed)
    }

    @Test func safeLetsItGoOnOnceAndThePatternPassesThisSession() async {
        let (m, s, allowed) = await paused(.allow("ordinary"))
        #expect(m.prompts.isEmpty && s.sent.map(\.1) == [SIGSTOP, SIGCONT] && allowed == ["dropper"])
        var again = ProtectionReactive().launch("/usr/bin/curl")
        m.consider(&again, status: .unclassified)
        #expect(m.prompts.isEmpty && s.sent.count == 2)       // not paused again
    }

    @Test func anythingElseBecomesYourQuestionWithTheAIsView() async {
        let (m, s, allowed) = await paused(.ask("AI: suspicious, high confidence."))
        #expect(m.prompts.count == 1 && m.prompts[0].checking == false && allowed.isEmpty)
        #expect(m.prompts[0].aiNote == "AI: suspicious, high confidence." && s.sent.map(\.1) == [SIGSTOP])
        let (m2, _, _) = await paused(nil)
        #expect(m2.prompts.first?.aiNote?.contains("No fast AI model") == true)
    }
}

/// The Overview's cards wrap instead of pushing past a narrow window: three across, then two and one, then one.
@MainActor @Suite struct OverviewCardColumns {
    @Test func cardsWrapByWidth() {
        #expect(ProtectionOverview.columns(width: 0, cards: 3) == 3)          // before it's measured
        #expect(ProtectionOverview.columns(width: 1200, cards: 3) == 3)
        #expect(ProtectionOverview.columns(width: 600, cards: 3) == 2)
        #expect(ProtectionOverview.columns(width: 300, cards: 3) == 1)
        #expect(ProtectionOverview.columns(width: 2000, cards: 2) == 2)      // never more columns than cards
    }
}

/// Found doesn't grow forever: entries that don't happen again leave by themselves, and Forget clears many at once.
@MainActor @Suite struct FoundForgetting {
    func finding(_ verdict: ProtectionVerdict, daysAgo: Double) -> ProtectionFinding {
        let seen = Date().addingTimeInterval(-daysAgo * 86_400)
        return ProtectionFinding(id: "x", area: .launches, patternKey: "k", name: "n", program: "/p", pattern: "/p",
                                 verdict: verdict, reason: "", group: nil, count: 1, firstSeen: seen, lastSeen: seen)
    }

    @Test func questionsLeaveAfterAWeekStopsAfterAMonth() {
        #expect(!finding(.ask, daysAgo: 6).isStale(now: Date()))
        #expect(finding(.ask, daysAgo: 8).isStale(now: Date()))
        #expect(!finding(.block, daysAgo: 20).isStale(now: Date()))
        #expect(finding(.block, daysAgo: 31).isStale(now: Date()))
    }

    @Test func forgetClearsWhatMatchesAndKeepsTheRest() {
        let suite = "found-\(UUID().uuidString)"
        let m = ProtectionMonitor(defaults: UserDefaults(suiteName: suite)!,
                                  fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("\(suite).json"))
        m.launchMode = .watch
        var stop = ActivityEvent(kind: .exec, time: "1", pid: 1, ppid: 1, name: "d", proc: "/tmp/d", target: "/tmp/d", extra: "", parent: "/bin/zsh")
        m.consider(&stop, status: .dangerous)
        var ask = ActivityEvent(kind: .exec, time: "1", pid: 2, ppid: 1, name: "curl", proc: "/usr/bin/curl", target: "/usr/bin/curl", extra: "", parent: "/bin/zsh")
        m.consider(&ask, status: .unclassified)
        #expect(m.findings.count == 2)
        m.forget { $0.verdict == .ask }
        #expect(m.findings.count == 1 && m.findings.values.first?.verdict == .block)
        m.forget { _ in true }
        #expect(m.findings.isEmpty)
    }
}

/// The collector's hold: invisible to your shell where macOS allows, SIGSTOP otherwise, paused here when the
/// collector can't hold it, and released where it was held.
@MainActor @Suite struct ProtectionRemoteHold {
    func engine() -> (ReactiveEnforcer, ProtectionReactive.Signals, Ref) {
        let (m, s) = ProtectionReactive().monitor(path: "/usr/bin/curl")
        let ref = Ref()
        m.engine.remote = ReactiveEnforcer.Remote(hold: { ref.held.append($0); return ref.connected },
                                                  release: { ref.released.append(($0, $1)) })
        return (m.engine, s, ref)
    }
    final class Ref { var held: [Int32] = []; var released: [(Int32, Bool)] = []; var connected = true }

    @Test func theCollectorHoldsAndTheMethodDecidesTheHint() {
        let (e, s, ref) = engine()
        #expect(e.pause(pid: 4242, path: "/usr/bin/curl") && ref.held == [4242] && s.sent.isEmpty)   // nothing signalled here
        e.holdResult(pid: 4242, method: "task")
        #expect(!e.pausedTheShellWay(4242))                   // invisible: no fg hint
        e.release(pid: 4242, path: "/usr/bin/curl", stop: false)
        #expect(ref.released.count == 1 && ref.released[0].1 == false && e.pausedCount == 0)
        #expect(e.pause(pid: 4243, path: "/usr/bin/curl"))
        e.holdResult(pid: 4243, method: "signal")
        #expect(e.pausedTheShellWay(4243))                    // the shell saw a stop: say "type fg"
    }

    @Test func whenTheCollectorCantItsPausedHere() {
        let (e, s, ref) = engine()
        #expect(e.pause(pid: 4242, path: "/usr/bin/curl"))
        e.holdResult(pid: 4242, method: "none")
        #expect(s.sent.map(\.1) == [SIGSTOP] && e.pausedTheShellWay(4242))
        ref.connected = false
        #expect(e.pause(pid: 4300, path: "/usr/bin/curl") && s.sent.map(\.1) == [SIGSTOP, SIGSTOP])   // not connected
    }
}

/// Block Once stops the program and decides nothing; Always Block marks its pattern too. The AI's conclusion reaches
/// the question with its verdict and why it's yours.
@MainActor @Suite struct ProtectionAnswers {
    @Test func blockOnceStopsWithoutDecidingThePattern() {
        let (m, s) = ProtectionReactive().monitor(path: "/usr/bin/curl")
        var marked: [SignatureStatus] = []
        m.markPattern = { _, status in marked.append(status) }
        m.launchMode = .ask
        var e = ProtectionReactive().launch("/usr/bin/curl")
        m.consider(&e, status: .unclassified)
        m.respond(m.prompts[0].id, .blockOnce)
        #expect(s.sent.map(\.1) == [SIGSTOP, SIGKILL] && marked.isEmpty)
        var again = ProtectionReactive().launch("/usr/bin/curl")
        m.consider(&again, status: .unclassified)
        m.respond(m.prompts[0].id, .block)
        #expect(marked == [.dangerous])
    }

    @Test func theConclusionCarriesTheVerdictAndWhyItsYours() {
        let v = LocalVerdict(verdict: .safe, confidence: .high, reason: "ordinary")
        guard case .ask(_, let verdict, let limit) = LiveAICheck.outcome(verdict: v, risk: .normal, warned: false,
                                                                          refusal: "curl runs whatever it is told") else {
            Issue.record("a refused Safe must be asked"); return
        }
        #expect(verdict == v && limit == "curl runs whatever it is told")
    }
}

@Suite struct OwnClaudeCalls {
    private let claude = "/Users/alex/.local/share/claude/versions/2.1.327"

    /// Hostwatch's own call to Claude runs without a question; Claude started by anyone else is still checked,
    /// and so is any other program Hostwatch starts.
    @Test func onlyClaudeStartedByHostwatchItselfPasses() {
        let own = 500
        #expect(ProtectionMonitor.isOwnClaudeCall(exec(claude, pid: 9, ppid: own, parent: "/Applications/Hostwatch.app"), own: own))
        #expect(!ProtectionMonitor.isOwnClaudeCall(exec(claude, pid: 9, ppid: 77, parent: "/bin/zsh"), own: own))
        #expect(!ProtectionMonitor.isOwnClaudeCall(exec("/bin/sh", pid: 9, ppid: own, parent: "/Applications/Hostwatch.app"), own: own))
        #expect(!ProtectionMonitor.isOwnClaudeCall(exec("/tmp/claude", pid: 9, ppid: own, parent: "/Applications/Hostwatch.app"), own: own))
    }
}
