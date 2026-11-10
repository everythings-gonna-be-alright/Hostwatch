import Foundation
import Testing
@testable import Hostwatch

/// When an AI's Safe may be applied: never for what run-anything tools launch, connect to or write, nor high-risk
/// patterns. Their plain reads of an exact folder in your own projects are the exception (ADR 0013).
@MainActor @Suite struct AISafeRefusals {
    func entry(_ kind: EventKind, actor: String, pattern: String, risk: PatternRisk = .normal) -> SignatureEntry {
        SignatureEntry(id: "\(kind.rawValue)|\(actor)|\(pattern)", kind: kind, process: actor, pattern: pattern, count: 3, risk: risk,
                       firstSeen: Date(), lastSeen: Date(), status: .unclassified, exampleName: (actor as NSString).lastPathComponent,
                       examplePid: 1, exampleProc: actor, exampleTarget: actor, exampleExtra: "r", exampleParent: "/bin/zsh")
    }

    @Test func aBuildFolderReadByCodesignMayBeAISafe() {
        #expect(SignatureBuilder.aiSafeRefusal(entry(.file, actor: "/usr/bin/codesign",
                                                    pattern: "r ~/Documents/ProcessHUD/.build-demo/out/Products/*")) == nil)
    }

    @Test func everythingElseStaysYoursWithItsReason() {
        let cases: [(SignatureEntry, String)] = [
            (entry(.file, actor: "/usr/bin/codesign", pattern: "w ~/Documents/ProcessHUD/.build/x"), "writing files"),
            (entry(.file, actor: "/usr/bin/codesign", pattern: "r ~/Library/Caches/x/*"), "outside your own project folders"),
            (entry(.file, actor: "/usr/bin/codesign", pattern: "r ~/Documents/*"), "outside your own project folders"),
            (entry(.file, actor: "/usr/bin/python3", pattern: "r ~/.ssh/*  [SSH keys]"), "sensitive place"),
            (entry(.net, actor: "/usr/bin/curl", pattern: "TCP internet:443"), "connections"),
            (entry(.file, actor: "/usr/bin/codesign", pattern: "r ~/Documents/P/build/*", risk: .high), "high-risk"),
        ]
        for (e, words) in cases { #expect(SignatureBuilder.aiSafeRefusal(e)?.contains(words) == true, "\(e.pattern)") }
        var launch = entry(.exec, actor: "/bin/zsh", pattern: "/bin/bash ~/x.sh")
        launch.exampleTarget = "/bin/bash"
        #expect(SignatureBuilder.aiSafeRefusal(launch)?.contains("runs whatever it is told") == true)
        #expect(SignatureBuilder.aiSafeRefusal(entry(.file, actor: "/Applications/Slack.app/Contents/MacOS/Slack",
                                                     pattern: "r ~/Library/Caches/x/*")) == nil)    // not a run-anything tool
    }

    @Test func aRefusedSafeIsKeptAsASuggestionWithWhyAndYouCanAcceptIt() {
        let store = SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("refuse-\(UUID().uuidString)"))
        store.autoAcceptAI = true
        let e = ActivityEvent(kind: .file, time: "12:00:00", pid: 10, ppid: 9, name: "codesign", proc: "/usr/bin/codesign",
                              target: NSHomeDirectory() + "/Downloads/Tool.app/Contents/MacOS/Tool", extra: "w", parent: "/bin/zsh")
        _ = store.observe(e)
        #expect(store.status(forKey: e.signatureKey) == .unclassified)            // a New pattern to start with
        store.suggest(.safe, key: e.signatureKey, source: "claude", note: "ordinary")
        #expect(store.status(forKey: e.signatureKey) == .unclassified)            // not applied, even with auto-accept
        #expect(store.decidedBy(e.signatureKey).hasPrefix("AI suggests Safe · yours:"))
        #expect(store.acceptSuggestions(keys: [e.signatureKey], yours: false) == 0)
        #expect(store.acceptSuggestions(keys: [e.signatureKey], yours: true) == 1)  // your click decides it
        #expect(store.status(forKey: e.signatureKey) == .safe)
    }
}
