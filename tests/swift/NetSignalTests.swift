import Foundation
import Testing
@testable import Hostwatch

/// Beaconing, raw-IP connections and opt-in Homebrew trust.
@MainActor @Suite(.serialized) struct NetSignalTests {
    init() { _ = TestEnv.ready }

    func times(_ gaps: [TimeInterval]) -> [Date] {
        var t = [Date(timeIntervalSince1970: 1_800_000_000)]
        for g in gaps { t.append(t.last!.addingTimeInterval(g)) }
        return t
    }

    @Test func steadyIntervalMaths() {
        let range: ClosedRange<TimeInterval> = 10...3600
        #expect(BeaconDetector.steadyInterval(times([60, 60, 60, 60, 60]), range: range, maxJitter: 0.25) == 60)
        #expect(BeaconDetector.steadyInterval(times([55, 66, 58, 63, 60]), range: range, maxJitter: 0.25) != nil)
        #expect(BeaconDetector.steadyInterval(times([5, 300, 40, 900, 12]), range: range, maxJitter: 0.25) == nil)
        #expect(BeaconDetector.steadyInterval(times([3, 3, 3, 3, 3]), range: range, maxJitter: 0.25) == nil)
        #expect(BeaconDetector.steadyInterval(times([7200, 7200, 7200, 7200, 7200]), range: range, maxJitter: 0.25) == nil)
        #expect(BeaconDetector.steadyInterval(times([60, 60, 60, 60]), range: range, maxJitter: 0.25) == nil)  // too few
    }

    @Test func untrustedDropperBeaconIsFlaggedAtTheSixthContact() {
        let dropper = Binaries.make("beaconer", unsigned: true)
        let s = Scenario()
        var flags: [String] = []
        for (i, gap) in [0, 61, 58, 62, 59, 60, 61].enumerated() {
            s.feed(net(dropper, pid: 70, to: "45.33.12.7:8443"), after: TimeInterval(gap))
            flags.append(s.lastEvent?.beacon ?? "")
            if i < 5 { #expect(s.lastEvent?.beacon.isEmpty == true) }
        }
        #expect(flags[5].hasPrefix("every ~"))
        #expect(flags[6].hasPrefix("every ~"))
    }

    @Test func trustedProgramBeaconingToANamedHostIsNotFlagged() {
        let app = Binaries.make("telemetry")                        // Apple-signed copy: trusted
        let s = Scenario(learningMinutes: 10)                       // the host is a known (baseline) domain
        for _ in 0..<8 { s.feed(net(app, pid: 71, to: "34.149.66.165:443", host: "intake.telemetry.example"), after: 60) }
        #expect(s.lastEvent?.beacon.isEmpty == true)
    }

    @Test func trustedProgramBeaconingToARawIPIsFlagged() {
        let app = Binaries.make("telemetry-raw")
        let s = Scenario()
        for _ in 0..<8 { s.feed(net(app, pid: 72, to: "34.149.66.165:443"), after: 60) }
        #expect(s.lastEvent?.beacon.hasPrefix("every ~") == true)
    }

    @Test func rawIPRules() {
        let dropper = Binaries.make("rawip", unsigned: true)
        #expect(NetSignals.isRawIP(net(dropper, pid: 80, to: "45.33.1.1:4444")))
        #expect(!NetSignals.isRawIP(net(dropper, pid: 80, to: "45.33.1.1:4444", host: "c2.example")))  // DNS seen
        #expect(!NetSignals.isRawIP(net(dropper, pid: 80, to: "45.33.1.1:443")))                       // web port
        #expect(!NetSignals.isRawIP(net(dropper, pid: 80, to: "192.168.1.10:4444")))                   // LAN
        #expect(!NetSignals.isRawIP(net("/usr/libexec/apsd", pid: 81, to: "17.57.146.20:5223")))       // macOS daemon
        #expect(NetSignals.isRawIP(net("/usr/bin/curl", pid: 82, to: "45.33.1.1:8443")))               // LOLBin
        #expect(!NetSignals.isRawIP(net(Binaries.make("signed-app"), pid: 83, to: "45.33.1.1:4444")))  // trusted
    }

    @Test func dropperBeaconingToARawIPIsADangerousStory() throws {
        let dropper = Binaries.make("implant", unsigned: true)
        let s = Scenario()
        s.feed(exec(dropper, pid: 90, ppid: 1, parent: "/sbin/launchd"))
        for _ in 0..<7 { s.feed(net(dropper, pid: 90, to: "45.33.12.7:4444"), after: 60) }
        let story = try #require(s.fired.first)
        #expect(story.severity == .dangerous)
        #expect(Set(story.stages).isSuperset(of: [.beaconing, .rawIP, .runFromDrop]))
    }

    /// Real Homebrew binary (skipped when none is installed): ad-hoc, so never routine by signature.
    @Test(.enabled(if: realHomebrewBinary != nil)) func homebrewToolsAreNotTrustedBySignature() throws {
        let git = try #require(realHomebrewBinary)
        #expect(file(git, pid: 95, "r", "\(home)/Documents/repo/main.go").signatureRisk == .normal)
    }
}

/// A Homebrew-installed, ad-hoc-signed executable on this Mac, if any.
let realHomebrewBinary: String? = {
    let fm = FileManager.default
    for formula in ["git", "fish", "kubernetes-cli", "watchman", "ripgrep", "jq"] {
        let dir = "/opt/homebrew/Cellar/\(formula)"
        guard let versions = try? fm.contentsOfDirectory(atPath: dir) else { continue }
        for v in versions {
            let binDir = "\(dir)/\(v)/bin"
            guard fm.fileExists(atPath: "\(dir)/\(v)/INSTALL_RECEIPT.json"),
                  let bins = try? fm.contentsOfDirectory(atPath: binDir) else { continue }
            for b in bins where fm.isExecutableFile(atPath: "\(binDir)/\(b)") {
                let path = (("\(binDir)/\(b)") as NSString).resolvingSymlinksInPath
                if path.hasPrefix("/opt/homebrew/Cellar/") { return path }
            }
        }
    }
    return nil
}()
