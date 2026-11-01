import Foundation
import Testing
@testable import Hostwatch

/// Code signing on real binaries (copies of /bin/echo in a temp folder).
@Suite(.serialized) struct Signing {
    init() { _ = TestEnv.ready }

    @Test func identifiesSignerKinds() throws {
        let cache = SigningCache.shared
        let apple = try #require(cache.identity(Binaries.make("apple-copy")))
        #expect(apple.signed && apple.apple && !apple.adhoc)
        let unsigned = try #require(cache.identity(Binaries.make("unsigned", unsigned: true)))
        #expect(!unsigned.signed && unsigned.untrustedCode)
        let adhoc = try #require(cache.identity(Binaries.make("adhoc", adhoc: true)))
        #expect(adhoc.signed && adhoc.adhoc && adhoc.untrustedCode)
        let quarantined = try #require(cache.identity(Binaries.make("quarantined", adhoc: true, quarantined: true)))
        #expect(quarantined.quarantined && quarantined.label == "Ad-hoc · quarantined")
    }

    @Test func unsignedCodeFromTempIsHighRisk() {
        let path = Binaries.make("dropper", unsigned: true)
        #expect(net(path, pid: 50, to: "45.33.1.1:443").signatureRisk == .high)
        #expect(file(path, pid: 50, "r", "\(home)/Documents/a").signatureRisk == .high)
    }

    @Test func unsignedCodeOutsideDropZonesIsLeftToPathRules() {
        // Homebrew-style ad-hoc tools are everyday: reading system files stays routine.
        let e = file("/opt/homebrew/Cellar/git/2.54.0/bin/git", pid: 51, "r", "/usr/share/git-core/templates/x")
        #expect(e.signatureRisk == .routine)
    }

    @Test func replacedBinaryIsDetected() throws {
        let cache = SigningCache.shared
        let path = Binaries.make("updater")                       // Apple-signed copy
        _ = cache.identity(path)
        #expect(cache.swapReason(path) == nil)
        // Same path, now an unsigned binary (new inode/size): noticed without restarting.
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.copyItem(atPath: Binaries.make("unsigned-replacement", unsigned: true), toPath: path)
        let now = try #require(cache.identity(path))
        #expect(!now.signed)
        #expect(cache.swapReason(path)?.contains("now unsigned") == true)
        #expect(net(path, pid: 52, to: "1.2.3.4:443").signatureRisk == .high)
    }

    @Test func swapRulesIgnoreNormalUpdates() {
        var old = CodeIdentity(); old.signed = true; old.teamID = "EQHXZ8M8AV"; old.organization = "Google LLC"
        var update = old; update.cdhash = "new-build"
        #expect(update.swapped(from: old) == nil)                   // same team, new build
        var other = old; other.teamID = "ABCDE12345"; other.organization = "Someone Else"
        #expect(other.swapped(from: old) != nil)                    // different signer
        var adhoc = old; adhoc.adhoc = true; adhoc.teamID = nil
        #expect(adhoc.swapped(from: old) != nil)                    // lost its identity
    }

    @MainActor @Test func unsignedDownloadChainIsDangerous() throws {
        let path = Binaries.make("downloaded", adhoc: true, quarantined: true)
        let s = Scenario()
        s.feed(exec(path, pid: 60, ppid: 1, parent: "/sbin/launchd"))
        s.feed(file(path, pid: 60, "w", "\(home)/Library/LaunchAgents/com.update.helper.plist"))
        s.feed(net(path, pid: 60, to: "45.33.1.1:8443", host: "c2.example"))
        let story = try #require(s.fired.first)
        #expect(story.severity == .dangerous)
        #expect(story.stages.contains(.unsignedCode))
    }
}
