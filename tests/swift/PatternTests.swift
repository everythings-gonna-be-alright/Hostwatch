import Testing
@testable import Hostwatch

/// Pattern grouping (one fingerprint per "who did what, where") and the local risk levels.
@Suite struct PatternGrouping {
    @Test func randomTempFileNamesAreOnePattern() {
        let biome = "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent"
        let a = file(biome, pid: 1, "rw", "\(home)/Library/Biome/tmp/.tmp.TY4MFKF5uR")
        let b = file(biome, pid: 1, "rw", "\(home)/Library/Biome/tmp/.tmp.0vRMxxd0Tn")
        #expect(a.signatureKey == b.signatureKey)
        #expect(a.signatureRisk == .routine)
    }

    @Test func homeFoldersCollapseToOneZone() {
        let rg = "/opt/homebrew/bin/rg"
        let a = file(rg, pid: 2, "r", "\(home)/Documents/git/my-project/src/main.go")
        let b = file(rg, pid: 2, "r", "\(home)/Documents/notes.txt")
        #expect(a.signaturePattern == "r ~/Documents/**")
        #expect(a.signatureKey == b.signatureKey)
    }

    @Test func versionNamedExecutablesAreOneProcess() {
        let a = file("\(home)/.local/share/claude/versions/2.1.316", pid: 3, "r", "\(home)/Documents/a")
        let b = file("\(home)/.local/share/claude/versions/2.1.317", pid: 3, "r", "\(home)/Documents/a")
        #expect(a.signatureProcess == b.signatureProcess)
        #expect(displayProcessName(a.signatureProcess) == "claude/#.#.#")
    }

    @Test func webTrafficIsOneInternetBucket() {
        let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        #expect(net(chrome, pid: 4, to: "142.250.154.100:443").signaturePattern == "TCP internet:443")
        #expect(net(chrome, pid: 4, to: "17.57.172.10:443").signaturePattern == "TCP internet:443")
    }
}

@Suite struct PatternRiskRules {
    @Test func sensitiveReadByNonOwnerIsHigh() {
        let e = file("/opt/homebrew/bin/python3", pid: 10, "r", "\(home)/.ssh/id_ed25519")
        #expect(e.signatureRisk == .high)
        #expect(e.signaturePattern.hasSuffix("[SSH keys]"))
    }

    @Test func sshReadingItsKeysIsNormal() {
        #expect(file("/usr/bin/ssh", pid: 11, "r", "\(home)/.ssh/config").signatureRisk == .normal)
    }

    @Test func keychainReadIsNormalButWriteIsHigh() {
        let slack = "/Applications/Slack.app/Contents/MacOS/Slack"
        #expect(file(slack, pid: 12, "r", "\(home)/Library/Keychains/login.keychain-db").signatureRisk == .normal)
        #expect(file(slack, pid: 12, "w", "\(home)/Library/Keychains/login.keychain-db").signatureRisk == .high)
    }

    @Test func launchAgentWriteIsPersistenceButReadIsNot() {
        let tool = "/opt/homebrew/bin/sometool"
        let write = file(tool, pid: 13, "w", "\(home)/Library/LaunchAgents/com.x.plist")
        #expect(write.signatureRisk == .high)
        #expect(write.signaturePattern.hasSuffix("[persistence]"))
        #expect(!file(tool, pid: 13, "r", "\(home)/Library/LaunchAgents/com.x.plist").signaturePattern.contains("persistence"))
    }

    @Test func appOwnDataIsRoutineButOtherAppsDataIsNot() {
        let cursor = "/Applications/Cursor.app/Contents/MacOS/Cursor"
        let own = file(cursor, pid: 14, "rw", "\(home)/Library/Application Support/Cursor/User/state.vscdb")
        #expect(own.signatureRisk == .routine)
        #expect(own.signaturePattern.hasSuffix("[own data]"))
        #expect(!file(cursor, pid: 14, "r", "\(home)/Library/Application Support/Google/x").signaturePattern.contains("own data"))
    }

    @Test func systemServicesAreOneRoutinePattern() {
        let e = exec("/usr/libexec/keyboardservicesd", pid: 15, ppid: 1, parent: "/usr/libexec/xpcproxy")
        #expect(e.signaturePattern == "macOS system service")
        #expect(e.signatureRisk == .routine)
    }

    @Test func appSpawningShellIsHigh() {
        let e = exec("/bin/sh", pid: 16, ppid: 5, parent: "/Applications/Slack.app/Contents/MacOS/Slack")
        #expect(e.signatureRisk == .high)
    }

    @Test func terminalSpawningShellIsNotHigh() {
        let e = exec("/bin/zsh", pid: 17, ppid: 5, parent: "/Applications/iTerm.app/Contents/MacOS/iTerm2")
        #expect(e.signatureRisk != .high)
    }

    @Test func networkRules() {
        #expect(net("/usr/bin/curl", pid: 18, to: "45.33.1.1:8443").signatureRisk == .high)    // LOLBin, odd port
        #expect(net("/usr/bin/ssh", pid: 19, to: "140.82.121.4:22").signatureRisk != .high)    // ssh on 22
        #expect(net("/opt/homebrew/bin/node", pid: 20, to: "127.0.0.1:3000").signatureRisk == .routine)
    }
}

@Suite struct ShowFilter {
    @Test func newMeansNotReviewedByYou() {
        let f = SignatureFilter.unclassified
        #expect(f.admits(.unclassified, risk: .normal, reviewed: false))
        #expect(f.admits(.suspicious, risk: .normal, reviewed: false))     // flagged by Claude only
        #expect(!f.admits(.suspicious, risk: .normal, reviewed: true))     // you reviewed it
        #expect(!f.admits(.safe, risk: .routine, reviewed: false))
    }

    @Test func importantIsFlaggedOrNewHighRisk() {
        let f = SignatureFilter.important
        #expect(f.admits(.dangerous, risk: .normal, reviewed: true))
        #expect(f.admits(.unclassified, risk: .high, reviewed: false))
        #expect(!f.admits(.unclassified, risk: .normal, reviewed: false))
    }
}
