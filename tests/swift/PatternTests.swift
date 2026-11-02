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

    /// The general rule: no pattern covers a whole area like ~/Documents/** or ~/*.
    @Test func patternsAreSpecific() {
        let rg = "/opt/homebrew/bin/rg"
        #expect(file(rg, pid: 2, "r", "\(home)/Documents/git/my-project/src/main.go").signaturePattern == "r ~/Documents/git/my-project/src/*")
        #expect(file(rg, pid: 2, "r", "\(home)/Documents/notes.txt").signaturePattern == "r ~/Documents/notes.txt")
        #expect(file(rg, pid: 2, "r", "\(home)/todo.txt").signaturePattern == "r ~/todo.txt")
        #expect(file(rg, pid: 2, "r", "\(home)/Projects/app/node_modules/a/b/c/index.js").signaturePattern
                == "r ~/Projects/app/node_modules/a/**")                          // deep trees end in /**
        #expect(file(rg, pid: 2, "r", "/Users/Shared/run.sh").signaturePattern == "r /Users/Shared/run.sh")
        for pattern in ["r ~/*", "r ~/Documents/*", "r ~/Documents/**", "r /*", "r /Users/**", "r /tmp/*", "r *", "w /Users/Shared/*"] {
            #expect(SignatureBuilder.isTooWide(filePattern: pattern), "\(pattern)")
        }
        for pattern in ["r ~/Documents/work/*", "r /Users/Shared/tools/*", "r ~/.ssh/*  [ssh keys]", "r ~/todo.txt"] {
            #expect(!SignatureBuilder.isTooWide(filePattern: pattern), "\(pattern)")
        }
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

/// Interpreters and shells get narrow patterns: the domain, the exact folder; never "internet" or "~/Documents/**".
@Suite struct NarrowInterpreterPatterns {
    @Test func networkNamesTheDomain() {
        let e = net("/opt/homebrew/bin/python3.12", pid: 11, to: "151.101.0.223:443", host: "files.pythonhosted.org")
        #expect(e.signaturePattern == "TCP pythonhosted.org:443")
        let raw = net("/opt/homebrew/bin/node", pid: 12, to: "45.1.2.3:443")
        #expect(raw.signaturePattern == "TCP 45.1.2.3:443")
        let app = net("/Applications/Slack.app/Contents/MacOS/Slack", pid: 13, to: "3.68.170.153:443", host: "app.slack.com")
        #expect(app.signaturePattern == "TCP internet:443")                      // apps keep the broad bucket
    }

    @Test func filesNameTheExactFolder() {
        let py = file("/opt/homebrew/bin/python3", pid: 14, "r", "\(home)/Documents/work/report/data.csv")
        #expect(py.signaturePattern == "r ~/Documents/work/report/*")
        let other = file("/opt/homebrew/bin/python3", pid: 14, "r", "\(home)/Documents/notes.txt")
        #expect(other.signatureKey != py.signatureKey)
        let app = file("/Applications/Tool.app/Contents/MacOS/Tool", pid: 15, "r", "\(home)/Documents/work/report/data.csv")
        #expect(app.signaturePattern == "r ~/Documents/work/report/*")             // the same general rule for apps
        #expect(file("/opt/homebrew/bin/python3", pid: 18, "r", "\(home)/todo.txt").signaturePattern == "r ~/todo.txt")
        #expect(other.signaturePattern == "r ~/Documents/notes.txt")
        #expect(file("/bin/bash", pid: 19, "r", "/Users/Shared/run.sh").signaturePattern == "r /Users/Shared/run.sh")
        let bash = file("/bin/bash", pid: 16, "r", "/Users/Shared/tools/run.sh")
        #expect(bash.signaturePattern == "r /Users/Shared/tools/*")
        #expect(!file("/bin/zsh", pid: 17, "r", "\(home)/Projects/a/b/c.txt").signaturePattern.contains("**"))
    }
}

/// Launches of interpreters and tools name what was run: never "bash → perl" (perl running anything).
@Suite struct SpecificLaunchPatterns {
    @Test func interpretersNameTheScriptOrTheCode() {
        #expect(exec("/usr/bin/perl", pid: 1, ppid: 0, parent: "/bin/bash", args: "perl \(home)/bin/build.pl --fast")
                .signaturePattern == "/usr/bin/perl ~/bin/build.pl")
        #expect(exec("/bin/sh", pid: 2, ppid: 0, parent: "/bin/zsh", args: "sh -c 'curl -s https://x.example/p | sh'")
                .signaturePattern == "/bin/sh -c ‹curl -s https://x.example/p | sh›")
        #expect(exec("/opt/homebrew/bin/python3.12", pid: 3, ppid: 0, parent: "/bin/zsh", args: "python3.12 -u tools/run.py")
                .signaturePattern == "/opt/homebrew/bin/python3.12 tools/run.py")
    }

    @Test func toolsNameTheirArguments() {
        let ditto = exec("/usr/bin/ditto", pid: 4, ppid: 0, parent: "/bin/bash",
                         args: "ditto -x -k '\(home)/Downloads/My App.zip' \(home)/Downloads")
        #expect(ditto.signaturePattern == "/usr/bin/ditto -x -k ~/Downloads/My App.zip ~/Downloads")
        let a = exec("/usr/bin/curl", pid: 5, ppid: 0, parent: "/bin/bash", args: "curl -s https://a.example/x")
        let b = exec("/usr/bin/curl", pid: 6, ppid: 0, parent: "/bin/bash", args: "curl -s https://b.example/y")
        #expect(a.signatureKey != b.signatureKey)                                   // two downloads, two patterns
    }

    @Test func otherProgramsAndBareShellsStayAsTheyWere() {
        #expect(exec("/bin/ls", pid: 7, ppid: 0, parent: "/bin/zsh", args: "ls -la").signaturePattern == "/bin/ls")
        #expect(exec("/bin/zsh", pid: 8, ppid: 0, parent: "/usr/bin/login", args: "-zsh").signaturePattern.hasPrefix("/bin/zsh"))
        #expect(SignatureBuilder.shellTokens("ditto -x 'a b' c") == ["ditto", "-x", "a b", "c"])
    }

    @Test func appSpawningAShellIsStillHighRisk() {
        let e = exec("/bin/sh", pid: 9, ppid: 0, parent: "/Applications/Slack.app/Contents/MacOS/Slack", args: "sh -c 'id'")
        #expect(e.signatureRisk == .high && e.signaturePattern == "/bin/sh -c ‹id›")
    }
}
