import Foundation
import Testing
@testable import Hostwatch

/// Fewer patterns where the detail says nothing: macOS's own programs' ordinary reads are one pattern per program,
/// random temp names fold. What could be a signal stays specific.
@Suite struct FewerPatterns {
    let mds = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds"
    let tccd = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"

    @Test func systemProgramsReadsAreOnePattern() {
        let a = file(mds, pid: 1, "r", "/System/Library/Fonts/Helvetica.ttc")
        let b = file(mds, pid: 1, "r", "\(home)/Documents/work/report.pdf")
        let c = file(mds, pid: 1, "r", "/Library/Preferences/com.apple.x.plist")
        #expect(a.signaturePattern == "r *  [ordinary files]")
        #expect(a.signatureKey == b.signatureKey && b.signatureKey == c.signatureKey)
        #expect(a.signatureRisk == .routine)
        #expect(!SignatureBuilder.isTooWide(filePattern: a.signaturePattern))
        #expect(file(tccd, pid: 2, "r", "/Library/Preferences/x.plist").signatureKey != a.signatureKey)   // per program
    }

    /// Exceptions: writes, sensitive places, shells and command-line tools keep their exact folders.
    @Test func whatCouldBeASignalStaysSpecific() {
        #expect(file(mds, pid: 1, "w", "\(home)/Documents/work/report.pdf").signaturePattern == "w ~/Documents/work/*")
        #expect(file(mds, pid: 1, "rw", "/Library/Preferences/x.plist").signaturePattern != "rw *  [ordinary files]")
        #expect(file(mds, pid: 1, "r", "\(home)/.ssh/id_ed25519").signaturePattern.hasSuffix("[SSH keys]"))
        #expect(file(mds, pid: 1, "r", "\(home)/Library/Keychains/login.keychain-db").signaturePattern.hasSuffix("[keychain]"))
        for tool in ["/bin/zsh", "/bin/cat", "/usr/bin/python3", "/usr/bin/osascript", "/usr/bin/curl"] {
            let p = file(tool, pid: 3, "r", "\(home)/Documents/work/report.pdf").signaturePattern
            #expect(p == "r ~/Documents/work/*", "\(tool): \(p)")
        }
        let app = "/Applications/Tool.app/Contents/MacOS/Tool"                // not macOS's own
        #expect(file(app, pid: 4, "r", "\(home)/Documents/work/report.pdf").signaturePattern == "r ~/Documents/work/*")
    }

    @Test func randomTempNamesFold() {
        #expect(SignatureBuilder.foldTempName("/private/tmp/zshVJbGMW") == "/private/tmp/zsh*")
        #expect(SignatureBuilder.foldTempName("/tmp/hostwatch.29Cjgb/a/b.txt") == "/tmp/hostwatch.*/a/b.txt")
        #expect(SignatureBuilder.foldTempName("/tmp/claude-ssh-config-CjazuK") == "/tmp/claude-ssh-config-*")
        #expect(SignatureBuilder.foldTempName("/tmp/hwg-58FCB94D") == "/tmp/hwg-*")
        #expect(SignatureBuilder.foldTempName("/tmp/hwCDDEE408") == "/tmp/hw*")
        #expect(SignatureBuilder.foldTempName("/private/var/folders/ab/cd12/T/tmp.aB3dE9xy") == "/private/var/folders/ab/cd12/T/tmp.*")
        // Real names stay.
        for name in ["/tmp/caroline-main.hcl", "/tmp/hw-perf-runs.txt", "/tmp/agent-alex-hardening-patches",
                     "/tmp/bento-src/x.go", "/tmp/Makefile", "/tmp/README", "/tmp/testCase", "/tmp/h1test",
                     "/Users/x/zshVJbGMW"] {
            #expect(SignatureBuilder.foldTempName(name) == nil, "\(name)")
        }
        let zsh = "/bin/zsh"
        let a = file(zsh, pid: 5, "r", "/private/tmp/zshVJbGMW"), b = file(zsh, pid: 5, "r", "/private/tmp/zsh7MY2Kf")
        #expect(a.signatureKey == b.signatureKey && a.signaturePattern == "r /tmp/zsh*")
        #expect(!SignatureBuilder.isTooWide(filePattern: "r /tmp/zsh*"))
        #expect(!SignatureBuilder.isTooWide(filePattern: "r $TMPDIR/hostwatch.*"))
        #expect(SignatureBuilder.isTooWide(filePattern: "r /tmp/*"))
        #expect(SignatureBuilder.isTooWide(filePattern: "r /tmp/z*"))                // one letter names nothing
    }
}

/// The store from an earlier version: what today's rules write as one moves into it, at launch.
@MainActor @Suite(.serialized) struct RegroupPatterns {
    let mds = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds"

    func store() -> SignatureStore {
        _ = TestEnv.ready
        return SignatureStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("hw-regroup-\(UUID().uuidString)"))
    }

    /// A pattern as an earlier version saved it.
    func old(_ s: SignatureStore, _ e: ActivityEvent, pattern: String, count: Int = 2, daysAgo: Double = 1,
             status: SignatureStatus = .safe, source: String? = "auto") -> String {
        _ = s.observe(e)
        var entry = s.entry(e.signatureKey)!
        s.delete(keys: [entry.id])
        entry.id = "file|\(entry.process)|\(pattern)"
        entry.pattern = pattern
        entry.count = count
        entry.firstSeen = Date().addingTimeInterval(-daysAgo * 86_400)
        entry.status = status
        entry.source = source
        s.restore(entry)
        return entry.id
    }

    @Test func automaticPatternsMoveYoursStay() throws {
        let s = store()
        let a = old(s, file(mds, pid: 1, "r", "/System/Library/Fonts/A.ttc"), pattern: "r /System/Library/Fonts/*", count: 5, daysAgo: 9)
        let b = old(s, file(mds, pid: 1, "r", "/Library/Preferences/x.plist"), pattern: "r /Library/Preferences/*", count: 3)
        let yours = old(s, file(mds, pid: 1, "r", "\(home)/Documents/work/x.pdf"), pattern: "r ~/Documents/work/*",
                        status: .suspicious, source: "you")
        let z1 = old(s, file("/bin/zsh", pid: 2, "r", "/private/tmp/zshVJbGMW"), pattern: "r /tmp/zshVJbGMW")
        let z2 = old(s, file("/bin/zsh", pid: 2, "r", "/private/tmp/zsh7MY2Kf"), pattern: "r /tmp/zsh#MY#Kf",
                     status: .unclassified, source: nil)
        let before = s.allEntries.count

        let r = s.regroup()
        #expect(r.moved == 4 && r.into == 2)
        #expect(s.allEntries.count == before - 2)
        let reads = try #require(s.allEntries.first { $0.pattern == "r *  [ordinary files]" })
        #expect(reads.count == 8 && reads.status == .safe && reads.source == "auto")
        #expect(reads.firstSeen < Date().addingTimeInterval(-8 * 86_400))            // the earliest is kept
        #expect(s.entry(a) == nil && s.entry(b) == nil)
        #expect(s.entry(yours)?.status == .suspicious)                              // your decision stays as it was
        let temp = try #require(s.entry(z1))                                         // old temp keys answer for it
        #expect(temp.pattern == "r /tmp/zsh*" && temp.status == .unclassified)      // a New one among them: New
        #expect(s.entry(z2)?.id == temp.id)
        #expect(s.regroup().moved == 0)                                              // once
    }

    @Test func newEventsJoinTheRegroupedPattern() {
        let s = store()
        _ = old(s, file(mds, pid: 1, "r", "/System/Library/Fonts/A.ttc"), pattern: "r /System/Library/Fonts/*")
        s.regroup()
        let e = file(mds, pid: 1, "r", "/usr/share/zoneinfo/UTC")
        #expect(s.observe(e) == false)                                              // nothing new to look at
        #expect(s.entry(e.signatureKey)?.count == 3)
    }
}
