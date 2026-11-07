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

    /// Reads inside a project by a tool: one pattern per project. Writes, shells and files outside stay per folder.
    @Test func projectReadsAreOnePattern() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("hw-proj-\(UUID().uuidString)")
        let repo = root.appendingPathComponent("code/apps/shop")
        try FileManager.default.createDirectory(at: repo.appendingPathComponent("src/model"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("code/notes"), withIntermediateDirectories: true)
        try Data().write(to: repo.appendingPathComponent(".git"))                    // a worktree's .git is a file
        defer { try? FileManager.default.removeItem(at: root) }
        let rg = "/opt/homebrew/bin/rg", norm = SignatureBuilder.normalize(repo.path)
        let a = file(rg, pid: 1, "r", repo.appendingPathComponent("src/model/user.go").path)
        let b = file(rg, pid: 1, "r", repo.appendingPathComponent("README.md").path)
        #expect(a.signaturePattern == "r \(norm)/**" && a.signatureKey == b.signatureKey)
        #expect(!SignatureBuilder.isTooWide(filePattern: a.signaturePattern))
        // (The test tree lives in a scratch folder, so the others follow the scratch-tree rule; what matters here is
        // that none of them is the project's pattern.)
        #expect(!file(rg, pid: 1, "w", repo.appendingPathComponent("src/model/user.go").path).signaturePattern.hasSuffix("\(norm)/**"))
        #expect(file("/bin/zsh", pid: 2, "r", repo.appendingPathComponent("src/model/user.go").path).signaturePattern.hasSuffix("/src/model/*"))
        #expect(!file(rg, pid: 1, "r", root.appendingPathComponent("code/notes/todo.md").path).signaturePattern.hasSuffix("\(norm)/**"))
        #expect(SignatureBuilder.projectRoot(of: "\(home)/x.txt") == nil)            // never the home folder
    }

    @Test func scratchTreesAndFormulasAreOnePattern() {
        let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        #expect(file(chrome, pid: 1, "r", "/private/tmp/site-shot/profile1/Default/Service Worker/x").signaturePattern == "r /tmp/site-shot/**")
        #expect(file(chrome, pid: 1, "r", "/private/tmp/site-shot/x.png").signaturePattern == "r /tmp/site-shot/x.png")
        let py = "/opt/homebrew/Cellar/python@3.12/3.12.4/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python"
        let a = file(py, pid: 2, "r", "/opt/homebrew/Cellar/awscli/2.17.0/libexec/lib/python3.12/site-packages/botocore/x.py")
        let b = file(py, pid: 2, "r", "/opt/homebrew/Cellar/awscli/2.17.0/libexec/lib/python3.12/site-packages/boto3/y.py")
        #expect(a.signaturePattern == "r /opt/homebrew/Cellar/awscli/**" && a.signatureKey == b.signatureKey)
        #expect(file(py, pid: 2, "w", "/opt/homebrew/Cellar/awscli/2.17.0/libexec/lib/python3.12/site-packages/boto3/y.py").signaturePattern != a.signaturePattern)
        #expect(file(py, pid: 2, "r", "\(home)/Documents/work/x.py").signaturePattern == "r ~/Documents/work/*")   // interpreters stay exact elsewhere
    }

    /// A shell starting plain tools: one pattern per folder. Watched and admin tools keep theirs, with arguments.
    @Test func shellsStartingPlainToolsAreOnePattern() {
        func run(_ tool: String, _ args: String, parent: String = "/bin/zsh") -> String {
            exec(tool, pid: 3, ppid: 0, parent: parent, args: args).signaturePattern
        }
        #expect(run("/usr/bin/awk", "awk {print}") == "/usr/bin/*  (plain tools)")
        #expect(run("/usr/bin/cut", "cut -d: -f1") == run("/usr/bin/awk", "awk x"))
        #expect(run("/bin/ls", "ls") == "/bin/*  (plain tools)")
        #expect(run("/usr/bin/curl", "curl https://x.example/a").hasPrefix("/usr/bin/curl "))
        #expect(run("/usr/bin/defaults", "defaults write com.apple.x y 1") == "/usr/bin/defaults")
        #expect(run("/usr/bin/sudo", "sudo rm -rf /") == "/usr/bin/sudo")
        #expect(run("/usr/sbin/chown", "chown root x") == "/usr/sbin/chown")
        #expect(run("/opt/homebrew/bin/jq", "jq .") == "/opt/homebrew/bin/jq")          // not macOS's own
        #expect(run("/usr/bin/awk", "awk x", parent: "/Applications/Tool.app/Contents/MacOS/Tool") == "/usr/bin/awk")
        #expect(exec("/usr/bin/awk", pid: 4, ppid: 0, parent: "/bin/zsh", args: "awk x").signatureRisk == .routine)
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

    @Test func launchesRegroupToo() throws {
        let s = store()
        _ = s.observe(exec("/usr/bin/awk", pid: 1, ppid: 0, parent: "/bin/zsh", args: "awk x"))
        var e = try #require(s.allEntries.first)
        s.delete(keys: [e.id])
        e.id = "exec|/bin/zsh|/usr/bin/awk"; e.pattern = "/usr/bin/awk"
        s.restore(e)
        #expect(s.regroup().moved == 1)
        #expect(s.allEntries.first?.pattern == "/usr/bin/*  (plain tools)")
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
