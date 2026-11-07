import AppKit
import Combine
import Foundation

enum SignatureBuilder {
    private static let home = AppPaths.userHome

    private static let rewrites: [(NSRegularExpression, String)] = [
        (#"^/(private/)?var/folders/[^/]+/[^/]+/[A-Za-z0-9]+"#, #"\$TMPDIR"#),
        (#"^/private/tmp(/|$)"#, "/tmp$1"),
        (#"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"#, "<uuid>"),
        (#"\b[0-9A-Fa-f]{12,}\b"#, "<hex>"),
        (#"[0-9]+"#, "#"),
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }

    /// Like `normalize`, but keeps the executable's own name intact (base64, python3.12),
    /// unless the name is only a version or hash (claude/versions/2.1.316), which changes on update.
    static func normalizeExecutable(_ path: String) -> String {
        let ns = path as NSString
        guard ns.pathComponents.count > 1 else { return path }
        let name = ns.lastPathComponent
        let volatile = !name.contains(where: \.isLetter) || name.count >= 16 && name.allSatisfy(\.isHexDigit)
        return normalize(ns.deletingLastPathComponent) + "/" + (volatile ? normalize(name) : name)
    }

    /// Collapses volatile parts of a path: home, temp dirs, UUIDs, hashes, numbers. Pure, and called several
    /// times per event with the same few thousand paths, so results are remembered (the regexes are the
    /// slowest part of reading history).
    static func normalize(_ path: String) -> String {
        if let hit = normalized.get(path) { return hit }
        let out = normalizeUncached(path)
        normalized.set(path, out)
        return out
    }

    private static let normalized = MemoCache<String, String>(limit: 50_000)
    private static let filePatterns = MemoCache<String, (String, PatternRisk, String)>(limit: 50_000)

    private static func normalizeUncached(_ path: String) -> String {
        var s = path
        if s.hasPrefix(home) { s = "~" + s.dropFirst(home.count) }
        for (regex, template) in rewrites {
            s = regex.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: template)
        }
        return s
    }

    // MARK: Path knowledge

    /// Places where any access is security-relevant. Patterns here keep full detail.
    static let sensitive: [(prefix: String, label: String)] = [
        ("~/.ssh", "SSH keys"), ("~/.gnupg", "GPG keys"), ("~/.aws", "cloud credentials"),
        ("~/.kube", "Kubernetes credentials"), ("~/.config/gcloud", "cloud credentials"),
        ("~/.azure", "cloud credentials"), ("~/.docker/config.json", "registry credentials"),
        ("~/.netrc", "credentials"), ("~/.git-credentials", "credentials"), ("~/.npmrc", "credentials"),
        ("~/.pypirc", "credentials"), ("~/.password-store", "password store"), ("~/.config/gh", "GitHub token"),
        ("~/Library/Keychains", "keychain"), ("/Library/Keychains", "keychain"),
        ("~/Library/Application Support/com.apple.TCC", "TCC database"),
        ("/Library/Application Support/com.apple.TCC", "TCC database"),
        ("~/Library/Cookies", "cookies"), ("~/Library/Safari", "Safari data"),
        ("~/Library/Messages", "Messages"), ("~/Library/Mail", "Mail"),
        ("/private/var/db/dslocal", "local accounts"), ("/private/etc/sudoers", "sudoers"),
        ("/private/etc/pam.d", "PAM config"), ("/private/etc/ssh", "SSH config"),
    ]

    /// Programs expected to touch a sensitive place (matched by executable-name prefix).
    static let owners: [String: [String]] = [
        "SSH keys": ["ssh", "scp", "sftp", "git", "sshd"],
        "SSH config": ["ssh", "scp", "sftp", "git", "sshd"],
        "GPG keys": ["gpg", "gpg-agent", "pinentry"],
        "Kubernetes credentials": ["kubectl", "kubecolor", "helm", "k9s", "kubelogin", "lens"],
        "keychain": ["security", "securityd", "secd", "trustd"],
        "cloud credentials": ["aws", "gcloud", "az", "terraform", "session-manager-plugin", "bq", "gsutil"],
        "registry credentials": ["docker", "com.docker", "podman", "colima"],
        "GitHub token": ["gh"],
    ]

    /// Browser credential stores, matched by file name anywhere in Application Support.
    static let credentialFiles: Set<String> = [
        "Login Data", "Login Data For Account", "Cookies", "Web Data", "Local State",
        "key4.db", "logins.json", "cookies.sqlite", "signons.sqlite",
    ]

    /// Places where a write makes something run later. Writes here keep full detail.
    static let persistence: [String] = [
        "~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/StartupItems",
        "/private/var/at", "/usr/lib/cron", "/private/etc/periodic", "/private/etc/paths.d",
        "/Library/Security/SecurityAgentPlugins", "/Library/DirectoryServices/PlugIns",
        "~/Library/Application Support/com.apple.backgroundtaskmanagementagent",
        "/private/var/db/com.apple.backgroundtaskmanagement", "~/Library/Preferences/com.apple.loginitems.plist",
        "/private/etc/profile", "/private/etc/zshrc", "/private/etc/zprofile", "/private/etc/bashrc",
        "~/.zshrc", "~/.zshenv", "~/.zprofile", "~/.zlogin", "~/.bashrc", "~/.bash_profile", "~/.profile",
        "~/.config/fish/config.fish", "~/.config/fish/conf.d",
    ]

    /// How many folders below each root a pattern keeps; deeper paths become "root/…/**".
    /// Longest matching prefix wins; anything else keeps 2 levels.
    private static let zoneDepth: [(prefix: String, depth: Int)] = [
        ("/System/Volumes/Data", 3), ("/System", 1), ("/usr/local", 2), ("/usr", 1), ("/bin", 1), ("/sbin", 1),
        ("/dev", 1), ("/private/var/folders", 1), ("/private/var", 3), ("/private/etc", 2), ("/Library", 2),
        ("/Applications", 1), ("/opt/homebrew", 2), ("/Volumes", 1), ("/tmp", 1), ("$TMPDIR", 0),
        ("/Users/Shared", 2), ("~/Library", 2), ("~", 1),
    ]

    /// Read-mostly locations where reading is never a signal by itself.
    private static let routineReadRoots = [
        "/System", "/usr", "/bin", "/sbin", "/dev", "/private/var", "/private/etc", "/Library", "/Applications",
        "/opt/homebrew", "/tmp", "$TMPDIR", "~/Library/Caches", "~/Library/Containers", "~/Library/Group Containers",
        "~/Library/Preferences", "~/Library/Biome", "~/Library/HTTPStorages", "~/Library/Logs",
        "~/Library/Saved Application State", "~/Library/Developer", "~/Library/Fonts", "/",
    ]

    /// Scratch locations where writing is never a signal by itself (what runs from there is).
    private static let routineWriteRoots = [
        "/tmp", "$TMPDIR", "/dev", "/private/var/folders", "~/Library/Caches", "~/Library/Containers",
        "~/Library/Group Containers", "~/Library/HTTPStorages", "~/Library/Logs", "~/Library/Biome",
        "~/Library/Saved Application State", "~/Library/Preferences", "~/Library/WebKit",
    ]

    /// Living-off-the-land binaries: legit tools attackers love.
    static let lolbins: Set<String> = [
        "sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "osascript", "osacompile", "perl", "ruby",
        "php", "node", "curl", "wget", "nc", "ncat", "netcat", "socat", "base64", "openssl", "security",
        "sqlite3", "launchctl", "dscl", "xattr", "spctl", "tclsh", "expect", "ssh", "scp", "sftp", "ftp",
        "telnet", "screencapture", "funzip", "ditto", "hdiutil", "pkgutil", "installer", "codesign",
    ]

    /// Apps that spawn shells all day long.
    static let shellHosts = [
        "/Terminal.app/", "/iTerm.app/", "/Cursor.app/", "/Visual Studio Code.app/", "/Xcode.app/",
        "/Ghostty.app/", "/Warp.app/", "/Alacritty.app/", "/kitty.app/", "/WezTerm.app/", "/Zed.app/",
        "/Claude.app/", "/Sublime Text.app/", "/Android Studio.app/", "JetBrains", "/IntelliJ", "/PyCharm",
        "/GoLand", "/WebStorm", "/Nova.app/",
        // AI coding agents run your commands for you, like a terminal: Claude Code (native, npm).
        "/.local/share/claude/versions/", "/@anthropic-ai/claude-code/",
    ]

    private static func under(_ path: String, _ root: String) -> Bool {
        root == "/" ? path == "/" : path == root || path.hasPrefix(root + "/")
    }

    /// On the sealed, read-only system volume: cannot be modified by malware.
    static func isSealedSystem(_ rawPath: String) -> Bool {
        if rawPath.hasPrefix("/System/Volumes/") { return rawPath.hasPrefix("/System/Volumes/Preboot/Cryptexes/") }
        return rawPath.hasPrefix("/System/") || rawPath.hasPrefix("/usr/") && !rawPath.hasPrefix("/usr/local/")
            || rawPath.hasPrefix("/bin/") || rawPath.hasPrefix("/sbin/") || rawPath.hasPrefix("/Library/Apple/")
    }

    // MARK: Launch patterns for interpreters and tools

    /// Interpreters: the script they run is what matters.
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "perl", "ruby",
                                             "php", "node", "osascript", "tclsh", "expect"]

    /// "perl ~/bin/build.pl", "sh -c ‹curl -s https://x/p | sh›", "ditto -x -k ~/Downloads/app.zip ~/Downloads":
    /// a launch of an interpreter or tool names what it was told to do, never just the program (which
    /// would trust it running anything). Paths and numbers are normalised, secrets were masked by the
    /// collector; at most ~120 characters.
    static func launchPattern(target: String, args: String) -> String {
        var tokens = shellTokens(args)
        if !tokens.isEmpty { tokens.removeFirst() }                      // argv[0]
        guard !tokens.isEmpty else { return target }                     // an interactive shell or a bare run
        let name = (target as NSString).lastPathComponent.lowercased()
        let interpreter = interpreters.contains(name) || name.hasPrefix("python")
        if interpreter {
            if let i = tokens.firstIndex(where: { ["-c", "-e", "-E", "--eval", "-r"].contains($0) }), i + 1 < tokens.count {
                return "\(target) \(tokens[i]) ‹\(String(normalize(tokens[i + 1]).prefix(80)))›"
            }
            if let script = tokens.first(where: { !$0.hasPrefix("-") }) {
                return "\(target) \(normalizeToken(script))"
            }
        }
        var out = target
        for token in tokens {
            let next = out + " " + normalizeToken(token)
            if next.count > 120 { return out + " …" }
            out = next
        }
        return out
    }

    private static func normalizeToken(_ token: String) -> String {
        token.count > 60 && !token.contains("/") ? "<long>" : normalize(token)
    }

    /// Splits a command line the way `Agent.formatArgs` wrote it (single quotes around spaced arguments).
    static func shellTokens(_ line: String) -> [String] {
        var tokens: [String] = [], current = "", quoted = false, any = false
        for c in line {
            if c == "'" { quoted.toggle(); any = true; continue }
            if c == " " && !quoted {
                if any || !current.isEmpty { tokens.append(current) }
                current = ""; any = false
            } else { current.append(c) }
        }
        if any || !current.isEmpty { tokens.append(current) }
        return tokens
    }

    /// The program a pattern is about (what runs, or what acts) is an interpreter or shell: it runs any
    /// script it's given, so trusting it broadly would trust a virus's script too.
    static func runsAnyCode(_ e: SignatureEntry) -> Bool { isLolbin(SignatureStore.subjectPath(e)) }

    /// Programs that carry the network traffic of containers or virtual machines: on macOS the connection is theirs,
    /// whatever program inside the VM made it. Their connections are judged per destination and never pass on the
    /// gateway's trusted signature (Docker Inc. signs the backend, not what runs in your containers).
    static let vmGateways: [String: String] = [
        "com.docker.backend": "Docker container", "com.docker.vpnkit": "Docker container", "vpnkit": "Docker container",
        "gvproxy": "Podman container", "OrbStack Helper": "OrbStack container", "limactl": "Lima VM",
        "qemu-system-aarch64": "virtual machine", "qemu-system-x86_64": "virtual machine",
    ]

    /// "Docker container" for Docker Desktop's backend, nil for an ordinary program.
    static func vmGateway(_ path: String) -> String? { vmGateways[(path as NSString).lastPathComponent] }

    static func isLolbin(_ path: String) -> Bool {
        var name = (path as NSString).lastPathComponent.lowercased()
        if name.hasPrefix("python") || name.hasPrefix("pip") || lolbins.contains(name) { return true }   // sqlite3
        name = String(name.prefix(while: { !$0.isNumber && $0 != "." }))
        return lolbins.contains(name)
    }

    /// Where droppers run from: temp, Downloads, shared, mounted volumes.
    static func isDropZone(_ normalized: String) -> Bool {
        ["/tmp", "$TMPDIR", "/private/var/folders", "~/Downloads", "/Users/Shared", "/Volumes"]
            .contains { under(normalized, $0) }
    }

    // MARK: Path patterns

    // MARK: Specific patterns (the general rule)

    /// Folders a file pattern needs before it may use a wildcard: 2 below home ("~/Documents/work/*"),
    /// 3 elsewhere ("/Users/Shared/tools/*"). Never "r ~/*", "r ~/Documents/*", "r /*", "r /tmp/*" or "r /Users/**".
    static func minWildcardDepth(_ dir: String) -> Int { dir.hasPrefix("~") ? 2 : 3 }
    /// Deeper than this, an app's pattern ends in "/**" (so node_modules isn't a pattern per folder).
    static func maxFolderDepth(_ dir: String) -> Int {
        // Scratch trees ("/tmp/site-shot/profile/Default/…"): the tree's name is all that matters.
        if dir.hasPrefix("/tmp/") || dir.hasPrefix("$TMPDIR/") { return 2 }
        return dir.hasPrefix("~") ? 4 : 5
    }

    /// Folders below "~" or "/": "~/Documents/work" → 2, "/usr/bin" → 2, "~" → 0.
    static func depth(_ dir: String) -> Int {
        dir.split(separator: "/", omittingEmptySubsequences: true).filter { $0 != "~" }.count
    }

    /// The general rule for file patterns: specific enough that deciding one never covers a whole area.
    /// A file in a shallow folder is its own pattern ("~/todo.txt", "~/Documents/a.pdf", "/tmp/x.log");
    /// otherwise its folder ("~/Documents/work/*"); for apps, very deep trees end in "/**" (4 folders below
    /// home, 5 elsewhere). Interpreters and shells (`deep: false`) always get the exact folder.
    static func specificPath(_ path: String, deep: Bool) -> String {
        let file = normalize(path)
        let folder = normalize((path as NSString).deletingLastPathComponent)
        let d = depth(folder)
        if d < minWildcardDepth(folder) { return file }
        let max = maxFolderDepth(folder)
        if !deep || d <= max { return folder + "/*" }
        let parts = folder.split(separator: "/", omittingEmptySubsequences: true)
        return (folder.hasPrefix("/") ? "/" : "") + parts.prefix(folder.hasPrefix("~") ? max + 1 : max).joined(separator: "/") + "/**"
    }

    /// A file pattern (or a rule's file glob) that covers a whole area: a wildcard too few folders down
    /// ("r ~/*", "r ~/Documents/*", "r /Users/**", "r *"). Labelled sensitive places ("[ssh keys]") and an
    /// app's own data folder are specific by construction.
    static func isTooWide(filePattern: String) -> Bool {
        if filePattern.hasSuffix("]") { return false }
        let path = filePattern.split(separator: " ", maxSplits: 1).last.map(String.init) ?? filePattern
        guard let star = path.firstIndex(where: { $0 == "*" || $0 == "?" }) else { return false }
        let prefix = String(path[..<star])
        // A family of temp files ("/tmp/zsh*", "$TMPDIR/hostwatch.*"): named, so not a whole area.
        if prefix.hasPrefix("/tmp/") || prefix.hasPrefix("$TMPDIR/"),
           (prefix.split(separator: "/", omittingEmptySubsequences: false).last?.count ?? 0) >= 2 { return false }
        return depth(prefix) < minWildcardDepth(prefix)
    }

    // MARK: Fewer patterns

    /// What macOS's own programs read, other than sensitive places: one pattern per program ("r *  [ordinary
    /// files]"). Which of thousands of system files a sealed daemon reads says nothing, and nothing can change it.
    static let ordinaryFiles = "ordinary files"

    /// Programs whose reads are one pattern: on the sealed system volume, and not a shell, interpreter or
    /// command-line tool (`cat`, `cp`, `python3` read whatever a script or a person tells them to).
    static func readsAsOnePattern(_ actor: String) -> Bool {
        isSealedSystem(actor) && !isLolbin(actor) && !BaselinePolicy.isCommandLineTool(actor)
    }

    private static let tempRoot = try! NSRegularExpression(
        pattern: #"^(/private)?/tmp(?=/)|^/private/var/folders/[^/]+/[^/]+/[A-Za-z0-9]+(?=/)"#)

    /// "/tmp/zshVJbGMW" → "/tmp/zsh*", "$TMPDIR/hostwatch.JazhOu/x" → "$TMPDIR/hostwatch.*/x": a temp file or
    /// folder named like mkstemp does (a name, then 6 random letters and digits), directly in a temp folder. The
    /// raw path with that name folded, or nil.
    static func foldTempName(_ path: String) -> String? {
        guard let m = tempRoot.firstMatch(in: path, range: NSRange(path.startIndex..., in: path)),
              let r = Range(m.range, in: path) else { return nil }
        let root = path[..<r.upperBound]
        let rest = path[r.upperBound...].dropFirst()                 // after the "/"
        let name = rest.prefix { $0 != "/" }
        func alnum(_ c: Character) -> Bool { c.isASCII && (c.isLetter || c.isNumber) }
        func upperHex(_ c: Character) -> Bool { c.isASCII && (c.isNumber || "ABCDEF".contains(c)) }
        // The random part: all after the last "-", "." or "_" ("hostwatch.29Cjgb"), else the last 6 ("zshiteQSf"),
        // or a whole uppercase hex run ("hwCDDEE408").
        var tail = name.suffix(6)
        if let sep = name.lastIndex(where: { "-._".contains($0) }) { tail = name[name.index(after: sep)...] }
        else if tail.allSatisfy(upperHex) { tail = name.suffix(name.reversed().prefix(while: upperHex).count) }
        guard tail.count >= 6, tail.allSatisfy(alnum), name.count - tail.count >= 2 else { return nil }
        let upper = tail.filter(\.isUppercase).count, lower = tail.filter(\.isLowercase).count
        let digits = tail.filter(\.isNumber).count
        guard upper >= 2 && lower >= 1 || digits >= 1 && upper >= 1 && (lower >= 1 || upper >= 2) else { return nil }
        return root + "/" + name.dropLast(tail.count) + "*" + rest.dropFirst(name.count)
    }

    /// A pattern one of the rules above writes for many former ones (what `SignatureStore.regroup` moves into).
    static func isRegrouped(_ pattern: String) -> Bool {
        if pattern.hasSuffix("[\(ordinaryFiles)]") || pattern.hasSuffix(plainTools) || pattern.hasSuffix("/**") { return true }
        let path = pattern.split(separator: " ", maxSplits: 1).last.map(String.init) ?? ""
        guard path.hasPrefix("/tmp/") || path.hasPrefix("$TMPDIR/") else { return false }
        let name = path.split(separator: "/").dropFirst().first ?? ""
        return name.hasSuffix("*") && name.count >= 3
    }

    /// A project: the folder with the `.git` of the file's repository (a worktree's `.git` file counts), or nil.
    /// Reads inside a project by a tool are one pattern per project ("r ~/Documents/git/devops/**"): which of
    /// its files git, an editor or a search tool read says nothing. Never the home folder itself, and never a
    /// repository so near the root that its pattern would cover a whole area. Remembered per folder.
    static func projectRoot(of raw: String) -> String? {
        var dir = (raw as NSString).deletingLastPathComponent
        var walked: [String] = []
        var found: String?
        while dir.count > 1, dir != home {
            if let hit = projects.get(dir) { found = hit.isEmpty ? nil : hit; break }
            walked.append(dir)
            if FileManager.default.fileExists(atPath: dir + "/.git") { found = dir; break }
            dir = (dir as NSString).deletingLastPathComponent
        }
        for d in walked { projects.set(d, found ?? "") }
        guard let root = found else { return nil }
        let norm = normalize(root)
        return depth(norm) >= minWildcardDepth(norm) ? norm : nil
    }
    private static let projects = MemoCache<String, String>(limit: 20_000)

    /// "/opt/homebrew/Cellar/python@3.12" for a file inside that formula: reads of a formula's own tree are one
    /// pattern per formula (and per program), interpreters included: an interpreter loading its library says
    /// nothing about the script.
    static func homebrewFormula(_ norm: String) -> String? {
        let parts = norm.split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count > 4, parts[0] == "opt", parts[1] == "homebrew", parts[2] == "Cellar" else { return nil }
        return "/opt/homebrew/Cellar/" + parts[3]
    }

    /// A shell or interpreter starting macOS's plain tools (`awk`, `cut`, `ls`, `du`…): one pattern per folder,
    /// "/usr/bin/*  (plain tools)". Not the tools attackers use (`curl`, `osascript`, `security`…), nor admin
    /// tools: those keep one pattern each, with their arguments.
    static let plainTools = "(plain tools)"

    /// Built-in tools whose run is a signal in itself (Stories count them too).
    static let watchedTools: Set<String> = [
        "curl", "wget", "nc", "ncat", "netcat", "socat", "osascript", "osacompile", "base64", "openssl",
        "security", "sqlite3", "launchctl", "dscl", "xattr", "spctl", "screencapture", "scp", "sftp", "ftp",
        "telnet", "ditto", "hdiutil", "pkgutil", "installer", "codesign", "chflags", "csrutil", "tccutil",
        "defaults", "profiles", "networksetup", "systemsetup", "kextload", "funzip",
    ]
    static let adminTools: Set<String> = [
        "sudo", "su", "doas", "login", "passwd", "visudo", "fdesetup", "sysadminctl", "dseditgroup", "dscacheutil",
        "kmutil", "nvram", "bless", "diskutil", "mount", "umount", "tmutil", "softwareupdate", "pfctl", "pmset",
        "chown", "chmod", "killall", "kill", "crontab", "at", "ssh-add", "ssh-keygen", "plutil", "PlistBuddy",
    ]

    static func isPlainTool(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        return isSealedSystem(path) && !isLolbin(path) && !watchedTools.contains(name.lowercased()) && !adminTools.contains(name)
    }

    /// Keeps up to `depth` folders below the zone root, then "/**".
    static func collapse(_ dir: String) -> String {
        if dir.isEmpty || dir == "/" { return "/*" }
        let zone = zoneDepth.filter { under(dir, $0.prefix) }.max { $0.prefix.count < $1.prefix.count }
        let root = zone?.prefix ?? ""
        let depth = zone?.depth ?? 2
        let rest = dir.dropFirst(root.count).split(separator: "/", omittingEmptySubsequences: true)
        // Files directly in the root stay "root/*"; anything below is one "root/x/**" pattern.
        if rest.isEmpty || depth == 0 && dir == root { return dir + "/*" }
        let kept = ([root.isEmpty ? "" : root] + rest.prefix(depth).map(String.init)).joined(separator: "/")
        return kept + "/**"
    }

    /// Detailed pattern for sensitive places: "dir/*.ext", deep trees collapse below 5 levels.
    static func detailedPattern(_ path: String) -> String {
        let ns = path as NSString
        let dir = normalize(ns.deletingLastPathComponent)
        let parts = dir.split(separator: "/", omittingEmptySubsequences: true)
        if parts.count > 5 {
            let lead = dir.hasPrefix("/") ? "/" : ""
            return lead + parts.prefix(5).joined(separator: "/") + "/**"
        }
        let ext = ns.pathExtension
        return dir + "/*" + (looksLikeExtension(ext) ? "." + normalize(ext.lowercased()) : "")
    }

    private static let longExtensions: Set<String> = [
        "framework", "bundle", "plugin", "appex", "xpc", "kext", "dylib", "sqlite", "sqlite3",
        "db-wal", "db-shm", "sqlite-wal", "sqlite-shm", "mobileconfig", "plist", "json", "db",
    ]

    /// Rejects mkstemp-style random suffixes ("file.vgaktavl0r", "x.aB3dE9").
    static func looksLikeExtension(_ raw: String) -> Bool {
        if raw.isEmpty { return false }
        let ext = raw.lowercased()
        if longExtensions.contains(ext) { return true }
        guard ext.count <= 6, ext.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return false }
        if raw != raw.lowercased() && raw != raw.uppercased() { return false }
        let letters = ext.drop(while: { $0.isNumber })
        let body = letters.prefix(while: { !$0.isNumber })
        let rest = letters.dropFirst(body.count)
        if !rest.allSatisfy({ $0.isNumber }) || rest.count > 3 { return false }
        let vowels = Set("aeiouy")
        if body.count >= 5 && !body.contains(where: { vowels.contains($0) }) { return false }
        return true
    }

    /// (pattern, risk, reason) for a file access.
    static func fileTarget(_ raw: String, mode: String, actor: String) -> (String, PatternRisk, String) {
        var path = raw
        if path.hasPrefix("/etc/") { path = "/private" + path }
        if path.hasPrefix("/var/") { path = "/private" + path }
        let norm = normalize(path)
        let writes = mode.contains("w")
        let sealedActor = isSealedSystem(actor) && !isLolbin(actor)

        let actorName = (actor as NSString).lastPathComponent
        if let s = sensitive.first(where: { under(norm, $0.prefix) }) {
            let where_ = norm == s.prefix ? s.prefix : detailedPattern(path)
            let owner = sealedActor || owners[s.label]?.contains(where: { actorName.hasPrefix($0) }) == true
            // Security.framework reads keychain files in-process in every app; only writes stand out.
            let inProcessRead = s.label == "keychain" && !writes
            return ("\(mode) \(where_)  [\(s.label)]", owner || inProcessRead ? .normal : .high,
                    "\(s.label) accessed")
        }
        let name = (path as NSString).lastPathComponent
        if credentialFiles.contains(name), under(norm, "~/Library/Application Support") {
            let vendor = norm.split(separator: "/").dropFirst(3).first.map(String.init) ?? "*"
            // The browser/Electron app reading its own store, or Spotlight indexing it, is expected.
            let owner = sealedActor || actor.localizedCaseInsensitiveContains("/\(vendor)")
            return ("\(mode) ~/Library/Application Support/\(vendor)/**/\(name)  [browser credentials]",
                    owner ? .normal : .high, "browser credential store accessed")
        }
        if writes, persistence.contains(where: { under(norm, $0) }) {
            return ("\(mode) \(detailedPattern(path))  [persistence]",
                    sealedActor ? .normal : .high, "write to an autostart location")
        }

        if !writes, readsAsOnePattern(actor) {
            return ("\(mode) *  [\(ordinaryFiles)]", .routine, "macOS system process")
        }

        if let own = ownDataRoot(raw: path, actor: actor) {
            return ("\(mode) \(normalize(own))/**  [own data]", .routine, "app's own data folder")
        }

        var pattern = "\(mode) \(specificPath(foldTempName(path) ?? path, deep: !isLolbin(actor)))"
        if !writes, let formula = homebrewFormula(norm) {
            pattern = "\(mode) \(formula)/**"
        } else if !writes, !isLolbin(actor), let project = projectRoot(of: path) {
            pattern = "\(mode) \(project)/**"
        }
        if writes {
            if routineWriteRoots.contains(where: { under(norm, $0) }) {
                return (pattern, .routine, "scratch/cache write")
            }
            if sealedActor { return (pattern, .routine, "macOS system process") }
            return (pattern, .normal, "")
        }
        if routineReadRoots.contains(where: { under(norm, $0) }) {
            return (pattern, .routine, "read of system/app/cache files")
        }
        if sealedActor { return (pattern, .routine, "macOS system process") }
        return (pattern, .normal, "")
    }

    /// "~/Library/Application Support/Cursor" for Cursor, "~/.claude" for claude: a data folder whose
    /// name appears in the actor's path. Part of the pattern, so it never covers other folders.
    static func ownDataRoot(raw: String, actor: String) -> String? {
        guard raw.hasPrefix(home + "/") else { return nil }
        let rel = raw.dropFirst(home.count + 1).split(separator: "/", omittingEmptySubsequences: true)
        let root: [Substring]
        if rel.count >= 4, rel[0] == "Library", rel[1] == "Application Support" { root = Array(rel.prefix(3)) }
        else if rel.count >= 2, rel[0].hasPrefix("."), rel[0].count > 1 { root = [rel[0]] }
        else { return nil }
        func squash<S: StringProtocol>(_ s: S) -> String { s.lowercased().filter { $0.isLetter || $0.isNumber } }
        let token = squash(root.last!)
        guard token.count >= 3, squash(actor).contains(token) else { return nil }
        return home + "/" + root.joined(separator: "/")
    }

    // MARK: Network

    static func hostBucket(_ host: String) -> String {
        let h = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        let octets = h.split(separator: ".").compactMap { Int($0) }
        if octets.count == 4 {
            switch (octets[0], octets[1]) {
            case (127, _): return "loopback"
            case (10, _), (192, 168): return "lan"
            case (172, 16...31): return "lan"
            case (169, 254): return "link-local"
            case (100, 64...127): return "cgnat"
            case (224...239, _): return "multicast"
            case (0, _): return "any"
            default: return "\(octets[0]).\(octets[1]).*.*"
            }
        }
        if h.contains(":") {
            if h == "::1" || h == "::" { return "loopback" }
            if h.hasPrefix("fe80") { return "link-local" }
            if h.hasPrefix("fc") || h.hasPrefix("fd") { return "lan" }
            if h.hasPrefix("ff") { return "multicast" }
            let groups = h.split(separator: ":", omittingEmptySubsequences: false).prefix(2)
            return groups.joined(separator: ":") + "::*"
        }
        return h
    }

    static func portBucket(_ port: String) -> String {
        guard let p = Int(port) else { return port }
        return p >= 49152 ? "ephemeral" : String(p)
    }

    static let localBuckets: Set<String> = ["loopback", "lan", "link-local", "multicast", "any", "cgnat"]
    static let webPorts: Set<String> = ["80", "443", "53", "853", "123"]

    // MARK: Signature

    /// The pattern for an event, after combined patterns (`PatternMerges`) have their say.
    static func signature(for e: ActivityEvent) -> Signature {
        var sig = baseSignature(for: e)
        if let (process, pattern) = PatternMerges.shared.apply(kind: e.kind, process: sig.process, pattern: sig.pattern) {
            sig.process = process
            sig.pattern = pattern
            sig.key = "\(e.kind.rawValue)|\(process)|\(pattern)"
        }
        return sig
    }

    /// "r ~/Documents/work/a/*" + "r ~/Documents/work/b/*" → "r ~/Documents/work/*/*": the patterns' common
    /// shape, a `*` where they differ (token by token, split at / . : and spaces), or their common start + `*`.
    static func commonGlob(_ texts: [String]) -> String {
        guard let first = texts.first else { return "" }
        guard texts.count > 1 else { return first }
        func tokens(_ s: String) -> [String] {
            var out: [String] = [], cur = ""
            for c in s {
                if "/.: ".contains(c) { if !cur.isEmpty { out.append(cur) }; out.append(String(c)); cur = "" } else { cur.append(c) }
            }
            if !cur.isEmpty { out.append(cur) }
            return out
        }
        let all = texts.map(tokens)
        if Set(all.map(\.count)).count == 1 {
            return (0..<all[0].count).map { i in Set(all.map { $0[i] }).count == 1 ? all[0][i] : "*" }.joined()
        }
        var prefix: [String] = []
        for i in 0..<(all.map(\.count).min() ?? 0) {
            guard Set(all.map { $0[i] }).count == 1 else { break }
            prefix.append(all[0][i])
        }
        return prefix.joined() + "*"
    }

    static func baseSignature(for e: ActivityEvent) -> Signature {
        let rawActor = e.proc
        let actor = e.proc.isEmpty ? e.name : normalizeExecutable(e.proc)
        switch e.kind {
        case .exec:
            let parent = e.parent.isEmpty ? "?" : normalizeExecutable(e.parent)
            let parentName = (e.parent as NSString).lastPathComponent
            let target = normalizeExecutable(e.target)
            let normTarget = normalize(e.target)
            // Interpreters and tools that do what they're told: the pattern names what was run, not just
            // the program ("bash → perl ~/bin/build.pl", never "bash → perl").
            var pattern = isLolbin(e.target) ? launchPattern(target: target, args: e.args) : target
            var risk = PatternRisk.normal, reason = ""
            if isDropZone(normTarget) {
                pattern = (normTarget as NSString).deletingLastPathComponent.isEmpty ? target
                    : collapse((normTarget as NSString).deletingLastPathComponent) + "/" + (target as NSString).lastPathComponent
                risk = .high; reason = "runs from a temp/download location"
            } else if isLolbin(e.target), e.parent.contains(".app/"), !isLolbin(e.parent),
                      !shellHosts.contains(where: { e.parent.contains($0) }), !isSealedSystem(e.parent) {
                risk = .high; reason = "app spawned a shell/interpreter/LOLBin"
            } else if (parentName == "launchd" || parentName == "xpcproxy"), isSealedSystem(e.target) {
                pattern = "macOS system service"; risk = .routine; reason = "launchd started a sealed system binary"
            } else if isSealedSystem(e.parent), isSealedSystem(e.target), !isLolbin(e.target) {
                risk = .routine; reason = "system binary started by system binary"
            }
            if risk != .high, isLolbin(e.parent), isPlainTool(e.target) {
                pattern = (target as NSString).deletingLastPathComponent + "/*  \(plainTools)"
            }
            if risk != .high, let why = BuiltInSafe.reason(kind: .exec, parent: e.parent, pattern: pattern) {
                risk = .routine; reason = why
            }
            return withSigning(make(e.kind, parent, pattern, risk, reason), e)

        case .net:
            let host = e.remoteHost ?? e.target
            let port = e.target.split(separator: ":").last.map(String.init) ?? ""
            var bucket = hostBucket(host)
            // Which cloud /16 a web request lands in says nothing; odd ports keep the /16.
            if !localBuckets.contains(bucket), webPorts.contains(port) { bucket = "internet" }
            // Interpreters, shells and VM gateways (anything may run behind them): the destination itself (its
            // domain, or the address), never "internet".
            let gateway = vmGateway(rawActor)
            if isLolbin(rawActor) || gateway != nil, !localBuckets.contains(bucket) {
                bucket = e.host.isEmpty ? host.lowercased() : (DomainRegistry.registrable(e.host) ?? e.host.lowercased())
            }
            let pattern = "\(e.extra) \(bucket):\(portBucket(port))"
            var risk = PatternRisk.normal, reason = ""
            let actorName = (rawActor as NSString).lastPathComponent
            let sshOn22 = port == "22" && ["ssh", "scp", "sftp", "git"].contains(where: { actorName.hasPrefix($0) })
            if isDropZone(normalize(rawActor)) {
                risk = .high; reason = "network from a temp/download location"
            } else if isLolbin(rawActor), !localBuckets.contains(bucket), !webPorts.contains(port), !sshOn22 {
                risk = .high; reason = "shell/interpreter on an unusual port"
            } else if bucket == "loopback" {
                risk = .routine; reason = "loopback"
            } else if isSealedSystem(rawActor), !isLolbin(rawActor) {
                risk = .routine; reason = "macOS system process"
            } else if let gateway, !localBuckets.contains(bucket) {
                reason = "from a \(gateway.lowercased()) (inside its virtual machine)"
            }
            return withSigning(make(e.kind, actor, pattern, risk, reason), e)

        case .file:
            // Pure in (actor, mode, path), and file events repeat those all day: remembered.
            let memoKey = rawActor + "\u{0}" + e.extra + "\u{0}" + e.target
            let (pattern, risk, reason) = filePatterns.get(memoKey) ?? {
                var (pattern, risk, reason) = fileTarget(e.target, mode: e.extra, actor: rawActor)
                if risk != .high, let why = BuiltInSafe.reason(kind: .file, parent: rawActor, pattern: pattern) {
                    risk = .routine; reason = why
                }
                filePatterns.set(memoKey, (pattern, risk, reason))
                return (pattern, risk, reason)
            }()
            return withSigning(make(e.kind, actor, pattern, risk, reason), e)
        }
    }

    /// Code-signing adjustments on top of the path rules. Looks only at the binary the key names:
    /// what runs (exec) or what acts (file/net), so risk stays a function of the pattern.
    static func withSigning(_ sig: Signature, _ e: ActivityEvent) -> Signature {
        let cache = SigningCache.shared
        let subject = e.kind == .exec ? e.target : e.proc
        guard cache.enabled, !subject.isEmpty, !isSealedSystem(subject), let id = cache.identity(subject) else { return sig }
        var s = sig
        if let why = cache.swapReason(subject) {
            s.risk = .high; s.reason = "binary replaced: \(why)"
        } else if id.valid == false {
            s.risk = .high; s.reason = "signature does not match the binary (modified?)"
        } else if id.untrustedCode, id.quarantined || isDropZone(normalize(subject)) {
            // Unsigned/ad-hoc code is everyday on a dev Mac (Homebrew, builds, bundled runtimes);
            // it only matters when it came from a download or temp folder.
            s.risk = .high; s.reason = "\(id.label.lowercased()) code from a download/temp folder"
        } else if s.risk == .normal, cache.trusts(subject, id), !s.pattern.hasSuffix("]"),
                  !(e.kind == .net && vmGateway(subject) != nil) {
            // Apple or a trusted developer doing non-sensitive things. A spawn
            // also needs a trusted (or system) parent, and never covers starting shells/LOLBins.
            var ok = true
            if e.kind == .exec {
                ok = !isLolbin(e.target) && (isSealedSystem(e.parent)
                     || cache.identity(e.parent).map { cache.trusts(e.parent, $0) } == true)
            }
            if ok { s.risk = .routine; s.reason = "trusted signer: \(id.label)" }
        }
        return s
    }

    private static func make(_ kind: EventKind, _ process: String, _ pattern: String,
                             _ risk: PatternRisk, _ reason: String) -> Signature {
        Signature(key: "\(kind.rawValue)|\(process)|\(pattern)", process: process, pattern: pattern,
                  risk: risk, reason: reason)
    }

    /// Key for a whole-process rule ("everything this process does of this kind").
    static func processRuleKey(kind: EventKind, process: String) -> String {
        "\(kind.rawValue)|\(process)|*"
    }
}
