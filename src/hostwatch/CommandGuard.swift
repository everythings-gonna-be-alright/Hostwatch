import Foundation

/// How dangerous a Claude Code tool call looks: run as usual, ask you first, or block it.
enum GuardLevel: Int, Codable, Comparable, Sendable {
    case ok, ask, deny
    static func < (a: GuardLevel, b: GuardLevel) -> Bool { a.rawValue < b.rawValue }
}

struct GuardFinding: Equatable, Sendable {
    var level: GuardLevel
    var reason: String
}

struct GuardVerdict: Equatable, Sendable {
    var level: GuardLevel
    var reasons: [String]
    static let ok = GuardVerdict(level: .ok, reasons: [])

    init(level: GuardLevel, reasons: [String]) { self.level = level; self.reasons = reasons }

    /// The most serious findings decide; their reasons, without repeats.
    init(_ findings: [GuardFinding]) {
        let top = findings.map(\.level).max() ?? .ok
        var seen = Set<String>()
        reasons = findings.filter { $0.level == top }.map(\.reason).filter { seen.insert($0).inserted }
        level = top
    }

    var summary: String { reasons.prefix(3).joined(separator: "; ") }
}

/// Judges what Claude Code is about to do (a shell command, a file write or read, a web fetch) before it
/// happens, from the text alone: destructive, hidden, persistent or secret-reading commands. Pure and
/// fast; the app adds the threat lists through `listed`.
struct CommandGuard {
    let home: String
    /// Host or IP → why it's known-bad (the threat lists); nil when not listed.
    var listed: (String) -> String? = { _ in nil }
    /// A script's text (to judge `bash x.sh` by what x.sh does); nil if unreadable or not a small text file.
    var readScript: (String) -> String? = CommandGuard.readSmallTextFile

    init(home: String = FileManager.default.homeDirectoryForCurrentUser.path,
         listed: @escaping (String) -> String? = { _ in nil }) {
        self.home = (home as NSString).standardizingPath
        self.listed = listed
    }

    /// The tools the hook is installed for.
    static let tools = ["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep", "WebFetch"]

    func assess(tool: String, input: [String: Any], cwd: String) -> GuardVerdict {
        let cwd = cwd.isEmpty ? home : cwd
        switch tool {
        case "Bash":
            return GuardVerdict(shell(input["command"] as? String ?? "", cwd: cwd))
        case "Write", "Edit", "MultiEdit", "NotebookEdit":
            let path = input["file_path"] as? String ?? input["notebook_path"] as? String ?? ""
            var text = [input["content"], input["new_string"], input["new_source"]].compactMap { $0 as? String }
            text += (input["edits"] as? [[String: Any]] ?? []).compactMap { $0["new_string"] as? String }
            return GuardVerdict(write(path, text: text.joined(separator: "\n"), cwd: cwd))
        case "Read", "Grep":
            let path = input["file_path"] as? String ?? input["path"] as? String ?? ""
            guard !path.isEmpty else { return .ok }
            let target = lower(resolve(path, cwd: cwd))
            return GuardVerdict(Self.secrets.filter { $0.0.matches(target) }.map {
                GuardFinding(level: .ask, reason: "reads \($0.1); what it reads goes to Claude")
            })
        case "WebFetch":
            let url = (input["url"] as? String ?? "").lowercased()
            return GuardVerdict(knownBad(in: url))
        default:
            return .ok
        }
    }

    // MARK: Shell commands

    func shell(_ command: String, cwd: String, depth: Int = 0) -> [GuardFinding] {
        guard !command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return [] }
        let text = expandHome(command)
        let lc = text.lowercased()
        var found: [GuardFinding] = []
        func add(_ level: GuardLevel, _ reason: String) { found.append(GuardFinding(level: level, reason: reason)) }

        for rule in Self.rules where rule.0.matches(lc) { add(rule.1, rule.2) }

        // Code from the internet, run unseen.
        if Self.downloadAndRun.contains(where: { $0.matches(lc) }) {
            add(.ask, "downloads code from \(firstHost(lc) ?? "the internet") and runs it without saving it first")
        }
        // Secrets: reading one is worth a question; reading one and sending data out, more so.
        let withoutKeyUse = Self.keyUse.replace(lc, with: " ")
        let secrets = Self.secrets.filter { $0.0.matches(withoutKeyUse) }.map(\.1)
        let sends = Self.senders.matches(lc)
        let drop = Self.exfilHosts.firstMatch(lc).map { String($0) } ?? publicIP(lc)
        if let drop, sends {
            add(secrets.isEmpty ? .ask : .deny, secrets.isEmpty ? "uploads to \(drop), a place often used to move stolen data"
                : "sends \(secrets[0]) to \(drop)")
        } else if let secret = secrets.first {
            add(.ask, sends ? "reads \(secret) and sends data over the network" : "reads \(secret)")
        } else if sends, Self.envDump.matches(lc) {
            add(.ask, "sends your environment variables (they often hold tokens) over the network")
        }
        if let ip = publicIP(lc), Self.connectors.matches(lc) {
            add(.ask, "connects to a bare IP address (\(ip)) rather than a named server")
        }
        found += knownBad(in: lc)

        // Command by command: deletions, sudo, crontab, scripts.
        var dir = cwd
        for segment in Self.segments(text) {
            var tokens = Self.tokens(segment)
            while let first = tokens.first, first.contains("="), !first.hasPrefix("-"), !first.hasPrefix("/") {
                tokens.removeFirst()                                            // VAR=value prefixes
            }
            if tokens.first == "sudo" {
                add(.ask, "runs as administrator (sudo works without a password for a few minutes after you used it)")
                tokens.removeFirst()
                while let f = tokens.first, f.hasPrefix("-") { tokens.removeFirst() }
            }
            while let f = tokens.first, ["command", "exec", "nohup", "time", "env", "builtin", "noglob"].contains(f) {
                tokens.removeFirst()
            }
            guard let program = tokens.first.map({ ($0 as NSString).lastPathComponent }) else { continue }
            let args = Array(tokens.dropFirst())
            switch program {
            case "cd":
                if let to = args.first, to != "-" { dir = resolve(to, cwd: dir) } else if args.isEmpty { dir = home }
            case "rm", "srm", "shred", "unlink", "rmdir", "trash":
                let recursive = program != "rm" || args.contains { $0 == "--recursive" || ($0.hasPrefix("-") && !$0.hasPrefix("--") && $0.lowercased().contains("r")) }
                for target in args where !target.hasPrefix("-") {
                    if let f = deletion(target, cwd: dir, project: cwd, recursive: recursive || program == "rmdir") { found.append(f) }
                }
            case "find":
                let deletes = args.contains("-delete") || zip(args, args.dropFirst()).contains { $0 == "-exec" && ["rm", "/bin/rm"].contains($1) }
                if deletes {
                    for target in args.prefix(while: { !$0.hasPrefix("-") && !$0.hasPrefix("(") && $0 != "!" }) {
                        if let f = deletion(target, cwd: dir, project: cwd, recursive: true) { found.append(f) }
                    }
                }
            case "crontab":
                if !(args.count == 1 && args[0] == "-l") { add(.ask, "changes scheduled jobs (crontab), which run on their own") }
            default:
                if depth < 2, let script = scriptPath(program: tokens[0], args: args, cwd: dir), let body = readScript(script) {
                    let name = (script as NSString).lastPathComponent
                    for f in shell(body, cwd: dir, depth: depth + 1) {
                        found.append(GuardFinding(level: f.level, reason: "runs \(name), which " + f.reason))
                    }
                }
            }
        }
        return found
    }

    /// A deletion worth stopping: everything (deny), or a path outside the project (ask).
    func deletion(_ raw: String, cwd: String, project: String, recursive: Bool) -> GuardFinding? {
        if raw.contains("$") {
            // `rm -rf $DIR/` with $DIR empty is `rm -rf /`.
            let rest = raw.replacingOccurrences(of: #"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"#, with: "", options: .regularExpression)
            if recursive, ["", "/", "/*", "/.*"].contains(rest) {
                return GuardFinding(level: .ask, reason: "deletes \(raw); if that variable is empty, it's the whole disk")
            }
            return nil
        }
        var path = resolve(raw, cwd: cwd)
        for suffix in ["/*", "/.*", "/.[!.]*", "/"] where path.hasSuffix(suffix) && path.count > suffix.count {
            path.removeLast(suffix.count)
        }
        if path.isEmpty || path == "/*" { path = "/" }
        let p = lower(path)
        if isHostwatch(p) { return GuardFinding(level: .deny, reason: "deletes Hostwatch or its records") }
        if recursive, Self.everything(home: lower(home)).contains(p) {
            return GuardFinding(level: .deny, reason: "deletes \(display(path)) and everything in it")
        }
        let projectRoot = lower(project)
        let inProject = !Self.everything(home: lower(home)).contains(projectRoot) && (p == projectRoot || p.hasPrefix(projectRoot + "/"))
        let temporary = ["/tmp/", "/private/tmp/", "/private/var/folders/", "/var/folders/"].contains { p.hasPrefix($0) }
            || p.hasPrefix(lower(NSTemporaryDirectory()))
        if inProject || temporary { return nil }
        guard recursive else { return nil }                     // single files outside: Claude Code's own prompt covers it
        return GuardFinding(level: .ask, reason: "deletes \(display(path)) and everything in it, outside this project")
    }

    // MARK: Files Claude writes

    func write(_ path: String, text: String, cwd: String) -> [GuardFinding] {
        guard !path.isEmpty else { return [] }
        let full = resolve(path, cwd: cwd)
        let p = lower(full)
        var found: [GuardFinding] = []
        if isHostwatch(p) { found.append(GuardFinding(level: .deny, reason: "changes Hostwatch's own files")) }
        for (rx, why) in Self.sensitiveFiles where rx.matches(p) { found.append(GuardFinding(level: .ask, reason: why)) }
        // A script being written is judged by what it would do when run (never more than a question).
        let ext = (full as NSString).pathExtension.lowercased()
        if Self.scriptExtensions.contains(ext) || text.hasPrefix("#!") {
            for f in shell(text, cwd: cwd, depth: 1) {
                found.append(GuardFinding(level: .ask, reason: "writes \((full as NSString).lastPathComponent), a script that " + f.reason))
            }
        }
        return found
    }

    // MARK: Helpers

    private func knownBad(in lc: String) -> [GuardFinding] {
        var hosts = Self.urlHost.allMatches(lc) + Self.atHost.allMatches(lc)
        hosts += Self.ipv4.allMatches(lc)
        var seen = Set<String>()
        return hosts.filter { seen.insert($0).inserted }.compactMap { host in
            listed(host).map { GuardFinding(level: .deny, reason: "contacts \(host), a known malware address (\($0))") }
        }
    }

    /// Hostwatch's app, data or logs (lower-cased path).
    private func isHostwatch(_ p: String) -> Bool {
        let h = lower(home)
        return [h + "/library/application support/hostwatch", h + "/library/logs/hostwatch", "/applications/hostwatch.app"]
            .contains { p == $0 || p.hasPrefix($0 + "/") }
    }

    private func firstHost(_ lc: String) -> String? { Self.urlHost.allMatches(lc).first }

    /// A public IPv4 address in the text (not loopback, private or link-local).
    private func publicIP(_ lc: String) -> String? {
        Self.ipv4.allMatches(lc).first { ip in
            let o = ip.split(separator: ".").compactMap { Int($0) }
            guard o.count == 4, o.allSatisfy({ $0 <= 255 }) else { return false }
            return !(o[0] == 127 || o[0] == 10 || o[0] == 0 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16...31).contains(o[1]))
                     || (o[0] == 169 && o[1] == 254) || o[0] >= 224)
        }
    }

    /// `bash x.sh`, `python3 tool.py`, `./run.sh`: the script file, if it's one.
    private func scriptPath(program: String, args: [String], cwd: String) -> String? {
        let name = (program as NSString).lastPathComponent
        if Self.interpreters.contains(name) || name.hasPrefix("python") {
            guard !args.contains(where: { ["-c", "-e", "-m", "--eval"].contains($0) }),
                  let file = args.first(where: { !$0.hasPrefix("-") }) else { return nil }
            return resolve(file, cwd: cwd)
        }
        if program.hasPrefix("./") || program.hasPrefix("/") || program.hasPrefix("~") {
            let path = resolve(program, cwd: cwd)
            return path.hasPrefix("/bin/") || path.hasPrefix("/usr/") || path.hasPrefix("/sbin/") ? nil : path
        }
        return nil
    }

    func resolve(_ path: String, cwd: String) -> String {
        var p = path
        if p == "~" { p = home } else if p.hasPrefix("~/") { p = home + p.dropFirst(1) }
        if !p.hasPrefix("/") { p = cwd + "/" + p }
        return (p as NSString).standardizingPath
    }

    private func lower(_ s: String) -> String { s.lowercased() }

    private func display(_ path: String) -> String {
        path == home ? "~" : path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }

    /// `~/x`, `$HOME/x`, `${HOME}/x` → the home folder.
    func expandHome(_ text: String) -> String {
        var t = text.replacingOccurrences(of: "${HOME}", with: home).replacingOccurrences(of: "$HOME", with: home)
        t = Self.tilde.stringByReplacingMatches(in: t, range: NSRange(t.startIndex..., in: t),
                                                withTemplate: "$1" + NSRegularExpression.escapedTemplate(for: home))
        return t
    }

    /// Simple commands of a command line: split at `;`, `&&`, `||`, `|`, `&` and newlines (outside quotes).
    static func segments(_ text: String) -> [String] {
        var out: [String] = [], current = "", quote: Character? = nil
        var chars = Array(text)[...]
        while let c = chars.popFirst() {
            if let q = quote {
                current.append(c)
                if c == q { quote = nil } else if c == "\\", q == "\"", let n = chars.popFirst() { current.append(n) }
                continue
            }
            switch c {
            case "'", "\"": quote = c; current.append(c)
            case "\\": current.append(c); if let n = chars.popFirst() { current.append(n) }
            case ";", "\n", "|", "&":
                // `2>&1`, `>&2` and `&>` are redirections, not separators.
                if c == "&", current.last == ">" || chars.first == ">" { current.append(c); continue }
                out.append(current); current = ""
            case "(", ")", "{", "}", "`": out.append(current); current = ""
            default: current.append(c)
            }
        }
        out.append(current)
        return out.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// Words of one simple command, with quotes removed.
    static func tokens(_ segment: String) -> [String] {
        var out: [String] = [], current = "", quote: Character? = nil, any = false
        var chars = Array(segment)[...]
        while let c = chars.popFirst() {
            if let q = quote {
                if c == q { quote = nil } else if c == "\\", q == "\"", let n = chars.popFirst() { current.append(n) } else { current.append(c) }
                continue
            }
            switch c {
            case "'", "\"": quote = c; any = true
            case "\\": if let n = chars.popFirst() { current.append(n) }
            case " ", "\t":
                if any || !current.isEmpty { out.append(current) }
                current = ""; any = false
            default: current.append(c)
            }
        }
        if any || !current.isEmpty { out.append(current) }
        return out
    }

    static func readSmallTextFile(_ path: String) -> String? {
        var st = stat()
        guard stat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size < 256_000,
              let data = FileManager.default.contents(atPath: path), !data.contains(0) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: Rules

    static func everything(home: String) -> Set<String> {
        var set: Set<String> = ["/", "/users", "/system", "/library", "/applications", "/usr", "/bin", "/sbin", "/etc",
                                "/private", "/private/etc", "/private/var", "/var", "/opt", "/opt/homebrew", "/volumes", "/cores"]
        set.insert(home)
        for d in ["library", "documents", "desktop", "pictures", "downloads", "movies", "music", ".ssh", ".config", "applications"] {
            set.insert(home + "/" + d)
        }
        return set
    }

    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "fish", "perl", "ruby", "node", "osascript", "source", "."]
    static let scriptExtensions: Set<String> = ["sh", "bash", "zsh", "command", "tool", "py", "rb", "pl", "js", "mjs", "applescript", "scpt"]

    private static let shells = #"(sudo\s+)?(env\s+)?(\S*/)?((ba|z|da|k|c|tc|fi)?sh|python[0-9.]*|perl|ruby|node|osascript)\b"#

    static let downloadAndRun: [Regex] = [
        Regex(#"\b(curl|wget)\b[^;&\n]*\|\s*"# + shells),
        Regex(#"(\b(ba|z)?sh|\bsource|(^|[\s;&|])\.)\s+(-c\s+)?["']?(<\(|\$\()\s*(curl|wget)\b"#),
        Regex(#"\beval\s+["']?\$\(\s*(curl|wget)\b"#),
    ]

    /// (pattern on the lower-cased command, level, why).
    static let rules: [(Regex, GuardLevel, String)] = [
        (Regex(#"/dev/(tcp|udp)/"#), .deny, "opens a network connection a remote shell can use (/dev/tcp)"),
        (Regex(#"\b(nc|ncat|netcat)\b[^|;&\n]*\s-[a-z]*[ec]\s"#), .deny, "opens a remote shell (nc -e)"),
        (Regex(#"\bsocat\b[^\n]*\b(exec|system):"#), .deny, "opens a remote shell (socat exec)"),
        (Regex(#"\bdiskutil\s+(erasedisk|erasevolume|zerodisk|randomdisk|secureerase|partitiondisk|reformat|apfs\s+(deletecontainer|deletevolume|erasevolume))\b"#),
         .deny, "erases a disk"),
        (Regex(#"\bdd\b[^|;&\n]*\bof=/dev/"#), .deny, "writes directly over a disk"),
        (Regex(#"(^|[\s;&|])(mkfs(\.\w+)?|newfs(_\w+)?)\s"#), .deny, "formats a disk"),
        (Regex(#":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}"#), .deny, "a fork bomb (freezes the Mac)"),
        (Regex(#"\bcsrutil\s+(disable|authenticated-root\s+disable)"#), .deny, "turns off System Integrity Protection"),
        (Regex(#"\bspctl\s+(--master-disable|--global-disable)"#), .deny, "turns off Gatekeeper, so unchecked apps can run"),
        (Regex(#"\bsqlite3\b[^\n]*tcc\.db"#), .deny, "edits macOS's privacy permissions database"),
        (Regex(#"\b(rm|mv|srm|shred)\b[^;|&\n]*(/applications/hostwatch\.app|/application\\? support/hostwatch|/logs/hostwatch)"#),
         .deny, "deletes Hostwatch or its records"),
        (Regex(#"\b(pkill|killall)\b[^;|&\n]*\bhostwatch"#), .ask, "stops Hostwatch"),
        (Regex(#"\blaunchctl\s+(bootout|remove|unload|disable)\b[^;|&\n]*hostwatch"#), .ask, "stops Hostwatch's collector"),
        (Regex(#"\bdefaults\s+(delete|write)\s+local\.hostwatch\.app\b"#), .ask, "changes Hostwatch's settings"),
        (Regex(#"\bxattr\s+(-[a-z]*c[a-z]*\b|[^;|&\n]*-[a-z]*d[a-z]*\s+com\.apple\.quarantine)"#), .ask,
         "removes macOS's download check (quarantine) from files"),
        (Regex(#"\bspctl\s+--add\b"#), .ask, "tells Gatekeeper to allow a program"),
        (Regex(#"\btccutil\s+reset\b"#), .ask, "resets privacy permissions"),
        (Regex(#"\bsocketfilterfw\b[^\n]*--setglobalstate\s+off"#), .ask, "turns off the firewall"),
        (Regex(#"\bsystemsetup\b[^\n]*-setremotelogin\s+on|\bkickstart\b[^\n]*-activate|\blaunchctl\s+(load|enable)\b[^\n]*ssh"#),
         .ask, "turns on remote access to this Mac"),
        (Regex(#"\blaunchctl\s+(load|bootstrap|submit|enable)\b"#), .ask,
         "registers a background program with launchd (it starts by itself)"),
        (Regex(#"\bdefaults\s+write\s+com\.apple\.loginwindow\b|login item"#), .ask, "adds something that starts at login"),
        (Regex(#"history\s+-c\b|\bunset\s+histfile\b|\b(rm|shred|truncate)\b[^;|&\n]*_history\b"#), .ask, "erases shell history"),
        (Regex(#"\bosascript\b(?![^;|&\n]*display notification)"#), .ask,
         "runs AppleScript, which can control other apps or show a fake password dialog"),
        (Regex(#"with administrator privileges"#), .ask, "asks for an administrator password through AppleScript"),
        (Regex(#"\bvisudo\b|/etc/sudoers"#), .ask, "changes who can use sudo"),
        (Regex(#"(base64\s+(-d|--decode)\b|\bxxd\s+-r\b|\bopenssl\s+(enc|base64)\b[^|]*\s-d\b)[^\n]*\|\s*"# + shells), .ask,
         "decodes hidden text and runs it"),
        (Regex(#"\beval\b[^\n]*(base64|xxd|\\x[0-9a-f]{2})|\b(ba|z)?sh\s+-c\s+["']?\$\([^)]*base64"#), .ask, "decodes hidden text and runs it"),
        (Regex(#"python[0-9.]*\s+-c\b[^\n]*(b64decode|exec\(|eval\()"#), .ask, "decodes hidden text and runs it"),
        (Regex(#"disableallhooks"#), .ask, "turns off Claude Code's hooks, Hostwatch's check included"),
    ] + sensitiveWrites

    /// Writes to files that make things start by themselves, open the Mac, or switch off this check.
    static let sensitiveFiles: [(Regex, String)] = [
        (Regex(#"/library/launch(agents|daemons)/"#), "makes a program start by itself (a launch agent or daemon)"),
        (Regex(#"/\.(zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|bash_login|profile)$|/\.config/fish/config\.fish$"#),
         "changes a shell startup file (it runs whenever a terminal opens)"),
        (Regex(#"/\.ssh/authorized_keys2?$"#), "lets someone log in to this Mac with a key"),
        (Regex(#"/\.claude/settings(\.local)?\.json$|/library/application support/claudecode/"#),
         "changes Claude Code's settings (this could switch off Hostwatch's check)"),
        (Regex(#"^/(private/)?etc/"#), "changes system settings in /etc"),
        (Regex(#"/library/startupitems/|^/(private/)?etc/periodic/"#), "makes a program start by itself"),
    ]

    /// The same files, written from the shell: `>`, `>>`, `tee`, `cp`, `mv`, `ln`, `sed -i`, `defaults write`…
    static let sensitiveWrites: [(Regex, GuardLevel, String)] = {
        let writer = #"(>>?\s*["']?|\btee\s+(-a\s+)?["']?|\b(cp|mv|ln|install|ditto|rsync)\b[^;|&\n]*\s["']?|\bsed\s+-i[^;|&\n]*\s["']?|\bperl\s+-[a-z]*i[^;|&\n]*\s["']?|\bdefaults\s+write\s+["']?|\bplutil\b[^;|&\n]*\s["']?)"#
        let paths: [(String, String)] = [
            (#"\S*/library/launch(agents|daemons)/"#, "makes a program start by itself (a launch agent or daemon)"),
            (#"\S*/\.(zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|bash_login|profile|config/fish/config\.fish)\b"#,
             "changes a shell startup file (it runs whenever a terminal opens)"),
            (#"\S*/\.ssh/authorized_keys"#, "lets someone log in to this Mac with a key"),
            (#"\S*/\.claude/settings(\.local)?\.json"#, "changes Claude Code's settings (this could switch off Hostwatch's check)"),
            (#"(/private)?/etc/"#, "changes system settings in /etc"),
        ]
        return paths.map { (Regex(writer + $0.0), .ask, $0.1) }
    }()

    /// Secret files and Keychain reads: (pattern, what it is).
    static let secrets: [(Regex, String)] = [
        (Regex(#"/\.ssh/id_[a-z0-9_-]+(?![a-z0-9_.-]*\.pub)\b"#), "your SSH private key"),
        (Regex(#"/\.aws/(credentials|sso/cache)"#), "your AWS credentials"),
        (Regex(#"/\.netrc\b|/\.git-credentials\b"#), "saved passwords (.netrc / git credentials)"),
        (Regex(#"/\.config/gh/hosts\.yml"#), "your GitHub token"),
        (Regex(#"/\.docker/config\.json"#), "your Docker registry logins"),
        (Regex(#"/\.kube/config\b"#), "your Kubernetes credentials"),
        (Regex(#"/\.(npmrc|pypirc)\b"#), "package registry tokens"),
        (Regex(#"/\.gnupg/"#), "your GPG keys"),
        (Regex(#"/library/keychains\b"#), "the Keychain files"),
        (Regex(#"(google/chrome|bravesoftware|microsoft edge|arc/user data|firefox/profiles|vivaldi)[^\n]*(login data|cookies|logins\.json|key4\.db|web data)"#),
         "browser passwords or cookies"),
        (Regex(#"/library/cookies\b|/library/containers/com\.apple\.safari/"#), "Safari's cookies or data"),
        (Regex(#"/library/(messages|mail)/"#), "your Messages or Mail"),
        (Regex(#"\bsecurity\s+(find-generic-password|find-internet-password)\b[^;|&\n]*\s-[a-z]*[wg]\b"#), "a password from the Keychain"),
        (Regex(#"\bsecurity\s+(dump-keychain|export)\b"#), "the Keychain"),
    ]

    /// `ssh -i ~/.ssh/id_x` uses a key; it doesn't read it out.
    static let keyUse = Regex(#"\s-i\s+["']?\S*/\.ssh/id_\S+"#)
    static let senders = Regex(#"\b(curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|socat|telnet|ssh)\b|/dev/(tcp|udp)/"#)
    static let connectors = Regex(#"\b(curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|socat|telnet)\b"#)
    static let envDump = Regex(#"\b(env|printenv)\b\s*(\||>|$)"#)
    static let exfilHosts = Regex(#"\b(pastebin\.com|paste\.ee|hastebin\.com|termbin\.com|transfer\.sh|file\.io|0x0\.st|webhook\.site|requestbin\.\w+|[a-z0-9-]+\.pipedream\.net|[a-z0-9-]+\.ngrok(-free)?\.(io|app)|discord(app)?\.com/api/webhooks|api\.telegram\.org|[a-z0-9-]+\.oast\.\w+|interact\.sh|[a-z0-9-]+\.burpcollaborator\.net)\b"#)
    static let urlHost = Regex(#"\b(?:https?|ftp)://(?:[^/@\s'"]+@)?([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})"#, group: 1)
    static let atHost = Regex(#"\b[a-z0-9._-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})\b"#, group: 1)
    static let ipv4 = Regex(#"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"#, group: 1)
    static let tilde = try! NSRegularExpression(pattern: #"(^|[\s=:'"(])~(?=/|\s|$|['")])"#)
}

/// A compiled pattern with the small API the guard needs.
struct Regex: @unchecked Sendable {
    let regex: NSRegularExpression
    let group: Int
    var pattern: String { regex.pattern }

    init(_ pattern: String, group: Int = 0) {
        regex = try! NSRegularExpression(pattern: pattern)
        self.group = group
    }

    func matches(_ s: String) -> Bool { regex.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }

    func firstMatch(_ s: String) -> Substring? {
        guard let m = regex.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)),
              let r = Range(m.range(at: group), in: s) else { return nil }
        return s[r]
    }

    func allMatches(_ s: String) -> [String] {
        regex.matches(in: s, range: NSRange(s.startIndex..., in: s)).compactMap { Range($0.range(at: group), in: s).map { String(s[$0]) } }
    }

    func replace(_ s: String, with template: String) -> String {
        regex.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: template)
    }
}
