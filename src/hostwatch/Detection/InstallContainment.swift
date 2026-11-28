import Foundation

// Containment of install scripts (ADR 0024, layer 4): what a process started by a package's install script, or by a
// package run at once (npx, uvx, pnpm dlx), may not do. Pure lists and decisions: the app sends the paths, the
// collector decides inside the holds and the firewall relay.

enum InstallContainment {
    /// Secrets an install script never needs: read or written, the open is stopped. The package manager itself is
    /// not contained, so it still reads `.npmrc` to log in to your registry.
    static func readPaths(home: String) -> [String] {
        let h = home.hasSuffix("/") ? String(home.dropLast()) : home
        var paths = [".ssh", ".aws", ".azure", ".config/gcloud", ".kube", ".docker/config.json", ".npmrc", ".yarnrc.yml",
                     ".pypirc", ".netrc", ".git-credentials", ".config/gh", ".config/hub", ".gnupg", ".vault-token",
                     ".terraform.d/credentials.tfrc.json", ".claude/.credentials.json", ".codex/auth.json",
                     ".config/github-copilot", "Library/Keychains", ".config/solana", ".ethereum/keystore",
                     ".electrum/wallets", "Library/Application Support/Exodus", "Library/Cookies"]
            .map { "\(h)/\($0)" }
        // Browsers: only their password and cookie stores (a whole profile is opened thousands of times a minute).
        let browsers = ["Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Arc/User Data", "Vivaldi"]
        for b in browsers {
            for profile in ["Default", "Profile 1", "Profile 2", "Profile 3"] {
                for file in ["Login Data", "Cookies", "Network/Cookies", "Web Data"] {
                    paths.append("\(h)/Library/Application Support/\(b)/\(profile)/\(file)")
                }
            }
        }
        return paths
    }

    /// Places that start code later (login items, launch agents, shell startup): writing there is stopped.
    static func writePaths(home: String) -> [String] {
        let h = home.hasSuffix("/") ? String(home.dropLast()) : home
        return ["Library/LaunchAgents", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile",
                ".config/fish/config.fish", ".config/fish/conf.d", "Library/Application Support/com.apple.backgroundtaskmanagementagent"]
            .map { "\(h)/\($0)" } + ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
    }

    /// Programs an install script has no business starting: AI CLIs (nx's script ran three to hunt for secrets),
    /// secret scanners (Shai-Hulud ran trufflehog), and the tools that read the keychain, add a launch agent or a
    /// scheduled job, or show a fake password dialog.
    static let launches: [String: String] = [
        "claude": "an AI assistant", "gemini": "an AI assistant", "q": "an AI assistant", "codex": "an AI assistant",
        "copilot": "an AI assistant", "cursor-agent": "an AI assistant", "aider": "an AI assistant", "opencode": "an AI assistant",
        "trufflehog": "a secret scanner", "gitleaks": "a secret scanner", "noseyparker": "a secret scanner",
        "detect-secrets": "a secret scanner", "ggshield": "a secret scanner",
        "security": "the keychain tool", "launchctl": "the launch-agent tool", "crontab": "the scheduled-job tool",
        "osascript": "AppleScript (fake password dialogs)",
    ]

    /// Why a contained process may not start this, nil when it may. An AI CLI is often a script: its interpreter is
    /// what launches (`node …/claude`), so the first words count too.
    static func blockedLaunch(path: String, args: [String]) -> (name: String, why: String)? {
        for word in [path] + args.prefix(2) {
            let base = (word as NSString).lastPathComponent
            if let why = launches[base] { return (base, why) }
        }
        return nil
    }

    enum Violation: String, Sendable { case read, write, launch, connect, lookalike }

    /// A contained open: a secret (any mode) or a startup place (writes).
    static func open(_ file: String, mode: String, read: [String], write: [String]) -> Violation? {
        func under(_ list: [String]) -> Bool {
            list.contains { file == $0 || file.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }
        }
        if under(read) { return .read }
        if mode.contains("w"), under(write) { return .write }
        return nil
    }

    /// Package registries and the few hosts native builds download from (node-gyp's headers, prebuilt binaries on
    /// GitHub releases, Puppeteer's and Playwright's browsers, Prisma's engines). Not api.github.com: nx's script
    /// published what it stole there.
    static let hosts = [
        "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "cdn.npmmirror.com", "pypi.org",
        "files.pythonhosted.org", "crates.io", "static.crates.io", "index.crates.io", "rubygems.org", "index.rubygems.org",
        "proxy.golang.org", "sum.golang.org", "repo.packagist.org", "api.nuget.org", "nodejs.org", "github.com",
        "objects.githubusercontent.com", "release-assets.githubusercontent.com", "codeload.github.com",
        "storage.googleapis.com", "edgedl.me.gvt1.com", "cdn.playwright.dev", "playwright.download.prss.microsoft.com",
        "playwright.azureedge.net", "binaries.prisma.sh",
    ]

    /// Allowed: exactly one of `hosts` or `extra` (your own registries), or this Mac. Exact, not subdomains:
    /// github.com is allowed, api.github.com isn't.
    static func hostAllowed(_ host: String, extra: [String] = []) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if h.isEmpty { return false }
        if ["localhost", "127.0.0.1", "::1"].contains(h) || h.hasPrefix("127.") { return true }
        return hosts.contains(h) || extra.contains(h)
    }

    /// Your own registries, from `.npmrc` (`registry=`, `@scope:registry=`) and pip's config (`index-url`).
    static func configuredRegistries(npmrc: String?, pipConf: String?) -> [String] {
        var out: [String] = []
        for line in (npmrc ?? "").split(separator: "\n") + (pipConf ?? "").split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.hasPrefix("#"), !t.hasPrefix(";"), let eq = t.firstIndex(of: "=") else { continue }
            let key = t[..<eq].trimmingCharacters(in: .whitespaces)
            guard key == "registry" || key.hasSuffix(":registry") || key == "index-url" || key == "extra-index-url" else { continue }
            let value = t[t.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if let host = URL(string: value)?.host, !host.isEmpty { out.append(host.lowercased()) }
        }
        return Array(Set(out)).sorted()
    }
}
