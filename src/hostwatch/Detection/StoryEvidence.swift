import Foundation

// What counts as evidence in a story, as pure functions over steps and command lines. Every rule here came from a
// false story on a real Mac: a connection counted as a second sign beside the threat match it carried, one Discord
// listing raised a story every 40 minutes, the AWS command-line tool reading its own ~/.aws was "credential access",
// and `python3 -c 'import json…'` was an encoded command, three times over as Python's launchers handed it on.

extension StoryStage {
    /// Detail, not evidence: shown in the chain, never what makes it a story or adds to its score. Every connection
    /// is one, so it was a free second sign beside whatever a connection itself proved.
    var isContext: Bool { self == .network }

    /// Signs the baseline can make everyday (ADR 0023). Never: a threat match, a swapped or unsigned binary, an
    /// autostart write or quarantine removal, which stay evidence however often they happen.
    var discountable: Bool {
        ![.knownBad, .listed, .swappedBinary, .unsignedCode, .persistence, .unquarantine].contains(self)
    }
}

enum StoryEvidence {
    /// Two signs from two different events: one event (a listed connection, a launch) is one piece of evidence,
    /// however many stages it shows.
    static func independent(_ steps: [StoryStep]) -> Bool {
        let signs = steps.filter(counts).map { (event: eventKey($0), stage: $0.stage) }
        for a in signs where signs.contains(where: { $0.stage != a.stage && $0.event != a.event }) { return true }
        return false
    }

    /// Evidence: not context, and not a weaker sign the baseline says is everyday.
    static func counts(_ s: StoryStep) -> Bool { !s.stage.isContext && s.routine != true }

    static func eventKey(_ s: StoryStep) -> String { "\(s.kind)|\(s.pid)|\(s.target)|\(s.time)" }

    /// A threat-list match that is a story by itself. A broad list (HaGeZi's: ad networks, trackers, phishing) is
    /// a sign that needs another; the malware trackers' exact matches and known malware files stand alone.
    static func standsAlone(_ steps: [StoryStep]) -> Bool {
        steps.contains { $0.stage == .knownBad && !$0.note.hasPrefix(ThreatIntel.Feed.hagezi.title) }
    }

    /// The listed destinations in a story, by program: the same listing for the same program is one story a day.
    static func threatKeys(_ story: Story) -> Set<String> {
        Set(story.steps.filter { $0.stage == .knownBad || $0.stage == .listed }.map { s in
            let dest = s.host.isEmpty ? s.target.split(separator: ":").dropLast().joined(separator: ":") : s.host.lowercased()
            return "\(s.name)|\(dest.isEmpty ? s.target : dest)"
        })
    }

    // MARK: Browsers

    /// Web browsers and their helpers (and Safari's networking, WebKit's): reaching a domain for the first time is
    /// what browsing is, so it isn't a sign. An ad network on a blocklist plus a "new" ad domain was a story.
    static let browserBundles = ["/Google Chrome.app/", "/Google Chrome Beta.app/", "/Google Chrome Canary.app/", "/Chromium.app/",
                                 "/Safari.app/", "/Safari Technology Preview.app/", "/Firefox.app/", "/Firefox Developer Edition.app/",
                                 "/Microsoft Edge.app/", "/Brave Browser.app/", "/Arc.app/", "/Opera.app/", "/Vivaldi.app/",
                                 "/Orion.app/", "/Zen.app/", "/Zen Browser.app/", "/DuckDuckGo.app/"]

    static func isBrowser(_ path: String) -> Bool {
        browserBundles.contains { path.contains($0) } || path.hasPrefix("/System/Library/Frameworks/WebKit.framework/")
    }

    // MARK: Not a threat

    static let exceptionsKey = "storyExceptions"

    /// One exact sign: its stage, the program, and the destination (net), folder (file), command (inline code) or
    /// parent (other launches). Marking a story Not a Threat records these, so the same thing never counts again,
    /// while the same program doing anything else, or another program doing this, still does.
    static func exceptionKey(_ s: StoryStep) -> String {
        let program = s.kind == .exec ? s.target : s.proc
        let what: String
        switch s.kind {
        case .file: what = (s.target as NSString).deletingLastPathComponent
        case .net: what = s.host.isEmpty ? s.target.split(separator: ":").dropLast().joined(separator: ":") : s.host.lowercased()
        case .exec: what = s.stage == .encodedCommand ? commandKey(s.args) : s.parent
        }
        return "\(s.stage.rawValue)|\(s.name)|\(program)|\(what)"
    }

    // MARK: Inline code

    private static let inlineFlags: Set<String> = ["-c", "-e", "-E", "--eval", "-r"]

    /// The code an interpreter was given on its command line (`python3 -c '…'`), if any.
    static func inlineCode(_ args: String) -> String? {
        let tokens = SignatureBuilder.shellTokens(args)
        guard tokens.count >= 3, let name = tokens.first.map({ ($0 as NSString).lastPathComponent.lowercased() }),
              name.hasPrefix("python") || ["perl", "ruby", "node"].contains(name),
              let i = tokens.firstIndex(where: inlineFlags.contains), i + 1 < tokens.count else { return nil }
        return tokens[i + 1]
    }

    private static let riskyCode = try! NSRegularExpression(pattern:
        #"base64|b64decode|fromhex|unhexlify|marshal|zlib|\bexec\s*\(|\beval\s*\(|compile\s*\(|subprocess|os\.system|"#
        + #"popen|pty\.spawn|socket|urllib|requests\.|http\.client|urlopen|`|\bsystem\s*\(|child_process|IO\.popen"#,
        options: [.caseInsensitive])

    /// Inline code that decodes, runs something else or goes online. Reading JSON from a pipe is everyday work.
    static func riskyInline(_ args: String) -> Bool {
        guard let code = inlineCode(args) else { return false }
        return riskyCode.firstMatch(in: code, range: NSRange(code.startIndex..., in: code)) != nil
    }

    /// One command, however many launchers it passes through (python3 → python3.9 → Python.app, same arguments):
    /// the arguments after the program.
    static func commandKey(_ args: String) -> String {
        inlineCode(args) ?? SignatureBuilder.shellTokens(args).dropFirst().joined(separator: " ")
    }

    // MARK: Credentials a tool owns

    /// Command-line tools and the folder (under your home) where they keep their own sign-in.
    static let ownCredentials: [String: [String]] = [
        "aws": [".aws/"], "kubectl": [".kube/"], "gcloud": [".config/gcloud/"], "gsutil": [".config/gcloud/"],
        "az": [".azure/"], "gh": [".config/gh/"], "docker": [".docker/"], "terraform": [".terraform.d/"],
        "doctl": ["Library/Application Support/doctl/"], "flyctl": [".fly/"], "heroku": [".netrc", ".local/share/heroku/"],
    ]

    /// The script an interpreter runs (`Python /opt/homebrew/bin/aws sso login` → /opt/homebrew/bin/aws).
    static func script(_ args: String) -> String? {
        let tokens = SignatureBuilder.shellTokens(args)
        guard tokens.count >= 2, let name = tokens.first.map({ ($0 as NSString).lastPathComponent.lowercased() }),
              name.hasPrefix("python") || SignatureBuilder.interpreters.contains(name),
              let s = tokens.dropFirst().first(where: { !$0.hasPrefix("-") }), s.hasPrefix("/") else { return nil }
        return s
    }

    /// The tool reads its own sign-in: `aws` (the program, or the script Python runs) under ~/.aws. A script in a
    /// download or temp folder never counts, so `~/Downloads/aws` reading ~/.aws stays credential access.
    static func ownsCredential(program: String, args: String, file: String, home: String) -> Bool {
        let tools = [program, script(args)].compactMap { $0 }.filter { !SignatureBuilder.isDropZone(SignatureBuilder.normalize($0)) }
        return tools.contains { tool in
            let name = (tool as NSString).lastPathComponent.lowercased()
            return (ownCredentials[name] ?? []).contains { file.hasPrefix(home + "/" + $0) || file == home + "/" + $0.trimmingCharacters(in: ["/"]) }
        }
    }
}

// MARK: - Loading and evidence for AI

extension StoryEngine {
    /// Known-bad steps about a platform that is never flagged (`FeedCheck.neverFlag`), made before it was: they go,
    /// and a story left with nothing known-bad and too little else to stand on goes with them (www.youtube.com was
    /// called malware this way).
    static func withoutPlatformMatches(_ stories: [Story]) -> [Story] {
        stories.compactMap { story in
            var s = story
            s.steps.removeAll { $0.stage == .knownBad && $0.kind == .net && !$0.host.isEmpty && FeedCheck.neverFlag($0.host) }
            guard s.steps.count != story.steps.count else { return story }
            // What made it a story was the match: without one, it needs two stages as any other story does.
            if s.steps.isEmpty || !s.stages.contains(.knownBad) && s.stages.count < 2 { return nil }
            return s
        }
    }

    /// Evidence for Claude: the whole chain in order.
    static func evidence(for story: Story) -> String {
        var lines = ["## Story (correlated by Hostwatch)",
                     "chain: \(story.title)",
                     "origin: \(story.originName) (\(story.origin.rawValue)) \(story.originPath)",
                     "stages: \(story.summary)",
                     "score: \(story.score), severity: \(story.severity.rawValue)", "", "steps:"]
        for s in story.steps {
            lines.append("- \(s.time) [\(s.stage.title)] \(s.name) pid \(s.pid) ← \(s.ppid): \(s.detail)  (\(s.note))")
        }
        return lines.joined(separator: "\n")
    }

    /// Not a threat: this story's exact signs never count again (`StoryEvidence.exceptionKey`), and it goes.
    func notAThreat(_ id: UUID) {
        guard let story = stories.first(where: { $0.id == id }) else { return }
        exceptions.formUnion(story.steps.filter { !$0.stage.isContext }.map(StoryEvidence.exceptionKey))
        if persistent { UserDefaults.standard.set(Array(exceptions.sorted().suffix(5000)), forKey: StoryEvidence.exceptionsKey) }
        delete(id)
    }
}
