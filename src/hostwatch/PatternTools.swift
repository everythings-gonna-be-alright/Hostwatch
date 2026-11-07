import Foundation

// MARK: - Developer report

/// `Hostwatch --signature-report file.jsonl`: prints how events group into patterns.
func runSignatureReport(_ path: String) -> Never {
    SigningCache.shared.live = false
    SigningCache.shared.trustInstalledAppsInMemory()
    guard FileManager.default.isReadableFile(atPath: path) else { print("cannot read \(path)"); exit(1) }
    var counts: [String: Int] = [:]
    var total = 0
    let decoder = JSONDecoder()
    HistoryFiles.forEachLine(path: path) { line in
        guard let e = try? decoder.decode(ActivityEvent.self, from: line) else { return }
        total += 1
        counts["[\(e.kind.rawValue)/\(e.signatureRisk)] \(e.signatureProcess) -> \(e.signaturePattern)", default: 0] += 1
    }
    print("\(total) events -> \(counts.count) patterns")
    for kind in EventKind.allCases {
        let k = counts.filter { $0.key.hasPrefix("[\(kind.rawValue)/") }
        print("  \(kind.rawValue): \(k.values.reduce(0, +)) events -> \(k.count) patterns")
    }
    for risk in PatternRisk.allCases {
        let k = counts.filter { $0.key.contains("/\(risk)] ") }
        print("  \(risk): \(k.count) patterns")
    }
    if let only = ProcessInfo.processInfo.environment["REPORT_KIND"] {
        counts = counts.filter { $0.key.hasPrefix("[\(only)") || $0.key.contains("/\(only)] ") }
    }
    if let grep = ProcessInfo.processInfo.environment["REPORT_GREP"] {
        counts = counts.filter { $0.key.localizedCaseInsensitiveContains(grep) }
        print("matching \(grep): \(counts.count) patterns")
    }
    let top = Int(ProcessInfo.processInfo.environment["REPORT_TOP"] ?? "") ?? 40
    for (key, n) in counts.sorted(by: { $0.value > $1.value }).prefix(top) { print(String(format: "%7d  ", n) + key) }
    exit(0)
}

/// `--regroup-report [folder]`: what the next launch's regrouping would do to the saved patterns (read-only).
func runRegroupReport(_ folder: String?) -> Never {
    let dir = folder.map { URL(fileURLWithPath: $0) } ?? AppPaths.support
    guard let saved = SignatureStore.readSaved(from: dir) else { print("no patterns in \(dir.path)"); exit(1) }
    let plan = SignatureStore.regroupPlan(saved.entries)
    let moved = plan.values.reduce(0) { $0 + $1.count }
    let existing = Set(saved.entries.map(\.id))
    let new = plan.keys.filter { !existing.contains($0) }.count
    func kind(_ key: String) -> String {
        if key.hasSuffix("[\(SignatureBuilder.ordinaryFiles)]") { return "system programs' ordinary reads" }
        if key.hasSuffix(SignatureBuilder.plainTools) { return "shells starting plain tools" }
        if key.contains(" /opt/homebrew/Cellar/") { return "Homebrew formula trees" }
        if key.hasSuffix("/**") { return key.contains("|r /tmp/") || key.contains("|r $TMPDIR/") || key.contains("|w /tmp/")
            || key.contains("|w $TMPDIR/") || key.contains("|rw /tmp/") || key.contains("|rw $TMPDIR/") ? "scratch trees" : "project trees" }
        return "random temp names"
    }
    print("\(saved.entries.count) patterns -> \(saved.entries.count - moved + new)")
    var byKind: [String: (Int, Int)] = [:]
    for (key, group) in plan { byKind[kind(key), default: (0, 0)].0 += group.count; byKind[kind(key), default: (0, 0)].1 += 1 }
    for (k, v) in byKind.sorted(by: { $0.value.0 > $1.value.0 }) { print("  \(k): \(v.0) -> \(v.1)") }
    for (key, group) in plan.sorted(by: { $0.value.count > $1.value.count }).prefix(15) {
        print(String(format: "%6d  ", group.count) + key)
    }
    exit(0)
}
