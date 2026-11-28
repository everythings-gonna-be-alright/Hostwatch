import Foundation

// MARK: - Replay (developer tool)

/// The value of the `"ts":"…"` field, searched from the end of the line.
private func replayTimestamp(_ line: Data) -> String? {
    guard let key = line.range(of: Data(#""ts":""#.utf8), options: .backwards),
          let end = line[key.upperBound...].firstIndex(of: UInt8(ascii: "\""))
    else { return nil }
    return String(decoding: line[key.upperBound..<end], as: UTF8.self)
}

/// `Hostwatch --story-replay history.jsonl`: feeds recorded events through the story engine
/// with their recorded timestamps and prints the stories it would raise.
@MainActor
func runStoryReplay(_ path: String) -> Never {
    guard FileManager.default.isReadableFile(atPath: path) else { print("cannot read \(path)"); exit(1) }
    SigningCache.shared.live = false
    SigningCache.shared.trustInstalledAppsInMemory()
    let engine = StoryEngine(persistent: false)
    engine.liveLookups = false
    var alerts = 0                                          // stories that would have alerted (joined ones don't)
    engine.onFired = { _ in alerts += 1 }
    // As live (REPLAY_PLAIN=1 leaves them out): today's threat lists, from a scratch copy so nothing is written beside
    // the real ones, and your patterns, for what was everyday at the time.
    let plain = ProcessInfo.processInfo.environment["REPLAY_PLAIN"] == "1"
    let intel = plain ? nil : replayIntel()
    var replayClock = Date()
    intel?.now = { replayClock }
    let patterns = plain ? [:] : Dictionary((SignatureStore.readSaved(from: AppPaths.support)?.entries ?? []).map { ($0.id, $0) },
                                            uniquingKeysWith: { a, _ in a })
    let knownDomains = plain ? [] : DomainRegistry.saved()
    print("threat lists: \(intel == nil ? "off" : "on"), patterns: \(patterns.count), known domains: \(knownDomains.count)")
    let decoder = JSONDecoder()
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let learnMinutes = Double(ProcessInfo.processInfo.environment["REPLAY_LEARN_MINUTES"] ?? "") ?? 60
    var domains: DomainRegistry?
    let beacons = BeaconDetector()
    var beaconHits: [String: String] = [:]                  // key -> label
    var rawIPs = Set<String>()
    var newDomains: [(String, String, String)] = []   // time, domain, program
    var n = 0
    // Streamed: a .jsonl, a .jsonl.gz, or a whole history folder (plain and compressed files).
    HistoryFiles.forEachLine(path: path) { data in
        guard var e = try? decoder.decode(ActivityEvent.self, from: data) else { return }
        // The recorder writes "ts" last; read it without parsing the line a second time.
        let date = replayTimestamp(data).flatMap { iso.date(from: $0) } ?? Date()
        if domains == nil {
            // Domains you had seen before this day are known, as they were live.
            let before = knownDomains.filter { $0.firstSeen < date }
            domains = DomainRegistry(replayLearningUntil: before.isEmpty ? date.addingTimeInterval(learnMinutes * 60) : date,
                                     known: before)
        }
        if e.kind == .net {
            if let d = domains?.observe(e, at: date) {
                e.newDomain = d
                if domains?.records[d]?.count == 1 { newDomains.append((e.time, d, e.name)) }
            }
            if let b = beacons.observe(e, at: date) {
                e.beacon = b
                beaconHits["\(e.name) → \(BeaconDetector.destination(e))"] = b
            }
            e.rawIP = NetSignals.isRawIP(e)
            if e.rawIP { rawIPs.insert("\(e.name) → \(e.target)") }
            replayClock = date
            if let hit = intel?.check(e) { e.knownBad = hit.summary; e.listedOnly = !hit.confident }
        }
        let routine = patterns[e.signatureKey].map { SignatureStore.routine($0, now: date) } ?? false
        engine.ingest(e, decidedSafe: false, at: date, routine: routine)
        n += 1
        if n % 20_000 == 0 { engine.maintain(now: date) }
    }
    print("domains: \(domains?.records.count ?? 0) seen, learning \(Int(learnMinutes)) min, "
          + "\(newDomains.count) new after learning")
    for (time, d, program) in newDomains.prefix(40) { print("   \(time) NEW DOMAIN \(d)  (\(program))") }
    print("beacons: \(beaconHits.count), raw-IP connections: \(rawIPs.count)")
    for (k, b) in beaconHits.sorted(by: { $0.key < $1.key }).prefix(20) { print("   BEACON \(k) \(b)") }
    for k in rawIPs.sorted().prefix(20) { print("   RAW IP \(k)") }
    let fired = engine.stories
    print("\(n) events -> \(fired.count) stories, \(alerts) alerts")
    for s in fired.reversed() {
        print("\n[\(s.severity.rawValue.uppercased())] score \(s.score)  \(s.title)   (origin \(s.origin.rawValue): \(s.originPath))")
        print("   stages: \(s.summary)")
        for st in s.steps.prefix(12) {
            print("   \(st.time) \(st.stage.rawValue.padding(toLength: 14, withPad: " ", startingAt: 0)) \(st.name): \(st.detail.prefix(110))")
        }
        if s.steps.count > 12 { print("   … \(s.steps.count - 12) more") }
    }
    exit(0)
}

/// The threat lists as they are now, loaded from a scratch copy: a replay records its matches there, never in yours.
@MainActor
private func replayIntel() -> ThreatIntel? {
    let source = AppPaths.support.appendingPathComponent("intel", isDirectory: true)
    let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-replay-intel-\(getpid())")
    try? FileManager.default.removeItem(at: scratch)
    guard (try? FileManager.default.copyItem(at: source, to: scratch)) != nil else { return nil }
    try? FileManager.default.removeItem(at: scratch.appendingPathComponent("hits.json"))
    // An empty suite: the lists are on by default, and nothing is written to your settings.
    let intel = ThreatIntel(directory: scratch, defaults: UserDefaults(suiteName: "hostwatch-replay") ?? .standard)
    var loaded = false
    Task { await intel.load(); loaded = true }
    while !loaded { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
    return intel
}

