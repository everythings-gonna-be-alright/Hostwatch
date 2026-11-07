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
        if domains == nil { domains = DomainRegistry(replayLearningUntil: date.addingTimeInterval(learnMinutes * 60)) }
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
        }
        engine.ingest(e, decidedSafe: false, at: date)
        n += 1
    }
    print("domains: \(domains?.records.count ?? 0) seen, learning \(Int(learnMinutes)) min, "
          + "\(newDomains.count) new after learning")
    for (time, d, program) in newDomains.prefix(40) { print("   \(time) NEW DOMAIN \(d)  (\(program))") }
    print("beacons: \(beaconHits.count), raw-IP connections: \(rawIPs.count)")
    for (k, b) in beaconHits.sorted(by: { $0.key < $1.key }).prefix(20) { print("   BEACON \(k) \(b)") }
    for k in rawIPs.sorted().prefix(20) { print("   RAW IP \(k)") }
    let fired = engine.stories
    print("\(n) events -> \(fired.count) stories")
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
