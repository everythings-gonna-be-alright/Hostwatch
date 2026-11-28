import Foundation
import Testing
@testable import Hostwatch

/// The story corpus (tests/corpus/stories.jsonl): every false story seen on a real Mac, anonymised, beside attack
/// chains that must still alert. Fails if a false alarm comes back or an attack goes quiet (ADR 0022, 0023).
/// Threat-list matches go through the same filters as live (`FeedCheck`, `ThreatHit.confident`).
@MainActor @Suite struct StoryCorpus {
    struct Row: Decodable {
        struct Listed: Decodable { var source: String; var kind: ThreatHit.Kind }
        var `case`: String, label: String, t: Double
        var kind: EventKind, pid: Int, ppid: Int, proc: String, target: String, extra: String, parent: String, host: String, args: String
        var listed: Listed?, rawIP: Bool?, newDomain: String?, routine: Bool?
    }

    static let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("corpus/stories.jsonl")

    static func rows() throws -> [Row] {
        let text = try String(contentsOf: url, encoding: .utf8).replacingOccurrences(of: "$HOME", with: home)
        return try text.split(separator: "\n").map { try JSONDecoder().decode(Row.self, from: Data($0.utf8)) }
    }

    /// What the live check would make of a listing: nothing for a platform, a local or a CDN address.
    static func match(_ l: Row.Listed, host: String, target: String) -> (summary: String, confident: Bool)? {
        switch l.kind {
        case .domain:
            guard !FeedCheck.neverFlag(host), !FeedCheck.sharedHost(host) else { return nil }
        case .ip, .file:
            let ip = target.split(separator: ":").dropLast().joined(separator: ":")
            guard !FeedCheck.platformHost(host), !FeedCheck.localAddress(ip), !FeedCheck.sharedNetwork(ip) else { return nil }
        }
        let hit = ThreatHit(date: Date(), kind: l.kind, indicator: host, source: l.source, detail: "listed", process: "", path: "", pid: 0)
        return (hit.summary, hit.confident)
    }

    @Test func noFalseStoryAndEveryAttackAlerts() throws {
        _ = TestEnv.ready
        let rows = try Self.rows()
        let engine = StoryEngine(persistent: false)
        engine.liveLookups = false
        var alerted: [Story] = []
        engine.onFired = { alerted.append($0) }
        let start = Date().addingTimeInterval(-86_400)
        var caseOf: [Int: String] = [:]
        for r in rows {
            caseOf[r.pid] = r.case
            let actor = r.kind == .exec ? r.target : r.proc
            var e = ActivityEvent(kind: r.kind, time: "12:00:00", pid: r.pid, ppid: r.ppid, name: (actor as NSString).lastPathComponent,
                                  proc: r.proc, target: r.target, extra: r.extra, parent: r.parent, host: r.host,
                                  hostSource: r.host.isEmpty ? "" : "dns", args: r.args)
            if let l = r.listed, let m = Self.match(l, host: r.host, target: r.target) { e.knownBad = m.summary; e.listedOnly = !m.confident }
            e.rawIP = r.rawIP ?? false
            e.newDomain = r.newDomain ?? ""
            engine.ingest(e, decidedSafe: false, at: start.addingTimeInterval(r.t), routine: r.routine ?? false)
        }
        let alertedCases = Set(alerted.flatMap { $0.steps.compactMap { caseOf[$0.pid] } })
        let attacks = Set(rows.filter { $0.label == "attack" }.map(\.case))
        let noise = Set(rows.filter { $0.label == "noise" }.map(\.case))
        #expect(alertedCases.isDisjoint(with: noise), "false stories came back: \(alertedCases.intersection(noise).sorted())")
        #expect(attacks.isSubset(of: alertedCases), "attacks that no longer alert: \(attacks.subtracting(alertedCases).sorted())")
    }
}
