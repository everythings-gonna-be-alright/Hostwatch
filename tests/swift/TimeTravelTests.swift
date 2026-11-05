import Foundation
import Testing
@testable import Hostwatch

/// Time travel reads history by time: right slice, right order, cheap overview.
@Suite struct HistoryArchiveReading {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    /// Two files: events every second for `count` seconds, then a gap, then more.
    func makeArchive(count: Int = 3000, gap: TimeInterval = 600) throws -> (HistoryArchive, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-tt-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func line(_ i: Int, at date: Date) -> String {
            #"{"kind":"exec","time":"12:00:00","pid":\#(i),"ppid":1,"name":"tool\#(i)","proc":"/usr/bin/true","target":"/usr/bin/true","args":"\#(String(repeating: "x", count: i % 50))","ts":"\#(f.string(from: date))"}"#
        }
        let first = (0..<count).map { line($0, at: t0.addingTimeInterval(Double($0))) }.joined(separator: "\n") + "\n"
        let start2 = t0.addingTimeInterval(Double(count) + gap)
        let second = (0..<count).map { line(count + $0, at: start2.addingTimeInterval(Double($0))) }
            .joined(separator: "\n") + "\n"
        try first.write(to: dir.appendingPathComponent("activity-20270115-080000-000.jsonl"), atomically: true, encoding: .utf8)
        try second.write(to: dir.appendingPathComponent("activity-20270115-090000-000.jsonl"), atomically: true, encoding: .utf8)
        return (HistoryArchive(directory: dir), dir)
    }

    @Test func segmentsKnowTheirTimeSpan() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let segs = archive.segments()
        #expect(segs.count == 2)
        #expect(abs(segs[0].start.timeIntervalSince(t0)) < 0.01)
        #expect(abs(segs[0].end.timeIntervalSince(t0.addingTimeInterval(2999))) < 0.01)
        let range = try #require(HistoryArchive.range(of: segs))
        #expect(abs(range.upperBound.timeIntervalSince(t0.addingTimeInterval(3000 + 600 + 2999))) < 0.01)
    }

    @Test func sliceHasExactlyTheEventsInsideItNewestFirst() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let segs = archive.segments()
        let (events, clipped) = archive.events(segs, from: t0.addingTimeInterval(1000), to: t0.addingTimeInterval(1060))
        #expect(!clipped)
        #expect(events.count == 60)
        #expect(events.first?.pid == 1059 && events.last?.pid == 1000)
    }

    @Test func sliceAcrossTheGapAndBothFiles() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let segs = archive.segments()
        // Last 10 s of file 1, the 600 s gap, first 10 s of file 2.
        let (events, _) = archive.events(segs, from: t0.addingTimeInterval(2990), to: t0.addingTimeInterval(3610))
        #expect(events.count == 20)
        #expect(events.first?.pid == 3009 && events.last?.pid == 2990)
    }

    @Test func busySliceKeepsItsNewestPart() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let segs = archive.segments()
        let (events, clipped) = archive.events(segs, from: t0, to: t0.addingTimeInterval(3000), maxBytes: 20_000)
        #expect(clipped)
        #expect(!events.isEmpty && events.count < 3000)
        #expect(events.first?.pid == 2999)
    }

    @Test func activityIsZeroInTheGapAndBusyElsewhere() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let segs = archive.segments()
        let range = try #require(HistoryArchive.range(of: segs))
        let buckets = archive.activity(segs, over: range, buckets: 66)       // ~100 s each
        #expect(buckets.count == 66)
        #expect(buckets[5] > 0 && buckets[60] > 0)
        #expect(buckets[33] == 0)                                             // inside the gap
        let total = segs.reduce(Int64(0)) { $0 + $1.size }
        #expect(abs(buckets.reduce(0, +) - Double(total)) / Double(total) < 0.01)
    }

    @Test func offsetSearchFindsTheFirstLineAtOrAfter() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let seg = try #require(archive.segments().first)
        let handle = try FileHandle(forReadingFrom: seg.url)
        defer { try? handle.close() }
        for second in [0, 1, 777, 1500, 2999] {
            let offset = HistoryArchive.offset(of: t0.addingTimeInterval(Double(second)), in: handle, size: seg.size)
            try handle.seek(toOffset: UInt64(offset))
            let data = try #require(try handle.read(upToCount: 400))
            let line = data.prefix(upTo: data.firstIndex(of: 0x0A) ?? data.endIndex)
            #expect(String(decoding: line, as: UTF8.self).contains(#""pid":\#(second),"#))
        }
        #expect(HistoryArchive.offset(of: t0.addingTimeInterval(5000), in: handle, size: seg.size) == seg.size)
    }

    @Test(arguments: ["2026-11-01T05:41:56.360+02:00", "2026-11-01T03:41:56.360Z", "2024-02-29T23:59:59.999-05:30",
                      "1999-12-31T00:00:00+00:00", "2026-03-29T03:00:00.5+03:00"])
    func fastTimestampParserMatchesFoundation(_ text: String) throws {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let expected = try #require(f.date(from: text) ?? ISO8601DateFormatter().date(from: text))
        let parsed = try #require(HistoryArchive.parseISO(Data(text.utf8)))
        #expect(abs(parsed.timeIntervalSince(expected)) < 0.001)
    }
}

/// Searching all of history: exact matches, newest first, capped, across compressed and plain files.
@Suite struct HistorySearch {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    /// File 1 (compressed into small blocks) and file 2 (plain, being written): `tool<i>` every second;
    /// every 10th event runs Curl (mixed case), the rest `true`.
    func makeArchive(count: Int = 2000) throws -> (HistoryArchive, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func line(_ i: Int) -> String {
            let target = i % 10 == 0 ? "/usr/bin/Curl" : "/usr/bin/true"
            return #"{"kind":"exec","time":"12:00:00","pid":\#(1000 + i),"ppid":1,"name":"tool\#(i)","proc":"\#(target)","target":"\#(target)","ts":"\#(f.string(from: t0.addingTimeInterval(Double(i))))"}"#
        }
        let first = dir.appendingPathComponent("activity-20270115-080000-000.jsonl")
        try ((0..<count).map(line).joined(separator: "\n") + "\n").write(to: first, atomically: true, encoding: .utf8)
        try HistoryFiles.compress(first, blockBytes: 16_384)
        try ((count..<count * 2).map(line).joined(separator: "\n") + "\n")
            .write(to: dir.appendingPathComponent("activity-20270115-090000-000.jsonl"), atomically: true, encoding: .utf8)
        return (HistoryArchive(directory: dir), dir)
    }

    func run(_ archive: HistoryArchive, _ query: String, limit: Int = 10_000) -> ([ActivityEvent], Bool) {
        var hits: [ActivityEvent] = []
        let capped = archive.search(archive.segments(), query: query, limit: limit, stop: { false }) { hits += $0.hits }
        return (hits, capped)
    }

    @Test func findsEveryMatchInBothFilesNewestFirstIgnoringCase() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (hits, capped) = run(archive, "curl")
        #expect(!capped)
        #expect(hits.count == 400)
        #expect(hits.allSatisfy { $0.target == "/usr/bin/Curl" })
        #expect(hits.map(\.ts) == hits.map(\.ts).sorted(by: >))
        #expect(hits.first?.pid == 1000 + 3990 && hits.last?.pid == 1000)
        #expect(abs(hits[0].ts - t0.addingTimeInterval(3990).timeIntervalSince1970) < 0.01)
    }

    @Test func stopsAtTheLimitWithTheNewestMatches() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        let (hits, capped) = run(archive, "CURL", limit: 25)
        #expect(capped)
        #expect(hits.count == 25)
        #expect(hits.first?.pid == 1000 + 3990 && hits.last?.pid == 1000 + 3750)
    }

    @Test func matchesLikeTheEventListSearch() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        // A PID matches exactly (1234), a name by its text (tool1234 is PID 2234); never a part of a longer
        // PID or the timestamp.
        let (byNumber, _) = run(archive, "1234")
        #expect(byNumber.map(\.pid) == [2234, 1234])
        // Bytes in the line that aren't a searched field ("ppid", the kind) are not matches.
        #expect(run(archive, "ppid").0.isEmpty)
        #expect(run(archive, "no-such-thing").0.isEmpty)
    }

    @Test func cancellingStopsTheScan() throws {
        let (archive, dir) = try makeArchive()
        defer { try? FileManager.default.removeItem(at: dir) }
        var reports = 0
        archive.search(archive.segments(), query: "curl", limit: 10_000, stop: { reports > 0 }) { _ in reports += 1 }
        #expect(reports == 1)
    }

    @Test func fastParserAgreesWithTheDecoder() throws {
        let line = #"{"kind":"net","time":"10:00:01","pid":42,"ppid":1,"name":"curl","proc":"/usr/bin/curl","target":"1.2.3.4:443","extra":"tcp","host":"example.com","host_src":"dns","inferred":true,"note":"n","ts":"2027-01-15T08:00:00.500+02:00"}"#
        let a = try #require(ActivityEvent.parse(Data(line.utf8)))
        let b = try JSONDecoder().decode(ActivityEvent.self, from: Data(line.utf8))
        #expect(a.kind == b.kind && a.pid == b.pid && a.ppid == b.ppid && a.name == b.name && a.proc == b.proc)
        #expect(a.target == b.target && a.extra == b.extra && a.host == b.host && a.hostSource == b.hostSource)
        #expect(a.inferred == b.inferred && a.note == b.note && a.signatureKey == b.signatureKey)
        #expect(a.ts == HistoryArchive.parseISO(Data("2027-01-15T08:00:00.500+02:00".utf8))!.timeIntervalSince1970)
        #expect(ActivityEvent.parse(Data(#"{"kind":"bogus"}"#.utf8)) == nil)
    }
}

/// A busy window is read a page at a time: every event exactly once, newest first, whatever the page size.
@Suite struct TimeTravelPaging {
    @Test func pagesCoverTheWindowWithoutGapsOrRepeats() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-pages-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        // 7 events per moment (same timestamp), 600 moments: page edges land inside groups.
        var lines: [String] = []
        for second in 0..<600 {
            for k in 0..<7 {
                lines.append(#"{"kind":"file","time":"12:00:00","pid":\#(second * 10 + k),"ppid":1,"name":"t","proc":"/usr/bin/t","target":"/tmp/f\#(k)","extra":"r","ts":"\#(f.string(from: t0.addingTimeInterval(Double(second))))"}"#)
            }
        }
        let url = dir.appendingPathComponent("activity-20270115-080000-000.jsonl")
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
        try HistoryFiles.compress(url, blockBytes: 16_384)
        let archive = HistoryArchive(directory: dir)
        let segments = archive.segments()
        let from = t0, to = t0.addingTimeInterval(600)
        var (loaded, more) = archive.events(segments, from: from, to: to, maxBytes: 9_000)
        var pages = 1
        while more {
            let page = archive.events(segments, from: from, to: TimeTravel.nextPageEnd(after: loaded), maxBytes: 9_000)
            let fresh = TimeTravel.newOnly(page.events, after: loaded)
            #expect(!fresh.isEmpty)
            loaded += fresh
            more = page.clipped && !fresh.isEmpty
            pages += 1
        }
        #expect(pages > 10)
        #expect(loaded.count == 4200)
        #expect(Set(loaded.map(TimeTravel.identity)).count == 4200)
        #expect(loaded.map(\.ts) == loaded.map(\.ts).sorted(by: >))
    }
}
