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
