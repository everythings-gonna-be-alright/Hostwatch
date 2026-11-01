import Foundation
import Testing
@testable import Hostwatch

/// Compressed history: lossless, readable by gzip, indexed by time, and the same answers as plain.
@Suite struct HistoryCompression {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func makeFile(lines count: Int = 2000) throws -> (URL, URL, Data) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-gz-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let text = (0..<count).map { i in
            #"{"kind":"file","time":"12:00:00","pid":\#(i),"ppid":1,"name":"tool","proc":"/usr/bin/true","target":"/tmp/f\#(i % 37)","extra":"r","ts":"\#(f.string(from: t0.addingTimeInterval(Double(i))))"}"#
        }.joined(separator: "\n") + "\n"
        let url = dir.appendingPathComponent("activity-20270115-080000-000.jsonl")
        let data = Data(text.utf8)
        try data.write(to: url)
        return (dir, url, data)
    }

    @Test func roundTripIsLosslessWithWholeLineBlocks() throws {
        let (dir, url, original) = try makeFile()
        defer { try? FileManager.default.removeItem(at: dir) }
        let index = try HistoryFiles.compress(url, blockBytes: 16_384)
        #expect(index.blocks.count > 5)
        #expect(!FileManager.default.fileExists(atPath: url.path))
        let gz = HistoryFiles.gzURL(url)
        var restored = Data()
        for block in index.blocks {
            let data = try #require(HistoryFiles.read(block, from: gz))
            #expect(data.last == 0x0A)                               // whole lines only
            #expect(Int64(data.count) == block.size)
            restored.append(data)
        }
        #expect(restored == original)
        #expect(index.size == Int64(original.count))
        #expect(abs(try #require(index.start).timeIntervalSince(t0)) < 0.01)
        #expect(abs(try #require(index.end).timeIntervalSince(t0.addingTimeInterval(1999))) < 0.01)
        // Blocks are in time order and don't overlap.
        for (a, b) in zip(index.blocks, index.blocks.dropFirst()) { #expect(a.end < b.start && a.offset < b.offset) }
        // Per-minute bytes add up to the whole file.
        #expect(try #require(index.minutes).reduce(Int64(0)) { $0 + $1[1] } == Int64(original.count))
        let onDisk = HistoryFiles.diskSize(url)
        #expect(onDisk < Int64(original.count) / 5)
    }

    @Test func systemGzipReadsTheFile() throws {
        let (dir, url, original) = try makeFile()
        defer { try? FileManager.default.removeItem(at: dir) }
        try HistoryFiles.compress(url, blockBytes: 16_384)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
        p.arguments = ["-dc", HistoryFiles.gzURL(url).path]
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        let out = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        #expect(p.terminationStatus == 0)
        #expect(out == original)
    }

    @Test func listingPrefersPlainAndIgnoresHalfWrittenFiles() throws {
        let (dir, url, _) = try makeFile()
        defer { try? FileManager.default.removeItem(at: dir) }
        // A .gz without an index (interrupted) is ignored; the plain file is used.
        try Data([0x1f, 0x8b]).write(to: HistoryFiles.gzURL(url))
        guard case .plain = try #require(HistoryFiles.list(in: dir).first) else { Issue.record("expected plain"); return }
        try FileManager.default.removeItem(at: HistoryFiles.gzURL(url))
        try HistoryFiles.compress(url, blockBytes: 16_384)
        let files = HistoryFiles.list(in: dir)
        #expect(files.count == 1)
        guard case .compressed = try #require(files.first) else { Issue.record("expected compressed"); return }
        HistoryFiles.remove(url)
        #expect(HistoryFiles.list(in: dir).isEmpty)
        #expect(HistoryFiles.diskSize(url) == 0)
    }

    @Test func timeTravelSeesTheSameHistoryCompressed() throws {
        let (dir, url, _) = try makeFile(lines: 3000)
        defer { try? FileManager.default.removeItem(at: dir) }
        let archive = HistoryArchive(directory: dir)
        let slices: [(Double, Double)] = [(100, 160), (0, 3000), (2950, 4000), (1234.5, 1240)]
        func read() -> ([[Int]], Double) {
            let segs = archive.segments()
            let events = slices.map { a, b in
                archive.events(segs, from: t0.addingTimeInterval(a), to: t0.addingTimeInterval(b)).events.map(\.pid)
            }
            let range = HistoryArchive.range(of: segs)!
            return (events, archive.activity(segs, over: range, buckets: 30).reduce(0, +))
        }
        let (plainEvents, plainTotal) = read()
        try HistoryFiles.compress(url, blockBytes: 20_000)
        let (gzEvents, gzTotal) = read()
        #expect(gzEvents == plainEvents)
        #expect(plainEvents[0].count == 60 && plainEvents[0].first == 159)
        #expect(abs(gzTotal - plainTotal) / plainTotal < 0.01)
    }

    @Test func timelineGapsStayEmptyWhenCompressed() throws {
        // 10 minutes of events, a 2-hour pause, 10 more minutes: one block spans the pause.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-gap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let times = (0..<600).map { Double($0) } + (0..<600).map { 7800 + Double($0) }
        let text = times.enumerated().map { i, t in
            #"{"kind":"exec","time":"12:00:00","pid":\#(i),"ppid":1,"name":"x","proc":"/x","target":"/x","ts":"\#(f.string(from: t0.addingTimeInterval(t)))"}"#
        }.joined(separator: "\n") + "\n"
        let url = dir.appendingPathComponent("activity-20270115-080000-000.jsonl")
        try Data(text.utf8).write(to: url)
        try HistoryFiles.compress(url)                                    // one 4 MB block for all of it
        let archive = HistoryArchive(directory: dir)
        let segs = archive.segments()
        let bars = archive.activity(segs, over: HistoryArchive.range(of: segs)!, buckets: 42)   // ~200 s each
        #expect(bars[20] == 0 && bars[10] == 0 && bars[30] == 0)
        #expect(bars[0] > 0 && bars[41] > 0)
    }

    @Test func replayToolsReadAWholeFolder() throws {
        let (dir, url, original) = try makeFile()
        defer { try? FileManager.default.removeItem(at: dir) }
        try HistoryFiles.compress(url, blockBytes: 16_384)
        var lines = 0
        HistoryFiles.forEachLine(path: dir.path) { _ in lines += 1 }
        #expect(lines == original.split(separator: 0x0A).count)
        var gzLines = 0
        HistoryFiles.forEachLine(path: HistoryFiles.gzURL(url).path) { _ in gzLines += 1 }
        #expect(gzLines == lines)
    }
}
