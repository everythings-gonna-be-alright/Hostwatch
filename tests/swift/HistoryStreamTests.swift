import Foundation
import Testing
@testable import Hostwatch

/// History written compressed as it arrives: readable while written, and an app crash loses at most the last second
/// (what wasn't flushed into the file), never doubles anything.
@Suite(.serialized) struct HistoryStreaming {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func lines(_ range: Range<Int>) -> Data {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return Data(range.map {
            #"{"kind":"exec","time":"12:00:00","pid":\#($0),"ppid":1,"name":"t","proc":"/usr/bin/t","target":"/usr/bin/t","ts":"\#(f.string(from: t0.addingTimeInterval(Double($0))))"}"#
                + "\n"
        }.joined().utf8)
    }

    func setup() throws -> (dir: URL, stem: URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-stream-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (dir, dir.appendingPathComponent("activity-20270115-080000-000.jsonl"))
    }

    /// Every pid recorded in the folder, in order (what Time Travel and search read: finished blocks).
    func recorded(_ dir: URL) -> [Int] {
        var pids: [Int] = []
        for file in HistoryFiles.list(in: dir) {
            HistoryFiles.forEachChunk(file) { chunk in
                for line in chunk.split(separator: 0x0A) { if let e = ActivityEvent.parse(Data(line)) { pids.append(e.pid) } }
                return true
            }
        }
        return pids
    }

    @Test func writtenCompressedReadableAndFinished() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        let stream = try HistoryStream(stem: s.stem)
        try stream.append(lines(0..<300))
        try stream.seal()
        try stream.append(lines(300..<600))
        try stream.sync()
        #expect(recorded(s.dir) == Array(0..<300))                      // the open block isn't listed yet
        try stream.seal()
        #expect(recorded(s.dir) == Array(0..<600))
        #expect(!FileManager.default.fileExists(atPath: s.stem.path))   // never a plain copy
        #expect(stream.diskBytes < Int64(lines(0..<600).count) / 4)
        try stream.finish()
        #expect(FileManager.default.fileExists(atPath: HistoryFiles.indexURL(s.stem).path))
        #expect(!FileManager.default.fileExists(atPath: HistoryFiles.blocksURL(s.stem).path))
        #expect(recorded(s.dir) == Array(0..<600))
    }

    /// The app crashes with a block open: what was flushed is recovered next launch; only the unflushed part is lost.
    @Test func flushedEventsSurviveACrash() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        do {
            let stream = try HistoryStream(stem: s.stem)
            try stream.append(lines(0..<100))
            try stream.seal()
            try stream.append(lines(100..<150))
            try stream.sync()                                           // flushed into the file
            try stream.append(lines(150..<155))                         // not flushed yet: then the "crash"
        }
        let stream = try HistoryStream(stem: s.stem)                    // the next launch
        #expect(recorded(s.dir) == Array(0..<150))
        try stream.append(lines(160..<170))
        try stream.seal()
        #expect(recorded(s.dir) == Array(0..<150) + Array(160..<170))
    }

    /// The crash comes after a block's trailer but before its line in the block list: read back once, not twice.
    @Test func aFinishedButUnlistedBlockIsNotWrittenTwice() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        do {
            let stream = try HistoryStream(stem: s.stem)
            try stream.append(lines(0..<50))
            try stream.seal()
            try stream.append(lines(50..<80))
            try stream.seal()
        }
        let list = try Data(contentsOf: HistoryFiles.blocksURL(s.stem))
        let firstLine = list[...list.firstIndex(of: 0x0A)!]
        try Data(firstLine).write(to: HistoryFiles.blocksURL(s.stem))    // the second block's line never got written
        _ = try HistoryStream(stem: s.stem)
        #expect(recorded(s.dir) == Array(0..<80))
    }

    /// A crash in the middle of a write: a torn tail and a half line in the block list are cut; the rest is kept.
    @Test func aTornTailIsCutBack() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        do {
            let stream = try HistoryStream(stem: s.stem)
            try stream.append(lines(0..<80))
            try stream.seal()
            try stream.append(lines(80..<120))
            try stream.sync()
        }
        let gz = try FileHandle(forUpdating: HistoryFiles.gzURL(s.stem))
        let size = try gz.seekToEnd()
        try gz.truncate(atOffset: size - 7)                              // the last flush only half written
        try gz.close()
        let list = try FileHandle(forWritingTo: HistoryFiles.blocksURL(s.stem))
        try list.seekToEnd(); try list.write(contentsOf: Data(#"{"s":1,"e":2,"o":99"#.utf8)); try list.close()
        let stream = try HistoryStream(stem: s.stem)
        let kept = recorded(s.dir)
        #expect(Array(kept.prefix(80)) == Array(0..<80))                 // finished blocks untouched
        #expect(kept == Array(0..<kept.count) && kept.count < 120)       // a clean prefix, nothing garbled
        try stream.append(lines(200..<210))
        try stream.seal()
        #expect(recorded(s.dir).suffix(10) == Array(200..<210))
    }

    /// Blocks are finished on time (30 s) or size, so readers see events soon; flushing is cheap.
    @Test func ticksSyncAndFinishBlocks() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        let stream = try HistoryStream(stem: s.stem)
        try stream.append(lines(0..<20))
        try stream.tick(now: Date())                                    // a second later: flushed, still open
        #expect(recorded(s.dir).isEmpty)
        try stream.tick(now: Date().addingTimeInterval(HistoryStream.blockInterval + 1))
        #expect(recorded(s.dir) == Array(0..<20))
    }

    /// A file an earlier run left open-ended and that isn't continued: its tail recovered, its final index.
    @Test func leftoverFilesAreFinished() throws {
        let s = try setup()
        defer { try? FileManager.default.removeItem(at: s.dir) }
        do {
            let stream = try HistoryStream(stem: s.stem)
            try stream.append(lines(0..<40))
            try stream.seal()
            try stream.append(lines(40..<60))
            try stream.sync()
        }
        HistoryStream.finishOrphan(s.stem)
        #expect(HistoryFiles.readIndex(s.stem)?.blocks.count == 2)
        #expect(!FileManager.default.fileExists(atPath: HistoryFiles.blocksURL(s.stem).path))
        #expect(recorded(s.dir) == Array(0..<60))
    }
}
