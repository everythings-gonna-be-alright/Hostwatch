import Foundation
import Testing
@testable import Hostwatch

/// History written compressed as it arrives: readable while written, and nothing lost or doubled by a crash.
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

    /// A temporary folder, its stem and a shared buffer of its own; all removed by `cleanup`.
    func setup() throws -> (dir: URL, stem: URL, name: String) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-stream-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (dir, dir.appendingPathComponent("activity-20270115-080000-000.jsonl"), PendingBuffer.name(for: dir))
    }

    func cleanup(_ s: (dir: URL, stem: URL, name: String)) {
        try? FileManager.default.removeItem(at: s.dir)
        PendingBuffer.remove(name: s.name)
    }

    /// Every pid recorded in the folder, in order (what Time Travel and search read).
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

    @Test func writtenCompressedReadableWhileOpenAndFinished() throws {
        let s = try setup()
        defer { cleanup(s) }
        let buffer = try #require(PendingBuffer(name: s.name))
        let stream = try HistoryStream(stem: s.stem, buffer: buffer)
        try stream.append(lines(0..<300))
        try stream.flush()
        try stream.append(lines(300..<600))
        try stream.flush()
        #expect(recorded(s.dir) == Array(0..<600))                      // read while still being written
        #expect(!FileManager.default.fileExists(atPath: s.stem.path))   // never a plain copy
        let raw = lines(0..<600).count
        #expect(stream.diskBytes < Int64(raw) / 4)                       // compressed (with the block list)
        try stream.finish()
        #expect(FileManager.default.fileExists(atPath: HistoryFiles.indexURL(s.stem).path))
        #expect(!FileManager.default.fileExists(atPath: HistoryFiles.blocksURL(s.stem).path))
        #expect(recorded(s.dir) == Array(0..<600))
    }

    /// The app crashes with events still waiting: the next launch writes them.
    @Test func waitingEventsSurviveACrash() throws {
        let s = try setup()
        defer { cleanup(s) }
        do {
            let buffer = try #require(PendingBuffer(name: s.name))
            let stream = try HistoryStream(stem: s.stem, buffer: buffer)
            try stream.append(lines(0..<100))
            try stream.flush()
            try stream.append(lines(100..<150))                         // waiting, not flushed: then the "crash"
        }
        #expect(recorded(s.dir) == Array(0..<100))
        let buffer = try #require(PendingBuffer(name: s.name))           // the next launch, same shared memory
        let stream = try HistoryStream(stem: s.stem, buffer: buffer)
        #expect(recorded(s.dir) == Array(0..<150))
        #expect(buffer.used == 0)
        try stream.append(lines(150..<160))
        try stream.flush()
        #expect(recorded(s.dir) == Array(0..<160))
    }

    /// The crash comes after a member was written but before the buffer was emptied: not written twice.
    @Test func writtenEventsAreNotWrittenTwice() throws {
        let s = try setup()
        defer { cleanup(s) }
        let buffer = try #require(PendingBuffer(name: s.name))
        let stream = try HistoryStream(stem: s.stem, buffer: buffer)
        try stream.append(lines(0..<50))
        let waiting = buffer.contents(), base = buffer.base
        try stream.flush()
        buffer.reset(segment: HistoryStream.id(s.stem), base: base)        // undo the empty: as if it never happened
        #expect(buffer.append(waiting))
        _ = try HistoryStream(stem: s.stem, buffer: buffer)
        #expect(recorded(s.dir) == Array(0..<50))
    }

    /// A crash in the middle of writing a member and its line: cut back to the last whole one.
    @Test func aTornLastMemberIsCutBack() throws {
        let s = try setup()
        defer { cleanup(s) }
        do {
            let buffer = try #require(PendingBuffer(name: s.name))
            let stream = try HistoryStream(stem: s.stem, buffer: buffer)
            try stream.append(lines(0..<80))
            try stream.flush()
        }
        let gz = try FileHandle(forWritingTo: HistoryFiles.gzURL(s.stem))
        try gz.seekToEnd(); try gz.write(contentsOf: Data([0x1f, 0x8b, 8, 0, 1, 2])); try gz.close()
        let list = try FileHandle(forWritingTo: HistoryFiles.blocksURL(s.stem))
        try list.seekToEnd(); try list.write(contentsOf: Data(#"{"s":1,"e":2,"o":99"#.utf8)); try list.close()
        let buffer = try #require(PendingBuffer(name: s.name))
        let stream = try HistoryStream(stem: s.stem, buffer: buffer)
        try stream.append(lines(80..<90))
        try stream.flush()
        #expect(recorded(s.dir) == Array(0..<90))
    }

    /// The waiting events are as private as the history files and don't linger once written.
    @Test func theBufferIsOwnerOnlyAndWipedAfterWriting() throws {
        let s = try setup()
        defer { cleanup(s) }
        let buffer = try #require(PendingBuffer(name: s.name))
        #expect(PendingBuffer.mode(name: s.name) == 0o600)                 // other users can't open it
        let stream = try HistoryStream(stem: s.stem, buffer: buffer)
        try stream.append(lines(0..<200))
        #expect(buffer.residue() > 0)
        try stream.flush()
        #expect(buffer.residue() == 0)                                     // written: wiped from memory
        try stream.append(lines(200..<210))
        buffer.reset(segment: 0, base: 0)                                  // discarded (history cleared): wiped too
        #expect(buffer.residue() == 0)
        PendingBuffer.remove(name: s.name)
        #expect(PendingBuffer.mode(name: s.name) == nil)                   // removed: gone, not just empty
    }

    /// A file an earlier run left open-ended and that isn't continued gets its final index.
    @Test func leftoverFilesAreFinished() throws {
        let s = try setup()
        defer { cleanup(s) }
        do {
            let buffer = try #require(PendingBuffer(name: s.name))
            let stream = try HistoryStream(stem: s.stem, buffer: buffer)
            try stream.append(lines(0..<40))
            try stream.flush()
        }
        HistoryStream.finishOrphan(s.stem)
        #expect(HistoryFiles.readIndex(s.stem)?.blocks.count == 1)
        #expect(!FileManager.default.fileExists(atPath: HistoryFiles.blocksURL(s.stem).path))
        #expect(recorded(s.dir) == Array(0..<40))
    }
}
