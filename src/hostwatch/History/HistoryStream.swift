import Foundation
import zlib

// MARK: - Writing history compressed, as it arrives

/// The history file being written, compressed as events arrive: `activity-<start>.jsonl.gz` grows by gzip members
/// ("blocks") of up to 30 s or 4 MB of events, and `activity-<start>.jsonl.blocks` gets a line per finished block
/// (where it is, which time it covers). Nothing is rewritten or written twice: ~1/22 of the raw bytes reach the disk.
/// When the file is full its `.idx` replaces the block list.
final class HistoryStream {
    // Crash safety without an extra copy: the open block is one compressed stream, flushed into the file every
    // second (zlib's sync flush keeps its dictionary, so it costs ~nothing in size). After an app crash those bytes
    // are in the file, so the next launch decompresses that unfinished tail up to the last whole event and writes it
    // as a finished block. An app crash loses at most the last second; a panic or power loss the last few seconds.
    static let blockInterval: TimeInterval = 30
    static let syncInterval: TimeInterval = 1

    let stem: URL
    /// Uncompressed bytes in the file (finished blocks and the open one): when it's full.
    private(set) var rawBytes: Int64 = 0
    /// Bytes on disk (the .gz and the block list).
    private(set) var diskBytes: Int64 = 0

    private var gz: FileHandle
    private var blockList: FileHandle
    private var blocks: [HistoryFiles.Block] = []
    private var minutes: [Int64: Int64] = [:]
    private var gzLength: Int64 = 0              // where the open block starts (the end of the finished ones)

    // The open block.
    private var stream = z_stream()
    private var streamOpen = false
    private var blockWritten: Int64 = 0          // compressed bytes of it in the file so far
    private var blockRaw: Int64 = 0
    private var blockFirst: Date?, blockLast: Date?
    private var blockMinutes: [Int64: Int64] = [:]
    private var blockStarted = Date()
    private var unsynced = false

    /// Opens `stem` for appending: creates it, or continues it, finishing what a crash left unfinished.
    init(stem: URL) throws {
        self.stem = stem
        let fm = FileManager.default
        for url in [HistoryFiles.gzURL(stem), HistoryFiles.blocksURL(stem)] where !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        gz = try FileHandle(forUpdating: HistoryFiles.gzURL(stem))
        blockList = try FileHandle(forUpdating: HistoryFiles.blocksURL(stem))
        try recover()
    }

    /// Without `close()` (a crash, or a test pretending to be one): the open block stays unfinished in the file.
    deinit {
        if streamOpen { deflateEnd(&stream) }
        try? gz.close()
        try? blockList.close()
    }

    // MARK: Writing

    /// Whole lines, as they arrive: compressed into the open block at once.
    func append(_ lines: Data) throws {
        guard !lines.isEmpty else { return }
        if !streamOpen { try openBlock() }
        var perMinute: [Int64: Int64] = [:]
        if let (first, last) = HistoryFiles.timeRange(lines, perMinute: &perMinute) {
            blockFirst = min(blockFirst ?? first, first)
            blockLast = max(blockLast ?? last, last)
            for (m, b) in perMinute { blockMinutes[m, default: 0] += b }
        }
        try deflateWrite(lines, flush: Z_NO_FLUSH)
        blockRaw += Int64(lines.count)
        rawBytes += Int64(lines.count)
        unsynced = true
        if blockRaw >= Int64(HistoryFiles.blockBytes) { try seal() }
    }

    /// Every second (the recorder's timer): what arrived goes into the file; a block 30 s old is finished.
    func tick(now: Date = Date()) throws {
        guard streamOpen else { return }
        if now.timeIntervalSince(blockStarted) >= Self.blockInterval { try seal() } else { try sync() }
    }

    /// Pushes everything compressed so far into the file (the open block stays open).
    func sync() throws {
        guard streamOpen, unsynced else { return }
        try deflateWrite(Data(), flush: Z_SYNC_FLUSH)
        unsynced = false
    }

    /// Finishes the open block: its gzip trailer, then its line in the block list (in that order: a crash between
    /// the two leaves a whole member that recovery reads back, once).
    func seal() throws {
        guard streamOpen else { return }
        try deflateWrite(Data(), flush: Z_FINISH)
        deflateEnd(&stream)
        streamOpen = false
        unsynced = false
        guard blockRaw > 0, let first = blockFirst, let last = blockLast else {
            // Nothing with a timestamp: drop the empty member.
            try gz.truncate(atOffset: UInt64(gzLength))
            try gz.seekToEnd()
            diskBytes -= blockWritten
            return
        }
        let block = HistoryFiles.Block(start: first, end: last, offset: gzLength, length: blockWritten, size: blockRaw)
        try addToList(block, minutes: blockMinutes)
        gzLength += blockWritten
    }

    /// The file is full: everything written, the final index in place of the block list.
    @discardableResult
    func finish() throws -> HistoryFiles.Index {
        try seal()
        try gz.synchronize()
        let index = HistoryFiles.Index(blocks: blocks, minutes: minutes.keys.sorted().map { [$0, minutes[$0]!] })
        try HistoryFiles.writeIndex(index, for: stem)
        try? FileManager.default.removeItem(at: HistoryFiles.blocksURL(stem))
        return index
    }

    /// Stops writing (quit): the open block is finished; the file stays open-ended and continues next launch.
    func close() throws { try seal() }

    // MARK: Blocks

    private func openBlock() throws {
        stream = z_stream()
        guard deflateInit2_(&stream, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else { throw HistoryFiles.ZError.failed(-1) }
        streamOpen = true
        blockWritten = 0
        blockRaw = 0
        blockFirst = nil
        blockLast = nil
        blockMinutes = [:]
        blockStarted = Date()
    }

    private func deflateWrite(_ input: Data, flush: Int32) throws {
        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 65_536)
        var status: Int32 = Z_OK
        input.withUnsafeBytes { src in
            stream.next_in = UnsafeMutablePointer(mutating: src.bindMemory(to: Bytef.self).baseAddress)
            stream.avail_in = uInt(src.count)
            repeat {
                chunk.withUnsafeMutableBytes { dst in
                    stream.next_out = dst.bindMemory(to: Bytef.self).baseAddress
                    stream.avail_out = uInt(dst.count)
                    status = deflate(&stream, flush)
                    out.append(dst.bindMemory(to: UInt8.self).baseAddress!, count: dst.count - Int(stream.avail_out))
                }
            } while stream.avail_out == 0 || (flush == Z_FINISH && status == Z_OK)
        }
        stream.next_in = nil
        guard status >= 0 || status == Z_BUF_ERROR else { throw HistoryFiles.ZError.failed(status) }
        guard !out.isEmpty else { return }
        try gz.write(contentsOf: out)
        blockWritten += Int64(out.count)
        diskBytes += Int64(out.count)
    }

    private func addToList(_ block: HistoryFiles.Block, minutes perMinute: [Int64: Int64]) throws {
        var line = HistoryFiles.blockLine(block, minutes: perMinute)
        line.append(0x0A)
        try blockList.write(contentsOf: line)
        diskBytes += Int64(line.count)
        blocks.append(block)
        for (m, b) in perMinute { minutes[m, default: 0] += b }
    }

    // MARK: After a crash

    /// The block list may end in a half-written line (cut), and the .gz in an unfinished block: everything in it up to
    /// the last whole event is written again as one finished block (and nothing after it, so nothing twice).
    private func recover() throws {
        let listData = try blockList.readToEnd() ?? Data()
        let (parsed, validBytes) = HistoryFiles.parseBlockList(listData)
        if validBytes < listData.count { try blockList.truncate(atOffset: UInt64(validBytes)) }
        try blockList.seekToEnd()
        blocks = parsed.blocks
        for pair in parsed.minutes ?? [] where pair.count == 2 { minutes[pair[0], default: 0] += pair[1] }
        gzLength = blocks.last.map { $0.offset + $0.length } ?? 0
        rawBytes = blocks.reduce(0) { $0 + $1.size }
        diskBytes = gzLength + Int64(validBytes)
        try gz.seek(toOffset: UInt64(gzLength))
        let tail = try gz.readToEnd() ?? Data()
        try gz.truncate(atOffset: UInt64(gzLength))
        try gz.seekToEnd()
        let rescued = Self.wholeLines(Self.inflatePartial(tail))
        if !rescued.isEmpty {
            try append(rescued)
            try seal()
        }
    }

    /// As much of a (possibly unfinished, possibly torn) gzip stream as decompresses.
    static func inflatePartial(_ data: Data) -> Data {
        guard !data.isEmpty else { return Data() }
        var out = Data()
        HistoryFiles.gunzipMembers(data, partial: true) { out.append($0) }
        return out
    }

    /// Up to and including the last line break (a torn last event is dropped).
    static func wholeLines(_ data: Data) -> Data {
        guard let nl = data.lastIndex(of: 0x0A) else { return Data() }
        return Data(data[data.startIndex...nl])
    }

    /// A file an earlier run left open-ended that isn't continued: its unfinished tail recovered, its final index.
    static func finishOrphan(_ stem: URL) {
        guard let s = try? HistoryStream(stem: stem) else { return }
        if s.blocks.isEmpty { HistoryFiles.remove(stem); return }
        _ = try? s.finish()
    }
}
