import Darwin
import Foundation
import HostwatchShim

// MARK: - Writing history compressed, as it arrives

/// Events wait in a `PendingBuffer` and go to disk as one gzip member every 30 s (or 4 MB), appended to
/// `activity-<start>.jsonl.gz`; a line per member goes to `activity-<start>.jsonl.blocks` (where it is and which
/// time it covers). Nothing is rewritten, and nothing is written twice (it used to be written plain, then again
/// compressed): about an eighth of the bytes reach the disk. A finished file gets its `.idx` and loses `.blocks`.
final class HistoryStream {
    static let flushInterval: TimeInterval = 30

    let stem: URL
    /// Uncompressed bytes in the file, flushed or waiting: when it's full.
    private(set) var rawBytes: Int64 = 0
    /// Bytes on disk (compressed members and the block list).
    private(set) var diskBytes: Int64 = 0
    private let buffer: PendingBuffer
    private var gz: FileHandle
    private var blockList: FileHandle
    private var gzLength: Int64 = 0
    private var blocks: [HistoryFiles.Block] = []
    private var minutes: [Int64: Int64] = [:]
    private var lastFlush = Date()

    /// Opens `stem` for appending (creating it, or recovering it after a crash: see `recover`).
    init(stem: URL, buffer: PendingBuffer) throws {
        self.stem = stem
        self.buffer = buffer
        let fm = FileManager.default
        let gzURL = HistoryFiles.gzURL(stem), listURL = HistoryFiles.blocksURL(stem)
        for url in [gzURL, listURL] where !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        gz = try FileHandle(forUpdating: gzURL)
        blockList = try FileHandle(forUpdating: listURL)
        try recover()
    }

    deinit { try? gz.close(); try? blockList.close() }

    /// After a crash: the block list may end in a half-written line and the .gz in a half-written member (both
    /// cut back to the last complete block), and the buffer may hold events that never reached the file.
    private func recover() throws {
        let listData = try blockList.readToEnd() ?? Data()
        let (parsed, validBytes) = HistoryFiles.parseBlockList(listData)
        if validBytes < listData.count { try blockList.truncate(atOffset: UInt64(validBytes)) }
        try blockList.seekToEnd()
        blocks = parsed.blocks
        for pair in parsed.minutes ?? [] where pair.count == 2 { minutes[pair[0], default: 0] += pair[1] }
        gzLength = blocks.last.map { $0.offset + $0.length } ?? 0
        let onDisk = Int64(try gz.seekToEnd())
        if onDisk > gzLength { try gz.truncate(atOffset: UInt64(gzLength)) }
        try gz.seekToEnd()
        rawBytes = blocks.reduce(0) { $0 + $1.size }
        diskBytes = gzLength + Int64(validBytes)
        // Waiting events for this file, never written: the .gz is still as long as when they started waiting.
        // Longer means they were written just before the crash (only the buffer reset was lost): drop them.
        if buffer.segment == Self.id(stem), buffer.used > 0 {
            if buffer.base == gzLength { try flush() } else { buffer.reset(segment: Self.id(stem), base: gzLength) }
        } else {
            buffer.reset(segment: Self.id(stem), base: gzLength)
        }
    }

    /// Whole lines, as they arrive.
    func append(_ lines: Data) throws {
        guard !lines.isEmpty else { return }
        if buffer.used + lines.count > HistoryFiles.blockBytes { try flush() }
        if !buffer.append(lines) {                      // larger than the whole buffer: straight to disk
            try writeMember(lines)
        }
        rawBytes += Int64(lines.count)
        if Date().timeIntervalSince(lastFlush) >= Self.flushInterval { try flush() }
    }

    /// Writes what's waiting when it has waited long enough (called every few seconds, also when it's quiet).
    func flushIfDue(now: Date = Date()) throws {
        if buffer.used > 0, now.timeIntervalSince(lastFlush) >= Self.flushInterval { try flush() }
    }

    /// Writes what's waiting as one member. Order matters for crash safety: the member, then its line in the block
    /// list, then the buffer is emptied (`used` first, then the new base).
    func flush() throws {
        lastFlush = Date()
        guard buffer.used > 0 else { return }
        try writeMember(buffer.contents())
        buffer.markWritten(newBase: gzLength)
    }

    private func writeMember(_ data: Data) throws {
        var perMinute: [Int64: Int64] = [:]
        guard let (first, last) = HistoryFiles.timeRange(data, perMinute: &perMinute) else { return }
        let member = try HistoryFiles.gzip(data)
        try gz.write(contentsOf: member)
        let block = HistoryFiles.Block(start: first, end: last, offset: gzLength, length: Int64(member.count),
                                       size: Int64(data.count))
        var line = HistoryFiles.blockLine(block, minutes: perMinute)
        line.append(0x0A)
        try blockList.write(contentsOf: line)
        gzLength += Int64(member.count)
        diskBytes += Int64(member.count + line.count)
        blocks.append(block)
        for (m, b) in perMinute { minutes[m, default: 0] += b }
    }

    /// The file is full or recording stops for good: everything written, the final index in place of the list.
    @discardableResult
    func finish() throws -> HistoryFiles.Index {
        try flush()
        try gz.synchronize()
        let index = HistoryFiles.Index(blocks: blocks, minutes: minutes.keys.sorted().map { [$0, minutes[$0]!] })
        try HistoryFiles.writeIndex(index, for: stem)
        try? FileManager.default.removeItem(at: HistoryFiles.blocksURL(stem))
        buffer.reset(segment: 0, base: 0)
        return index
    }

    /// Stops writing without finishing (quit): the file stays open-ended (.blocks), continued next launch.
    func close() throws {
        try flush()
    }

    /// A file left open-ended by an earlier run that isn't continued (it's full, or another one is newer): its final
    /// index from the block list, without touching the waiting events (they belong to the file being written).
    static func finishOrphan(_ stem: URL) {
        guard let list = try? Data(contentsOf: HistoryFiles.blocksURL(stem)) else { return }
        let index = HistoryFiles.parseBlockList(list).index
        if let last = index.blocks.last, let gz = try? FileHandle(forUpdating: HistoryFiles.gzURL(stem)) {
            try? gz.truncate(atOffset: UInt64(last.offset + last.length))      // a half-written last member
            try? gz.close()
        }
        guard !index.blocks.isEmpty else { HistoryFiles.remove(stem); return }
        guard (try? HistoryFiles.writeIndex(index, for: stem)) != nil else { return }
        try? FileManager.default.removeItem(at: HistoryFiles.blocksURL(stem))
    }

    /// A short, stable number for a file: which file the waiting events belong to.
    static func id(_ stem: URL) -> UInt64 { HashedSet.hash(stem.lastPathComponent) | 1 }
}

// MARK: - The waiting events, in memory that outlives a crash

/// POSIX shared memory: like the app's own memory it never touches the disk, but it stays after the app crashes
/// (until it's removed, or the Mac restarts), so the next launch writes what was waiting. A kernel panic or power
/// loss loses it, as it loses any write the system hadn't flushed yet.
final class PendingBuffer {
    static let capacity = 8 << 20
    private struct Header {
        var magic: UInt64
        var segment: UInt64          // which file these events are for (HistoryStream.id)
        var base: Int64              // that file's .gz length when they started waiting
        var used: Int64              // bytes waiting
    }
    private static let magic: UInt64 = 0x4857_4842_5546_0001      // "HWBUF", v1
    private static let headerSize = 64

    let name: String
    private let memory: UnsafeMutableRawPointer
    private let size: Int

    /// One per history folder (a demo or test folder gets its own). Names are short: macOS allows 31 characters.
    static func name(for directory: URL) -> String {
        String(format: "/hw.%u.%016llx", getuid(), HashedSet.hash(directory.standardizedFileURL.path))
    }

    /// Ordinary memory, when shared memory can't be had: works the same, but a crash loses what was waiting.
    init(localCapacity: Int = PendingBuffer.capacity) {
        name = ""
        size = Self.headerSize + localCapacity
        memory = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 16)
        isLocal = true
        header = Header(magic: Self.magic, segment: 0, base: 0, used: 0)
    }
    private var isLocal = false

    init?(name: String) {
        self.name = name
        let fd = hw_shm_open(name, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { return nil }
        if st.st_size == 0, ftruncate(fd, off_t(Self.headerSize + Self.capacity)) != 0 { return nil }
        guard fstat(fd, &st) == 0, Int(st.st_size) >= Self.headerSize + 4096 else { return nil }
        size = Int(st.st_size)
        let p = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
        guard let p, p != MAP_FAILED else { return nil }
        memory = p
        if header.magic != Self.magic { header = Header(magic: Self.magic, segment: 0, base: 0, used: 0) }
    }

    deinit { if isLocal { memory.deallocate() } else { munmap(memory, size) } }

    private var header: Header {
        get { memory.load(as: Header.self) }
        set { memory.storeBytes(of: newValue, as: Header.self) }
    }

    var segment: UInt64 { header.segment }
    var base: Int64 { header.base }
    var used: Int { Int(header.used) }
    private var room: Int { size - Self.headerSize }

    /// Adds bytes after the waiting ones; false if they don't fit. The count is updated after the copy, so a crash
    /// in between loses only these bytes, never corrupts what was waiting.
    func append(_ data: Data) -> Bool {
        let at = used
        guard at + data.count <= room else { return false }
        data.withUnsafeBytes { memory.advanced(by: Self.headerSize + at).copyMemory(from: $0.baseAddress!, byteCount: data.count) }
        memory.storeBytes(of: Int64(at + data.count), toByteOffset: MemoryLayout<UInt64>.size * 3, as: Int64.self)
        return true
    }

    func contents() -> Data { Data(bytes: memory.advanced(by: Self.headerSize), count: min(used, room)) }

    /// After a flush: empty first (so a crash here can't write them twice), then the file's new length.
    func markWritten(newBase: Int64) {
        memory.storeBytes(of: Int64(0), toByteOffset: MemoryLayout<UInt64>.size * 3, as: Int64.self)
        memory.storeBytes(of: newBase, toByteOffset: MemoryLayout<UInt64>.size * 2, as: Int64.self)
    }

    func reset(segment: UInt64, base: Int64) {
        header = Header(magic: Self.magic, segment: segment, base: base, used: 0)
    }

    /// Removes the shared memory (tests; history cleared).
    static func remove(name: String) { _ = hw_shm_unlink(name) }
}
