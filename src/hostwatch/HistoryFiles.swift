import Foundation
import zlib

/// Activity history on disk. The file being written is plain JSONL (`activity-<start>.jsonl`), so
/// appends are cheap and a crash loses nothing. A finished file is compressed into
/// `activity-<start>.jsonl.gz`: independent gzip members of ~4 MB of whole lines (a normal .gz:
/// zcat/zgrep read it), plus `activity-<start>.jsonl.idx`, the time range and position of each
/// block. Readers decompress only the blocks a time range needs.
enum HistoryFiles {
    static let blockBytes = 4 << 20

    struct Block: Codable, Equatable, Sendable {
        var start: Date          // first line's timestamp
        var end: Date            // last line's timestamp
        var offset: Int64        // position of the gzip member in the .gz file
        var length: Int64        // compressed length
        var size: Int64          // uncompressed length
    }

    struct Index: Codable, Equatable, Sendable {
        var version = 1
        var blocks: [Block]
        /// Uncompressed bytes per minute: [minute since 1970, bytes], minutes with activity only.
        /// Gives the timeline exact bars (and real gaps) without decompressing anything.
        var minutes: [[Int64]]? = nil
        var start: Date? { blocks.first?.start }
        var end: Date? { blocks.map(\.end).max() }
        var size: Int64 { blocks.reduce(0) { $0 + $1.size } }
    }

    /// One history file, either form.
    enum File: Sendable {
        case plain(URL)
        case compressed(URL, Index)

        var name: String {
            switch self {
            case .plain(let url): return url.lastPathComponent
            case .compressed(let url, _): return url.deletingPathExtension().lastPathComponent
            }
        }
    }

    // MARK: Names

    static func isHistoryName(_ name: String) -> Bool {
        name.hasPrefix("activity-") && (name.hasSuffix(".jsonl") || name.hasSuffix(".jsonl.gz") || name.hasSuffix(".jsonl.idx"))
    }

    /// `activity-x.jsonl` for any of its forms.
    static func stem(_ url: URL) -> URL {
        let name = url.lastPathComponent
        for suffix in [".gz", ".idx", ".tmp"] where name.hasSuffix(suffix) {
            return stem(url.deletingLastPathComponent().appendingPathComponent(String(name.dropLast(suffix.count))))
        }
        return url
    }

    static func gzURL(_ stem: URL) -> URL { stem.appendingPathExtension("gz") }
    static func indexURL(_ stem: URL) -> URL { stem.appendingPathExtension("idx") }

    /// History files in `directory`, oldest first. A compressed file counts only with a readable index;
    /// when both forms exist (compression interrupted), the plain one is authoritative.
    static func list(in directory: URL) -> [File] {
        let names = Set((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
        let plain = names.filter { $0.hasPrefix("activity-") && $0.hasSuffix(".jsonl") }
        let compressed = names.filter { $0.hasPrefix("activity-") && $0.hasSuffix(".jsonl.gz") }.map { String($0.dropLast(3)) }
        var out: [File] = []
        for name in plain.union(compressed).sorted() {
            let stem = directory.appendingPathComponent(name)
            if names.contains(name) {
                out.append(.plain(stem))
            } else if let index = readIndex(stem) {
                out.append(.compressed(gzURL(stem), index))
            }
        }
        return out
    }

    /// Bytes on disk for a stem (all of its forms).
    static func diskSize(_ stem: URL) -> Int64 {
        [stem, gzURL(stem), indexURL(stem)].reduce(0) { total, url in
            total + (((try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.int64Value ?? 0)
        }
    }

    static func remove(_ stem: URL) {
        for url in [stem, gzURL(stem), indexURL(stem), gzURL(stem).appendingPathExtension("tmp"),
                    indexURL(stem).appendingPathExtension("tmp")] {
            try? FileManager.default.removeItem(at: url)
        }
    }

    static func readIndex(_ stem: URL) -> Index? {
        guard let data = try? Data(contentsOf: indexURL(stem)) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(Index.self, from: data)
    }

    // MARK: Compressing a finished file

    /// Compresses a finished plain file into blocks + index, then removes the plain file.
    /// Safe to interrupt: the plain file is removed only after both new files are in place.
    @discardableResult
    static func compress(_ plain: URL, blockBytes: Int = HistoryFiles.blockBytes) throws -> Index {
        let stem = stem(plain)
        let gzTmp = gzURL(stem).appendingPathExtension("tmp")
        let idxTmp = indexURL(stem).appendingPathExtension("tmp")
        try? FileManager.default.removeItem(at: gzTmp)
        FileManager.default.createFile(atPath: gzTmp.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let input = try FileHandle(forReadingFrom: plain)
        let output = try FileHandle(forWritingTo: gzTmp)
        defer { try? input.close(); try? output.close() }

        var blocks: [Block] = []
        var offset: Int64 = 0
        var carry = Data()
        var perMinute: [Int64: Int64] = [:]
        func emit(_ block: Data) throws {
            guard !block.isEmpty, let (first, last) = timeRange(block, perMinute: &perMinute) else { return }
            let member = try gzip(block)
            try output.write(contentsOf: member)
            blocks.append(Block(start: first, end: last, offset: offset, length: Int64(member.count), size: Int64(block.count)))
            offset += Int64(member.count)
        }
        while let chunk = try input.read(upToCount: blockBytes), !chunk.isEmpty {
            carry.append(chunk)
            // Blocks hold whole lines only.
            guard let lastNewline = carry.lastIndex(of: 0x0A) else { continue }
            try emit(carry[carry.startIndex...lastNewline])
            carry = Data(carry[(lastNewline + 1)...])
        }
        if !carry.isEmpty { try emit(carry + Data([0x0A])) }   // a final line without a line break
        try output.synchronize()

        let index = Index(blocks: blocks, minutes: perMinute.keys.sorted().map { [$0, perMinute[$0]!] })
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        try encoder.encode(index).write(to: idxTmp, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: idxTmp.path)
        // Index first: a .gz without an index is ignored, a .gz with one is complete.
        try? FileManager.default.removeItem(at: indexURL(stem))
        try FileManager.default.moveItem(at: idxTmp, to: indexURL(stem))
        try? FileManager.default.removeItem(at: gzURL(stem))
        try FileManager.default.moveItem(at: gzTmp, to: gzURL(stem))
        try FileManager.default.removeItem(at: plain)
        return index
    }

    // MARK: Masking secrets in finished files

    /// Masks passwords and tokens in launch events' command lines (`Secrets`) in a finished file: a compressed
    /// one is rewritten (blocks and index), a plain one replaced. Returns how many lines changed (0: untouched).
    @discardableResult
    static func scrubSecrets(_ file: File) throws -> Int {
        let stem: URL
        switch file {
        case .plain(let url): stem = url
        case .compressed(let gz, _): stem = Self.stem(gz)
        }
        let tmp = stem.deletingLastPathComponent().appendingPathComponent(".scrub-" + stem.lastPathComponent)
        try? FileManager.default.removeItem(at: tmp)
        FileManager.default.createFile(atPath: tmp.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let out = try FileHandle(forWritingTo: tmp)
        var changed = 0
        var failure: Error?
        forEachChunk(file) { chunk in
            var buffer = Data(capacity: chunk.count)
            for line in chunk.split(separator: 0x0A, omittingEmptySubsequences: false) where !line.isEmpty {
                var bytes = Data(line)
                // Only launches carry a command line ("args"); everything else is copied as is.
                if bytes.range(of: Data(#""kind":"exec""#.utf8)) != nil, let text = String(data: bytes, encoding: .utf8) {
                    let masked = Secrets.mask(text, marker: Secrets.historyMarker)
                    if masked != text { bytes = Data(masked.utf8); changed += 1 }
                }
                buffer.append(bytes)
                buffer.append(0x0A)
            }
            do { try out.write(contentsOf: buffer) } catch { failure = error; return false }
            return true
        }
        try out.close()
        if let failure { try? FileManager.default.removeItem(at: tmp); throw failure }
        guard changed > 0 else { try? FileManager.default.removeItem(at: tmp); return 0 }
        switch file {
        case .plain(let url):
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
        case .compressed:
            // compress() writes the new .gz and index, then removes the plain input.
            let plain = stem
            try FileManager.default.moveItem(at: tmp, to: plain)
            try compress(plain)
        }
        return changed
    }

    // MARK: Reading

    /// Decompresses one block.
    static func read(_ block: Block, from gz: URL) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: gz) else { return nil }
        defer { try? handle.close() }
        try? handle.seek(toOffset: UInt64(block.offset))
        guard let member = try? handle.read(upToCount: Int(block.length)) else { return nil }
        return gunzip(member, expected: Int(block.size))
    }

    /// Every line of a file, in order, as whole-line chunks (plain: 8 MB reads; compressed: blocks
    /// overlapping `range`, or all). `body` returns false to stop.
    static func forEachChunk(_ file: File, in range: ClosedRange<Date>? = nil, _ body: (Data) -> Bool) {
        switch file {
        case .plain(let url):
            guard let handle = try? FileHandle(forReadingFrom: url) else { return }
            defer { try? handle.close() }
            var carry = Data()
            while let chunk = try? handle.read(upToCount: 8 << 20), !chunk.isEmpty {
                carry.append(chunk)
                guard let nl = carry.lastIndex(of: 0x0A) else { continue }
                guard body(Data(carry[carry.startIndex...nl])) else { return }
                carry = Data(carry[(nl + 1)...])
            }
            if !carry.isEmpty { _ = body(carry) }
        case .compressed(let gz, let index):
            for block in index.blocks where range.map({ block.end >= $0.lowerBound && block.start <= $0.upperBound }) ?? true {
                guard let data = read(block, from: gz) else { continue }
                guard body(data) else { return }
            }
        }
    }

    /// Lines of a plain or gzip file at `path`, or of a whole history folder in time order (for the
    /// replay and report tools; any .gz works).
    static func forEachLine(path: String, _ body: (Data) -> Void) {
        let url = URL(fileURLWithPath: path)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue {
            for file in list(in: url) {
                switch file {
                case .plain(let plain): forEachLine(path: plain.path, body)
                case .compressed:
                    forEachChunk(file) { chunk in
                        var start = chunk.startIndex
                        while let nl = chunk[start...].firstIndex(of: 0x0A) {
                            if nl > start { body(chunk[start..<nl]) }
                            start = nl + 1
                        }
                        return true
                    }
                }
            }
            return
        }
        func emit(_ chunk: Data) {
            var start = chunk.startIndex
            while let nl = chunk[start...].firstIndex(of: 0x0A) {
                if nl > start { body(chunk[start..<nl]) }
                start = nl + 1
            }
            if start < chunk.endIndex { body(chunk[start...]) }
        }
        if path.hasSuffix(".gz") {
            guard let data = try? Data(contentsOf: url, options: .alwaysMapped) else { return }
            gunzipMembers(data) { emit($0) }
        } else {
            forEachChunk(.plain(url)) { emit($0); return true }
        }
    }

    // MARK: Timestamps of a block

    /// Earliest and latest timestamp in a block (lines are nearly, not strictly, in time order).
    static func timeRange(_ block: Data, perMinute: inout [Int64: Int64]) -> (Date, Date)? {
        var low: Date?, high: Date?
        var start = block.startIndex
        while start < block.endIndex {
            let end = block[start...].firstIndex(of: 0x0A) ?? block.endIndex
            if let ts = HistoryArchive.timestamp(block[start..<end]) {
                if low.map({ ts < $0 }) ?? true { low = ts }
                if high.map({ ts > $0 }) ?? true { high = ts }
                perMinute[Int64((ts.timeIntervalSince1970 / 60).rounded(.down)), default: 0] += Int64(end - start + 1)
            }
            start = end + 1
        }
        guard let low, let high else { return nil }
        return (low, high)
    }

    static func firstTimestamp(_ block: Data) -> Date? {
        var start = block.startIndex
        while start < block.endIndex {
            let end = block[start...].firstIndex(of: 0x0A) ?? block.endIndex
            if let ts = HistoryArchive.timestamp(block[start..<end]) { return ts }
            start = end + 1
        }
        return nil
    }

    static func lastTimestamp(_ block: Data) -> Date? {
        var end = block.endIndex
        while end > block.startIndex {
            var lineEnd = end
            if block[lineEnd - 1] == 0x0A { lineEnd -= 1 }
            let start = block[block.startIndex..<lineEnd].lastIndex(of: 0x0A).map { $0 + 1 } ?? block.startIndex
            if let ts = HistoryArchive.timestamp(block[start..<lineEnd]) { return ts }
            end = start
        }
        return nil
    }

    // MARK: zlib

    enum ZError: Error { case failed(Int32) }

    /// One gzip member.
    static func gzip(_ input: Data, level: Int32 = 6) throws -> Data {
        var stream = z_stream()
        guard deflateInit2_(&stream, level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION,
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else { throw ZError.failed(-1) }
        defer { deflateEnd(&stream) }
        var output = Data(count: Int(deflateBound(&stream, uLong(input.count))) + 32)
        let status: Int32 = input.withUnsafeBytes { src in
            output.withUnsafeMutableBytes { dst in
                stream.next_in = UnsafeMutablePointer(mutating: src.bindMemory(to: Bytef.self).baseAddress)
                stream.avail_in = uInt(src.count)
                stream.next_out = dst.bindMemory(to: Bytef.self).baseAddress
                stream.avail_out = uInt(dst.count)
                return deflate(&stream, Z_FINISH)
            }
        }
        guard status == Z_STREAM_END else { throw ZError.failed(status) }
        output.count = Int(stream.total_out)
        return output
    }

    /// One gzip member (its uncompressed size is known from the index).
    static func gunzip(_ member: Data, expected: Int) -> Data? {
        var result: Data?
        gunzipMembers(member, sizeHint: expected) { result = $0; }
        return result
    }

    /// Every member of a (multi-member) gzip stream, in order.
    static func gunzipMembers(_ data: Data, sizeHint: Int = blockBytes, _ body: (Data) -> Void) {
        var stream = z_stream()
        guard inflateInit2_(&stream, 31, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return }
        defer { inflateEnd(&stream) }
        data.withUnsafeBytes { src in
            guard let base = src.bindMemory(to: Bytef.self).baseAddress else { return }
            stream.next_in = UnsafeMutablePointer(mutating: base)
            stream.avail_in = uInt(src.count)
            var buffer = [UInt8](repeating: 0, count: 1 << 20)
            var member = Data()
            member.reserveCapacity(sizeHint)
            while true {
                let status: Int32 = buffer.withUnsafeMutableBytes { out in
                    stream.next_out = out.bindMemory(to: Bytef.self).baseAddress
                    stream.avail_out = uInt(out.count)
                    return inflate(&stream, Z_NO_FLUSH)
                }
                member.append(buffer, count: buffer.count - Int(stream.avail_out))
                if status == Z_STREAM_END {
                    body(member)
                    member = Data()
                    if stream.avail_in == 0 { return }
                    inflateReset(&stream)
                } else if status != Z_OK || (stream.avail_in == 0 && stream.avail_out > 0) {
                    return                               // damaged or truncated
                }
            }
        }
    }
}

/// `Hostwatch --compress-history <dir>`: compresses every plain history file in a folder (testing,
/// or by hand; the app compresses finished files by itself). Prints sizes and timings.
func runCompressHistory(_ path: String) -> Never {
    let dir = URL(fileURLWithPath: path)
    let clock = ContinuousClock()
    for case .plain(let url) in HistoryFiles.list(in: dir) {
        let before = HistoryFiles.diskSize(url)
        var index: HistoryFiles.Index?
        let t = clock.measure { index = try? HistoryFiles.compress(url) }
        let after = HistoryFiles.diskSize(url)
        print("\(url.lastPathComponent): \(before / 1_000_000) MB -> \(after / 1_000_000) MB "
              + "(\(index?.blocks.count ?? 0) blocks) in \(t)")
    }
    exit(0)
}
