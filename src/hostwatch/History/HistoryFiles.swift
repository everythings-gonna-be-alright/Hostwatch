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
        name.hasPrefix("activity-") && (name.hasSuffix(".jsonl") || name.hasSuffix(".jsonl.gz") || name.hasSuffix(".jsonl.idx")
                                        || name.hasSuffix(".jsonl.blocks"))
    }

    /// `activity-x.jsonl` for any of its forms.
    static func stem(_ url: URL) -> URL {
        let name = url.lastPathComponent
        for suffix in [".gz", ".idx", ".tmp", ".blocks"] where name.hasSuffix(suffix) {
            return stem(url.deletingLastPathComponent().appendingPathComponent(String(name.dropLast(suffix.count))))
        }
        return url
    }

    static func gzURL(_ stem: URL) -> URL { stem.appendingPathExtension("gz") }
    static func indexURL(_ stem: URL) -> URL { stem.appendingPathExtension("idx") }
    /// The block list of a file being written (one JSON line per member; replaced by the .idx when finished).
    static func blocksURL(_ stem: URL) -> URL { stem.appendingPathExtension("blocks") }

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
            } else if names.contains(name + ".blocks"),
                      let list = try? Data(contentsOf: blocksURL(stem)) {
                out.append(.compressed(gzURL(stem), parseBlockList(list).index))      // being written
            }
        }
        return out
    }

    /// Bytes on disk for a stem (all of its forms).
    static func diskSize(_ stem: URL) -> Int64 {
        [stem, gzURL(stem), indexURL(stem), blocksURL(stem)].reduce(0) { total, url in
            total + (((try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.int64Value ?? 0)
        }
    }

    // MARK: One size limit for everything recorded

    /// One file (or one history segment in all its forms) that counts toward the history size limit.
    struct Kept: Equatable {
        enum Kind { case activity, daily }        // activity-* segment; metrics-* / processes-* day file
        var url: URL                              // segment stem, or the day file
        var bytes: Int64
        var day: String                           // "20261105"
        var kind: Kind
        var removable: Bool                       // not the segment or day files being written now
    }

    /// Everything Hostwatch keeps in `directory`: activity segments (all forms of each), and the metrics and
    /// process-list day files. `current` (the segment being written) and `today`'s day files can't be removed.
    static func kept(in directory: URL, current: URL?, today: String) -> [Kept] {
        let fm = FileManager.default
        let names = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
        var out: [Kept] = []
        let stems = Set(names.filter(isHistoryName).map { stem(directory.appendingPathComponent($0)).lastPathComponent })
        for name in stems.sorted() {
            let url = directory.appendingPathComponent(name)
            let day = MetricsStore.day(ofHistory: name) ?? ""
            out.append(Kept(url: url, bytes: diskSize(url), day: day, kind: .activity, removable: url != current))
        }
        for name in names.sorted() where name.hasPrefix("metrics-") || name.hasPrefix(ProcessHistory.prefix + "-") {
            let day = String(name.drop { $0 != "-" }.dropFirst().prefix(8))
            let url = directory.appendingPathComponent(name)
            let bytes = ((try? fm.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.int64Value ?? 0
            out.append(Kept(url: url, bytes: bytes, day: day, kind: .daily, removable: day != today && day.count == 8))
        }
        return out
    }

    /// What to delete, oldest day first (a day's activity before its metrics and process lists), so the total
    /// plus `reserve` (room for the file being written) fits in `limit`. Returns the files and what remains.
    static func trimPlan(_ files: [Kept], limit: Int64, reserve: Int64) -> (delete: [Kept], remaining: Int64) {
        var total = files.reduce(0) { $0 + $1.bytes }
        let order = files.filter(\.removable).sorted {
            ($0.day, $0.kind == .activity ? 0 : 1, $0.url.lastPathComponent) < ($1.day, $1.kind == .activity ? 0 : 1, $1.url.lastPathComponent)
        }
        var delete: [Kept] = []
        for f in order where total + reserve > limit {
            delete.append(f)
            total -= f.bytes
        }
        return (delete, total)
    }

    static func remove(_ stem: URL) {
        for url in [stem, gzURL(stem), indexURL(stem), blocksURL(stem), gzURL(stem).appendingPathExtension("tmp"),
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

    // MARK: The block list of a file being written

    private struct BlockLine: Codable {
        var s: Double, e: Double, o: Int64, l: Int64, z: Int64
        var m: [[Int64]]?
    }

    /// `{"s":start,"e":end,"o":offset,"l":length,"z":size,"m":[[minute,bytes]…]}` for one member.
    static func blockLine(_ b: Block, minutes: [Int64: Int64]) -> Data {
        let line = BlockLine(s: b.start.timeIntervalSince1970, e: b.end.timeIntervalSince1970, o: b.offset, l: b.length,
                             z: b.size, m: minutes.keys.sorted().map { [$0, minutes[$0]!] })
        return (try? JSONEncoder().encode(line)) ?? Data()
    }

    /// The index of a file being written, and how many bytes of the list are whole, valid lines (a crash can leave
    /// a half-written last line; everything after the first bad one is ignored).
    static func parseBlockList(_ data: Data) -> (index: Index, validBytes: Int) {
        var blocks: [Block] = [], minutes: [Int64: Int64] = [:], valid = 0
        let decoder = JSONDecoder()
        var start = data.startIndex
        while let nl = data[start...].firstIndex(of: 0x0A) {
            guard let b = try? decoder.decode(BlockLine.self, from: data[start..<nl]),
                  b.o == (blocks.last.map { $0.offset + $0.length } ?? 0) else { break }   // members follow each other
            blocks.append(Block(start: Date(timeIntervalSince1970: b.s), end: Date(timeIntervalSince1970: b.e),
                                offset: b.o, length: b.l, size: b.z))
            for pair in b.m ?? [] where pair.count == 2 { minutes[pair[0], default: 0] += pair[1] }
            start = nl + 1
            valid = start - data.startIndex
        }
        return (Index(blocks: blocks, minutes: minutes.keys.sorted().map { [$0, minutes[$0]!] }), valid)
    }

    /// The final index of a finished file (atomically: a .gz with an index is complete).
    static func writeIndex(_ index: Index, for stem: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let tmp = indexURL(stem).appendingPathExtension("tmp")
        try encoder.encode(index).write(to: tmp, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        try? FileManager.default.removeItem(at: indexURL(stem))
        try FileManager.default.moveItem(at: tmp, to: indexURL(stem))
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
            let member = sealRecord(try gzip(block))
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
        guard let stored = try? handle.read(upToCount: Int(block.length)), let member = openRecords(stored) else { return nil }
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
    /// `since`: for a folder, skip files that end before it (their index says so without opening them).
    static func forEachLine(path: String, since: Date? = nil, _ body: (Data) -> Void) {
        let url = URL(fileURLWithPath: path)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue {
            func lines(_ chunk: Data) {
                var start = chunk.startIndex
                while let nl = chunk[start...].firstIndex(of: 0x0A) {
                    if nl > start { body(chunk[start..<nl]) }
                    start = nl + 1
                }
            }
            let files = list(in: url)
            for (i, file) in files.enumerated() {
                let newest = i == files.count - 1          // the file being written: its end isn't in its index yet
                switch file {
                case .plain(let plain):
                    if !newest, let since, let modified = (try? plain.resourceValues(forKeys: [.contentModificationDateKey]))?
                        .contentModificationDate, modified < since { continue }
                    forEachLine(path: plain.path, body)
                case .compressed(let gz, let index):
                    if !newest, let since, let end = index.end, end < since { continue }
                    forEachChunk(file) { chunk in lines(chunk); return true }
                    // The newest file's events since its last finished block: the unfinished member after it.
                    if newest, let handle = try? FileHandle(forReadingFrom: gz) {
                        defer { try? handle.close() }
                        let finished = index.blocks.last.map { $0.offset + $0.length } ?? 0
                        try? handle.seek(toOffset: UInt64(finished))
                        if let tail = try? handle.readToEnd(), !tail.isEmpty {
                            lines(HistoryStream.wholeLines(HistoryStream.inflatePartial(tail)))
                        }
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
            let stem = stem(url)
            if let index = readIndex(stem) ?? (try? Data(contentsOf: blocksURL(stem))).map({ parseBlockList($0).index }) {
                forEachChunk(.compressed(url, index)) { emit($0); return true }     // block by block, plain or sealed
                return
            }
            guard let stored = try? Data(contentsOf: url, options: .alwaysMapped), let data = openRecords(stored) else { return }
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
    // MARK: Sealed records

    /// A block on disk is a run of records, `[u32 little-endian length][sealed bytes]`, whose opened bytes joined
    /// are the gzip member; a block that starts with gzip's magic is from an older version, plain.
    static let gzipMagic = Data([0x1F, 0x8B])

    static func sealRecord(_ data: Data) -> Data {
        let sealed = Vault.shared.seal(data)
        var out = Data(capacity: sealed.count + 4)
        var length = UInt32(sealed.count).littleEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(sealed)
        return out
    }

    /// The gzip bytes a block's records hold (a torn last record is dropped); a plain block as it is; nil when a
    /// record can't be opened (another key).
    static func openRecords(_ data: Data) -> Data? {
        if data.starts(with: gzipMagic) || data.isEmpty { return data }
        var out = Data(capacity: data.count)
        var i = data.startIndex
        while i + 4 <= data.endIndex {
            let length = Int(data[i..<i + 4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian)
            let end = i + 4 + length
            guard length > 0, end <= data.endIndex else { break }                      // torn: what's whole counts
            guard let opened = Vault.shared.open(Data(data[i + 4..<end])) else { return nil }
            out.append(opened)
            i = end
        }
        return out
    }

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

    /// Every member of a (multi-member) gzip stream, in order. `partial`: a member cut short (a block still being
    /// written when the app crashed) hands over what decompressed before the end.
    static func gunzipMembers(_ data: Data, sizeHint: Int = blockBytes, partial: Bool = false, _ body: (Data) -> Void) {
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
                    if partial && !member.isEmpty { body(member) }
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

/// `Hostwatch --export-history [file or folder]`: the recorded events as plain JSON lines on stdout, through the data
/// key (the files themselves are sealed). Default: the history folder.
func runExportHistory(_ path: String?) -> Never {
    let target = path ?? AppPaths.logs.appendingPathComponent("History").path
    guard FileManager.default.fileExists(atPath: target) else { print("nothing at \(target)"); exit(1) }
    let out = FileHandle.standardOutput
    var buffer = Data()
    HistoryFiles.forEachLine(path: target) { line in
        buffer.append(line); buffer.append(0x0A)
        if buffer.count > 1 << 20 { out.write(buffer); buffer.removeAll(keepingCapacity: true) }
    }
    out.write(buffer)
    exit(0)
}
