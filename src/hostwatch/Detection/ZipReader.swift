import Compression
import Foundation

/// Reads the entries of a zip archive (stored or deflated, ZIP64 included) without unpacking it to disk. Enough for
/// OSV's bulk exports, which hold a quarter of a million small JSON files: unpacking them would cost minutes of disk
/// work, and `unzip` would put a subprocess and its output parsing between the download and the list.
struct ZipReader {
    enum ZipError: Error { case notZip, damaged }

    private let data: Data
    private let entries: [(name: String, method: UInt16, compressed: Int, size: Int, offset: Int)]

    init(url: URL) throws {
        try self.init(data: Data(contentsOf: url, options: .alwaysMapped))
    }

    init(data: Data) throws {
        self.data = data
        entries = try Self.centralDirectory(data)
    }

    var names: [String] { entries.map(\.name) }

    /// Calls `body` with each entry `wanted` accepts, decompressed. A damaged entry is skipped, not fatal: one bad
    /// record must not cost the rest of the list.
    func forEach(where wanted: (String) -> Bool, _ body: (String, Data) -> Void) {
        for e in entries where wanted(e.name) {
            if let content = content(e) { body(e.name, content) }
        }
    }

    private func content(_ e: (name: String, method: UInt16, compressed: Int, size: Int, offset: Int)) -> Data? {
        guard e.offset + 30 <= data.count, Self.u32(data, e.offset) == 0x0403_4b50 else { return nil }
        let start = e.offset + 30 + Int(Self.u16(data, e.offset + 26)) + Int(Self.u16(data, e.offset + 28))
        guard start + e.compressed <= data.count, e.size <= 64 << 20 else { return nil }
        let raw = data.subdata(in: start..<start + e.compressed)
        switch e.method {
        case 0: return raw
        case 8:
            guard e.size > 0 else { return Data() }
            var out = Data(count: e.size)
            let n = out.withUnsafeMutableBytes { dst in
                raw.withUnsafeBytes { src in
                    // COMPRESSION_ZLIB is raw DEFLATE (RFC 1951), which is what zip stores.
                    compression_decode_buffer(dst.bindMemory(to: UInt8.self).baseAddress!, e.size,
                                              src.bindMemory(to: UInt8.self).baseAddress!, raw.count, nil, COMPRESSION_ZLIB)
                }
            }
            return n == e.size ? out : nil
        default: return nil
        }
    }

    private static func centralDirectory(_ d: Data) throws -> [(name: String, method: UInt16, compressed: Int, size: Int, offset: Int)] {
        guard d.count >= 22 else { throw ZipError.notZip }
        // The end record is the last thing in the file, before a comment of at most 64 KB.
        var eocd = -1
        var i = d.count - 22
        while i >= max(0, d.count - 22 - 65_535) {
            if u32(d, i) == 0x0605_4b50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError.notZip }
        var count = Int(u16(d, eocd + 10))
        var cdOffset = Int(u32(d, eocd + 16))
        // ZIP64: more than 65,535 entries (npm's export has 230,000) or a directory past 4 GB.
        if count == 0xFFFF || cdOffset == 0xFFFF_FFFF, eocd >= 20, u32(d, eocd - 20) == 0x0706_4b50 {
            let z = Int(u64(d, eocd - 12))
            guard z + 56 <= d.count, u32(d, z) == 0x0606_4b50 else { throw ZipError.damaged }
            count = Int(u64(d, z + 32))
            cdOffset = Int(u64(d, z + 48))
        }
        var out: [(name: String, method: UInt16, compressed: Int, size: Int, offset: Int)] = []
        out.reserveCapacity(min(count, 1_000_000))
        var p = cdOffset
        for _ in 0..<count {
            guard p + 46 <= d.count, u32(d, p) == 0x0201_4b50 else { throw ZipError.damaged }
            let method = u16(d, p + 10)
            var compressed = Int(u32(d, p + 20)), size = Int(u32(d, p + 24))
            let nameLen = Int(u16(d, p + 28)), extraLen = Int(u16(d, p + 30)), commentLen = Int(u16(d, p + 32))
            var offset = Int(u32(d, p + 42))
            guard p + 46 + nameLen + extraLen <= d.count else { throw ZipError.damaged }
            let name = String(decoding: d.subdata(in: p + 46..<p + 46 + nameLen), as: UTF8.self)
            // ZIP64 sizes and offset, in that order, only for the fields that overflowed.
            var x = p + 46 + nameLen
            let extraEnd = x + extraLen
            while x + 4 <= extraEnd {
                let id = u16(d, x), len = Int(u16(d, x + 2))
                if id == 0x0001 {
                    var f = x + 4
                    if size == 0xFFFF_FFFF, f + 8 <= x + 4 + len { size = Int(u64(d, f)); f += 8 }
                    if compressed == 0xFFFF_FFFF, f + 8 <= x + 4 + len { compressed = Int(u64(d, f)); f += 8 }
                    if offset == 0xFFFF_FFFF, f + 8 <= x + 4 + len { offset = Int(u64(d, f)) }
                }
                x += 4 + len
            }
            out.append((name, method, compressed, size, offset))
            p = extraEnd + commentLen
        }
        return out
    }

    private static func u16(_ d: Data, _ at: Int) -> UInt16 {
        d.withUnsafeBytes { UInt16(littleEndian: $0.loadUnaligned(fromByteOffset: at, as: UInt16.self)) }
    }
    private static func u32(_ d: Data, _ at: Int) -> UInt32 {
        d.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: at, as: UInt32.self)) }
    }
    private static func u64(_ d: Data, _ at: Int) -> UInt64 {
        d.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(fromByteOffset: at, as: UInt64.self)) }
    }
}
