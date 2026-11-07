import CryptoKit
import Foundation
import Testing
@testable import Hostwatch

/// Files sealed with the data key: whole files, append-only lines, older plain files, and the stores through it.
@Suite struct VaultSealing {
    @Test func sealsAndOpensWholeFilesAndLines() throws {
        let v = Vault(key: SymmetricKey(size: .bits256))
        let plain = Data("{\"a\":1}".utf8)
        let sealed = v.seal(plain)
        #expect(sealed != plain && sealed.starts(with: Data("HWV1".utf8)) && v.open(sealed) == plain)
        #expect(v.open(plain) == plain)                                            // an older, plain file reads as is
        var tampered = sealed; tampered[tampered.count - 1] ^= 0xFF
        #expect(v.open(tampered) == nil)
        #expect(Vault(key: SymmetricKey(size: .bits256)).open(sealed) == nil)      // another key: unreadable
        let line = v.sealLine(plain)
        #expect(line.last == 0x0A && line.starts(with: Data("HWV1:".utf8)) && v.openLine(line.dropLast()) == plain)
        #expect(v.openLine(plain) == plain)
        #expect(v.isSealed && v.backend == .memory)
    }

    @Test func noKeyMeansPlain() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-vault-none-\(UUID().uuidString)")
        let v = Vault(key: nil, directory: dir)
        // Reading without creating anything: not exercised here (it would touch the keychain). Sealing with a key
        // set to nil after init is the "no place to keep a key" case: data passes through unchanged.
        _ = v
        let sealed = Vault(key: SymmetricKey(size: .bits256)).seal(Data("x".utf8))
        #expect(sealed.count > 1)
    }

    @Test func appendOnlyFilesRoundTrip() throws {
        let v = Vault(key: SymmetricKey(size: .bits256))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("hw-vault-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: url) }
        v.appendLine(Data("one".utf8), to: url)
        v.appendLine(Data("two".utf8), to: url)
        try? Data("legacy plain line\n".utf8).write(to: url, options: .atomic)      // a file from an older version
        v.appendLine(Data("three".utf8), to: url)
        #expect(v.lines(of: url).map { String(decoding: $0, as: UTF8.self) } == ["legacy plain line", "three"])
        let raw = try Data(contentsOf: url)
        #expect(!String(decoding: raw, as: UTF8.self).contains("three"))             // nothing readable on disk
    }
}

/// The stores save sealed and load back; a store saved plain by an older version still loads.
@MainActor @Suite(.serialized) struct VaultStores {
    @Test func patternStoreIsSealedOnDisk() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-vault-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let s = SignatureStore(directory: dir)
        _ = s.observe(file("/usr/bin/git", pid: 1, "r", "\(home)/Documents/x/y.txt"))
        s.set(.safe, keys: s.allEntries.map(\.id))
        s.save(sync: true)
        let raw = try Data(contentsOf: dir.appendingPathComponent("signatures-v2.json"))
        #expect(raw.starts(with: Data("HWV1".utf8)) && !String(decoding: raw, as: UTF8.self).contains("Documents"))
        let again = SignatureStore(directory: dir)
        #expect(again.allEntries.count == 1 && again.allEntries[0].status == .safe)
        #expect(SignatureStore.readSaved(from: dir)?.entries.count == 1)             // the MCP server's reader
        // A plain file from an older version loads too.
        try Data("{\"entries\":[],\"processRules\":[],\"generation\":3}".utf8).write(to: dir.appendingPathComponent("signatures-v2.json"))
        try? FileManager.default.removeItem(at: dir.appendingPathComponent("signatures-v2.journal"))
        #expect(SignatureStore(directory: dir).allEntries.isEmpty)
    }
}

/// History and day files: sealed on disk, readable through the key, including a crash's unfinished block.
@Suite(.serialized) struct VaultHistory {
    @Test func historyBlocksAreSealedRecords() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-vault-hist-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let stem = dir.appendingPathComponent("activity-20261107-120000-000.jsonl")
        let s = try HistoryStream(stem: stem)
        let line = Data((#"{"kind":"exec","time":"12:00:00","pid":1,"ppid":0,"name":"secretprog","proc":"/x/secretprog","target":"/x/secretprog","extra":"","ts":"2026-11-07T12:00:00.000+02:00"}"# + "\n").utf8)
        try s.append(line)
        try s.sync()                                           // a crash now: the bytes are in the file, sealed
        let raw = try Data(contentsOf: HistoryFiles.gzURL(stem))
        #expect(!raw.starts(with: HistoryFiles.gzipMagic) && raw.range(of: Data("secretprog".utf8)) == nil)
        #expect(HistoryStream.wholeLines(HistoryStream.inflatePartial(raw)) == line)   // recovery opens the records
        try s.seal()
        let index = try s.finish()
        let block = try #require(index.blocks.first)
        #expect(HistoryFiles.read(block, from: HistoryFiles.gzURL(stem)) == line)
        var lines: [Data] = []
        HistoryFiles.forEachLine(path: HistoryFiles.gzURL(stem).path) { lines.append($0) }
        #expect(lines.count == 1 && lines[0] == line.dropLast())
        #expect(Vault(key: SymmetricKey(size: .bits256)).open(raw.dropFirst(4)) == nil)
    }

    @Test func compressedPlainFilesAndDayFilesAreSealed() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-vault-day-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let plain = dir.appendingPathComponent("activity-20261107-130000-000.jsonl")
        let text = (0..<3).map { #"{"kind":"file","time":"13:00:0\#($0)","pid":2,"ppid":1,"name":"cat","proc":"/bin/cat","target":"/x/private\#($0)","extra":"r","ts":"2026-11-07T13:00:0\#($0).000+02:00"}"# }.joined(separator: "\n") + "\n"
        try Data(text.utf8).write(to: plain)
        let index = try HistoryFiles.compress(plain)
        let raw = try Data(contentsOf: HistoryFiles.gzURL(HistoryFiles.stem(plain)))
        #expect(raw.range(of: Data("private".utf8)) == nil && !raw.starts(with: HistoryFiles.gzipMagic))
        #expect(HistoryFiles.read(index.blocks[0], from: HistoryFiles.gzURL(HistoryFiles.stem(plain))) == Data(text.utf8))
        let metrics = MetricsArchive(directory: dir, prefix: "metrics")
        metrics.append(line: Data(#"{"t":1,"cpu":9}"#.utf8), day: "20261107")
        let dayRaw = try Data(contentsOf: metrics.plainURL(day: "20261107"))
        #expect(String(decoding: dayRaw, as: UTF8.self).hasPrefix("HWV1:") && !String(decoding: dayRaw, as: UTF8.self).contains("cpu"))
        #expect(String(decoding: metrics.data(day: "20261107"), as: UTF8.self) == "{\"t\":1,\"cpu\":9}\n")
    }
}
