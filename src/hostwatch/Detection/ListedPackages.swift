import Foundation

/// The malicious-package lists in a form small enough to hold in memory and fast enough for a launch hold (ADR 0024,
/// layer 3): per ecosystem, the 64-bit hashes of names listed for every version (most of them), sorted, plus the
/// few records that name versions. npm's 225,000 records come to about 2 MB. Built by the app from its sealed index
/// and sent to the collector, which can't read the vault.
struct ListedPackages: Equatable, Sendable {
    var every: [String: [UInt64]] = [:]
    var some: [String: [UInt64: [MalwareRecord]]] = [:]

    var isEmpty: Bool { every.values.allSatisfy(\.isEmpty) && some.values.allSatisfy(\.isEmpty) }
    var count: Int { every.values.reduce(0) { $0 + $1.count } + some.values.reduce(0) { $0 + $1.count } }

    /// FNV-1a over the registry's form of the name: the same on both sides of the socket, whatever Swift's hasher does.
    static func hash(_ name: String) -> UInt64 {
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in name.utf8 { h = (h ^ UInt64(b)) &* 0x0000_0100_0000_01b3 }
        return h
    }

    /// The record that lists this version, nil when none does. An every-version record carries no id here: the
    /// app finds it in the index when it tells you.
    func record(for ref: PackageRef) -> MalwareRecord? {
        let eco = ref.ecosystem.osv
        let h = Self.hash(ref.ecosystem.normalize(ref.name))
        if let list = every[eco], Self.contains(list, h) { return MalwareRecord(id: "", allVersions: true) }
        return some[eco]?[h]?.first { $0.covers(ref.version) }
    }

    private static func contains(_ sorted: [UInt64], _ h: UInt64) -> Bool {
        var lo = 0, hi = sorted.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if sorted[mid] < h { lo = mid + 1 } else { hi = mid }
        }
        return lo < sorted.count && sorted[lo] == h
    }

    /// One ecosystem's part, from its index lines.
    mutating func add(index: Data, ecosystem: PackageEcosystem) {
        var all = Set<UInt64>(), versioned: [UInt64: [MalwareRecord]] = [:]
        let text = String(decoding: index, as: UTF8.self)
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "\t", maxSplits: 2)
            guard parts.count == 3 else { continue }
            let h = Self.hash(String(parts[0]))
            if parts[2] == "*" { all.insert(h) }
            else if let r = MalwareRecord(id: String(parts[1]), spec: String(parts[2])) { versioned[h, default: []].append(r) }
        }
        for h in all { versioned[h] = nil }
        every[ecosystem.osv] = all.sorted()
        some[ecosystem.osv] = versioned
    }

    // MARK: Over the socket

    /// `{"npm": {"every": base64 of little-endian hashes, "some": ["<hex>\t<id>\t<spec>", …]}, …}`
    var payload: [String: Any] {
        var out: [String: Any] = [:]
        for eco in Set(every.keys).union(some.keys) {
            var bytes = Data(capacity: (every[eco]?.count ?? 0) * 8)
            for var h in every[eco] ?? [] { h = h.littleEndian; withUnsafeBytes(of: &h) { bytes.append(contentsOf: $0) } }
            let lines = (some[eco] ?? [:]).flatMap { h, records in
                records.map { String(h, radix: 16) + "\t" + $0.id + "\t" + $0.spec }
            }
            out[eco] = ["every": bytes.base64EncodedString(), "some": lines.sorted()]
        }
        return out
    }

    init() {}

    init(payload: [String: Any]) {
        for (eco, value) in payload {
            guard let d = value as? [String: Any] else { continue }
            if let b64 = d["every"] as? String, let bytes = Data(base64Encoded: b64) {
                let n = bytes.count / 8
                var list = [UInt64](repeating: 0, count: n)
                _ = list.withUnsafeMutableBytes { bytes.copyBytes(to: $0, count: n * 8) }
                list = list.map { UInt64(littleEndian: $0) }
                // Sorted by the sender, but a lookup must never miss because of the order: cheap to make sure.
                if zip(list, list.dropFirst()).contains(where: { $0 > $1 }) { list.sort() }
                every[eco] = list
            }
            var versioned: [UInt64: [MalwareRecord]] = [:]
            for line in d["some"] as? [String] ?? [] {
                let parts = line.split(separator: "\t", maxSplits: 2)
                guard parts.count == 3, let h = UInt64(parts[0], radix: 16),
                      let r = MalwareRecord(id: String(parts[1]), spec: String(parts[2])) else { continue }
                versioned[h, default: []].append(r)
            }
            some[eco] = versioned
        }
    }
}
