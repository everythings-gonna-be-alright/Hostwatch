import Foundation

/// One value of one series at one moment, for the Running Now charts.
struct ResourcePoint: Identifiable, Equatable {
    let date: Date
    let series: String
    let value: Double
    var id: String { "\(series)|\(date.timeIntervalSince1970)" }
}

/// The Running Now charts' series, worked out from samples: pure, so it is testable without a store.
enum ResourceSeries {
    static let other = "Other"

    /// The program a process belongs to: an app's helpers count as the app ("Google Chrome Helper" is Google Chrome),
    /// a versioned install as its program (claude, not 2.1.361).
    static func program(path: String, name: String) -> String {
        if let app = path.split(separator: "/").first(where: { $0.hasSuffix(".app") }) {
            return String(app.dropLast(4))
        }
        return versionedProgramName(path) ?? name
    }

    /// The `limit` programs with the most over the whole window, each as a series, and Other for the rest of each
    /// moment's total. A program missing at a moment is 0 there, so the stack never has holes. Programs can add up
    /// to more than the total (memory they share), and Other is then 0, never negative.
    /// `names` fixes the programs (the network's sent half uses the ones chosen for both directions together).
    static func split(_ rows: [(date: Date, total: Double, parts: [String: Double])],
                      limit: Int = 4, names fixed: [String]? = nil) -> (names: [String], points: [ResourcePoint]) {
        var sums: [String: Double] = [:]
        for row in rows { for (name, v) in row.parts { sums[name, default: 0] += v } }
        let names = fixed ?? sums.filter { $0.value > 0 }.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(limit).map(\.key)
        var points: [ResourcePoint] = []
        points.reserveCapacity(rows.count * (names.count + 1))
        for row in rows {
            var named = 0.0
            for name in names {
                let v = row.parts[name] ?? 0
                named += v
                points.append(ResourcePoint(date: row.date, series: name, value: v))
            }
            points.append(ResourcePoint(date: row.date, series: other, value: max(0, row.total - named)))
        }
        return (names, points)
    }

    /// A sample's programs: the processes summed by program, then the ten busiest by CPU and the ten biggest by
    /// memory (the same program once), as [% of one core, MB], rounded so history stays small.
    static func programs(_ procs: [TopProcess], limit: Int = 10) -> [String: [Double]] {
        var sums: [String: (cpu: Double, mem: Double)] = [:]
        for p in procs {
            let name = program(path: p.path, name: p.name)
            sums[name, default: (0, 0)].cpu += p.cpu
            sums[name, default: (0, 0)].mem += Double(p.mem)
        }
        let byCPU = sums.sorted { ($0.value.cpu, $1.key) > ($1.value.cpu, $0.key) }.prefix(limit).map(\.key)
        let byMem = sums.sorted { ($0.value.mem, $1.key) > ($1.value.mem, $0.key) }.prefix(limit).map(\.key)
        var out: [String: [Double]] = [:]
        for name in byCPU + byMem {
            guard let v = sums[name] else { continue }
            out[name] = [(v.cpu * 10).rounded() / 10, (v.mem / 1_048_576).rounded()]
        }
        return out
    }

    /// The rows of a metric's samples, programs summed: CPU as a share of all cores (as the total is), memory in
    /// bytes. A sample from before `programs` was kept falls back to its busiest processes.
    static func cpuRows(_ samples: [MetricSample], cores: Int) -> [(date: Date, total: Double, parts: [String: Double])] {
        measured(samples).map { s in (s.date, s.cpu, parts(s, index: 0).mapValues { $0 / Double(max(cores, 1)) }) }
    }

    /// A program at the edge of the biggest ten drops out of one sample and back into the next: its memory then jumped
    /// into Other and back, a zigzag in every band. Memory changes slowly, so a program missing for up to `carry`
    /// samples keeps its last value.
    static func memoryRows(_ samples: [MetricSample], physical: Double, carry: Int = 3) -> [(date: Date, total: Double, parts: [String: Double])] {
        var last: [String: (value: Double, missing: Int)] = [:]
        return measured(samples).map { s in
            var parts = parts(s, index: 1).mapValues { $0 * 1_048_576 }
            for name in Array(last.keys) {
                if let v = parts[name] {
                    last[name] = (v, 0)
                } else if let held = last[name], held.missing < carry {
                    last[name] = (held.value, held.missing + 1)
                    parts[name] = held.value
                } else {
                    last[name] = nil
                }
            }
            for (name, v) in parts where last[name] == nil { last[name] = (v, 0) }
            return (s.date, s.mem * physical, parts)
        }
    }

    /// The samples that know their programs. One taken while the collector was away (restarting, say) knows only
    /// the total, and drawn as all Other it cut a grey notch through every band. With none known, all of them.
    static func measured(_ samples: [MetricSample]) -> [MetricSample] {
        let known = samples.filter { $0.programs != nil || $0.top != nil }
        return known.isEmpty ? samples : known
    }

    /// % of one core (index 0) or MB (index 1) per program.
    private static func parts(_ s: MetricSample, index: Int) -> [String: Double] {
        if let programs = s.programs { return programs.compactMapValues { $0.count > index ? $0[index] : nil } }
        var parts: [String: Double] = [:]
        for p in s.top ?? [] {
            parts[program(path: p.path, name: p.name), default: 0] += index == 0 ? p.cpu : Double(p.mem) / 1_048_576
        }
        return parts
    }

    /// Network by program, from the samples a traffic report arrived for: received (`direction` 0), sent (1) or
    /// both together (nil). Other in the record is the rest of the total, not a program.
    static func trafficRows(_ samples: [MetricSample], direction: Int? = nil) -> [(date: Date, total: Double, parts: [String: Double])] {
        samples.compactMap { s in
            s.traffic.map { t in
                let v = t.mapValues { pair in direction.map { pair.count > $0 ? pair[$0] : 0 } ?? pair.reduce(0, +) }
                return (s.date, v.values.reduce(0, +), v.filter { $0.key != other })
            }
        }
    }

    /// Rows averaged into buckets of `bucket` seconds, each dated by its newest row: a 30-minute chart needs about a
    /// hundred points across, not one every 5 seconds (360 per program, thousands of marks per chart, and every one
    /// laid out again on each update). Rows already further apart than `bucket` pass unchanged.
    static func thin(_ rows: [(date: Date, total: Double, parts: [String: Double])],
                     bucket: TimeInterval) -> [(date: Date, total: Double, parts: [String: Double])] {
        guard bucket > 0, rows.count > 1 else { return rows }
        var out: [(date: Date, total: Double, parts: [String: Double])] = []
        var key = Int.min, count = 0.0
        var acc: (date: Date, total: Double, parts: [String: Double]) = (Date.distantPast, 0, [:])
        func flush() {
            guard count > 0 else { return }
            out.append((acc.date, acc.total / count, acc.parts.mapValues { $0 / count }))
        }
        for r in rows {
            let k = Int((r.date.timeIntervalSince1970 / bucket).rounded(.down))
            if k != key { flush(); key = k; count = 0; acc = (r.date, 0, [:]) }
            count += 1
            acc.date = r.date
            acc.total += r.total
            for (name, v) in r.parts { acc.parts[name, default: 0] += v }
        }
        flush()
        return out
    }

    /// The index of the point nearest `date` in points sorted by date (binary search: hovering reads every series).
    static func nearest(_ points: [ResourcePoint], _ date: Date) -> Int? {
        guard !points.isEmpty else { return nil }
        var lo = 0, hi = points.count - 1
        while lo < hi {
            let mid = (lo + hi) / 2
            if points[mid].date < date { lo = mid + 1 } else { hi = mid }
        }
        if lo > 0, abs(points[lo - 1].date.timeIntervalSince(date)) <= abs(points[lo].date.timeIntervalSince(date)) { return lo - 1 }
        return lo
    }

    /// One collector traffic report as [received, sent] per program over `seconds`: the ten busiest by both
    /// together, the rest as Other.
    static func traffic(_ report: [NetTraffic], seconds: Double, limit: Int = 10) -> [String: [Double]] {
        var by: [String: (rx: Double, tx: Double)] = [:]
        let s = max(seconds, 1)
        for t in report {
            let name = program(path: t.proc, name: t.name)
            by[name, default: (0, 0)].rx += Double(t.received) / s
            by[name, default: (0, 0)].tx += Double(t.sent) / s
        }
        let top = by.sorted { ($0.value.rx + $0.value.tx, $1.key) > ($1.value.rx + $1.value.tx, $0.key) }.prefix(limit)
        var out = Dictionary(uniqueKeysWithValues: top.map { ($0.key, [$0.value.rx.rounded(), $0.value.tx.rounded()]) })
        let kept = Set(top.map(\.key))
        let rest = by.filter { !kept.contains($0.key) }.values.reduce((rx: 0.0, tx: 0.0)) { ($0.rx + $1.rx, $0.tx + $1.tx) }
        if rest.rx + rest.tx >= 1 { out[other] = [rest.rx.rounded(), rest.tx.rounded()] }
        return out
    }
}
