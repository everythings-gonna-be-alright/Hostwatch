import Foundation
import Testing
@testable import Hostwatch

/// System metrics: sane readings, durable daily files, readable by time.
@Suite struct SystemMetrics {
    func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-metrics-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func sample(_ t: Date, cpu: Double = 10) -> MetricSample {
        MetricSample(t: t.timeIntervalSince1970.rounded(), cpu: cpu, mem: 0.5, pressure: 1, netIn: 100, netOut: 50,
                     diskRead: 10, diskWrite: 20,
                     top: [TopProcess(pid: 42, name: "x", path: "/x", cpu: 150, mem: 1_000_000, read: 0, write: 5)])
    }

    @Test func readingsAreInRange() {
        let sampler = SystemSampler()
        _ = sampler.read(now: 0)
        for _ in 0..<200_000 { _ = sqrt(Double.random(in: 1...2)) }
        let r = sampler.read(now: 1)
        #expect((0...100).contains(r.cpu))
        #expect(r.mem > 0 && r.mem <= 1)
        #expect([1, 2, 4].contains(r.pressure))
        #expect(r.netIn >= 0 && r.netOut >= 0)
    }

    @Test func compactJSONAndCollectorFormat() throws {
        let data = try JSONEncoder().encode(sample(Date(timeIntervalSince1970: 1_800_000_000)))
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains(#""c":10"#) && text.contains(#""ni":100"#) && !text.contains("netIn"))
        let fromCollector = #"{"pid":7,"name":"mds","path":"/usr/libexec/mds","cpu":12.5,"mem":2048,"read":1,"write":2}"#
        let p = try JSONDecoder().decode(TopProcess.self, from: Data(fromCollector.utf8))
        #expect(p.name == "mds" && p.cpu == 12.5)
    }

    @Test func daysAreWrittenCompressedAndReadAcrossMidnight() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let archive = MetricsArchive(directory: dir)
        let cal = Calendar.current
        let midnight = cal.startOfDay(for: Date(timeIntervalSince1970: 1_800_000_000))
        let before = (1...12).map { midnight.addingTimeInterval(-Double($0) * 5) }.reversed()
        let after = (0..<12).map { midnight.addingTimeInterval(Double($0) * 5) }
        for t in before + after { archive.append(sample(t)) }
        let yesterday = MetricsArchive.dayName(midnight.addingTimeInterval(-60))
        let today = MetricsArchive.dayName(midnight)
        #expect(archive.days() == [yesterday, today])
        archive.maintain(today: today, keepFrom: nil)
        #expect(FileManager.default.fileExists(atPath: archive.gzURL(day: yesterday).path))
        #expect(!FileManager.default.fileExists(atPath: archive.plainURL(day: yesterday).path))
        #expect(FileManager.default.fileExists(atPath: archive.plainURL(day: today).path))   // today stays plain
        let span = MetricsCache().samples(archive, from: midnight.addingTimeInterval(-30), to: midnight.addingTimeInterval(30))
        #expect(span.count == 13)                                   // 6 before midnight, 7 from midnight
        #expect(span.first?.top?.first?.pid == 42)
        // Days older than the oldest activity history go away.
        archive.maintain(today: today, keepFrom: today)
        #expect(archive.days() == [today])
        archive.removeAll()
        #expect(archive.days().isEmpty)
    }

    @Test func historyFileNameGivesItsDay() {
        #expect(MetricsStore.day(ofHistory: "activity-20261101-071732-871.jsonl") == "20261101")
        #expect(MetricsStore.day(ofHistory: "nonsense") == nil)
    }
}
