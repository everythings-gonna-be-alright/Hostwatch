import Foundation
import Testing
@testable import Hostwatch

/// Running Now's charts: programs named as people know them, the top four kept, the rest as Other.
@Suite struct ResourceSeriesSplit {
    @Test func helpersCountAsTheirApp() {
        #expect(ResourceSeries.program(path: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
                                       name: "Google Chrome Helper (Renderer)") == "Google Chrome")
        #expect(ResourceSeries.program(path: "/usr/sbin/mDNSResponder", name: "mDNSResponder") == "mDNSResponder")
    }

    @Test func topProgramsAndOther() {
        let t0 = Date(timeIntervalSince1970: 0), t1 = t0.addingTimeInterval(5)
        let rows: [(date: Date, total: Double, parts: [String: Double])] = [
            (t0, 50, ["a": 10, "b": 5, "c": 1, "d": 1, "e": 30]),
            (t1, 40, ["a": 20, "e": 1]),
        ]
        let split = ResourceSeries.split(rows, limit: 2)
        #expect(split.names == ["e", "a"])
        // every moment has every series, so the stack has no holes
        #expect(split.points.filter { $0.date == t1 }.map(\.series) == ["e", "a", "Other"])
        #expect(split.points.first { $0.date == t0 && $0.series == "Other" }?.value == 10)
        #expect(split.points.first { $0.date == t1 && $0.series == "Other" }?.value == 19)
    }

    @Test func otherIsNeverNegative() {
        // programs share memory: their footprints can add up to more than is used
        let split = ResourceSeries.split([(Date(), 10, ["a": 8, "b": 7])])
        #expect(split.points.first { $0.series == "Other" }?.value == 0)
    }

    @Test func trafficKeepsReceivedAndSentWithTheRestAsOther() {
        let report = [NetTraffic(proc: "/Applications/Safari.app/Contents/MacOS/Safari", name: "Safari", remote: "1.2.3.4", sent: 1000, received: 9000),
                      NetTraffic(proc: "/usr/bin/curl", name: "curl", remote: "1.2.3.5", sent: 100, received: 400)]
        let rates = ResourceSeries.traffic(report, seconds: 10, limit: 1)
        #expect(rates == ["Safari": [900, 100], "Other": [40, 10]])
        // Other is the rest of the total, never a program of its own
        var sample = MetricSample(t: 0, cpu: 0, mem: 0, pressure: 1, netIn: 0, netOut: 0)
        sample.traffic = rates
        let received = ResourceSeries.trafficRows([sample], direction: 0)[0]
        #expect(received.total == 940 && received.parts == ["Safari": 900])
        #expect(ResourceSeries.trafficRows([sample], direction: 1)[0].parts == ["Safari": 100])
        #expect(ResourceSeries.trafficRows([sample])[0].total == 1050)
    }

    @Test func programsAreCompactAndSummed() {
        let procs = [TopProcess(pid: 1, name: "Helper", path: "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper", cpu: 12.34, mem: 200 * 1_048_576, read: 0, write: 0),
                     TopProcess(pid: 2, name: "Slack", path: "/Applications/Slack.app/Contents/MacOS/Slack", cpu: 3, mem: 100 * 1_048_576, read: 0, write: 0)]
        #expect(ResourceSeries.programs(procs) == ["Slack": [15.3, 300]])
        var sample = MetricSample(t: 0, cpu: 50, mem: 0.5, pressure: 1, netIn: 0, netOut: 0)
        sample.programs = ["Slack": [20, 300]]
        #expect(ResourceSeries.cpuRows([sample], cores: 10)[0].parts == ["Slack": 2])
        #expect(ResourceSeries.memoryRows([sample], physical: 1)[0].parts == ["Slack": 300 * 1_048_576])
    }

    @Test func historyKeepsFiveAndThree() {
        // the charts get ten of each, history keeps what it kept before: the five busiest and three biggest
        let procs = (1...20).map { TopProcess(pid: $0, name: "p\($0)", path: "", cpu: Double($0), mem: Int64(100 - $0), read: 0, write: 0) }
        let kept = MetricsStore.archived(procs)
        #expect(kept.map(\.pid) == [20, 19, 18, 17, 16, 1, 2, 3])
    }

    /// A program at the edge of the biggest ten drops out of a sample: its memory is carried for a few samples
    /// rather than jumping into Other and back.
    @Test func memoryCarriesAProgramThatDropsOut() {
        func sample(_ t: Double, _ programs: [String: [Double]]) -> MetricSample {
            var s = MetricSample(t: t, cpu: 0, mem: 1, pressure: 1, netIn: 0, netOut: 0)
            s.programs = programs
            return s
        }
        let rows = ResourceSeries.memoryRows([sample(0, ["a": [0, 100]]), sample(5, [:]), sample(10, [:]), sample(15, [:]),
                                              sample(20, [:])], physical: 1_000_000_000, carry: 3)
        #expect(rows.map { $0.parts["a"] ?? 0 } == [100, 100, 100, 100, 0].map { $0 * 1_048_576 })
    }

    /// A silence longer than a few intervals is a gap, and so is a late first sample: drawn hatched, not bridged.
    @Test func gapsAreSilencesAndALateStart() {
        let t0 = Date(timeIntervalSince1970: 1000)
        let dates = [0, 5, 10, 60, 65].map { t0.addingTimeInterval($0) }
        #expect(ResourceGaps.find(dates, from: t0, cadence: 5) == [t0.addingTimeInterval(10)...t0.addingTimeInterval(60)])
        let late = ResourceGaps.find(dates, from: t0.addingTimeInterval(-100), cadence: 5)
        #expect(late.first == t0.addingTimeInterval(-100)...t0 && late.count == 2)
        #expect(ResourceGaps.find([], from: t0, cadence: 5).isEmpty)
    }
}
