import Foundation
import Testing
@testable import Hostwatch

/// Running Now in Time Travel: process lists written as keyframes + changes, rebuilt for any moment.
@Suite struct ProcessHistoryRecording {
    let t0: Double = 1_800_000_000

    func proc(_ pid: Int, start: Double = 1_799_990_000, cpuTime: Double = 1, mem: Int64 = 10_000_000,
              threads: Int = 2, name: String? = nil) -> RunningProcessInfo {
        RunningProcessInfo(pid: pid, ppid: 1, start: start, uid: 501, user: "alex", name: name ?? "p\(pid)",
                           path: "/usr/bin/p\(pid)", args: "p\(pid) --flag", cpu: 12, cpuTime: cpuTime, mem: mem, threads: threads)
    }

    /// Writes `lists` one minute apart (same day) and returns the indexed lines.
    func record(_ lists: [[RunningProcessInfo]], day: String = "20270115") -> [ProcessHistory.Line] {
        var state = ProcessHistory.WriterState()
        var data = Data()
        for (i, list) in lists.enumerated() {
            data += ProcessHistory.line(for: list, at: t0 + Double(i) * 60, day: day, state: &state)
            data.append(0x0A)
        }
        return ProcessHistory.index(data)
    }

    @Test func rebuildsEachMomentFromAKeyframeAndChanges() throws {
        let lines = record([
            [proc(1), proc(2), proc(3)],
            [proc(1, cpuTime: 31), proc(2), proc(4, start: t0 + 70)],            // 3 ended, 4 started, 1 busy
            [proc(1, cpuTime: 31), proc(4, start: t0 + 70, cpuTime: 2), proc(5, start: t0 + 100)],
        ])
        #expect(lines.map(\.key) == [true, false, false])
        #expect(lines[1].bytes.count < lines[0].bytes.count)                     // only the change
        let first = try #require(ProcessHistory.rebuild(lines, at: t0 + 30))
        #expect(first.processes.map(\.pid) == [1, 2, 3])
        #expect(first.processes.allSatisfy { $0.cpu == nil })                      // nothing to compare yet
        #expect(first.processes[0].args == "p1 --flag" && first.processes[0].user == "alex")
        let second = try #require(ProcessHistory.rebuild(lines, at: t0 + 60))
        #expect(second.processes.map(\.pid) == [1, 2, 4])
        #expect(abs((second.processes[0].cpu ?? 0) - 50) < 0.01)                  // 30 s of CPU in 60 s
        #expect(second.processes[1].cpu == 0)
        #expect(second.processes[0].cpuTime == 31)
        let third = try #require(ProcessHistory.rebuild(lines, at: t0 + 150))
        #expect(third.processes.map(\.pid) == [1, 4, 5])
        #expect(third.at == Date(timeIntervalSince1970: t0 + 120))
    }

    @Test func aReusedPIDIsANewProcess() throws {
        let lines = record([[proc(7, name: "old")], [proc(7, start: t0 + 30, name: "new")]])
        let s = try #require(ProcessHistory.rebuild(lines, at: t0 + 60))
        #expect(s.processes.map(\.name) == ["new"])
    }

    @Test func memoryAndThreadChangesAreKept() throws {
        let lines = record([[proc(1)], [proc(1, mem: 50_000_000, threads: 9)], [proc(1, mem: 50_100_000, threads: 9)]])
        let s = try #require(ProcessHistory.rebuild(lines, at: t0 + 120))
        #expect(s.processes[0].mem == 50_000_000)                                  // under 1%: not rewritten
        #expect(s.processes[0].threads == 9)
    }

    @Test func nothingBeforeTheFirstListOrLongAfterTheLast() {
        let lines = record([[proc(1)], [proc(1)]])
        #expect(ProcessHistory.rebuild(lines, at: t0 - 1) == nil)
        #expect(ProcessHistory.rebuild(lines, at: t0 + 60 + ProcessHistory.maxAge) != nil)
        #expect(ProcessHistory.rebuild(lines, at: t0 + 61 + ProcessHistory.maxAge) == nil)
    }

    @Test func keyframesRepeatAndEachDayStartsWithOne() {
        var state = ProcessHistory.WriterState()
        let keys = (0..<62).map { i -> Bool in
            let line = ProcessHistory.line(for: [proc(1)], at: t0 + Double(i) * 60, day: "20270115", state: &state)
            return ProcessHistory.index(line)[0].key
        }
        #expect(keys.filter { $0 }.count == 3)                                    // minutes 0, 30, 60
        let nextDay = ProcessHistory.line(for: [proc(1)], at: t0 + 62 * 60, day: "20270116", state: &state)
        #expect(ProcessHistory.index(nextDay)[0].key)
    }

    @Test func readsBackFromTheDayFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-proc-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let history = ProcessHistory(directory: dir)
        let date = Date(timeIntervalSince1970: t0)
        let day = MetricsArchive.dayName(date)
        var state = ProcessHistory.WriterState()
        history.archive.append(line: ProcessHistory.line(for: [proc(1), proc(2)], at: t0, day: day, state: &state), day: day)
        history.archive.append(line: ProcessHistory.line(for: [proc(2)], at: t0 + 60, day: day, state: &state), day: day)
        #expect(history.snapshot(at: date.addingTimeInterval(90))?.processes.map(\.pid) == [2])
        #expect(history.snapshot(at: date.addingTimeInterval(90), cache: ProcessDayCache())?.processes.map(\.pid) == [2])
        // Other files in the folder are not process lists.
        #expect(MetricsArchive(directory: dir).days().isEmpty)
        #expect(history.archive.days() == [day])
    }
}
