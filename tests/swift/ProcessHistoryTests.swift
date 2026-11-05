import Foundation
import Testing
@testable import Hostwatch

/// Running Now in Time Travel: process lists written as keyframes + changes, rebuilt for any moment.
@Suite struct ProcessHistoryRecording {
    let t0: Double = 1_800_000_000

    func proc(_ pid: Int, start: Double = 1_799_990_000, cpuTime: Double = 1, mem: Int64 = 10_000_000,
              threads: Int = 2, name: String? = nil, written: Int64? = nil) -> RunningProcessInfo {
        RunningProcessInfo(pid: pid, ppid: 1, start: start, uid: 501, user: "alex", name: name ?? "p\(pid)",
                           path: "/usr/bin/\(name ?? "p\(pid)")", args: "p\(pid) --flag", cpu: 12, cpuTime: cpuTime, mem: mem,
                           threads: threads, written: written)
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
            [proc(1, cpuTime: 31), proc(2), proc(4, start: t0 + 50)],            // 3 ended, 4 started, 1 busy
            [proc(1, cpuTime: 31), proc(4, start: t0 + 50, cpuTime: 2), proc(5, start: t0 + 100)],
        ])
        #expect(lines.map(\.key) == [true, false, false])
        #expect(lines[1].bytes.count < lines[0].bytes.count)                     // only the change
        let first = try #require(ProcessHistory.rebuild(lines, at: t0 + 30))
        #expect(first.processes.map(\.pid) == [1, 2, 3])                        // 3 is gone only by the next list
        #expect(first.processes[0].args == "p1 --flag" && first.processes[0].user == "alex")
        #expect(abs((first.processes[0].cpu ?? 0) - 50) < 0.01)                   // 30 s of CPU in 60 s
        #expect(abs(first.processes[0].cpuTime - 16) < 0.01)                      // halfway between 1 and 31
        #expect(first.recordedAt == Date(timeIntervalSince1970: t0))
        #expect(first.at == Date(timeIntervalSince1970: t0 + 30))
        let third = try #require(ProcessHistory.rebuild(lines, at: t0 + 150))
        #expect(third.processes.map(\.pid) == [1, 4, 5])
        #expect(third.recordedAt == Date(timeIntervalSince1970: t0 + 120))
        #expect(third.processes[1].cpu.map { abs($0 - 1.0 / 60 * 100) < 0.01 } == true)   // last minute's rate
    }

    /// Playing through a minute: the list changes between recorded lists (it used to stay frozen).
    @Test func aMinuteBetweenListsMoves() throws {
        let lines = record([[proc(1, cpuTime: 0)], [proc(1, cpuTime: 60), proc(9, start: t0 + 45, cpuTime: 3)]])
        let at10 = try #require(ProcessHistory.rebuild(lines, at: t0 + 10))
        let at50 = try #require(ProcessHistory.rebuild(lines, at: t0 + 50))
        #expect(at10.processes.map(\.pid) == [1])                               // 9 hasn't started yet
        #expect(at50.processes.map(\.pid) == [1, 9])                            // 9 appears at its start
        #expect(at10.processes[0].cpuTime < at50.processes[0].cpuTime)
        #expect(abs(at50.processes[1].cpuTime - 1) < 0.01)                       // 5 s of its 15 s so far
        #expect(abs((at50.processes[1].cpu ?? 0) - 20) < 0.01)
    }

    /// Which programs wrote to disk in a period: from the minute lists, per program, ended processes included.
    @Test func writersCountBytesWrittenInThePeriod() throws {
        let gb: Int64 = 1_000_000_000
        let lines = record([
            [proc(1, written: 5 * gb), proc(2, name: "backupd", written: 100)],
            [proc(1, written: 6 * gb), proc(2, name: "backupd", written: 3 * gb + 100), proc(3, start: t0 + 70, name: "tool", written: gb)],
            [proc(1, written: 6 * gb), proc(3, start: t0 + 70, name: "tool", written: 2 * gb),
             proc(4, start: t0 + 130, name: "tool", written: gb / 2)],              // 2 ended; a second "tool"
        ])
        let all = ProcessHistory.writers(lines, from: t0 + 1, to: t0 + 200)
        #expect(all.map(\.name) == ["backupd", "tool", "p1"])
        #expect(all[0].bytes == 3 * gb)                                         // ended, still counted
        #expect(all[1].bytes == 2 * gb + gb / 2 && all[1].processes == 2)       // started in the period: from zero
        #expect(all[2].bytes == gb)                                             // running at the start: only the growth
        let lastMinute = ProcessHistory.writers(lines, from: t0 + 60, to: t0 + 200)
        #expect(lastMinute.map(\.name) == ["tool"])
        #expect(lastMinute[0].bytes == gb + gb / 2)
        // Interpolated between lists like CPU time.
        let mid = try #require(ProcessHistory.rebuild(lines, at: t0 + 30))
        #expect(mid.processes.first { $0.pid == 2 }?.written == 1_500_000_100)
    }

    /// What was writing at a moment: bytes per second between the lists around it, not the total since start.
    @Test func writeRateAroundTheMoment() throws {
        let mb: Int64 = 1_000_000
        let lines = record([
            [proc(1, written: 90_000 * mb), proc(2, written: 10 * mb)],
            [proc(1, written: 90_000 * mb), proc(2, written: 70 * mb)],
            [proc(1, written: 90_000 * mb), proc(2, written: 70 * mb), proc(3, start: t0 + 90, written: 30 * mb)],
        ])
        let at30 = try #require(ProcessHistory.rebuild(lines, at: t0 + 30))
        #expect(at30.processes.first { $0.pid == 1 }?.writeRate == 0)              // huge total, writing nothing
        #expect(at30.processes.first { $0.pid == 2 }?.writeRate == 1_000_000)       // 60 MB in 60 s
        let at100 = try #require(ProcessHistory.rebuild(lines, at: t0 + 100))
        let three = try #require(at100.processes.first { $0.pid == 3 })            // started at +90, 30 MB by +120
        #expect(three.writeRate == 1_000_000)
        #expect(abs((three.written ?? 0) - 10 * mb) <= 1)
        // The newest list (no next one): the minute before it.
        let at150 = try #require(ProcessHistory.rebuild(lines, at: t0 + 150))
        #expect(at150.processes.first { $0.pid == 2 }?.writeRate == 0)
    }

    @Test func aReusedPIDIsANewProcess() throws {
        let lines = record([[proc(7, name: "old")], [proc(7, start: t0 + 30, name: "new")]])
        let s = try #require(ProcessHistory.rebuild(lines, at: t0 + 60))
        #expect(s.processes.map(\.name) == ["new"])
        let before = try #require(ProcessHistory.rebuild(lines, at: t0 + 40))     // the new one started at +30
        #expect(before.processes.map(\.name) == ["new"])
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

/// The history size limit covers activity, metrics and process lists together.
@Suite struct HistorySizeLimit {
    func file(_ dir: URL, _ name: String, _ bytes: Int) throws {
        try Data(count: bytes).write(to: dir.appendingPathComponent(name))
    }

    @Test func oldestDayGoesFirstInEveryForm() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-limit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try file(dir, "activity-20270101-080000-000.jsonl.gz", 1000)
        try file(dir, "activity-20270101-080000-000.jsonl.idx", 10)
        try file(dir, "metrics-20270101.jsonl.gz", 300)
        try file(dir, "processes-20270101.jsonl.gz", 400)
        try file(dir, "activity-20270102-080000-000.jsonl.gz", 1000)
        try file(dir, "activity-20270102-080000-000.jsonl.idx", 10)
        try file(dir, "processes-20270102.jsonl.gz", 400)
        try file(dir, "activity-20270103-080000-000.jsonl", 500)              // being written
        try file(dir, "processes-20270103.jsonl", 900)                       // today
        try file(dir, "notes.txt", 5000)                                    // not ours: never counted
        let current = dir.appendingPathComponent("activity-20270103-080000-000.jsonl")
        let kept = HistoryFiles.kept(in: dir, current: current, today: "20270103")
        #expect(kept.reduce(0) { $0 + $1.bytes } == 4520)
        // Everything but the file being written must fit in 3000 with 500 free for it.
        let others = kept.filter { $0.url != current }
        let plan = HistoryFiles.trimPlan(others, limit: 3000, reserve: 500)
        #expect(plan.delete.map(\.url.lastPathComponent) == ["activity-20270101-080000-000.jsonl",
                                                              "metrics-20270101.jsonl.gz", "processes-20270101.jsonl.gz"])
        #expect(plan.remaining == 1410 + 900)
        for f in plan.delete where f.kind == .activity { HistoryFiles.remove(f.url) }
        let left = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(!left.contains { $0.hasPrefix("activity-20270101") })          // .gz and .idx both gone
    }

    @Test func todayAndTheCurrentFileStayEvenOverTheLimit() {
        let dir = URL(fileURLWithPath: "/h")
        let files = [
            HistoryFiles.Kept(url: dir.appendingPathComponent("processes-20270103.jsonl"), bytes: 9000, day: "20270103",
                              kind: .daily, removable: false),
            HistoryFiles.Kept(url: dir.appendingPathComponent("metrics-20270102.jsonl.gz"), bytes: 10, day: "20270102",
                              kind: .daily, removable: true),
        ]
        let plan = HistoryFiles.trimPlan(files, limit: 1000, reserve: 0)
        #expect(plan.delete.count == 1 && plan.remaining == 9000)
    }
}
