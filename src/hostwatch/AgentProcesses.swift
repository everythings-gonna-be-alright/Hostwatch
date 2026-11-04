import Darwin
import Foundation

/// One running process, as the collector (root) sees it: the Events tab's "Running Now" list.
struct RunningProcessInfo: Codable, Sendable, Equatable {
    var pid: Int
    var ppid: Int
    var start: Double            // s since 1970 (0: unknown)
    var uid: Int
    var user: String
    var name: String
    var path: String
    var args: String             // command line, secrets masked
    var cpu: Double?             // % of one core since the previous list (nil: no earlier list to compare)
    var cpuTime: Double          // CPU seconds used since it started
    var mem: Int64               // physical footprint
    var threads: Int
}

/// {"kind":"proc_list","list":[…]}: the answer to {"processes": true}.
struct ProcessListMessage: Codable, Sendable {
    var kind = "proc_list"
    var list: [RunningProcessInfo]
}

/// Every running process with its usage. CPU % is measured between two lists (the app asks every few
/// seconds while the list is open); command lines come from the kernel and are masked like history's.
enum ProcessTable {
    static func commandLine(_ pid: Int) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return [] }
        let argc = Int(buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
        var i = 4
        while i < size, buf[i] != 0 { i += 1 }          // the executable path
        while i < size, buf[i] == 0 { i += 1 }          // its padding
        var args: [String] = []
        while args.count < argc, i < size {
            let s = i
            while i < size, buf[i] != 0 { i += 1 }
            args.append(String(decoding: buf[s..<i], as: UTF8.self))
            i += 1
        }
        return args
    }

    static func threads(_ pid: Int) -> Int {
        var info = proc_taskinfo()
        let size = Int32(MemoryLayout<proc_taskinfo>.size)
        return proc_pidinfo(pid_t(pid), PROC_PIDTASKINFO, 0, &info, size) == size ? Int(info.pti_threadnum) : 0
    }

    static func userName(_ uid: Int, cache: inout [Int: String]) -> String {
        if let n = cache[uid] { return n }
        let n = getpwuid(uid_t(uid)).map { String(cString: $0.pointee.pw_name) } ?? String(uid)
        cache[uid] = n
        return n
    }

    /// The list, given the usage snapshot `before` taken `seconds` ago (nil: no CPU %).
    static func rows(now: [ProcessInstance: ProcessUsage], before: [ProcessInstance: ProcessUsage]?, seconds: Double,
                     knownArgs: (Int) -> String?) -> [RunningProcessInfo] {
        var users: [Int: String] = [:]
        var out: [RunningProcessInfo] = []
        out.reserveCapacity(now.count)
        for (key, usage) in now {
            let pid = key.pid
            let path = ProcessList.path(pid)
            let uid = ProcessList.uid(pid).map(Int.init) ?? -1
            var cpu: Double?
            if let before, seconds > 0.5, let prev = before[key] {
                cpu = (100 * max(0, usage.cpuNanos - prev.cpuNanos) / (seconds * 1e9) * 10).rounded() / 10
            }
            let argv = commandLine(pid)
            let args = argv.isEmpty ? (knownArgs(pid) ?? "") : Agent.formatArgs(argv)
            var name = Agent.base(path)
            if name.isEmpty { name = argv.first.map(Agent.base) ?? String(pid) }
            out.append(RunningProcessInfo(pid: pid, ppid: ProcessList.parent(pid), start: ProcessList.start(pid) ?? 0,
                                          uid: uid, user: uid < 0 ? "" : userName(uid, cache: &users), name: name,
                                          path: path, args: args, cpu: cpu, cpuTime: (usage.cpuNanos / 1e7).rounded() / 100,
                                          mem: Int64(usage.footprint), threads: threads(pid)))
        }
        return out.sorted { $0.pid < $1.pid }
    }
}

extension Agent {
    /// Answers {"processes": true} with every running process (on its own thread: a few ms of syscalls).
    func sendProcessList(to client: AgentClient) {
        Thread.detachNewThread { [self] in
            let snap = TopSampler.snapshot()
            let uptime = ProcessInfo.processInfo.systemUptime
            processTableLock.lock()
            let previous = processTableBefore
            processTableBefore = (snap, uptime)
            processTableLock.unlock()
            // A list older than a minute says nothing about CPU now.
            let before = previous.flatMap { uptime - $0.1 < 60 ? $0 : nil }
            let rows = ProcessTable.rows(now: snap, before: before?.0, seconds: before.map { uptime - $0.1 } ?? 0) { [self] pid in
                self.netLock.lock(); defer { self.netLock.unlock() }
                return self.pidArgs[pid]
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys          // "kind" first: the app looks for it there
            guard var data = try? encoder.encode(ProcessListMessage(list: rows)) else { return }
            data.append(0x0A)
            client.lock.lock()
            let ok = client.send(data)
            client.lock.unlock()
            if !ok { dropClient(client) }
        }
    }
}
