import Darwin
import Foundation

// MARK: - Processes (libproc)

enum ProcessList {
    static func allPids() -> [Int] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        return pids.prefix(max(0, Int(n))).filter { $0 > 0 }.map(Int.init)
    }

    static func path(_ pid: Int) -> String {
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid_t(pid), &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
    }

    private static func bsdInfo(_ pid: Int) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        return proc_pidinfo(pid_t(pid), PROC_PIDTBSDINFO, 0, &info, size) == size ? info : nil
    }

    static func parent(_ pid: Int) -> Int { bsdInfo(pid).map { Int($0.pbi_ppid) } ?? 0 }

    /// When the process started (wall clock, seconds since 1970, 0.01 s precision): with the pid, one
    /// exact process even when a pid is reused. Tests set `startLookup` to keep output deterministic.
    nonisolated(unsafe) static var startLookup: (Int) -> Double? = realStart
    static func realStart(_ pid: Int) -> Double? {
        bsdInfo(pid).map { (Double($0.pbi_start_tvsec) * 100 + Double($0.pbi_start_tvusec) / 10_000).rounded() / 100 }
    }
    static func start(_ pid: Int) -> Double? { startLookup(pid) }
    static func uid(_ pid: Int) -> uid_t? { bsdInfo(pid)?.pbi_uid }
}

// MARK: - Child processes

/// A helper program started with posix_spawn: its own session (eslogger ignores its own process
/// group, which would otherwise hide the Terminal it was started from), and no inherited files
/// besides the standard ones, so client sockets never leak into helpers.
struct Spawned {
    let pid: pid_t
    let stdout: Int32?          // read end, when captured
    let stdin: Int32?           // write end, when a pipe (kept open: see nettop)

    enum Input { case null, pipe }
    enum Output { case capture, null, inherit }

    static func start(_ path: String, _ args: [String], stdin: Input = .null, stdout: Output = .capture,
                      stderr: Output = .null) throws -> Spawned {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        // Default signal handling: the collector ignores SIGTERM/SIGINT (it handles them itself), and an ignored
        // signal is inherited, so without this a helper could never be stopped with terminate().
        var all = sigset_t(), none = sigset_t()
        sigfillset(&all); sigemptyset(&none)
        posix_spawnattr_setsigdefault(&attr, &all)
        posix_spawnattr_setsigmask(&attr, &none)
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))

        var inPipe: [Int32] = [-1, -1], outPipe: [Int32] = [-1, -1]
        switch stdin {
        case .null: posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        case .pipe:
            guard pipe(&inPipe) == 0 else { throw POSIXError(.EMFILE) }
            posix_spawn_file_actions_adddup2(&actions, inPipe[0], 0)
        }
        func route(_ output: Output, to fd: Int32) throws {
            switch output {
            case .null: posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", O_WRONLY, 0)
            case .inherit: posix_spawn_file_actions_addinherit_np(&actions, fd)
            case .capture:
                if outPipe[0] < 0 { guard pipe(&outPipe) == 0 else { throw POSIXError(.EMFILE) } }
                posix_spawn_file_actions_adddup2(&actions, outPipe[1], fd)
            }
        }
        try route(stdout, to: 1)
        try route(stderr, to: 2)

        let argv = ([path] + args).map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, path, &actions, &attr, argv, environ)
        if inPipe[0] >= 0 { close(inPipe[0]) }
        if outPipe[1] >= 0 { close(outPipe[1]) }
        guard rc == 0 else {
            if inPipe[1] >= 0 { close(inPipe[1]) }
            if outPipe[0] >= 0 { close(outPipe[0]) }
            throw POSIXError(POSIXErrorCode(rawValue: rc) ?? .EINVAL)
        }
        return Spawned(pid: pid, stdout: outPipe[0] >= 0 ? outPipe[0] : nil, stdin: inPipe[1] >= 0 ? inPipe[1] : nil)
    }

    func terminate() { kill(pid, SIGTERM) }

    /// Waits for exit; closes our pipe ends.
    func wait() {
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        if let stdout { close(stdout) }
        if let stdin { close(stdin) }
    }

    /// Runs a program to completion and returns its stdout (used for lsof).
    static func run(_ path: String, _ args: [String]) throws -> Data {
        let child = try start(path, args)
        var data = Data()
        if let fd = child.stdout {
            var buf = [UInt8](repeating: 0, count: 65_536)
            while true {
                let n = read(fd, &buf, buf.count)
                if n > 0 { data.append(buf, count: n) } else if n < 0 && errno == EINTR { continue } else { break }
            }
        }
        child.wait()
        return data
    }
}

/// Lines from a file descriptor (without the line break).
final class LineReader {
    private let fd: Int32
    private var buffer = Data()
    private var start = 0
    private var chunk = [UInt8](repeating: 0, count: 65_536)

    init(fd: Int32) { self.fd = fd }

    func next() -> Data? {
        while true {
            if let nl = buffer[(buffer.startIndex + start)...].firstIndex(of: 0x0A) {
                let line = buffer[(buffer.startIndex + start)..<nl]
                start = nl - buffer.startIndex + 1
                if start > 1 << 20 { buffer.removeFirst(start); start = 0 }
                return Data(line)
            }
            let n = read(fd, &chunk, chunk.count)
            if n > 0 { buffer.append(chunk, count: n); continue }
            if n < 0 && errno == EINTR { continue }
            // End of input: a last line without a line break.
            guard buffer.count > start else { return nil }
            let rest = Data(buffer[(buffer.startIndex + start)...])
            start = buffer.count
            return rest
        }
    }

    func nextString() -> String? { next().map { String(decoding: $0, as: UTF8.self) } }
}

// MARK: - The socket

enum AgentSocket {
    struct Failure: Error, CustomStringConvertible { let description: String }

    /// Launched by the app: only that process (and its user). Started by hand: only the sudo user.
    static func peerAllowed(pid: Int, uid: uid_t, ownerPid: Int, clientUID: uid_t?) -> Bool {
        if ownerPid > 0 { return pid == ownerPid && uid == clientUID }
        return uid == clientUID
    }

    /// Binds `path` inside a folder only root (we) can write, so nobody else can create or replace
    /// the socket; the socket belongs to `clientUID` with mode 0600, so only that user can connect.
    static func create(path: String, clientUID: uid_t?) throws -> Int32 {
        let folder = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        var st = stat()
        guard lstat(folder, &st) == 0, st.st_mode & S_IFMT == S_IFDIR, st.st_uid == geteuid() else {
            throw Failure(description: "\(folder) is not a folder owned by us; refusing to use it")
        }
        chmod(folder, 0o755)                                 // no group/other write
        if lstat(path, &st) == 0 {
            guard st.st_mode & S_IFMT == S_IFSOCK else {
                throw Failure(description: "\(path) exists and is not a socket; refusing to replace it")
            }
            unlink(path)                                     // stale socket from a crashed collector
        }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure(description: "socket: \(String(cString: strerror(errno)))") }
        // Bound inside a private 0700 folder, narrowed to 0600, then moved into place: nobody can reach it
        // while it's wider, and without changing the process-wide umask (which would race other threads).
        let staging = (path as NSString).deletingLastPathComponent + "/.bind-\(getpid())-\(fd)"
        rmdir(staging)
        guard mkdir(staging, 0o700) == 0 else {
            let e = String(cString: strerror(errno)); close(fd); throw Failure(description: "staging folder: \(e)")
        }
        defer { rmdir(staging) }
        let temp = staging + "/s"
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(temp.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd); throw Failure(description: "socket path too long: \(temp)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0 else {
            let e = String(cString: strerror(errno)); close(fd); throw Failure(description: "bind: \(e)")
        }
        chmod(temp, 0o600)
        if let clientUID, clientUID != geteuid() { chown(temp, clientUID, gid_t.max) }
        guard rename(temp, path) == 0 else {
            let e = String(cString: strerror(errno)); unlink(temp); close(fd); throw Failure(description: "rename: \(e)")
        }
        guard listen(fd, 8) == 0 else { close(fd); throw Failure(description: "listen failed") }
        return fd
    }

    /// (pid, uid) of the process on the other end, from the kernel.
    static func peer(_ fd: Int32) -> (pid: Int, uid: uid_t)? {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0 else { return nil }
        var cred = xucred()
        var clen = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &clen) == 0 else { return nil }
        return (Int(pid), cred.cr_uid)
    }
}

extension Agent {
    /// Accepts verified clients until shutdown; each gets a reader thread for its config lines.
    func acceptClients(_ server: Int32, ownerPid: Int, clientUID: uid_t?) {
        while !isStopped {
            var pfd = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, 1000)
            if ready <= 0 { if ready < 0 && errno != EINTR { break }; continue }
            let fd = accept(server, nil, nil)
            guard fd >= 0 else { if errno == EINTR || errno == EAGAIN { continue }; break }
            guard let peer = AgentSocket.peer(fd) else { close(fd); continue }
            guard AgentSocket.peerAllowed(pid: peer.pid, uid: peer.uid, ownerPid: ownerPid, clientUID: clientUID) else {
                let path = pidPath(peer.pid)
                Agent.log("rejected connection from pid \(peer.pid) (uid \(peer.uid), \(path.isEmpty ? "?" : path))")
                close(fd)
                continue
            }
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            let client = AgentClient(fd: fd)
            addClient(client)
            Thread.detachNewThread { [self] in readClient(client) }
        }
    }

    /// Config lines from a client; the shutdown command needs the token.
    func readClient(_ client: AgentClient) {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while !isStopped {
            let n = recv(client.fd, &chunk, chunk.count, 0)
            if n < 0 { if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }; break }
            if n == 0 { break }
            buffer.append(chunk, count: n)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<nl]
                buffer = Data(buffer[(nl + 1)...])
                guard let cfg = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
                if cfg["cmd"] as? String == "shutdown" {
                    if let token = shutdownToken, !token.isEmpty, cfg["token"] as? String == token {
                        Agent.log("shutdown requested by client")
                        requestShutdown()
                    }
                    continue
                }
                if let fw = cfg["firewall"] as? [String: Any] { firewall.configure(fw, from: client) }
                if let answer = cfg["fw_answer"] as? [String: Any] { firewall.answer(answer) }
                if let w = cfg["watch"] as? [String: Any] { watch.handle(w, from: client) }
                client.lock.lock()
                client.configure(cfg)
                client.lock.unlock()
            }
        }
        dropClient(client)
    }

    /// Exits when the app that launched us goes away.
    func watchOwner(_ pid: Int) {
        while !wait(2) {
            if kill(pid_t(pid), 0) != 0 && errno == ESRCH {
                Agent.log("owner PID \(pid) exited; stopping")
                requestShutdown()
                return
            }
        }
    }
}

// MARK: - Busiest processes (CPU, memory, disk)

struct ProcessUsage: Equatable {
    var cpuNanos: Double
    var footprint: UInt64
    var read: UInt64
    var written: UInt64
}

/// A process instance: pid plus start time, so a reused pid isn't compared with its predecessor.
struct ProcessInstance: Hashable { let pid: Int; let start: UInt64 }

struct TopRow: Equatable {
    var pid: Int
    var cpu: Double              // % of one core
    var mem: UInt64
    var read: Double             // bytes/s
    var write: Double
    var cpuSeconds: Double = 0   // CPU time used since it started
}

enum TopSampler {
    static let tickNanos: Double = {
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        return Double(tb.numer) / Double(tb.denom)
    }()

    static func snapshot() -> [ProcessInstance: ProcessUsage] {
        var out: [ProcessInstance: ProcessUsage] = [:]
        var info = rusage_info_v2()
        for pid in ProcessList.allPids() {
            let rc = withUnsafeMutablePointer(to: &info) {
                $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid_t(pid), RUSAGE_INFO_V2, $0) }
            }
            guard rc == 0 else { continue }
            out[ProcessInstance(pid: pid, start: info.ri_proc_start_abstime)] = ProcessUsage(
                cpuNanos: Double(info.ri_user_time + info.ri_system_time) * tickNanos,
                footprint: info.ri_phys_footprint, read: info.ri_diskio_bytesread, written: info.ri_diskio_byteswritten)
        }
        return out
    }

    /// The busiest processes between two snapshots (by CPU, plus the biggest by memory not already
    /// listed) and total disk read/write per second.
    static func top(before: [ProcessInstance: ProcessUsage], after: [ProcessInstance: ProcessUsage],
                    seconds: Double, limit: Int = 5) -> (rows: [TopRow], read: Double, write: Double) {
        var rows: [TopRow] = []
        var read = 0.0, write = 0.0
        for (key, now) in after {
            guard let prev = before[key] else { continue }   // started during the interval: no baseline
            let dcpu = max(0, now.cpuNanos - prev.cpuNanos)
            let drd = Double(now.read >= prev.read ? now.read - prev.read : 0)
            let dwr = Double(now.written >= prev.written ? now.written - prev.written : 0)
            read += drd
            write += dwr
            rows.append(TopRow(pid: key.pid, cpu: 100 * dcpu / (seconds * 1e9), mem: now.footprint,
                               read: drd / seconds, write: dwr / seconds, cpuSeconds: now.cpuNanos / 1e9))
        }
        let byCPU = Array(rows.sorted { ($0.cpu, $0.pid) > ($1.cpu, $1.pid) }.prefix(limit))
        let byMem = rows.sorted { ($0.mem, $0.pid) > ($1.mem, $1.pid) }.prefix(3).filter { !byCPU.contains($0) }
        return (byCPU + byMem, read / seconds, write / seconds)
    }

    /// Floors for the "vitals" list: below both, a process isn't worth reporting.
    static let vitalsCPU = 5.0                       // % of one core
    static let vitalsMemory: UInt64 = 300_000_000
    static let vitalsLimit = 50

    /// Every process above a floor (by CPU, then memory), so the app can follow processes it saw start.
    static func vitals(before: [ProcessInstance: ProcessUsage], after: [ProcessInstance: ProcessUsage],
                       seconds: Double) -> [TopRow] {
        var rows: [TopRow] = []
        for (key, now) in after {
            guard let prev = before[key] else { continue }
            let cpu = 100 * max(0, now.cpuNanos - prev.cpuNanos) / (seconds * 1e9)
            guard cpu >= vitalsCPU || now.footprint >= vitalsMemory else { continue }
            rows.append(TopRow(pid: key.pid, cpu: cpu, mem: now.footprint, read: 0, write: 0, cpuSeconds: now.cpuNanos / 1e9))
        }
        return Array(rows.sorted { ($0.cpu, $0.mem, $0.pid) > ($1.cpu, $1.mem, $1.pid) }.prefix(vitalsLimit))
    }
}

extension Agent {
    /// Every `interval` s, while a client asked for it: the busiest processes.
    func runTopSampler(interval: TimeInterval = 5) {
        var before: [ProcessInstance: ProcessUsage]?
        var started = ProcessInfo.processInfo.systemUptime
        while !wait(interval) {
            guard anyClientWantsTop else { before = nil; continue }
            let now = ProcessInfo.processInfo.systemUptime
            let snap = TopSampler.snapshot()
            if let before {
                let result = TopSampler.top(before: before, after: snap, seconds: now - started)
                let procs: [JValue] = result.rows.map { r in
                    let path = pidPath(r.pid)
                    let name = Agent.base(path)
                    return .object([("pid", .int(r.pid)), ("name", .str(name.isEmpty ? String(r.pid) : name)),
                                    ("path", .str(path)), ("cpu", .double((r.cpu * 10).rounded() / 10)),
                                    ("mem", .int(Int(r.mem))), ("read", .int(Int(r.read.rounded()))),
                                    ("write", .int(Int(r.write.rounded())))])
                }
                let vitals: [JValue] = TopSampler.vitals(before: before, after: snap, seconds: now - started).map { r in
                    let path = pidPath(r.pid)
                    return .object([("pid", .int(r.pid)), ("start", .double(ProcessList.start(r.pid) ?? 0)),
                                    ("name", .str(Agent.base(path))), ("path", .str(path)),
                                    ("cpu", .double((r.cpu * 10).rounded() / 10)), ("mem", .int(Int(r.mem))),
                                    ("cpu_total", .double(r.cpuSeconds.rounded()))])
                }
                publish(AgentEvent([("kind", .str("top")), ("procs", .array(procs)),
                                    ("disk_read", .int(Int(result.read.rounded()))),
                                    ("disk_write", .int(Int(result.write.rounded()))),
                                    ("vitals", .array(vitals))]))
            }
            before = snap
            started = now
        }
    }
}
