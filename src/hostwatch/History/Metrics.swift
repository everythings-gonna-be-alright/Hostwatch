import Darwin
import Combine
import Foundation

// MARK: - Samples

/// One of the busiest processes in a sample (from the collector, which can see every user's processes).
struct TopProcess: Codable, Hashable, Sendable {
    var pid: Int
    var name: String
    var path: String
    var cpu: Double              // % of one core (200 = two full cores)
    var mem: Int64               // physical footprint, bytes
    var read: Double             // disk bytes/s
    var write: Double
}

/// System-wide resource use at one moment (every 5 s).
struct MetricSample: Codable, Sendable, Equatable {
    var t: Double                // seconds since 1970
    var cpu: Double              // % of all cores, 0...100
    var mem: Double              // used memory, 0...1
    var pressure: Int            // macOS memory pressure: 1 normal, 2 warning, 4 critical
    var netIn: Double            // bytes/s
    var netOut: Double
    var diskRead: Double?        // bytes/s (from the collector)
    var diskWrite: Double?
    var top: [TopProcess]?
    /// Processes started while watching that ran heavy at this moment (live strip and badges, for Time Travel).
    var heavy: [HeavyProcess]?
    /// Free space on the startup disk, bytes (what Finder calls Available: includes purgeable space).
    var free: Double?

    var date: Date { Date(timeIntervalSince1970: t) }

    enum CodingKeys: String, CodingKey {
        case t, cpu = "c", mem = "m", pressure = "p", netIn = "ni", netOut = "no", diskRead = "dr", diskWrite = "dw", top
        case heavy = "h", free = "df"
    }
}

// MARK: - Reading the system (no root needed)

/// CPU, memory and network counters; rates come from the difference between two calls.
final class SystemSampler {
    private var lastTicks: (busy: UInt64, total: UInt64)?
    private var lastNet: (bytesIn: UInt64, bytesOut: UInt64, at: TimeInterval)?

    struct Reading { var cpu: Double; var mem: Double; var pressure: Int; var netIn: Double; var netOut: Double }

    func read(now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Reading {
        Reading(cpu: cpu(), mem: Self.memoryUsed(), pressure: Self.memoryPressure(), netIn: 0, netOut: 0)
            .with { r in
                let (i, o) = Self.networkBytes()
                if let last = lastNet, now > last.at {
                    r.netIn = Double(i &- last.bytesIn) / (now - last.at)
                    r.netOut = Double(o &- last.bytesOut) / (now - last.at)
                    if i < last.bytesIn || o < last.bytesOut { r.netIn = 0; r.netOut = 0 }   // counters reset
                }
                lastNet = (i, o, now)
            }
    }

    /// % of all cores busy since the previous call.
    private func cpu() -> Double {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let ok = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count)
            }
        }
        guard ok == KERN_SUCCESS else { return 0 }
        let user = UInt64(info.cpu_ticks.0), system = UInt64(info.cpu_ticks.1)
        let idle = UInt64(info.cpu_ticks.2), nice = UInt64(info.cpu_ticks.3)
        let busy = user + system + nice, total = busy + idle
        defer { lastTicks = (busy, total) }
        guard let last = lastTicks, total > last.total else { return 0 }
        return min(100, max(0, Double(busy - last.busy) / Double(total - last.total) * 100))
    }

    /// Used memory as Activity Monitor counts it (app + wired + compressed), as a fraction.
    static func memoryUsed() -> Double {
        var stats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let ok = withUnsafeMutablePointer(to: &stats) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        guard ok == KERN_SUCCESS else { return 0 }
        let page = UInt64(vm_kernel_page_size)
        let app = UInt64(stats.internal_page_count) &- UInt64(stats.purgeable_count)
        let used = (app + UInt64(stats.wire_count) + UInt64(stats.compressor_page_count)) * page
        return min(1, Double(used) / Double(ProcessInfo.processInfo.physicalMemory))
    }

    static func memoryPressure() -> Int {
        var level: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname("kern.memorystatus_vm_pressure_level", &level, &size, nil, 0) == 0 else { return 1 }
        return Int(level)
    }

    /// Total bytes in/out on physical interfaces (Wi-Fi, Ethernet, cellular); VPN tunnels and
    /// loopback are skipped so traffic isn't counted twice.
    static func networkBytes() -> (UInt64, UInt64) {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var size = 0
        guard sysctl(&mib, 6, nil, &size, nil, 0) == 0, size > 0 else { return (0, 0) }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 6, &buffer, &size, nil, 0) == 0 else { return (0, 0) }
        var bytesIn: UInt64 = 0, bytesOut: UInt64 = 0
        var offset = 0
        var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
        buffer.withUnsafeBytes { raw in
            while offset + MemoryLayout<if_msghdr>.size <= size {
                let header = raw.load(fromByteOffset: offset, as: if_msghdr.self)
                guard header.ifm_msglen > 0 else { break }
                if Int32(header.ifm_type) == RTM_IFINFO2, offset + MemoryLayout<if_msghdr2>.size <= size {
                    let msg = raw.loadUnaligned(fromByteOffset: offset, as: if_msghdr2.self)
                    if if_indextoname(UInt32(msg.ifm_index), &name) != nil {
                        let ifname = String(cString: name)
                        if ifname.hasPrefix("en") || ifname.hasPrefix("pdp_ip") {
                            bytesIn &+= msg.ifm_data.ifi_ibytes
                            bytesOut &+= msg.ifm_data.ifi_obytes
                        }
                    }
                }
                offset += Int(header.ifm_msglen)
            }
        }
        return (bytesIn, bytesOut)
    }
}

private extension SystemSampler.Reading {
    func with(_ change: (inout Self) -> Void) -> Self { var copy = self; change(&copy); return copy }
}

// MARK: - Files

/// Metrics on disk next to the activity history: one JSON line per sample in a daily file
/// (`metrics-YYYYMMDD.jsonl`, about 2-5 MB a day); past days are gzip-compressed (~10x smaller).
struct MetricsArchive: Sendable {
    let directory: URL
    /// File name prefix: "metrics" (resource samples) or "processes" (process lists for Time Travel).
    var prefix = "metrics"

    static func dayName(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd"
        return f.string(from: date)
    }

    func plainURL(day: String) -> URL { directory.appendingPathComponent("\(prefix)-\(day).jsonl") }
    func gzURL(day: String) -> URL { plainURL(day: day).appendingPathExtension("gz") }

    /// Day names with a metrics file, oldest first.
    func days() -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return Array(Set(names.filter { $0.hasPrefix(prefix + "-") }.compactMap { name -> String? in
            let day = name.dropFirst(prefix.count + 1).prefix(8)
            return day.count == 8 ? String(day) : nil
        })).sorted()
    }

    func append(_ sample: MetricSample) {
        guard let line = try? JSONEncoder().encode(sample) else { return }
        append(line: line, day: Self.dayName(sample.date))
    }

    /// One line (without its newline) at the end of a day's file.
    func append(line raw: Data, day: String) {
        var line = raw
        line.append(0x0A)
        let url = plainURL(day: day)
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: line)
            try? handle.close()
        } else {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: url.path, contents: line, attributes: [.posixPermissions: 0o600])
        }
    }

    /// A day's file, plain or decompressed (empty when there is none).
    func data(day: String) -> Data {
        var data = Data()
        if let plain = try? Data(contentsOf: plainURL(day: day)) {
            data = plain
        } else if let gz = try? Data(contentsOf: gzURL(day: day)) {
            HistoryFiles.gunzipMembers(gz) { data.append($0) }
        }
        return data
    }

    /// Every sample of one day, in time order.
    func samples(day: String) -> [MetricSample] {
        let data = data(day: day)
        let decoder = JSONDecoder()
        return data.split(separator: 0x0A).compactMap { try? decoder.decode(MetricSample.self, from: $0) }
    }

    /// Compresses finished days and removes days older than `keepFrom` (the oldest activity history).
    func maintain(today: String, keepFrom: String?) {
        for day in days() {
            if let keepFrom, day < keepFrom {
                try? FileManager.default.removeItem(at: plainURL(day: day))
                try? FileManager.default.removeItem(at: gzURL(day: day))
                continue
            }
            let plain = plainURL(day: day)
            guard day < today, FileManager.default.fileExists(atPath: plain.path),
                  let data = try? Data(contentsOf: plain), let gz = try? HistoryFiles.gzip(data) else { continue }
            let tmp = gzURL(day: day).appendingPathExtension("tmp")
            do {
                try gz.write(to: tmp, options: .atomic)
                try? FileManager.default.removeItem(at: gzURL(day: day))
                try FileManager.default.moveItem(at: tmp, to: gzURL(day: day))
                try FileManager.default.removeItem(at: plain)
            } catch {
                try? FileManager.default.removeItem(at: tmp)
            }
        }
    }

    func removeAll() {
        for day in days() {
            try? FileManager.default.removeItem(at: plainURL(day: day))
            try? FileManager.default.removeItem(at: gzURL(day: day))
        }
    }
}

// MARK: - Live store

/// Samples every 5 s, keeps the last 30 minutes in memory for the live strip, writes every sample
/// to disk for Time Travel, and reads past samples back by time.
@MainActor
final class MetricsStore: ObservableObject {
    static let interval: TimeInterval = 5
    @Published private(set) var recent: [MetricSample] = []
    @Published var showTop = false                       // the strip's "busiest processes" popover
    @Published var showDisk = false                      // the strip's disk space popover
    var latest: MetricSample? { recent.last }

    private let sampler = SystemSampler()
    private let directory: () -> URL
    private var timer: Timer?
    private var lastTop: (date: Date, procs: [TopProcess], read: Double, write: Double)?
    /// Heavy processes now (from `ProcessVitals`), stored with each sample.
    var heavyProvider: () -> [HeavyProcess] = { [] }
    private let writer = DispatchQueue(label: "hostwatch.metrics", qos: .utility)
    private var lastMaintenanceDay = ""
    private let cache = MetricsCache()

    init(directory: @escaping () -> URL) {
        self.directory = directory
    }

    var archive: MetricsArchive { MetricsArchive(directory: directory()) }

    func start() {
        guard timer == nil else { return }
        _ = sampler.read()                                   // baseline for the first rates
        timer = Timer.scheduledTimer(withTimeInterval: Self.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    /// From the collector: the busiest processes and disk throughput of the last 5 s.
    func receiveTop(_ procs: [TopProcess], diskRead: Double, diskWrite: Double, at date: Date = Date()) {
        lastTop = (date, procs, diskRead, diskWrite)
    }

    private func tick() {
        let now = Date()
        let r = sampler.read()
        var sample = MetricSample(t: now.timeIntervalSince1970.rounded(), cpu: (r.cpu * 10).rounded() / 10,
                                  mem: (r.mem * 1000).rounded() / 1000, pressure: r.pressure,
                                  netIn: r.netIn.rounded(), netOut: r.netOut.rounded())
        if let top = lastTop, now.timeIntervalSince(top.date) < Self.interval * 2 {
            sample.diskRead = top.read
            sample.diskWrite = top.write
            sample.top = top.procs
        }
        let heavy = heavyProvider()
        if !heavy.isEmpty { sample.heavy = heavy }
        sample.free = DiskSpace.shared.free(now: now).map(Double.init)
        recent.append(sample)
        if let first = recent.first, now.timeIntervalSince(first.date) > 30 * 60 { recent.removeFirst() }
        let archive = archive
        let today = MetricsArchive.dayName(now)
        let maintain = today != lastMaintenanceDay
        lastMaintenanceDay = today
        let keepFrom = maintain ? HistoryFiles.list(in: archive.directory).first.flatMap { Self.day(ofHistory: $0.name) } : nil
        writer.async {
            archive.append(sample)
            if maintain { archive.maintain(today: today, keepFrom: keepFrom) }
        }
        cache.invalidate(day: today)
    }

    /// "activity-20261101-071732-871.jsonl" -> "20261101".
    nonisolated static func day(ofHistory name: String) -> String? {
        let parts = name.split(separator: "-")
        return parts.count >= 2 && parts[1].count == 8 ? String(parts[1]) : nil
    }

    /// Samples between two moments (from memory when recent, else from disk; off the main thread).
    func samples(from: Date, to: Date) async -> [MetricSample] {
        if let first = recent.first, first.date <= from { return recent.filter { $0.date >= from && $0.date <= to } }
        let archive = archive, cache = cache
        return await Task.detached(priority: .userInitiated) {
            cache.samples(archive, from: from, to: to)
        }.value
    }
}

/// Parsed days, kept so scrubbing doesn't re-read files (today is re-read when it changes).
final class MetricsCache: @unchecked Sendable {
    private let lock = NSLock()
    private var days: [String: [MetricSample]] = [:]

    func invalidate(day: String) { lock.lock(); days[day] = nil; lock.unlock() }

    func samples(_ archive: MetricsArchive, from: Date, to: Date) -> [MetricSample] {
        var out: [MetricSample] = []
        var day = Calendar.current.startOfDay(for: from)
        while day <= to {
            let name = MetricsArchive.dayName(day)
            lock.lock()
            let cached = days[name]
            lock.unlock()
            let list = cached ?? archive.samples(day: name)
            if cached == nil { lock.lock(); days[name] = list; if days.count > 30 { days.removeAll() }; lock.unlock() }
            out += list.filter { $0.date >= from && $0.date <= to }
            guard let next = Calendar.current.date(byAdding: .day, value: 1, to: day) else { break }
            day = next
        }
        return out
    }
}
