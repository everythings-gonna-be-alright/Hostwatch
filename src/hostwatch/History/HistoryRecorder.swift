import AppKit
import Foundation
import Network

/// Appends every collector event to rotating JSONL files, capped at `maxBytes` in total.
/// Uses its own unthrottled connection, so history is independent of overlay pause/filters.
final class HistoryRecorder: ObservableObject, @unchecked Sendable {
    static let defaultMaxBytes: Int64 = 5_000_000_000   // 5 GB
    static let sizePresets: [Int64] = [500_000_000, 1_000_000_000, 5_000_000_000,
                                       10_000_000_000, 25_000_000_000, 50_000_000_000]
    static var defaultDirectory: URL {
        AppPaths.logs.appendingPathComponent("History", isDirectory: true)
    }

    // MARK: Settings (main thread)

    @Published var enabled: Bool {
        didSet { defaults.set(enabled, forKey: Keys.enabled); restart() }
    }
    @Published var maxBytes: Int64 {
        didSet {
            defaults.set(maxBytes, forKey: Keys.maxBytes)
            let limit = maxBytes
            queue.async { self.limit = limit; self.enforceLimit() }
        }
    }
    @Published var applyExclusions: Bool {
        didSet { defaults.set(applyExclusions, forKey: Keys.applyExclusions); pushConfig() }
    }
    @Published var directory: URL {
        didSet { defaults.set(directory.path, forKey: Keys.directory); restart() }
    }

    // MARK: Status (main thread)

    @Published private(set) var totalBytes: Int64 = 0
    @Published private(set) var recording = false
    @Published private(set) var lastError: String?

    // MARK: Queue-confined state

    private let queue = DispatchQueue(label: "hostwatch.history")
    private let compressQueue = DispatchQueue(label: "hostwatch.history.compress", qos: .utility)
    private var active = false
    private var limit: Int64
    private var connection: NWConnection?
    /// The file being written, compressed as it goes (`HistoryStream`).
    private var stream: HistoryStream?
    private var flushTimer: DispatchSourceTimer?
    private var currentURL: URL? { stream?.stem }
    private var currentSize: Int64 { stream?.diskBytes ?? 0 }
    private var otherSegmentsSize: Int64 = 0
    private var lastEnforce = Date.distantPast
    private var pending = Data()
    private var config: [String: Any] = [:]
    private var lastStatusPublish = Date.distantPast

    private let defaults = UserDefaults.standard
    private var exclusionLines: [String] = []
    private var kinds: [String] = EventKind.allCases.map(\.rawValue)

    private enum Keys {
        static let enabled = "historyEnabled"
        static let maxBytes = "historyMaxBytes"
        static let applyExclusions = "historyApplyExclusions"
        static let directory = "historyDirectory"
    }

    init() {
        let defaults = UserDefaults.standard
        enabled = defaults.object(forKey: Keys.enabled) as? Bool ?? true
        let stored = (defaults.object(forKey: Keys.maxBytes) as? NSNumber)?.int64Value ?? 0
        let initialMax = stored > 0 ? stored : Self.defaultMaxBytes
        maxBytes = initialMax
        limit = initialMax
        applyExclusions = defaults.object(forKey: Keys.applyExclusions) as? Bool ?? false
        directory = defaults.string(forKey: Keys.directory).map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? Self.defaultDirectory
    }

    /// A file is full at ~1/20 of the cap, between 1 MB and 100 MB of plain text: rotation trims in
    /// small steps, and finished files get compressed sooner.
    static let maxSegmentBytes: Int64 = 100_000_000
    private var segmentBytes: Int64 {
        min(max(limit / 20, 1_000_000), Self.maxSegmentBytes)
    }

    // MARK: Public API (main thread)

    func start() {
        let dir = directory, on = enabled
        queue.async {
            self.active = on
            guard on else { return }
            self.openFiles(in: dir)
            self.connect()
        }
        scrubOldSecretsOnce(in: dir)
    }

    /// History recorded before command lines were fully masked: mask it once, in the background. The
    /// file being written is skipped here and masked when it's finished (`compressLater`).
    private func scrubOldSecretsOnce(in dir: URL) {
        let flag = "historySecretsScrubbed2"
        guard !UserDefaults.standard.bool(forKey: flag) else { return }
        compressQueue.async {
            let files = HistoryFiles.list(in: dir)
            var total = 0
            for file in files.dropLast() {   // the newest one is still being written
                total += (try? HistoryFiles.scrubSecrets(file)) ?? 0
            }
            DispatchQueue.main.async { UserDefaults.standard.set(true, forKey: flag) }
            if total > 0 { NSLog("Hostwatch: masked secrets in %d recorded command lines", total) }
        }
    }

    func stop() {
        queue.sync { self.shutDown() }
    }

    /// Called whenever the UI's exclusions or kinds change.
    func updateFilters(exclusions: [String], kinds: [String]) {
        exclusionLines = exclusions
        self.kinds = kinds
        pushConfig()
    }

    func clearHistory() {
        let dir = directory, on = enabled
        queue.async {
            self.closeFile()
            for stem in self.segments(in: dir) { HistoryFiles.remove(stem) }
            self.otherSegmentsSize = 0
            if on { self.openFiles(in: dir) }
            self.publishStatus(force: true)
        }
    }

    func revealInFinder() {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        NSWorkspace.shared.open(directory)
    }

    private func restart() {
        queue.async { self.shutDown() }
        start()
    }

    private func pushConfig() {
        let cfg: [String: Any] = applyExclusions
            ? ["exclude": exclusionLines, "kinds": kinds, "rate_limit": false]
            : ["exclude": [String](), "kinds": EventKind.allCases.map(\.rawValue), "rate_limit": false]
        queue.async {
            self.config = cfg
            self.sendConfig()
        }
    }

    // MARK: Files (queue)

    /// History files as stems (`activity-x.jsonl`, whether plain or compressed), oldest first.
    private func segments(in dir: URL) -> [URL] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        let stems = Set(names.filter(HistoryFiles.isHistoryName).map {
            HistoryFiles.stem(dir.appendingPathComponent($0)).lastPathComponent
        })
        return stems.sorted().map { dir.appendingPathComponent($0) }
    }

    /// Bytes on disk (compressed files count compressed).
    private func size(of stem: URL) -> Int64 { HistoryFiles.diskSize(stem) }

    /// Compresses a finished file in the background, then re-applies the size limit.
    private func compressLater(_ plain: URL) {
        compressQueue.async { [weak self] in
            guard FileManager.default.fileExists(atPath: plain.path) else { return }
            _ = try? HistoryFiles.scrubSecrets(.plain(plain))   // anything recorded before full masking
            do { try HistoryFiles.compress(plain) } catch { self?.report("Compressing \(plain.lastPathComponent) failed") }
            self?.queue.async { self?.enforceLimit() }
        }
    }

    private func openFiles(in dir: URL) {
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            report("Cannot create \(dir.path): \(error.localizedDescription)")
            return
        }
        let fm = FileManager.default
        // Files an earlier run left open-ended (.blocks, no index; after a crash also an unfinished last block). The
        // newest one continues if it has room; the others are finished (their unfinished tail recovered first).
        let open = segments(in: dir).filter {
            fm.fileExists(atPath: HistoryFiles.blocksURL($0).path) && !fm.fileExists(atPath: HistoryFiles.indexURL($0).path)
                && !fm.fileExists(atPath: $0.path)
        }
        var continued: HistoryStream?
        for stem in open {
            let newest = stem == open.last
            if newest, let s = try? HistoryStream(stem: stem), s.rawBytes < segmentBytes {
                continued = s
            } else {
                HistoryStream.finishOrphan(stem)
            }
        }
        if let continued { stream = continued } else { openStream(dir.appendingPathComponent(Self.newSegmentName())) }
        // Finished files still plain (older versions, or compression interrupted): compress them once.
        for stem in segments(in: dir) where stem != currentURL && fm.fileExists(atPath: stem.path) {
            compressLater(stem)
        }
        startFlushTimer()
        enforceLimit()
    }

    private func openStream(_ stem: URL) {
        do {
            stream = try HistoryStream(stem: stem)
            report(nil)
        } catch {
            stream = nil
            report("Cannot open \(stem.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// Every second: what arrived goes into the file (an app crash loses at most this second); blocks are
    /// finished every 30 s.
    private func startFlushTimer() {
        guard flushTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + HistoryStream.syncInterval, repeating: HistoryStream.syncInterval, leeway: .milliseconds(200))
        t.setEventHandler { [weak self] in
            do { try self?.stream?.tick() } catch { self?.report("Write failed: \(error.localizedDescription)") }
        }
        t.resume()
        flushTimer = t
    }

    /// Writes what's waiting and lets go of the file (it stays open-ended and is continued next time).
    private func closeFile() {
        flushTimer?.cancel()
        flushTimer = nil
        do { try stream?.close() } catch { report("Write failed: \(error.localizedDescription)") }
        stream = nil
    }

    private static func newSegmentName() -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss-SSS"
        return "activity-\(f.string(from: Date())).jsonl"
    }

    /// Deletes oldest files so finished files plus a full current file fit within the cap.
    /// One limit for everything recorded here: activity, resource samples (metrics-*) and process lists
    /// (processes-*). The oldest day goes first, in every form (.jsonl, .gz, .idx).
    private func enforceLimit() {
        guard let current = currentURL else { return }
        lastEnforce = Date()
        let files = HistoryFiles.kept(in: current.deletingLastPathComponent(), current: current,
                                      today: MetricsArchive.dayName(Date()))
        let others = files.filter { $0.url != current }
        let plan = HistoryFiles.trimPlan(others, limit: limit, reserve: segmentBytes)
        for f in plan.delete {
            if f.kind == .activity { HistoryFiles.remove(f.url) } else { try? FileManager.default.removeItem(at: f.url) }
        }
        otherSegmentsSize = plan.remaining
        publishStatus(force: true)
    }

    private func write(_ chunk: Data) {
        guard let stream else { return }
        do {
            try stream.append(Data(chunk))
        } catch {
            report("Write failed: \(error.localizedDescription)")
            return
        }
        if stream.rawBytes >= segmentBytes {
            // Full: its index replaces the block list, and a new file starts (already compressed: nothing to redo).
            do { try stream.finish() } catch { report("Finishing \(stream.stem.lastPathComponent) failed") }
            let dir = stream.stem.deletingLastPathComponent()
            self.stream = nil
            openStream(dir.appendingPathComponent(Self.newSegmentName()))
            enforceLimit()
        } else if Date().timeIntervalSince(lastEnforce) > 10 * 60 {
            enforceLimit()          // metrics and process lists grow between segments too
        }
        publishStatus(force: false)
    }

    // MARK: Connection (queue)

    private func connect() {
        guard active, connection == nil else { return }
        // Same rule as the live view: only a socket that only the root collector could have made.
        guard CollectorSocket.check() == .ok else {
            queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.connect() }
            return
        }
        let conn = NWConnection(to: CollectorSocket.endpoint, using: .tcp)
        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self, conn === self.connection else { return }
            switch state {
            case .ready:
                self.setRecording(true)
                self.sendConfig()
                self.receive(conn)
            case .waiting, .failed, .cancelled:
                self.dropConnection()
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func dropConnection() {
        connection?.cancel()
        connection = nil
        pending.removeAll()
        setRecording(false)
        guard active else { return }
        queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.connect() }
    }

    private func sendConfig() {
        guard let connection, !config.isEmpty,
              var data = try? JSONSerialization.data(withJSONObject: config) else { return }
        data.append(0x0A)
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    private func receive(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 262_144) { [weak self] data, _, isComplete, error in
            guard let self, conn === self.connection else { return }
            if let data, !data.isEmpty {
                self.pending.append(data)
                // Only write whole lines so files always end on a line break.
                if let lastNewline = self.pending.lastIndex(of: 0x0A) {
                    self.write(self.pending[self.pending.startIndex...lastNewline])
                    self.pending.removeSubrange(...lastNewline)
                }
            }
            if error != nil || isComplete {
                self.dropConnection()
            } else {
                self.receive(conn)
            }
        }
    }

    private func shutDown() {
        active = false
        connection?.cancel()
        connection = nil
        pending.removeAll()
        closeFile()
        setRecording(false)
    }


    // MARK: Status

    private func publishStatus(force: Bool) {
        let now = Date()
        guard force || now.timeIntervalSince(lastStatusPublish) > 1 else { return }
        lastStatusPublish = now
        let total = otherSegmentsSize + currentSize
        DispatchQueue.main.async { self.totalBytes = total }
    }

    private func setRecording(_ value: Bool) {
        DispatchQueue.main.async { self.recording = value }
    }

    private func report(_ message: String?) {
        DispatchQueue.main.async { self.lastError = message }
    }

    // MARK: Formatting

    static func format(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    var statusText: String {
        if !enabled { return "History off" }
        if let lastError { return "History error: \(lastError)" }
        return "History \(Self.format(totalBytes)) of \(Self.format(maxBytes))" + (recording ? "" : " (waiting)")
    }
}
