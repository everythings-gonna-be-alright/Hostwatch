import Foundation
import SwiftUI

// MARK: - Time travel state

/// A moment on the timeline worth a mark: a story or a new domain.
struct TimelineMarker: Identifiable {
    enum Kind { case dangerous, suspicious, newDomain }
    let id: String
    let date: Date
    let kind: Kind
    let title: String
}

@MainActor
final class TimeTravel: ObservableObject {
    @Published private(set) var active = false
    /// The end of the shown slice: "what had happened by this moment".
    @Published private(set) var playhead = Date()
    @Published var span: TimeInterval = 5 * 60 { didSet { scheduleLoad() } }
    @Published private(set) var range: ClosedRange<Date>?
    @Published private(set) var activity: [Double] = []
    @Published private(set) var events: [ActivityEvent] = []
    @Published private(set) var loading = false
    /// Older events of the shown window are still on disk (scrolling to the end of the list loads them).
    @Published private(set) var clipped = false
    /// The window is loaded as far as Hostwatch goes for one window (`maxSliceBytes`): a shorter one shows the rest.
    @Published private(set) var capped = false
    @Published private(set) var loadingMore = false
    /// A window is read a page at a time, newest first: about 3,000 events each. Reading a busy hour at once
    /// (up to ~19,000 events and their rows) made the app's memory jump by 100–250 MB.
    nonisolated static let pageBytes: Int64 = 1_000_000
    nonisolated static let maxSliceBytes: Int64 = 6_000_000
    private var loadedBytes: Int64 = 0
    private var moreTask: Task<Void, Never>?
    @Published private(set) var playing = false
    @Published var speed: Double = 1            // history seconds per real second
    @Published private(set) var markers: [TimelineMarker] = []
    /// Running Now while traveling: what was running at the playhead (nil: nothing recorded near it).
    @Published private(set) var processSnapshot: ProcessHistory.Snapshot?
    /// Set while Running Now is shown in Time Travel: the list follows the playhead.
    var processesWanted = false { didSet { if processesWanted != oldValue { loadProcesses() } } }
    /// Receives each process list loaded for the playhead (Running Now shows it).
    var onProcesses: (ProcessHistory.Snapshot?, Date) -> Void = { _, _ in }
    private let processCache = ProcessDayCache()
    private var processTask: Task<Void, Never>?

    /// Bumped whenever the listed events change (slice or search hits): the event list re-derives its rows only then.
    @Published private(set) var revision = 0
    /// CPU and memory over the whole recording, per timeline bucket (0...1; nil where nothing was recorded).
    @Published private(set) var cpuLane: [Double?] = []
    @Published private(set) var memLane: [Double?] = []
    /// Resource samples inside the shown slice, for the strip and the banner.
    @Published private(set) var windowSamples: [MetricSample] = []
    /// The launch event to select once the slice is loaded (Running Now ▸ Show Spawn in Timeline).
    @Published private(set) var focusID: UUID?
    private var pendingFocus: (pid: Int, start: Double)?
    private var pendingEvent: ActivityEvent?

    // Search across all recorded history (the toolbar search field, scope All History).
    /// Search everything (true) or only the shown window (false).
    @Published var searchAll = true { didSet { if searchAll != oldValue { revision += 1 } } }
    /// Matches, newest first; never more than `maxSearchHits`.
    @Published private(set) var searchHits: [ActivityEvent] = []
    @Published private(set) var searchQuery = ""
    @Published private(set) var searching = false
    /// The scan has read everything from now back to here.
    @Published private(set) var searchReachedBack: Date?
    /// Stopped at `maxSearchHits`: older matches may exist.
    @Published private(set) var searchCapped = false
    private var searchTask: Task<Void, Never>?
    /// Enough to scroll through and see a pattern; more would only cost memory and a slower list.
    nonisolated static let maxSearchHits = 1000
    /// One or two letters would match nearly every line.
    nonisolated static let minSearchLength = 2

    /// Whether the event list shows search hits from all history rather than the window.
    var showingSearch: Bool { active && searchAll && searchQuery.count >= Self.minSearchLength }
    /// What the event list shows while traveling.
    var listed: [ActivityEvent] { showingSearch ? searchHits : events }
    /// The last sample at or before the playhead.
    var sampleAtPlayhead: MetricSample? { windowSamples.last { $0.date <= playhead } }

    static let spans: [(String, TimeInterval)] = [("1 min", 60), ("5 min", 300), ("15 min", 900), ("1 hour", 3600)]
    static let speeds: [(String, Double)] = [("1×", 1), ("10×", 10), ("60×", 60), ("600×", 600)]
    nonisolated static let buckets = 240

    private let history: HistoryRecorder
    private let stories: StoryEngine
    private let domains: DomainRegistry
    private let metrics: MetricsStore
    private var segments: [HistoryArchive.Segment] = []
    private var loadTask: Task<Void, Never>?
    private var overviewTask: Task<Void, Never>?
    private var playTimer: Timer?
    private var refreshTimer: Timer?

    init(history: HistoryRecorder, stories: StoryEngine, domains: DomainRegistry, metrics: MetricsStore) {
        self.history = history
        self.stories = stories
        self.domains = domains
        self.metrics = metrics
    }

    private var archive: HistoryArchive { HistoryArchive(directory: history.directory) }

    var windowStart: Date { playhead.addingTimeInterval(-span) }

    // MARK: Entering and leaving

    /// Opens time travel at `date` (default: a few minutes ago).
    func enter(at date: Date? = nil) {
        let wasActive = active
        active = true
        playhead = date ?? Date().addingTimeInterval(-span)
        refreshOverview(thenLoad: true)
        if !wasActive {
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshOverview(thenLoad: false) }
            }
        }
    }

    func exit() {
        pause()
        active = false
        loadTask?.cancel()
        moreTask?.cancel()
        loadingMore = false
        overviewTask?.cancel()
        refreshTimer?.invalidate()
        refreshTimer = nil
        events = []
        pendingFocus = nil
        pendingEvent = nil
        focusID = nil
        cancelSearch()
        searchQuery = ""
        revision += 1
        processTask?.cancel()
        processSnapshot = nil
        processCache.clear()
    }

    func toggle() { active ? exit() : enter() }

    /// Opens time travel at the moment a process started, its launch event selected when it was recorded.
    func reveal(pid: Int, start: Date) {
        pause()
        focusID = nil
        pendingFocus = (pid, start.timeIntervalSince1970)
        // The slice ends a little after the launch, so it's near the top of the newest-first list.
        enter(at: start.addingTimeInterval(min(30, span / 4)))
    }

    /// Shows the window around a recorded event (a search hit) with it selected.
    func reveal(_ event: ActivityEvent) {
        guard event.ts > 0 else { return }
        pause()
        focusID = nil
        pendingEvent = event
        searchAll = false
        let at = Date(timeIntervalSince1970: event.ts)
        enter(at: at.addingTimeInterval(min(30, span / 4)))
    }

    // MARK: Running Now at the playhead

    private func loadProcesses() {
        processTask?.cancel()
        guard active, processesWanted else { return }
        let history = ProcessHistory(directory: self.history.directory), cache = processCache, at = playhead
        processTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(60))          // coalesce drags
            guard !Task.isCancelled else { return }
            let snapshot = await Task.detached(priority: .userInitiated) { history.snapshot(at: at, cache: cache) }.value
            guard let self, !Task.isCancelled, self.active else { return }
            self.processSnapshot = snapshot
            self.onProcesses(snapshot, at)
        }
    }

    // MARK: Searching all history

    /// Searches all recorded history for `text` (debounced; the same query isn't searched twice).
    func search(_ text: String) {
        let q = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard q != searchQuery else { return }
        cancelSearch()
        searchQuery = q
        searchHits = []
        searchCapped = false
        searchReachedBack = nil
        revision += 1
        guard active, q.count >= Self.minSearchLength else { return }
        searching = true
        let archive = archive
        searchTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(300))           // typing
            guard !Task.isCancelled, let self else { return }
            // Fresh file list: the search may run long after the overview was read.
            let segments = await Task.detached(priority: .userInitiated) { archive.segments() }.value
            guard !Task.isCancelled else { return }
            let stream = AsyncStream<HistoryArchive.SearchProgress> { continuation in
                let worker = Task.detached(priority: .userInitiated) {
                    archive.search(segments, query: q, limit: Self.maxSearchHits,
                                   stop: { Task.isCancelled }, report: { continuation.yield($0) })
                    continuation.finish()
                }
                continuation.onTermination = { _ in worker.cancel() }
            }
            var pending: [ActivityEvent] = []
            var lastPublish = ContinuousClock.now
            for await progress in stream {
                guard !Task.isCancelled else { return }
                pending += progress.hits
                self.searchReachedBack = progress.reachedBack
                // Publish hits a few times a second at most: each publish rebuilds the list.
                if !pending.isEmpty, ContinuousClock.now - lastPublish > .milliseconds(250) || self.searchHits.isEmpty {
                    self.searchHits += pending
                    pending = []
                    lastPublish = .now
                    self.revision += 1
                }
            }
            guard !Task.isCancelled else { return }
            if !pending.isEmpty { self.searchHits += pending; self.revision += 1 }
            self.searchCapped = self.searchHits.count >= Self.maxSearchHits
            self.searching = false
        }
    }

    private func cancelSearch() {
        searchTask?.cancel()
        searchTask = nil
        searching = false
    }

    /// The launch event of `pid` that started at `start` (s since 1970; 0 or unknown on either side: any).
    nonisolated static func launch(in events: [ActivityEvent], pid: Int, start: Double) -> ActivityEvent? {
        let execs = events.filter { $0.kind == .exec && $0.pid == pid }
        return execs.first { start > 0 && $0.pstart > 0 && abs($0.pstart - start) < 2 }
            ?? execs.first { start <= 0 || $0.pstart <= 0 }
    }

    // MARK: Moving

    func move(to date: Date) {
        guard let range else { playhead = date; return }
        playhead = min(max(date, range.lowerBound.addingTimeInterval(min(span, 1))), range.upperBound)
        scheduleLoad()
    }

    /// One slice earlier (-1) or later (+1).
    func step(_ direction: Int) {
        pause()
        move(to: playhead.addingTimeInterval(Double(direction) * span))
    }

    func togglePlay() { playing ? pause() : play() }

    private func play() {
        guard let range else { return }
        if playhead >= range.upperBound { move(to: range.lowerBound.addingTimeInterval(span)) }
        playing = true
        playTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let range = self.range else { return }
                if self.playhead >= range.upperBound { self.pause(); return }
                self.move(to: self.playhead.addingTimeInterval(self.speed * 0.5))
            }
        }
    }

    func pause() {
        playing = false
        playTimer?.invalidate()
        playTimer = nil
    }

    // MARK: Loading (off the main thread)

    private func refreshOverview(thenLoad: Bool) {
        let archive = archive
        overviewTask?.cancel()
        overviewTask = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) { () -> ([HistoryArchive.Segment], ClosedRange<Date>?, [Double]) in
                let segments = archive.segments()
                guard let range = HistoryArchive.range(of: segments) else { return (segments, nil, []) }
                return (segments, range, archive.activity(segments, over: range, buckets: TimeTravel.buckets))
            }.value
            guard let self, !Task.isCancelled, self.active else { return }
            self.segments = result.0
            self.range = result.1
            // Square root: one huge burst shouldn't flatten every other bar.
            let scaled = result.2.map { $0.squareRoot() }
            let peak = scaled.max() ?? 0
            self.activity = peak > 0 ? scaled.map { $0 / peak } : scaled
            self.markers = self.collectMarkers()
            if thenLoad { self.move(to: self.playhead) }
            if let range = result.1 { await self.loadLanes(range) }
        }
    }

    private func scheduleLoad() {
        loadProcesses()
        guard active, !segments.isEmpty else { return }
        let archive = archive, segments = segments, from = windowStart, to = playhead
        loadTask?.cancel()
        loading = true
        loadTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(90))          // coalesce drags
            guard !Task.isCancelled else { return }
            let result = await Task.detached(priority: .userInitiated) {
                archive.events(segments, from: from, to: to, maxBytes: Self.pageBytes)
            }.value
            guard let self, !Task.isCancelled else { return }
            self.moreTask?.cancel()
            self.loadingMore = false
            self.events = result.events
            self.clipped = result.clipped
            self.capped = false
            self.loadedBytes = Self.pageBytes
            self.revision += 1
            self.resolveFocus()
            self.windowSamples = await self.metrics.samples(from: from, to: to)
            self.loading = false
        }
    }

    /// The next older page of the shown window (the list scrolled to its end, or a focus not found yet).
    func loadMore() {
        guard active, clipped, !loadingMore, let oldest = events.last, oldest.ts > 0 else { return }
        guard loadedBytes < Self.maxSliceBytes else { clipped = false; capped = true; return }
        let archive = archive, segments = segments, from = windowStart
        // Up to and including the oldest loaded moment: lines sharing its timestamp may have been cut off.
        let to = Self.nextPageEnd(after: events)
        let loaded = events
        loadingMore = true
        moreTask = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) {
                archive.events(segments, from: from, to: to, maxBytes: Self.pageBytes)
            }.value
            guard let self, !Task.isCancelled, self.loadingMore else { return }
            let older = Self.newOnly(result.events, after: loaded)
            self.events += older
            self.loadedBytes += Self.pageBytes
            // Nothing new although more was said to be there (one moment busier than a page): stop here.
            self.clipped = result.clipped && !older.isEmpty
            if self.clipped && self.loadedBytes >= Self.maxSliceBytes { self.clipped = false; self.capped = true }
            self.loadingMore = false
            self.revision += 1
            self.resolveFocus()
        }
    }

    /// Where the next older page ends: at the oldest loaded moment, inclusive (lines sharing its timestamp may have
    /// been cut off by the page size).
    nonisolated static func nextPageEnd(after loaded: [ActivityEvent]) -> Date {
        Date(timeIntervalSince1970: (loaded.last?.ts ?? 0) + 0.0005)
    }

    /// The events of a next page that aren't loaded yet (it overlaps the loaded ones at the boundary moment).
    nonisolated static func newOnly(_ page: [ActivityEvent], after loaded: [ActivityEvent]) -> [ActivityEvent] {
        guard let oldest = loaded.last?.ts else { return page }
        let boundary = Set(loaded.lazy.filter { $0.ts == oldest }.map(identity))
        return page.filter { $0.ts < oldest || !boundary.contains(identity($0)) }
    }

    /// A recorded line's identity across two reads of it (each read makes new event IDs).
    nonisolated static func identity(_ e: ActivityEvent) -> String {
        "\(e.ts)|\(e.pid)|\(e.kind.rawValue)|\(e.target)|\(e.extra)"
    }

    /// Selects the event a reveal asked for once it's loaded; reads older pages until it is, or there are none.
    private func resolveFocus() {
        if let target = pendingEvent {
            if let hit = events.first(where: {
                abs($0.ts - target.ts) < 0.001 && $0.pid == target.pid && $0.kind == target.kind && $0.target == target.target
            }) {
                pendingEvent = nil
                focusID = hit.id
            } else if clipped { loadMore() } else { pendingEvent = nil }
        }
        if let f = pendingFocus {
            if let hit = Self.launch(in: events, pid: f.pid, start: f.start) {
                pendingFocus = nil
                focusID = hit.id
            } else if clipped { loadMore() } else { pendingFocus = nil }
        }
    }

    /// Average CPU and memory per timeline bucket.
    private func loadLanes(_ range: ClosedRange<Date>) async {
        let samples = await metrics.samples(from: range.lowerBound, to: range.upperBound)
        let span = range.upperBound.timeIntervalSince(range.lowerBound)
        let n = Self.buckets
        guard span > 0 else { return }
        var cpu = [Double](repeating: 0, count: n), mem = cpu, count = cpu
        for s in samples {
            let i = min(n - 1, max(0, Int(s.date.timeIntervalSince(range.lowerBound) / span * Double(n))))
            cpu[i] += s.cpu / 100
            mem[i] += s.mem
            count[i] += 1
        }
        cpuLane = (0..<n).map { count[$0] > 0 ? cpu[$0] / count[$0] : nil }
        memLane = (0..<n).map { count[$0] > 0 ? mem[$0] / count[$0] : nil }
    }

    private func collectMarkers() -> [TimelineMarker] {
        guard let range else { return [] }
        var out = stories.stories.filter { range.contains($0.firstSeen) }.map {
            TimelineMarker(id: $0.id.uuidString, date: $0.firstSeen,
                           kind: $0.severity == .dangerous ? .dangerous : .suspicious, title: $0.title)
        }
        out += domains.records.values.filter { !$0.baseline && range.contains($0.firstSeen) }.map {
            TimelineMarker(id: "d:" + $0.domain, date: $0.firstSeen, kind: .newDomain, title: "New domain \($0.domain)")
        }
        return out.sorted { $0.date < $1.date }
    }
}
