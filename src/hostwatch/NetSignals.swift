import Foundation

// Per-connection network signals (not in pattern keys: whether DNS was seen depends on timing).
// Beaconing = one program contacting one destination at a steady interval; raw IP = public IP on an
// unusual port with no DNS answer. Both count only for untrusted programs or system tools.

enum NetSignals {
    /// Untrusted program or LOLBin: what makes beacons and raw-IP connections worth attention.
    static func suspiciousActor(_ e: ActivityEvent, signing: SigningCache = .shared) -> Bool {
        if SignatureBuilder.isLolbin(e.proc) { return true }
        if SignatureBuilder.isSealedSystem(e.proc) { return false }
        guard let id = signing.identity(e.proc) else { return true }
        return !signing.trusts(e.proc, id)
    }

    static func isPublic(_ e: ActivityEvent) -> Bool {
        guard e.kind == .net, !e.target.hasPrefix("?") else { return false }
        let bucket = SignatureBuilder.hostBucket(e.remoteHost ?? e.target)
        return !SignatureBuilder.localBuckets.contains(bucket) && bucket.contains("*")
    }

    /// Public IP, unusual port, no DNS answer (no name, or only reverse DNS), suspicious actor.
    static func isRawIP(_ e: ActivityEvent) -> Bool {
        guard e.kind == .net, !e.inferred, e.host.isEmpty || e.hostSource == "ptr", isPublic(e),
              !SignatureBuilder.webPorts.contains(e.remotePort), Int(e.remotePort) != nil else { return false }
        return suspiciousActor(e)
    }
}

/// Finds steady-interval connections per (program, destination).
@MainActor
final class BeaconDetector {
    /// Connections needed before judging (5 intervals).
    let minConnections = 6
    /// Accepted average interval range.
    let intervalRange: ClosedRange<TimeInterval> = 10...3600
    /// Max relative jitter (standard deviation / mean): beacons often randomise a little.
    let maxJitter = 0.25

    private struct Track { var times: [Date] = [] }
    private var tracks: [String: Track] = [:]

    /// Destination of a connection: its registrable domain, else the IP.
    static func destination(_ e: ActivityEvent) -> String {
        if !e.host.isEmpty, e.hostSource != "ptr", let d = DomainRegistry.registrable(e.host) { return d }
        return (e.remoteHost ?? e.target).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }

    /// Records a new connection; returns "every ~60s" when it is part of a worrying beacon.
    func observe(_ e: ActivityEvent, at now: Date = Date()) -> String? {
        guard NetSignals.isPublic(e), !e.inferred else { return nil }
        guard !SignatureBuilder.isSealedSystem(e.proc) || SignatureBuilder.isLolbin(e.proc) else { return nil }
        let key = e.signatureProcess + " → " + Self.destination(e)
        var track = tracks[key] ?? Track()
        // A burst of sockets opened together is one contact.
        if let last = track.times.last, now.timeIntervalSince(last) < 2 { return nil }
        track.times.append(now)
        if track.times.count > 12 { track.times.removeFirst(track.times.count - 12) }
        tracks[key] = track
        if tracks.count > 20_000 { tracks = tracks.filter { now.timeIntervalSince($0.value.times.last ?? now) < 3600 } }

        guard let interval = Self.steadyInterval(track.times.suffix(minConnections), range: intervalRange,
                                                 maxJitter: maxJitter) else { return nil }
        // Telemetry and heartbeats from trusted apps to known names are everyday.
        let worrying = NetSignals.suspiciousActor(e) || e.host.isEmpty || e.hostSource == "ptr" || !e.newDomain.isEmpty
        return worrying ? "every ~\(Self.format(interval))" : nil
    }

    /// Mean interval when `times` (oldest first) are evenly spaced, nil otherwise.
    nonisolated static func steadyInterval<C: Collection>(_ times: C, range: ClosedRange<TimeInterval>,
                                                          maxJitter: Double) -> TimeInterval? where C.Element == Date {
        let t = Array(times)
        guard t.count >= 6 else { return nil }
        let gaps = zip(t.dropFirst(), t).map { $0.timeIntervalSince($1) }
        let mean = gaps.reduce(0, +) / Double(gaps.count)
        guard range.contains(mean) else { return nil }
        let variance = gaps.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(gaps.count)
        return variance.squareRoot() / mean <= maxJitter ? mean : nil
    }

    nonisolated static func format(_ s: TimeInterval) -> String {
        s < 120 ? "\(Int(s.rounded()))s" : "\(Int((s / 60).rounded()))m"
    }
}
