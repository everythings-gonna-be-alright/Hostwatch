import Foundation
import SwiftUI

// MARK: - Event model

enum EventKind: String, CaseIterable, Codable {
    case exec, net, file

    var title: String {
        switch self {
        case .exec: return "Processes"
        case .net: return "Connections"
        case .file: return "Files"
        }
    }

    var symbol: String {
        switch self {
        case .exec: return "play.fill"
        case .net: return "network"
        case .file: return "doc.fill"
        }
    }

    var color: Color {
        switch self {
        case .exec: return .cyan
        case .net: return .green
        case .file: return .orange
        }
    }
}

struct ActivityEvent: Identifiable, Decodable {
    let id = UUID()
    let kind: EventKind
    let time: String
    let pid: Int
    let ppid: Int
    let name: String
    let proc: String
    let target: String
    let extra: String
    let parent: String           // exec only: program that spawned it
    let host: String             // net only: DNS name for the remote IP ("" if unknown)
    let hostSource: String       // "dns" (name the program looked up) or "ptr" (reverse DNS)
    let args: String             // exec only: command line, secrets masked by the collector
    let inferred: Bool           // net only: seen via traffic stats after it closed; target inferred
    let note: String             // collector's remark (e.g. why a connection is inferred)
    var pstart: Double = 0       // exec only: when the process started (s since 1970), 0 if unknown
    var ts: Double = 0           // when it was recorded (s since 1970), 0 if unknown
    private(set) var signatureKey = ""
    private(set) var signatureProcess = ""
    private(set) var signaturePattern = ""
    private(set) var signatureRisk = PatternRisk.normal
    private(set) var signatureReason = ""
    var isFirst = false          // first time this pattern was ever seen
    var seq = 0                  // arrival order, for sorting by time
    var newDomain = ""           // net: registrable domain first seen within the last hour
    var beacon = ""              // net: "every ~60s" when part of a worrying beacon
    var rawIP = false            // net: public IP, unusual port, no DNS, untrusted program
    var knownBad = ""            // on a threat list: "ThreatFox: AsyncRAT command server, reported …"
    var session = 0              // the coding-agent session (the agent's pid) it belongs to, 0 if none

    /// Any per-connection network signal that deserves attention.
    var networkSignal: Bool { !newDomain.isEmpty || !beacon.isEmpty || rawIP }

    enum CodingKeys: String, CodingKey {
        case kind, time, pid, ppid, name, proc, target, extra, parent, host, args, inferred, note, pstart
        case hostSource = "host_src"
    }

    init(kind: EventKind, time: String, pid: Int, ppid: Int, name: String,
         proc: String, target: String, extra: String, parent: String, host: String = "", hostSource: String = "", args: String = "") {
        self.kind = kind; self.time = time; self.pid = pid; self.ppid = ppid; self.name = name
        self.proc = proc; self.target = target; self.extra = extra; self.parent = parent
        self.host = host; self.hostSource = hostSource; self.args = args
        self.inferred = false; self.note = ""
        applySignature()
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(EventKind.self, forKey: .kind)
        time = ((try? c.decodeIfPresent(String.self, forKey: .time)) ?? nil) ?? ""
        pid = ((try? c.decodeIfPresent(Int.self, forKey: .pid)) ?? nil) ?? 0
        ppid = ((try? c.decodeIfPresent(Int.self, forKey: .ppid)) ?? nil) ?? 0
        name = ((try? c.decodeIfPresent(String.self, forKey: .name)) ?? nil) ?? "?"
        proc = ((try? c.decodeIfPresent(String.self, forKey: .proc)) ?? nil) ?? ""
        target = ((try? c.decodeIfPresent(String.self, forKey: .target)) ?? nil) ?? ""
        extra = ((try? c.decodeIfPresent(String.self, forKey: .extra)) ?? nil) ?? ""
        parent = ((try? c.decodeIfPresent(String.self, forKey: .parent)) ?? nil) ?? ""
        host = ((try? c.decodeIfPresent(String.self, forKey: .host)) ?? nil) ?? ""
        hostSource = ((try? c.decodeIfPresent(String.self, forKey: .hostSource)) ?? nil) ?? ""
        args = ((try? c.decodeIfPresent(String.self, forKey: .args)) ?? nil) ?? ""
        inferred = ((try? c.decodeIfPresent(Bool.self, forKey: .inferred)) ?? nil) ?? false
        note = ((try? c.decodeIfPresent(String.self, forKey: .note)) ?? nil) ?? ""
        pstart = ((try? c.decodeIfPresent(Double.self, forKey: .pstart)) ?? nil) ?? 0
        applySignature()
    }

    /// "14:02:11", without the fraction of a second: for narrow places (the overlay, story steps).
    var clockTime: String { String(time.prefix(8)) }
    /// "14:02:11.48": the Events table's Time column (the full microsecond stamp is in its tooltip).
    var shortTime: String { String(time.prefix(11)) }

    /// "Tue 3 Nov 14:02:11" for a recorded event; the clock time when the day is unknown.
    var dayTime: String {
        guard ts > 0 else { return time }
        return Date(timeIntervalSince1970: ts).formatted(.dateTime.weekday(.abbreviated).day().month(.abbreviated)
            .hour(.twoDigits(amPM: .omitted)).minute().second())
    }

    /// The event list's search: `query` (already lowercased) in the name, path, detail or host, or the exact PID.
    func matches(_ query: String) -> Bool {
        name.lowercased().contains(query) || proc.lowercased().contains(query)
            || target.lowercased().contains(query) || host.contains(query) || String(pid) == query
    }

    /// One recorded or streamed line. Same result as `JSONDecoder` but several times faster
    /// (`JSONSerialization` plus plain casts): Time Travel and history search parse tens of thousands of lines.
    static func parse(_ line: Data) -> ActivityEvent? {
        guard let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return nil }
        return ActivityEvent(record: obj)
    }

    init?(record r: [String: Any]) {
        guard let raw = r["kind"] as? String, let kind = EventKind(rawValue: raw) else { return nil }
        func str(_ k: String) -> String { r[k] as? String ?? "" }
        func int(_ k: String) -> Int { (r[k] as? NSNumber)?.intValue ?? 0 }
        self.kind = kind
        time = str("time"); pid = int("pid"); ppid = int("ppid")
        name = r["name"] as? String ?? "?"
        proc = str("proc"); target = str("target"); extra = str("extra"); parent = str("parent")
        host = str("host"); hostSource = str("host_src"); args = str("args")
        inferred = (r["inferred"] as? NSNumber)?.boolValue ?? false
        note = str("note")
        pstart = (r["pstart"] as? NSNumber)?.doubleValue ?? 0
        if let stamp = r["ts"] as? String, let date = HistoryArchive.parseISO(Data(stamp.utf8)) {
            ts = date.timeIntervalSince1970
        }
        applySignature()
    }

    private mutating func applySignature() {
        let sig = SignatureBuilder.signature(for: self)
        (signatureKey, signatureProcess, signaturePattern) = (sig.key, sig.process, sig.pattern)
        (signatureRisk, signatureReason) = (sig.risk, sig.reason)
    }

    var detail: String {
        switch kind {
        case .exec: return "\(pid) ← \(ppid)"
        case .net:
            if target.hasPrefix("?") { return "\(extra) (closed too fast to read)" }
            return "\(extra) \(hostLabel.map { "\($0):\(remotePort)" } ?? target)"
        case .file: return "\(extra) \(abbreviate(target))"
        }
    }

    /// Hostname to show: plain when it is the name the program looked up, "~name" when it is
    /// only reverse DNS (often a CDN/provider name).
    var hostLabel: String? {
        guard kind == .net, !host.isEmpty else { return nil }
        switch hostSource {
        case "ptr": return "~" + host        // reverse DNS: often a provider name
        case "args": return "≈" + host       // taken from the command line, not confirmed by DNS
        default: return host
        }
    }

    var remotePort: String { target.split(separator: ":").last.map(String.init) ?? "" }

    /// "www.google.com" -> "google.com", "a.b.co.uk" -> "b.co.uk".
    var registrableDomain: String? {
        guard !host.isEmpty, hostSource == "dns" else { return nil }
        return DomainRegistry.registrable(host)
    }

    /// Remote host part of a net target ("1.2.3.4:443" -> "1.2.3.4", "[::1]:53" -> "[::1]").
    var remoteHost: String? {
        guard kind == .net, let colon = target.lastIndex(of: ":") else { return nil }
        return String(target[..<colon])
    }
}

private let homeDir = AppPaths.userHome

private func abbreviate(_ path: String) -> String {
    path.hasPrefix(homeDir) ? "~" + path.dropFirst(homeDir.count) : path
}
