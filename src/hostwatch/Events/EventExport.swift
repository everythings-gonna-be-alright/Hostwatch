import Foundation

/// Events as JSON lines for File ▸ Export Events: one object per line, the fields people read, empty ones left out.
/// Command lines are already masked by the collector, and masked again here in case a rule was added since.
enum EventExport {
    static func jsonLines(_ events: [ActivityEvent]) -> Data {
        var out = Data()
        for e in events {
            var o: [String: Any] = ["kind": e.kind.rawValue, "time": e.time, "pid": e.pid, "name": e.name]
            let text: [(String, String)] = [("proc", e.proc), ("target", e.target), ("extra", e.extra), ("parent", e.parent),
                                            ("host", e.host), ("args", Secrets.mask(e.args)), ("knownBad", e.knownBad),
                                            ("newDomain", e.newDomain), ("beacon", e.beacon)]
            for (k, v) in text where !v.isEmpty { o[k] = v }
            if e.ppid != 0 { o["ppid"] = e.ppid }
            if e.ts > 0 { o["ts"] = e.ts }
            if e.rawIP { o["rawIP"] = true }
            guard let line = try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes]) else { continue }
            out.append(line)
            out.append(0x0A)
        }
        return out
    }
}
