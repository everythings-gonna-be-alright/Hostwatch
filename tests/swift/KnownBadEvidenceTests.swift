import Foundation
import Testing
@testable import Hostwatch

/// A threat-list match reaches the AI with the event, not only the event list.
@Suite struct KnownBadEvidence {
    func connection() -> ActivityEvent {
        // A PID that isn't running, so the live sections stay short.
        var e = ActivityEvent(kind: .net, time: "22:33:10", pid: 999_999, ppid: 1, name: "Google Chrome Helper",
                              proc: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", target: "127.0.0.1:9",
                              extra: "tcp", parent: "", host: "telegram.me", hostSource: "dns")
        e.knownBad = "ThreatFox: Vidar command server, reported 3 Nov 2026"
        e.newDomain = "telegram.me"
        return e
    }

    @Test func signalsSectionNamesTheListAndTheOtherSignals() {
        let text = EvidenceGatherer.gather(for: connection(), related: [])
        #expect(text.contains("## Hostwatch signals"))
        #expect(text.contains("ON A THREAT LIST: ThreatFox: Vidar command server"))
        #expect(text.contains("new domain: first contact with telegram.me"))
    }

    @Test func noSignalsNoSection() {
        var e = connection()
        e.knownBad = ""; e.newDomain = ""
        #expect(!EvidenceGatherer.gather(for: e, related: []).contains("Hostwatch signals"))
    }
}
