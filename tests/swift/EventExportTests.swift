import Foundation
import Testing
@testable import Hostwatch

/// File ▸ Export Events: one JSON object per line, empty fields left out, secrets masked even if they got through.
@Suite struct EventExports {
    @Test func oneLinePerEventMaskedAndCompact() throws {
        let launch = ActivityEvent(kind: .exec, time: "12:00:00", pid: 42, ppid: 1, name: "curl", proc: "/usr/bin/curl",
                                   target: "/usr/bin/curl", extra: "", parent: "/bin/zsh",
                                   args: "curl -H 'Authorization: Bearer abc123secret' https://example.com")
        let data = EventExport.jsonLines([launch, launch])
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
        #expect(lines.count == 2)
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(lines[0].utf8)) as? [String: Any])
        #expect(obj["pid"] as? Int == 42 && obj["parent"] as? String == "/bin/zsh")
        #expect(obj["extra"] == nil && obj["host"] == nil)                  // empty fields left out
        #expect((obj["args"] as? String)?.contains("abc123secret") == false)
    }
}
