import Foundation
import Testing
@testable import Hostwatch

/// Known-bad check: lists parsed, matched locally, a match is a Dangerous story; exploited macOS flaws.
@MainActor @Suite(.serialized) struct KnownBadCheck {
    func make() throws -> ThreatIntel {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-intel-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("# HaGeZi TIF\n*.evil-cdn.xyz\nphish.example\n\n#ips\n45.1.2.3\n".utf8)
            .write(to: dir.appendingPathComponent("hagezi"))
        try Data("# Feodo\r\n50.16.16.211\r\n".utf8).write(to: dir.appendingPathComponent("feodo"))   // CRLF, as served
        let tf = ThreatIntel.parseThreatFox(Data("""
        {"query_status":"ok","data":[
         {"ioc":"c2.badguys.net","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"AsyncRAT","first_seen":"2026-11-01 10:00:00 UTC"},
         {"ioc":"91.2.3.4:8443","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Cobalt Strike","first_seen":"2026-11-02 09:00:00 UTC"},
         {"ioc":"https://dl.payload.site/x.zip","ioc_type":"url","threat_type":"payload_delivery","threat_type_desc":"Payload delivery","malware_printable":"AMOS","first_seen":"2026-11-02 09:00:00 UTC"}
        ]}
        """.utf8))
        try JSONEncoder().encode(tf).write(to: dir.appendingPathComponent("threatfox"))
        return ThreatIntel(directory: dir, defaults: scratchDefaults("hw-intel"))
    }

    @Test func parsesTheLists() {
        let tf = ThreatIntel.parseThreatFox(Data(#"{"query_status":"ok","data":[{"ioc":"c2.x.net","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"AsyncRAT","first_seen":"2026-11-01 10:00:00 UTC"}]}"#.utf8))
        #expect(tf["c2.x.net"]?.detail.hasPrefix("AsyncRAT command server, reported") == true)
        let sha = String(repeating: "ab", count: 32)
        let mb = ThreatIntel.parseBazaar(Data("""
        # MalwareBazaar recent\r
        "2026-11-02 08:00:00", "\(sha)", "md5", "sha1", "reporter", "Setup.dmg", "dmg", "application/x-apple-diskimage", "AMOS"\r
        """.utf8))
        #expect(mb[sha]?.detail.hasPrefix("AMOS (dmg), first seen") == true)
        #expect(ThreatIntel.rejection(.threatfox, Data(#"{"query_status":"unknown_auth_key"}"#.utf8), parsed: 0) == "unknown_auth_key")
        #expect(ThreatIntel.rejection(.threatfox, Data(#"{"query_status":"no_result"}"#.utf8), parsed: 0) == nil)
        #expect(ThreatIntel.parsePendingUpdate("Software Update found:\n* Label: macOS Tahoe 27.2.1-25C60\n\tTitle: macOS Tahoe 27.2.1, Version: 27.2.1, Size: 1G")
                == "macOS Tahoe 27.2.1")
    }

    @Test func matchesDomainsSubdomainsIPsAndPorts() async throws {
        let intel = try make()
        await intel.load()
        #expect(intel.listedDomain("a.b.evil-cdn.xyz")?.domain == "evil-cdn.xyz")
        #expect(intel.listedDomain("evil-cdn.xyz.example.org") == nil)
        #expect(intel.listedDomain("c2.badguys.net")?.detail.contains("AsyncRAT") == true)
        #expect(intel.listedDomain("dl.payload.site")?.detail.contains("AMOS") == true)
        #expect(intel.listedIP("45.1.2.3", port: "443")?.contains("HaGeZi") == true)
        #expect(intel.listedIP("91.2.3.4", port: "8443")?.contains("Cobalt Strike") == true)
        #expect(intel.listedIP("50.16.16.211", port: "443")?.contains("Feodo") == true)
        #expect(intel.states["feodo"]?.count == 1)
        #expect(intel.listedIP("1.1.1.1", port: "443") == nil)
        let e = net("/opt/homebrew/bin/python3.12", pid: 4411, to: "45.9.9.9:443", host: "cdn.c2.badguys.net")
        let hit = try #require(intel.check(e))
        #expect(hit.indicator == "c2.badguys.net" && hit.source == "ThreatFox" && hit.process == "python3.12")
        #expect(intel.hits.count == 1)
        _ = intel.check(e)
        #expect(intel.hits.count == 1)                                             // once per day per program
    }

    @Test func aMatchIsADangerousStoryOnItsOwn() {
        let stories = StoryEngine(persistent: false)
        var e = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 50, to: "45.1.2.3:443", host: "evil-cdn.xyz")
        e.knownBad = "ThreatFox: AsyncRAT command server, reported Nov 1"
        _ = stories.ingest(e, decidedSafe: true)                                  // even a pattern you marked Safe
        let story = stories.stories.first
        #expect(story?.severity == .dangerous && story?.stages.contains(.knownBad) == true)
    }

    @Test func untrustedFilesAreHashedAndMatched() async throws {
        let intel = try make()
        let path = "/private/tmp/hw-known-bad-\(UUID().uuidString)"
        try Data("not really malware".utf8).write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let sha = try #require(ThreatIntel.sha256(of: path))
        let indicators = [sha: ThreatIntel.Indicator(detail: "AMOS (macho), first seen Nov 1", seen: Date(), type: "sha256")]
        try JSONEncoder().encode(indicators).write(to: intel.directory.appendingPathComponent("bazaar"))
        await intel.load()
        var found: ThreatHit?
        intel.onHit = { hit, _ in found = hit }
        intel.checkLaunch(exec(path, pid: 77, ppid: 1, parent: "/bin/zsh"))
        for _ in 0..<50 where found == nil { try await Task.sleep(nanoseconds: 20_000_000) }
        #expect(found?.kind == .file && found?.source == "MalwareBazaar" && found?.indicator == sha)
        #expect(intel.flag(for: exec(path, pid: 78, ppid: 1, parent: "/bin/zsh"))?.contains("AMOS") == true)
    }

    @Test func exploitedAppleFlawsAndWhetherTheyreFixed() throws {
        let kev = ThreatIntel.parseKEV(Data("""
        {"vulnerabilities":[
         {"cveID":"CVE-2026-1","vendorProject":"Apple","product":"Multiple Products","vulnerabilityName":"x","dateAdded":"2026-09-29",
          "shortDescription":"Apple iOS, macOS, and iPadOS contain an out-of-bounds write in CoreGraphics.","knownRansomwareCampaignUse":"Unknown",
          "notes":"https://support.apple.com/en-us/125000 ; https://nvd.nist.gov/x"},
         {"cveID":"CVE-2026-2","vendorProject":"Apple","product":"iOS","vulnerabilityName":"y","dateAdded":"2026-10-01","shortDescription":"iOS only"},
         {"cveID":"CVE-2026-3","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"z","dateAdded":"2026-10-01","shortDescription":"w"}
        ]}
        """.utf8))
        #expect(kev.map(\.cve) == ["CVE-2026-1"])
        #expect(kev[0].component == "CoreGraphics" && kev[0].advisory == "https://support.apple.com/en-us/125000")
    }
}
