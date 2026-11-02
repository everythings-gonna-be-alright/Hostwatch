import Foundation
import Testing
@testable import Hostwatch

/// Update check: right comparison, right parsing, honest results.
@MainActor @Suite struct Updates {
    func json(tag: String = "v0.4.0", draft: Bool = false, prerelease: Bool = false) -> Data {
        Data("""
        {"tag_name":"\(tag)","name":"Hostwatch \(tag.dropFirst())","draft":\(draft),"prerelease":\(prerelease),
         "html_url":"https://github.com/everythings-gonna-be-alright/Hostwatch/releases/tag/\(tag)",
         "published_at":"2026-11-02T10:00:00Z","body":"**Time travel.** Browse history.\\n## Changes\\n- one"}
        """.utf8)
    }

    func checker(_ current: String, answer: Data, status: Int = 200) -> UpdateChecker {
        let c = UpdateChecker(currentVersion: current,
                              defaults: scratchDefaults("updates"))
        c.fetch = { request in
            (answer, HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!)
        }
        return c
    }

    @Test(arguments: [("0.4.0", "0.3.0", true), ("0.10.0", "0.9.2", true), ("1.0", "1.0.0", false),
                      ("0.3.0", "0.3.0", false), ("0.2.9", "0.3.0", false), ("1.0.1", "1.0", true),
                      ("0.4.0-beta", "0.3.0", true)])
    func versionComparison(candidate: String, current: String, newer: Bool) {
        #expect(Version.isNewer(candidate, than: current) == newer)
    }

    @Test func parsesTheLatestRelease() throws {
        let r = try #require(Release.parse(json()))
        #expect(r.version == "0.4.0")
        #expect(r.name == "Hostwatch 0.4.0")
        #expect(r.url.absoluteString.hasSuffix("/releases/tag/v0.4.0"))
        #expect(r.published != nil)
        #expect(Release.parse(json(draft: true)) == nil)
        #expect(Release.parse(json(prerelease: true)) == nil)
    }

    @Test func newerReleaseIsAvailable() async {
        let c = checker("0.3.0", answer: json())
        let found = await c.check()
        #expect(found?.version == "0.4.0")
        #expect(c.available?.version == "0.4.0")
        #expect(c.lastError == nil)
    }

    @Test func sameVersionIsUpToDate() async {
        let c = checker("0.4.0", answer: json())
        #expect(await c.check() == nil)
        #expect(c.available == nil)
        #expect(c.statusText.hasPrefix("Up to date"))
    }

    @Test func gitHubErrorsAreReportedNotMistakenForUpToDate() async {
        let c = checker("0.3.0", answer: Data("{}".utf8), status: 403)
        #expect(await c.check() == nil)
        #expect(c.lastError == "GitHub rate limit, try later")
        #expect(c.statusText.hasPrefix("Couldn't check"))
    }

    @Test func notesLoseMarkdownAndStayShort() {
        let plain = UpdateChecker.plainNotes("**Time travel.** `Hostwatch`\n## Changes\n- one", limit: 600)
        #expect(plain == "Time travel. Hostwatch\nChanges\n- one")
        #expect(UpdateChecker.plainNotes(String(repeating: "a", count: 900)).count <= 601)
    }
}
