import Foundation
import Testing
@testable import Hostwatch

/// Passwords and tokens never reach history or an AI.
@Suite struct SecretMasking {
    // Built at runtime so this file doesn't contain anything that looks like a real credential.
    static let gh = "ghp_" + String(repeating: "A1b2", count: 9)
    static let aws = "AKIA" + String(repeating: "Z", count: 16)
    static let jwt = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".c2lnbmF0dXJlc2lnbmF0dXJl"
    static let longToken = String(repeating: "q7", count: 15)

    static let cases: [(String, String)] = [
        ("curl -H 'Authorization: Bearer s3cr3tvalue' https://api.example.com", "s3cr3tvalue"),
        ("curl -H 'X-API-Key: k-123456' https://api.example.com", "k-123456"),
        ("curl -u admin:hunter22 https://example.com", "hunter22"),
        ("curl https://user:hunter22@example.com/x", "hunter22"),
        ("git clone https://\(longToken)@github.com/o/r", longToken),
        ("git push https://\(gh)@github.com/o/r", String(gh.dropFirst(4))),
        ("https://h/x?token=zzz123&b=1", "zzz123"),
        ("mytool --password hunter22 --verbose", "hunter22"),
        ("mytool --api-key=k-987654", "k-987654"),
        ("env GITHUB_TOKEN=abc123def deploy", "abc123def"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI aws s3 ls", "wJalrXUtnFEMI"),
        ("aws configure set aws_access_key_id \(aws)", String(aws.dropFirst(4))),
        ("security add-generic-password -a me -s svc -w hunter22", "hunter22"),
        ("sshpass -p hunter22 ssh host", "hunter22"),
        ("mysql -u root -phunter22 db", "hunter22"),
        ("http --auth-type=jwt \(jwt)", jwt),
        ("psql postgresql://app:pg_pass_9@db:5432/x", "pg_pass_9"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXk"),
    ]

    @Test(arguments: cases)
    func masked(_ line: String, _ secret: String) {
        for marker in [Secrets.historyMarker, Secrets.aiMarker] {
            let out = Secrets.mask(line, marker: marker)
            #expect(!out.contains(secret), "\(out)")
            #expect(out.contains(marker))
        }
    }

    @Test func ordinaryCommandsAreUntouched() {
        for line in ["ls -la /Users/me/Projects", "git push origin main", "ssh -p 2222 host",
                     "xattr -d com.apple.quarantine '/Users/x/Downloads/Evil App.app'", "brew install jq",
                     "curl https://example.com/download?id=42", "python3 bypass.py --tokens-file list.txt"] {
            #expect(Secrets.mask(line) == line)
        }
    }

    @Test func historyGetsMaskedArguments() {
        let line = Agent.formatArgs(["mytool", "--password", "hunter22", "https://x/?api_key=k123456"])
        #expect(!line.contains("hunter22") && !line.contains("k123456") && line.contains("***"))
    }

    @Test func maskingInsideJSONKeepsItValid() throws {
        let json = #"{"args":"curl https://h/?token=abc\"x\" -d password=p4ss","k":1}"#
        let out = Secrets.mask(json)
        #expect(!out.contains("abc") && !out.contains("p4ss"))
        #expect(try JSONSerialization.jsonObject(with: Data(out.utf8)) is [String: Any])
    }

    @Test func everyPromptBuilderMasks() {
        #expect(EvidenceGatherer.redactSecrets("token=abc123") == "token=[REDACTED]")
    }
}

/// History recorded before full masking is masked in place, compressed files included.
@Suite struct HistorySecretScrub {
    @Test func compressedHistoryIsRewrittenWithoutSecrets() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-scrub-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let plain = dir.appendingPathComponent("activity-20261101-000000-000.jsonl")
        let lines = [
            #"{"kind":"exec","ts":"2026-11-01T00:00:01.000Z","args":"mytool --password hunter22 -v"}"#,
            #"{"kind":"net","ts":"2026-11-01T00:00:02.000Z","target":"1.2.3.4:443"}"#,
            #"{"kind":"exec","ts":"2026-11-01T00:00:03.000Z","args":"curl 'https://h/?token=abc\"q' -d x"}"#,
        ]
        try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: plain)
        try HistoryFiles.compress(plain)
        let file = try #require(HistoryFiles.list(in: dir).first)
        #expect(try HistoryFiles.scrubSecrets(file) == 2)

        let after = try #require(HistoryFiles.list(in: dir).first)
        guard case .compressed(_, let index) = after else { Issue.record("not compressed"); return }
        #expect(index.blocks.count == 1)
        var text = ""
        HistoryFiles.forEachChunk(after) { text += String(decoding: $0, as: UTF8.self); return true }
        #expect(!text.contains("hunter22") && !text.contains("abc") && text.contains("--password ***"))
        for line in text.split(separator: "\n") {
            #expect(try JSONSerialization.jsonObject(with: Data(line.utf8)) is [String: Any])
        }
        #expect(try HistoryFiles.scrubSecrets(after) == 0)                               // nothing left: untouched
    }
}
