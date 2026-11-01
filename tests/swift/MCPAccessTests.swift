import Foundation
import Testing
@testable import Hostwatch

/// MCP access: off by default, token required, revocable, nothing secret on disk.
@Suite struct MCPAccessRules {
    func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-mcp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func offUntilATokenIsIssued() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(!MCPAccess.isEnabled(in: dir))
        #expect(MCPAccess.check(token: "anything", in: dir) == .off)
    }

    @Test func onlyTheCurrentTokenIsAllowed() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let token = try MCPAccess.issueToken(in: dir)
        #expect(token.hasPrefix("hwmcp_") && token.count == 6 + 64)
        #expect(MCPAccess.check(token: token, in: dir) == .allowed)
        #expect(MCPAccess.check(token: nil, in: dir) == .missingToken)
        #expect(MCPAccess.check(token: "", in: dir) == .missingToken)
        #expect(MCPAccess.check(token: token + "0", in: dir) == .wrongToken)
        // A new token cuts off the old one; turning access off cuts off everything.
        let next = try MCPAccess.issueToken(in: dir)
        #expect(next != token)
        #expect(MCPAccess.check(token: token, in: dir) == .wrongToken)
        #expect(MCPAccess.check(token: next, in: dir) == .allowed)
        MCPAccess.disable(in: dir)
        #expect(MCPAccess.check(token: next, in: dir) == .off)
    }

    @Test func onlyTheHashIsStoredAndOnlyYouCanReadIt() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let token = try MCPAccess.issueToken(in: dir)
        let url = MCPAccess.hashFile(in: dir)
        let stored = try String(contentsOf: url, encoding: .utf8)
        #expect(!stored.contains(token) && !stored.contains(String(token.dropFirst(6))))
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
    }

    @Test func commandCarriesTheTokenAndReplacesOldRegistrations() {
        let cmd = MCPAccess.command(token: "hwmcp_abc", executable: "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch")
        #expect(cmd.hasPrefix("claude mcp remove --scope user hostwatch"))
        #expect(cmd.contains("claude mcp add --scope user hostwatch -e HOSTWATCH_MCP_TOKEN=hwmcp_abc -- "))
        #expect(cmd.hasSuffix("\"/Applications/Hostwatch.app/Contents/MacOS/Hostwatch\" --mcp"))
    }

    @Test func sessionsAreLoggedNewestFirst() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        MCPAccess.log(.wrongToken, in: dir, now: Date(timeIntervalSince1970: 1_800_000_000))
        MCPAccess.log(.allowed, in: dir, now: Date(timeIntervalSince1970: 1_800_000_060))
        let sessions = MCPAccess.recentSessions(in: dir)
        #expect(sessions.map(\.1) == [.allowed, .wrongToken])
        #expect(!sessions[0].2.isEmpty)
    }

    @Test func refusedServerAnswersEveryRequestWithTheReason() {
        let server = MCPServer(data: MCPDataSource(support: FileManager.default.temporaryDirectory,
                                                   history: FileManager.default.temporaryDirectory), version: "test")
        server.refusal = MCPAccess.Verdict.wrongToken.refusal
        for method in ["initialize", "tools/list", "tools/call"] {
            let reply = server.handle(#"{"jsonrpc":"2.0","id":1,"method":"\#(method)","params":{}}"#) ?? ""
            #expect(reply.contains("-32001") && reply.contains("no longer valid"))
            #expect(!reply.contains("\"result\""))
        }
        #expect(server.handle(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil)
    }
}
