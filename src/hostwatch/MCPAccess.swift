import CryptoKit
import Darwin
import Foundation

/// Who may use `Hostwatch --mcp`. Off until you turn it on in Settings ▸ AI; then a client must
/// present a random token (given to Claude Code in its registration command). Hostwatch keeps only
/// the token's SHA-256, so reading its files doesn't reveal it, and a new token cuts off every old
/// registration. Each session start is logged with the program that started it.
enum MCPAccess {
    static let environmentKey = "HOSTWATCH_MCP_TOKEN"

    enum Verdict: String, Equatable {
        case allowed, off, missingToken = "missing-token", wrongToken = "wrong-token"

        /// Shown to the MCP client (Claude Code) when access is refused.
        var refusal: String? {
            switch self {
            case .allowed: return nil
            case .off: return "Hostwatch MCP access is off. Turn it on in Hostwatch ▸ Settings ▸ AI."
            case .missingToken, .wrongToken:
                return "Hostwatch MCP token is missing or no longer valid. Copy the command from "
                    + "Hostwatch ▸ Settings ▸ AI (New Token) and run it again."
            }
        }
    }

    static func hashFile(in directory: URL) -> URL { directory.appendingPathComponent("mcp-token.sha256") }
    static func logFile(in directory: URL) -> URL { directory.appendingPathComponent("mcp-access.log") }

    static func isEnabled(in directory: URL = AppPaths.support) -> Bool {
        FileManager.default.fileExists(atPath: hashFile(in: directory).path)
    }

    /// A new random token; only its hash is stored (readable by you only). Old tokens stop working.
    static func issueToken(in directory: URL = AppPaths.support) throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw CocoaError(.featureUnsupported)
        }
        let token = "hwmcp_" + bytes.map { String(format: "%02x", $0) }.joined()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = hashFile(in: directory)
        try Data(hash(token).utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return token
    }

    /// Turns access off: every registration stops working.
    static func disable(in directory: URL = AppPaths.support) {
        try? FileManager.default.removeItem(at: hashFile(in: directory))
    }

    static func check(token: String?, in directory: URL = AppPaths.support) -> Verdict {
        guard let stored = try? String(contentsOf: hashFile(in: directory), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !stored.isEmpty else { return .off }
        guard let token, !token.isEmpty else { return .missingToken }
        return constantTimeEqual(hash(token), stored) ? .allowed : .wrongToken
    }

    static func hash(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        return zip(x, y).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// The command that registers Hostwatch with Claude Code (replacing an older registration).
    static func command(token: String, executable: String? = Bundle.main.executablePath) -> String {
        let exe = executable ?? "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch"
        return "claude mcp remove --scope user hostwatch >/dev/null 2>&1; "
            + "claude mcp add --scope user hostwatch -e \(environmentKey)=\(token) -- \"\(exe)\" --mcp"
    }

    // MARK: Access log

    /// Appends "time verdict program" (the program that started this MCP session).
    static func log(_ verdict: Verdict, in directory: URL = AppPaths.support, now: Date = Date()) {
        let line = "\(now.ISO8601Format()) \(verdict.rawValue) \(parentProgram())\n"
        let url = logFile(in: directory)
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: url.path, contents: Data(line.utf8),
                                           attributes: [.posixPermissions: 0o600])
        }
        // Keep it small: the last 200 sessions.
        if let text = try? String(contentsOf: url, encoding: .utf8) {
            let lines = text.split(separator: "\n")
            if lines.count > 400 { try? (lines.suffix(200).joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8) }
        }
    }

    /// Newest first: (date, verdict, program).
    static func recentSessions(in directory: URL = AppPaths.support, limit: Int = 5) -> [(Date, Verdict, String)] {
        guard let text = try? String(contentsOf: logFile(in: directory), encoding: .utf8) else { return [] }
        return text.split(separator: "\n").suffix(limit).reversed().compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 2).map(String.init)
            guard parts.count >= 2, let date = try? Date(parts[0], strategy: .iso8601),
                  let verdict = Verdict(rawValue: parts[1]) else { return nil }
            return (date, verdict, parts.count > 2 ? parts[2] : "?")
        }
    }

    /// Path of the process that started this one (Claude Code, or whatever ran `--mcp`).
    private static func parentProgram() -> String {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let n = proc_pidpath(getppid(), &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : "pid \(getppid())"
    }
}
