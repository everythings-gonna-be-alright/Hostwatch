import Foundation

/// Masks passwords, tokens and keys in text. One set of rules for everything that leaves the process or
/// lands on disk: the collector masks command lines before they reach history, and every prompt is
/// masked right before it goes to an AI (Claude or the on-device model), whatever built it.
enum Secrets {
    static let historyMarker = "***"
    static let aiMarker = "[REDACTED]"

    /// Header and flag names whose value is a credential.
    private static let names = "password|passwd|passphrase|pwd|pass|token|secret|api[-_]?key|apikey|access[-_]?key|"
        + "private[-_]?key|client[-_]?secret|auth|authtoken|session|credentials?|sig|signature"

    /// (pattern, template). `M` in a template is replaced by the marker. Values stop at whitespace,
    /// quotes, `&` and backslashes, so masking inside JSON or a query string never eats a delimiter.
    private static let rules: [(String, String)] = [
        // Private key blocks.
        (#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#, "M"),
        // Well-known token formats (prefix kept, so you can tell what it was).
        (#"\b(gh[pousr]_|github_pat_|glpat-|xox[abprs]-|sk-ant-|sk-|AKIA|ASIA|AIza|npm_|hf_)[A-Za-z0-9_-]{8,}"#, "$1M"),
        // JSON Web Tokens.
        (#"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"#, "M"),
        // Authorization headers, and other credential headers and cookies.
        (#"(?i)((?:proxy-)?authorization:\s*(?:bearer|basic|token|digest)?\s*)[^\s'"\\]+"#, "$1M"),
        (#"(?i)((?:x-api-key|x-auth-token|x-access-token|api-key|cookie|set-cookie):\s*)[^'"\\\n]+"#, "$1M"),
        (#"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"#, "$1 M"),
        // URL credentials: scheme://user:password@ and scheme://longtoken@.
        (#"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@'"]+:)[^@\s/'"]+@"#, "$1M@"),
        (#"(://)[A-Za-z0-9_-]{20,}@"#, "$1M@"),
        // name=value and name: value (also FOO_TOKEN=…, AWS_SECRET_ACCESS_KEY=…, ?token=… in URLs).
        (#"(?i)\b((?:[a-z0-9_]*[-_])?(?:"# + names + #")\s*[=:]\s*)[^\s'"&\\]+"#, "$1M"),
        // --password value, -token value (separate argument).
        (#"(?i)((?:^|\s)--?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret|auth[-_]?token)\s+)(?!-)[^\s'"\\]+"#, "$1M"),
        // Tools that take a password as a short flag.
        (#"(\bsecurity\b[^\n]*?\s-w\s+)[^\s'"\\]+"#, "$1M"),
        (#"(\bsshpass\s+-p\s*)[^\s'"\\]+"#, "$1M"),
        (#"(\bmysql(?:dump|admin)?\b[^\n]*?\s-p)[^\s'"\\]+"#, "$1M"),
        (#"((?:^|\s)(?:-u|--user)\s+[^\s:'"]+:)[^\s'"\\]+"#, "$1M"),
    ]

    private static let compiled: [(NSRegularExpression, String)] = rules.map {
        (try! NSRegularExpression(pattern: $0.0), $0.1)
    }

    static func mask(_ text: String, marker: String = aiMarker) -> String {
        guard !text.isEmpty else { return text }
        var out = text
        for (rx, template) in compiled {
            let t = template.replacingOccurrences(of: "M", with: NSRegularExpression.escapedTemplate(for: marker))
            out = rx.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: t)
        }
        return out
    }
}
