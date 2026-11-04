import Foundation
import Testing
@testable import Hostwatch

/// Ask and Strict: the collector asks once per program and destination, remembers the answer, and blocks what
/// gets no answer; the app answers with the rules, and your Allow / Block decides the pattern.
@Suite(.serialized) struct FirewallAskFlow {
    /// The collector's firewall with a fake app on the other end of a socket pair (no pf).
    final class Rig: @unchecked Sendable {
        let agent = Agent()
        let fw: AgentFirewall
        let client: AgentClient
        let appEnd: Int32
        init(mode: String) {
            var fds: [Int32] = [0, 0]
            socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
            client = AgentClient(fd: fds[0])
            appEnd = fds[1]
            fw = agent.firewall
            fw.turnOn = { _ in }
            fw.configure(["mode": mode], from: client)
        }
        /// fw_ask lines the app received so far.
        func asks(wait: TimeInterval = 0.3) -> [[String: Any]] {
            var tv = timeval(tv_sec: 0, tv_usec: Int32(wait * 1_000_000))
            setsockopt(appEnd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var data = Data(), buf = [UInt8](repeating: 0, count: 65_536)
            while true { let n = recv(appEnd, &buf, buf.count, 0); if n <= 0 { break }; data.append(contentsOf: buf[0..<n]) }
            return data.split(separator: 0x0A).compactMap { (try? JSONSerialization.jsonObject(with: Data($0))) as? [String: Any] }
                .filter { $0["kind"] as? String == "fw_ask" }
        }
    }

    func flow(_ program: String = "/Applications/Tool.app/Contents/MacOS/Tool", host: String = "api.example.com", pid: Int32 = 4242) -> RelayFlow {
        var f = RelayFlow(id: 1, tcp: true, client: IPEndpoint(ip: [192, 168, 1, 19], port: 50_000))
        f.program = program; f.pid = pid; f.host = host
        f.original = IPEndpoint(ip: [93, 184, 216, 34], port: 443)
        return f
    }

    final class Box: @unchecked Sendable { let lock = NSLock(); var results: [FirewallRelay.Decision] = [] }

    @Test func asksOnceRemembersTheAnswerAndBlocksSilence() async throws {
        let rig = Rig(mode: "ask")
        let box = Box()
        for _ in 0..<3 {                                   // a browser opening three connections at once
            Thread.detachNewThread { let d = rig.fw.decide(self.flow()); box.lock.lock(); box.results.append(d); box.lock.unlock() }
        }
        let asks = rig.asks()
        #expect(asks.count == 1)                           // one question for all three
        let ask = try #require(asks.first)
        #expect(ask["proc"] as? String == "/Applications/Tool.app/Contents/MacOS/Tool" && ask["host"] as? String == "api.example.com")
        #expect(ask["target"] as? String == "93.184.216.34:443" && ask["extra"] as? String == "TCP")
        rig.fw.answer(["key": ask["key"]!, "pass": true, "ttl": 300])
        for _ in 0..<100 { box.lock.lock(); let n = box.results.count; box.lock.unlock(); if n == 3 { break }; try await Task.sleep(nanoseconds: 10_000_000) }
        #expect(box.results == [.pass, .pass, .pass])
        #expect(rig.fw.decide(flow()) == .pass && rig.asks(wait: 0.1).isEmpty)      // remembered, no new question

        rig.fw.answer(["key": AgentFirewall.key(flow(host: "evil.example")), "pass": false, "ttl": 300])
        #expect(rig.fw.decide(flow(host: "evil.example")) == .block)
    }

    @Test func strictWithoutTheAppBlocksAndAskWithoutItPasses() {
        let strict = Rig(mode: "strict")
        strict.fw.clientGone(strict.client)
        #expect(strict.fw.decide(flow()) == .block)
        let ask = Rig(mode: "ask")
        ask.fw.clientGone(ask.client)
        #expect(ask.fw.decide(flow()) == .pass)            // no app to ask: Ask doesn't cut you off
    }

    @Test func theWebCheckAndHostwatchPass() {
        let rig = Rig(mode: "strict")
        rig.fw.clientGone(rig.client)
        #expect(rig.fw.decide(flow("/x", pid: Int32(getpid()))) == .pass)              // Hostwatch's own process
    }

    @MainActor @Test func theAppAnswersWithTheRules() throws {
        _ = TestEnv.ready
        let fw = FirewallMonitor(defaults: scratchDefaults("hw-fwa"), fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("fwa-\(UUID()).json"))
        var answers: [(String, Bool, TimeInterval)] = []
        var marked: [(String, SignatureStatus)] = []
        fw.answer = { answers.append(($0, $1, $2)) }
        fw.markPattern = { marked.append(($0, $1)) }
        var statuses: [String: SignatureStatus] = [:]
        fw.status = { statuses[$0.signatureKey] ?? .unclassified }
        let app = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 7, to: "93.184.216.34:443", host: "api.example.com")
        let other = net("/Applications/Tool.app/Contents/MacOS/Tool", pid: 7, to: "93.184.216.35:443", host: "cdn.example.com")

        fw.mode = .strict
        fw.handleAsk(key: "k1", event: app)
        #expect(answers.last?.0 == "k1" && answers.last?.1 == false && fw.blockedCount == 1)   // new: blocked
        statuses[app.signatureKey] = .safe
        fw.handleAsk(key: "k2", event: app)
        #expect(answers.last?.0 == "k2" && answers.last?.1 == true)                            // Safe: passes

        statuses = [:]
        fw.mode = .ask
        fw.handleAsk(key: "k3", event: app)
        fw.handleAsk(key: "k4", event: other)                // same program and kind of destination: same pattern
        #expect(fw.prompts.count == 2 && answers.count == 2)
        let prompt = try #require(fw.prompts.first)
        #expect(prompt.destination == "api.example.com")
        fw.resolve(prompt.id, allow: true)
        #expect(fw.prompts.isEmpty && marked.map(\.1) == [.safe])
        #expect(Set(answers.suffix(2).map(\.0)) == ["k3", "k4"] && answers.suffix(2).allSatisfy { $0.1 && $0.2 == 300 })

        fw.handleAsk(key: "k5", event: app)
        fw.resolve(try #require(fw.prompts.first).id, allow: nil)        // no answer in time
        #expect(answers.last?.0 == "k5" && answers.last?.1 == false && answers.last?.2 == 30 && marked.count == 1)
    }

    @MainActor @Test func theModelReadsQuestionsAndStatusEvenWhenPaused() throws {
        _ = TestEnv.ready
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hw-fwm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = HUDModel(signatures: SignatureStore(directory: dir), stories: StoryEngine(persistent: false),
                             domains: DomainRegistry(replayLearningUntil: Date()))
        var asked: [(String, ActivityEvent)] = []
        var states: [String] = []
        model.onFirewallAsk = { asked.append(($0, $1)) }
        model.onFirewallStatus = { s, _ in states.append(s) }
        model.paused = true
        model.receive(Data((#"{"kind":"fw_ask","id":3,"key":"k","time":"12:00:00","pid":7,"ppid":1,"name":"Tool","proc":"/Applications/Tool.app/Contents/MacOS/Tool","target":"93.184.216.34:443","extra":"TCP","host":"api.example.com","host_src":"dns"}"# + "\n"
                            + #"{"kind":"fw_status","state":"on","detail":""}"# + "\n").utf8))
        #expect(asked.count == 1 && asked.first?.0 == "k" && asked.first?.1.kind == .net && asked.first?.1.host == "api.example.com")
        #expect(states == ["on"] && model.history.isEmpty)
    }
}
