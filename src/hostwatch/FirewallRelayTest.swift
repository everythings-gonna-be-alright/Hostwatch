import Darwin
import Foundation

/// `sudo Hostwatch --firewall-relay-test [seconds]`: your real traffic through the relay for a while (60 s by
/// default), blocking nothing. Every new TCP and UDP connection from your programs (IPv4 and IPv6, every
/// interface; not root's, not macOS's DNS service, not the local network) goes through it. A check every 10 s
/// makes sure the web still works through it, and removes the redirect after two failures; a watchdog removes
/// it 30 s after the end whatever happens. Prints what passed, by program, and anything that failed.
enum FirewallRelayTest {
    static let flag = "--firewall-relay-test"
    static let port: UInt16 = 46_101

    final class Log: @unchecked Sendable {
        let lock = NSLock()
        var flows: [RelayFlow] = []
        func add(_ f: RelayFlow) { lock.lock(); if flows.count < 50_000 { flows.append(f) }; lock.unlock() }
        var all: [RelayFlow] { lock.lock(); defer { lock.unlock() }; return flows }
    }

    static func run(_ args: [String]) -> Never {
        setvbuf(stdout, nil, _IOLBF, 0)
        guard geteuid() == 0 else { print("Run it with sudo:  sudo '\(CommandLine.arguments[0])' \(flag) [seconds]"); exit(1) }
        let seconds = args.first.flatMap(Int.init).map { max(10, min($0, 600)) } ?? 60
        let uid = ProcessInfo.processInfo.environment["SUDO_UID"] ?? ""
        let mdns = getpwnam("_mdnsresponder")?.pointee.pw_uid ?? 65

        let relay = FirewallRelay(port: port)
        let log = Log()
        relay.onEnd = { log.add($0) }
        do { try relay.start() } catch { print("The relay couldn't start: \(error)"); exit(1) }
        for _ in 0..<50 where !relay.ready { usleep(20_000) }
        guard relay.ready else { print("The relay couldn't listen on port \(port) (in use?)."); exit(1) }

        let before = canary(uid)
        print("Hostwatch relay test · \(seconds) s · web check before: \(before ? "ok" : "FAILED")")
        guard before else { print("The web doesn't work even without the relay; try again when online."); exit(1) }

        let (loaded, problem) = PFRedirect.load(PFRedirect.rules(port: port, exemptUIDs: [0, mdns]), failsafe: TimeInterval(seconds + 30))
        guard let loaded else { print("pf didn't accept the rules:\n\(problem)"); exit(1) }
        var removed = false
        func remove() { if !removed { removed = true; PFRedirect.unload(loaded) } }
        signal(SIGINT, SIG_IGN)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        interrupt.setEventHandler { remove(); report(log.all, relay: relay, seconds: seconds, stoppedEarly: "you pressed Ctrl-C"); exit(1) }
        interrupt.resume()
        print("Redirect on. Use your Mac as usual (browse, apps, a call…); nothing is blocked.")

        var failures = 0, stoppedEarly = ""
        let start = Date()
        while Date().timeIntervalSince(start) < Double(seconds) {
            sleep(10)
            let ok = canary(uid)
            failures = ok ? 0 : failures + 1
            let f = log.all
            let errors = f.filter { !$0.error.isEmpty }.count
            print(String(format: "%3d s · %d connections done, %d open · %@ · %d with errors · web check %@",
                         Int(Date().timeIntervalSince(start)), f.count, relay.activeCount,
                         bytes(f.reduce(0) { $0 + $1.up + $1.down }), errors, ok ? "ok" : "FAILED"))
            if failures >= 2 { stoppedEarly = "the web check failed twice"; break }
        }
        remove()
        report(log.all, relay: relay, seconds: seconds, stoppedEarly: stoppedEarly)
        exit(stoppedEarly.isEmpty ? 0 : 2)
    }

    /// The web through the relay, as you (root is exempt from the redirect).
    static func canary(_ uid: String) -> Bool {
        guard !uid.isEmpty else { return true }
        let r = PFRedirect.run("/usr/bin/sudo", ["-u", "#\(uid)", "/usr/bin/curl", "-s", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}",
                                                  "https://www.apple.com/library/test/success.html"])
        return r.out.hasPrefix("2") || r.out.hasPrefix("3")
    }

    static func report(_ flows: [RelayFlow], relay: FirewallRelay, seconds: Int, stoppedEarly: String) {
        sleep(1)
        let rulesGone = !PFRedirect.isLoaded
        print("")
        if !stoppedEarly.isEmpty { print("Stopped early: \(stoppedEarly). The redirect was removed.") }
        let tcp = flows.filter(\.tcp), udp = flows.filter { !$0.tcp }
        let v6 = flows.filter { $0.client.isV6 }.count
        print("Connections: \(flows.count) (TCP \(tcp.count), UDP \(udp.count); IPv6 \(v6)) · \(bytes(flows.reduce(0) { $0 + $1.up + $1.down }))"
              + " · still open at the end: \(relay.activeCount)")
        let named = flows.filter { !$0.program.isEmpty }.count
        print("Program found: \(named) of \(flows.count)")
        let tls = tcp.filter { $0.original?.port == 443 }
        print("Host name read (TCP 443): \(tls.filter { !$0.host.isEmpty }.count) of \(tls.count)")
        let setups = tcp.map(\.setup).filter { $0 > 0 }.sorted()
        if !setups.isEmpty {
            print(String(format: "Time to connect onward: median %.0f ms, slowest 5%% %.0f ms",
                         setups[setups.count / 2] * 1000, setups[min(setups.count - 1, setups.count * 95 / 100)] * 1000))
        }
        let methods = Dictionary(grouping: flows, by: { "\($0.tcp ? "TCP" : "UDP") \($0.method.isEmpty ? "-" : $0.method)" }).mapValues(\.count)
        print("Original destination: " + methods.sorted { $0.value > $1.value }.map { "\($0.key) \($0.value)" }.joined(separator: " · "))

        print("\nBy program:")
        let byProgram = Dictionary(grouping: flows, by: { $0.program.isEmpty ? "(unknown)" : $0.program })
        for (program, list) in byProgram.sorted(by: { $0.value.count > $1.value.count }).prefix(15) {
            let hosts = Set(list.compactMap { $0.host.isEmpty ? $0.original?.address : $0.host }).sorted().prefix(3).joined(separator: ", ")
            print("  \(list.count)× \((program as NSString).lastPathComponent) · \(bytes(list.reduce(0) { $0 + $1.up + $1.down })) · \(hosts)")
        }
        let failed = flows.filter { !$0.error.isEmpty }
        if !failed.isEmpty {
            print("\nErrors (\(failed.count)):")
            for (error, list) in Dictionary(grouping: failed, by: \.error).sorted(by: { $0.value.count > $1.value.count }).prefix(10) {
                let who = Set(list.map { ($0.program as NSString).lastPathComponent }).sorted().prefix(3).joined(separator: ", ")
                let to = list.first?.original.map(\.description) ?? "?"
                print("  \(list.count)× \(error) · \(who) · e.g. \(to)")
            }
        }
        print("\npf rules removed: \(rulesGone ? "yes" : "NO — run: sudo pfctl -a \(PFRedirect.anchor) -F all")")
    }

    static func bytes(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }
}
