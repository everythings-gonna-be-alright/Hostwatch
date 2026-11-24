import Testing
@testable import Hostwatch

/// The relay's web check turns the firewall off only when the relay is the problem: no network at all (lid
/// closed, between work and home) must not count.
@Suite struct FirewallHealthCheck {
    @Test func noNetworkNeverTurnsItOff() {
        var failures = 0
        for _ in 0..<10 {
            let v = AgentFirewall.health(relayOK: false, directOK: false, failures: failures)
            #expect(!v.turnOff)
            failures = v.failures
        }
        #expect(failures == 0)
    }

    @Test func brokenRelayTurnsItOffAfterTwo() {
        let first = AgentFirewall.health(relayOK: false, directOK: true, failures: 0)
        #expect(!first.turnOff && first.failures == 1)
        let second = AgentFirewall.health(relayOK: false, directOK: true, failures: first.failures)
        #expect(second.turnOff && second.failures == 0)
    }

    @Test func anOutageInBetweenKeepsTheCount() {
        var v = AgentFirewall.health(relayOK: false, directOK: true, failures: 0)
        v = AgentFirewall.health(relayOK: false, directOK: false, failures: v.failures)
        #expect(!v.turnOff && v.failures == 1)
        v = AgentFirewall.health(relayOK: false, directOK: true, failures: v.failures)
        #expect(v.turnOff)
    }

    @Test func aWorkingRelayResets() {
        #expect(AgentFirewall.health(relayOK: true, directOK: true, failures: 1) == (0, false))
        #expect(AgentFirewall.webOK("204") && AgentFirewall.webOK("301") && !AgentFirewall.webOK("000") && !AgentFirewall.webOK(""))
    }
}
