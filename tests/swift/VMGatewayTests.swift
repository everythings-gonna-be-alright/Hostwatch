import Foundation
import Testing
@testable import Hostwatch

/// Containers and VMs: their connections are made on macOS by the gateway (Docker Desktop's backend…), so they're
/// judged per destination and never pass on the gateway's trusted signature.
@MainActor @Suite(.serialized) struct VMGateways {
    let docker = "/Applications/Docker.app/Contents/MacOS/com.docker.backend"

    @Test func gatewaysAreRecognisedByName() {
        #expect(SignatureBuilder.vmGateway(docker) == "Docker container")
        #expect(SignatureBuilder.vmGateway("/opt/homebrew/bin/gvproxy") == "Podman container")
        #expect(SignatureBuilder.vmGateway("/usr/bin/curl") == nil)
        #expect(SignatureBuilder.vmGateway("/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop") == nil)
    }

    @Test func eachDestinationIsItsOwnPattern() {
        _ = TestEnv.ready
        let a = SignatureBuilder.signature(for: net(docker, pid: 5, to: "93.184.216.34:443", host: "api.example.com"))
        let b = SignatureBuilder.signature(for: net(docker, pid: 5, to: "151.101.1.69:443", host: "pypi.org"))
        let c = SignatureBuilder.signature(for: net(docker, pid: 5, to: "151.101.1.70:443", host: "files.pypi.org"))
        #expect(a.pattern == "TCP example.com:443" && b.pattern == "TCP pypi.org:443")
        #expect(a.key != b.key && b.key == c.key)                                  // per domain, not per host
        #expect(a.risk == .normal && a.reason == "from a docker container (inside its virtual machine)")
        let local = SignatureBuilder.signature(for: net(docker, pid: 5, to: "127.0.0.1:2375"))
        #expect(local.risk == .routine)                                            // this Mac talking to itself
        let curl = SignatureBuilder.signature(for: net("/opt/tools/bin/fetch", pid: 6, to: "93.184.216.34:443", host: "api.example.com"))
        #expect(curl.pattern == "TCP internet:443")                                // ordinary programs: unchanged
    }

    @Test func trustedSignatureDoesntLetContainersThrough() {
        _ = TestEnv.ready
        guard FileManager.default.fileExists(atPath: docker),
              let id = SigningCache.shared.identity(docker), id.teamID?.isEmpty == false else { return }   // Docker not installed
        let team = id.teamID!
        let was = SigningCache.shared.trustedTeams.contains(team)
        SigningCache.shared.setTrusted(team, true)
        defer { if !was { SigningCache.shared.setTrusted(team, false) } }
        let sig = SignatureBuilder.signature(for: net(docker, pid: 5, to: "93.184.216.34:443", host: "api.example.com"))
        #expect(sig.risk == .normal)
        let f = FirewallFacts(program: docker, proto: "TCP", ip: "93.184.216.34", port: "443", host: "api.example.com",
                              risk: sig.risk, riskReason: sig.reason, knownBad: "", patternKey: sig.key)
        #expect(FirewallPolicy.decide(f, status: .unclassified).verdict == .ask)
    }

    @Test func questionsNameTheContainer() {
        _ = TestEnv.ready
        let e = net(docker, pid: 5, to: "93.184.216.34:443", host: "api.example.com")
        let p = FirewallPrompt(key: "k", event: e, reason: "new connection", since: Date())
        #expect(p.who == "Docker container")
        #expect(FirewallAdvice.preface(p).contains("inside its virtual machine"))
    }
}
