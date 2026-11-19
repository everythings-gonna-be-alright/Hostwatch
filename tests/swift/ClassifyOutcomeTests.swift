import Foundation
import Testing
@testable import Hostwatch

/// Classify with AI says why an answer was kept as a suggestion, so a pattern that stays New doesn't look decided.
@Suite struct ClassifyOutcome {
    func entry(_ process: String, risk: PatternRisk = .normal, reopened: String? = nil) -> SignatureEntry {
        var e = SignatureEntry(id: "net|\(process)|TCP internet:443", kind: .net, process: process, pattern: "TCP internet:443",
                               count: 3, risk: risk, firstSeen: Date(), lastSeen: Date(), status: .unclassified, source: nil,
                               note: nil, exampleName: "x", examplePid: 1, exampleProc: process, exampleTarget: "t",
                               exampleExtra: "TCP", exampleParent: "", exampleHost: nil, exampleHostSource: nil)
        e.reopened = reopened
        return e
    }

    @Test func eachReasonInPlainWords() {
        let app = "/Applications/Tool.app/Contents/MacOS/Tool"
        #expect(PatternClassifier.whyItWaits(.safe, entry(app, risk: .high), autoAccept: true).contains("high-risk"))
        #expect(PatternClassifier.whyItWaits(.safe, entry(app, reopened: "part of a story: x"), autoAccept: true)
            .contains("came back to you (part of a story: x)"))
        #expect(PatternClassifier.whyItWaits(.suspicious, entry(app), autoAccept: false).contains("accept them in Needs You"))
        #expect(PatternClassifier.whyItWaits(.safe, entry("/usr/bin/curl"), autoAccept: false).contains("only you can mark it Safe"))
    }
}
