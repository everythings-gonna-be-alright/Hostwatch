import Foundation
import Testing
@testable import Hostwatch

/// The all-time Claude token counter: read from every `claude -p` result, kept across launches.
@MainActor @Suite struct ClaudeUsageCounter {
    let result: [String: Any] = [
        "type": "result", "is_error": false, "result": "[]", "total_cost_usd": 0.0123,
        "usage": ["input_tokens": 12, "cache_creation_input_tokens": 3_000, "cache_read_input_tokens": 9_000,
                  "output_tokens": 450],
    ]

    @Test func readsTokensAndCostFromAResult() throws {
        let run = try #require(ClaudeRun(result: result))
        #expect(run == ClaudeRun(input: 12_012, output: 450, cached: 12_000, cost: 0.0123))
        #expect(ClaudeRun(result: ["type": "result", "is_error": true]) == nil)       // never reached Claude
    }

    @Test func countsPerFeatureAndKeepsItAcrossLaunches() {
        let defaults = scratchDefaults("hw-usage")
        let usage = ClaudeUsage(defaults: defaults)
        usage.add(result: result, .classify)
        usage.add(result: result, .classify)
        usage.add(ClaudeRun(input: 100, output: 50, cost: 0.5), .ask)
        usage.add(nil, .rules)
        let again = ClaudeUsage(defaults: defaults)                                  // next launch
        #expect(again.totals == usage.totals)
        #expect(again.tally(.classify).runs == 2 && again.tally(.classify).tokens == 2 * 12_462)
        #expect(again.totals.all.runs == 3 && again.tally(.rules).runs == 0)
        #expect(abs(again.totals.all.cost - 0.5246) < 1e-9)
        again.reset()
        #expect(ClaudeUsage(defaults: defaults).totals.all.runs == 0)
    }

    @Test func askAIStreamCarriesTheRun() async {
        var got: ClaudeRun?
        let parser = StreamParser { if case .result(_, _, _, _, let run) = $0 { got = run } }
        let line = try! JSONSerialization.data(withJSONObject: result)
        parser.feed(line + Data("\n".utf8))
        #expect(got?.output == 450 && got?.input == 12_012)
    }

    @Test func shortNumbers() {
        #expect(ClaudeUsage.short(950) == "950")
        #expect(ClaudeUsage.short(4_800) == "4.8K" && ClaudeUsage.short(48_000) == "48K")
        #expect(ClaudeUsage.short(1_240_000) == "1.2M" && ClaudeUsage.short(12_400_000) == "12M")
        #expect(ClaudeUsage.dollars(3.414) == "$3.41" && ClaudeUsage.dollars(42.6) == "$43")
    }
}
