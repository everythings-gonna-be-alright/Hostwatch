import Foundation

/// What Classify with AI is doing, pattern by pattern, as it happens: waiting, being asked, and the answer. Its own
/// object, so only the live list redraws on every step, not the windows that show the classifier's progress.
@MainActor
final class ClassifyLive: ObservableObject {
    struct Step: Identifiable, Equatable {
        enum State: Equatable {
            case waiting(String)                       // "local model", "Claude next"
            case asking(String)                        // who is being asked now
            case done(SignatureStatus, by: String, reason: String)
            case left(String)                          // stays New for you, with why
            case failed(String)
        }
        let id: String                                 // the pattern key
        let kind: EventKind
        let program: String
        let pattern: String
        var state: State
        var since = Date()
    }

    @Published private(set) var steps: [Step] = []
    /// The engine and models, in words: "Local model first (Apple General), then Claude (Sonnet)".
    @Published private(set) var engineText = ""
    @Published private(set) var startedAt: Date?
    static let limit = 500

    var asking: Step? { steps.first { if case .asking = $0.state { return true } else { return false } } }

    func start(engine: String) {
        steps = []
        engineText = engine
        startedAt = Date()
    }

    func add(_ entries: [SignatureEntry], as state: Step.State) {
        let known = Set(steps.map(\.id))
        for e in entries where !known.contains(e.id) {
            steps.append(Step(id: e.id, kind: e.kind, program: displayProcessName(e.process), pattern: e.pattern, state: state))
        }
        if steps.count > Self.limit { steps.removeFirst(steps.count - Self.limit) }
    }

    func set(_ id: String, _ state: Step.State) {
        guard let i = steps.firstIndex(where: { $0.id == id }) else { return }
        steps[i].state = state
        steps[i].since = Date()
    }

    /// Everything still waiting or being asked ends this way (cancelled, failed, no answer).
    func finishOpen(_ state: Step.State) {
        for i in steps.indices {
            switch steps[i].state {
            case .waiting, .asking: steps[i].state = state; steps[i].since = Date()
            default: break
            }
        }
    }

    func count(where match: (Step.State) -> Bool) -> Int { steps.filter { match($0.state) }.count }
}
