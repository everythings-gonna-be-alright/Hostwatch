import Foundation
import UserNotifications

/// The problems worth interrupting you for: protection silently stopped. Nothing else notifies (yet).
enum CriticalProblem: String, CaseIterable, Sendable {
    case collectorDown = "hostwatch.collector-down"
    case filterStopped = "hostwatch.filter-stopped"
}

/// When the collector being unreachable counts: at once once it has been connected (a stop you didn't ask for is
/// worth knowing about even if launchd starts it again seconds later: the alert goes when it is back), and after a
/// while at launch, when the service may still be coming up. Pure, so it is testable without a clock.
struct OutageClock: Equatable {
    enum Change: Equatable { case none, alert, recovered }

    static let grace: TimeInterval = 0
    static let launchGrace: TimeInterval = 30

    private(set) var downSince: Date?
    private(set) var alerted = false
    private(set) var connectedOnce = false

    init(launch: Date) { downSince = launch }

    /// `down`: expected to run and not connected.
    mutating func update(down: Bool, now: Date) -> Change {
        guard down else {
            connectedOnce = true
            downSince = nil
            defer { alerted = false }
            return alerted ? .recovered : .none
        }
        let since = downSince ?? now
        downSince = since
        guard !alerted, now.timeIntervalSince(since) >= (connectedOnce ? Self.grace : Self.launchGrace) else { return .none }
        alerted = true
        return .alert
    }
}

/// Posts the critical notifications and keeps the red dot. One notification per problem, a second outage replaces
/// the first. A recovery clears the dot but leaves the notification: launchd may start a stopped collector again
/// within seconds, and a notice gone before you read it says nothing.
@MainActor
final class CriticalAlerts: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published var enabled: Bool {
        didSet {
            defaults.set(enabled, forKey: "criticalNotifications")
            if enabled { requestPermission() } else { CriticalProblem.allCases.forEach(remove) }
        }
    }
    /// The problems going on now, notified or not (the switch is about notifications): the menu bar's red dot.
    @Published private(set) var active: Set<CriticalProblem> = []
    /// When each of them started: the window's banner says it.
    private(set) var since: [CriticalProblem: Date] = [:]
    /// What a click on a notification opens.
    var onOpen: (CriticalProblem) -> Void = { _ in }
    /// Delivery, replaceable in tests.
    var post: (CriticalProblem, String, String) -> Void
    var remove: (CriticalProblem) -> Void

    private let defaults: UserDefaults
    private var clock = OutageClock(launch: Date())
    private var timer: Timer?

    /// Notification Center needs an app bundle: the bare debug binary (command-line modes) and the test runner
    /// have none, and it traps there.
    private static var center: UNUserNotificationCenter? {
        Bundle.main.bundleURL.pathExtension == "app" ? UNUserNotificationCenter.current() : nil
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        enabled = defaults.object(forKey: "criticalNotifications") as? Bool ?? true
        post = { problem, title, body in
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            // The plain sound and level: critical and time-sensitive need entitlements, and a new entitlement
            // changes the signature the data key is bound to (see the vault notes).
            content.sound = .default
            Self.center?.add(UNNotificationRequest(identifier: problem.rawValue, content: content, trigger: nil))
        }
        remove = { problem in
            Self.center?.removeDeliveredNotifications(withIdentifiers: [problem.rawValue])
            Self.center?.removePendingNotificationRequests(withIdentifiers: [problem.rawValue])
        }
        super.init()
    }

    /// Starts watching the collector: `expected` says whether it should run, `connected` whether it does.
    /// The 5 s timer covers launch; `connectionChanged()` reacts to a drop at once.
    func start(expected: @escaping @MainActor () -> Bool, connected: @escaping @MainActor () -> Bool) {
        Self.center?.delegate = self
        if enabled { requestPermission() }
        isDown = { expected() && !connected() }
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.connectionChanged() }
        }
    }

    /// The collector connected or went away: checked now, not at the next tick.
    func connectionChanged() { check(down: isDown(), now: Date()) }
    private var isDown: @MainActor () -> Bool = { false }

    func check(down: Bool, now: Date) {
        switch clock.update(down: down, now: now) {
        case .alert:
            notify(.collectorDown, "Hostwatch isn't watching",
                   "The collector stopped at \(now.formatted(date: .omitted, time: .standard)). Nothing is recorded or "
                   + "protected while it is down. Click to check it.")
        case .recovered: withdraw(.collectorDown)
        case .none: break
        }
    }

    /// The network filter stopped by itself while it was stopping or asking about connections.
    func filterStopped(why: String) {
        notify(.filterStopped, "The network filter stopped",
               "Connections pass without being checked. " + (why.isEmpty ? "Click to see what happened." : why))
    }

    func filterRunning() { withdraw(.filterStopped) }

    private func notify(_ problem: CriticalProblem, _ title: String, _ body: String) {
        if since[problem] == nil { since[problem] = Date() }
        active.insert(problem)
        guard enabled else { return }
        post(problem, title, body)
    }

    private func withdraw(_ problem: CriticalProblem) {
        since[problem] = nil
        active.remove(problem)
    }

    private func requestPermission() {
        Self.center?.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    // MARK: UNUserNotificationCenterDelegate

    /// Shown even while Hostwatch is in front: the window may be on another Space, or showing another tab.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification)
        async -> UNNotificationPresentationOptions { [.banner, .sound, .list] }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let problem = CriticalProblem(rawValue: response.notification.request.identifier) else { return }
        await MainActor.run { onOpen(problem) }
    }
}
