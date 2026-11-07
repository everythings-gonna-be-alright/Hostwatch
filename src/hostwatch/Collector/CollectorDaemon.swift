import Foundation
import ServiceManagement

/// The collector as a background service: a LaunchDaemon shipped inside the app bundle
/// (`Contents/Library/LaunchDaemons/local.hostwatch.collector.plist`), registered with `SMAppService` once, approved
/// by you once (an admin password, then System Settings ▸ Login Items), and started by launchd as root from then
/// on: at boot, after a crash, after an update. No password at every launch. Only a Developer ID build carries the
/// plist; a development build falls back to the admin-prompted job.
@MainActor
final class CollectorDaemon: ObservableObject {
    static let plistName = "local.hostwatch.collectord.plist"   // not the admin-prompted job's label: both may exist
    /// Where launchd writes the service's output (root-owned, world-readable).
    static let logURL = URL(fileURLWithPath: "/var/log/hostwatch-collector.log")

    @Published private(set) var status: SMAppService.Status = .notFound
    @Published private(set) var problem: String?
    private let service = SMAppService.daemon(plistName: plistName)

    /// The bundle ships the daemon (release builds signed with a Developer ID).
    let available: Bool

    init() {
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(Self.plistName)")
        available = FileManager.default.fileExists(atPath: plist.path) && !AppPaths.isDemo
        if available { refresh() }
    }

    func refresh() { status = service.status }

    var isEnabled: Bool { status == .enabled }
    var needsApproval: Bool { status == .requiresApproval }

    /// Registers the service: macOS asks for an admin password, then lists it in Login Items (approved there, or
    /// at once on some systems). `status` says which.
    func register() {
        problem = nil
        do { try service.register() } catch { problem = Self.describe(error) }
        refresh()
    }

    /// Removes the service (an admin password again): the collector stops and won't start at boot.
    func unregister() {
        problem = nil
        do { try service.unregister() } catch { problem = Self.describe(error) }
        refresh()
    }

    func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }

    private static func describe(_ error: Error) -> String {
        let e = error as NSError
        // -128 / errAuthorizationCanceled: you pressed Cancel in the password dialog.
        if e.code == -128 || e.code == -60006 { return "cancelled" }
        return e.localizedDescription
    }

    /// What the status means, in words.
    var statusText: String {
        switch status {
        case .enabled: "Collector running as a background service (no password at launch)"
        case .requiresApproval: "Waiting for your approval in System Settings ▸ Login Items"
        case .notRegistered: "Collector not registered"
        case .notFound: "Collector service not found in this build"
        @unknown default: "Collector service: unknown state"
        }
    }
}
