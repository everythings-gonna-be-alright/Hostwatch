import Foundation
import ServiceManagement

/// Open Hostwatch at login: macOS's login item for this app (System Settings ▸ General ▸ Login Items). Off until you
/// turn it on; the state lives in macOS, so a change made there shows here too.
@MainActor
final class LoginItem: ObservableObject {
    @Published private(set) var status: SMAppService.Status = .notRegistered
    @Published private(set) var problem: String?

    init() { refresh() }

    /// On, or registered and waiting for your approval in Login Items.
    var isOn: Bool { status == .enabled || status == .requiresApproval }
    var needsApproval: Bool { status == .requiresApproval }

    func refresh() { status = SMAppService.mainApp.status }

    func set(_ on: Bool) {
        problem = nil
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            problem = error.localizedDescription
        }
        refresh()
    }

    func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }
}
