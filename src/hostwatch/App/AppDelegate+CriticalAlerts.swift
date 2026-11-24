import AppKit
import Combine

extension AppDelegate {
    /// Watches the collector and the network filter, and opens where to fix it from a click on the notification.
    func setUpCriticalAlerts() {
        guard !AppPaths.isDemo else { return }                   // the demo's collector is made up
        criticalAlerts.onOpen = { [weak self] problem in
            guard let self else { return }
            switch problem {
            case .collectorDown: self.openSettings(.general)
            case .filterStopped:
                self.rulesTab.open(.firewall)
                self.model.windowTab = 4
                self.openActivityWindow(fullScreen: false)
            }
        }
        alertDot = criticalAlerts.$active.receive(on: RunLoop.main).sink { [weak self] problems in
            let why = problems.contains(.collectorDown) ? "Hostwatch isn't watching: the collector stopped"
                : problems.contains(.filterStopped) ? "The network filter stopped" : ""
            MenuBarIcon.showAlert(!problems.isEmpty, on: self?.statusItem?.button, why: why)
        }
        collectorWatch = model.$connected.removeDuplicates().receive(on: RunLoop.main).sink { [weak self] _ in
            self?.criticalAlerts.connectionChanged()
        }
        firewall.onFilterStopped = { [weak self] why in self?.criticalAlerts.filterStopped(why: why) }
        firewall.onFilterRunning = { [weak self] in self?.criticalAlerts.filterRunning() }
        // Expected: you want it (started, not stopped or removed since) and it ran here before. Not what macOS says
        // about the service: disabled behind Hostwatch's back, it reads as off, and that is the case to report.
        criticalAlerts.start(expected: { [weak self] in
            guard let self else { return false }
            if self.model.connected { self.collector.connectedOnce = true }
            return self.collector.wanted && self.collector.connectedOnce
        }, connected: { [weak self] in self?.model.connected ?? false })
    }
}
