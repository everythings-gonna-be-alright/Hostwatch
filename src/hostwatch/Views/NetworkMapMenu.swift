import SwiftUI

/// The map's right-click menu: block or unblock what was clicked, in the way that fits it. Devices and addresses are
/// blocked both ways by the collector, whatever the firewall does. A port refuses other machines. A program's or a
/// domain's block is the firewall's, so it stops connections in Ask and Strict.
struct NetworkMapMenu: View {
    let node: MapNode
    @ObservedObject var store: NetworkMapStore
    let actions: NetworkMapActions
    let select: () -> Void
    /// Opens the process details panel (as under Events); nil where there's none to open.
    var showProcess: ((ActivityEvent) -> Void)? = nil
    /// Off in the full list: clicking a row already shows its details.
    var showDetailsItem = true

    var body: some View {
        if showDetailsItem { Button("Show Details") { select() } }
        if let showProcess, let event = processEvent {
            Button("Show Process Details") { select(); showProcess(event) }
        }
        if node.kind != .wayOut && node.kind != .closedPorts && (showDetailsItem || processEvent != nil) { Divider() }
        switch node.kind {
        case .device:
            if let d = store.devices[node.ref] ?? (node.ref.hasPrefix("ip:") ? MapDevice(mac: node.ref, ips: [String(node.ref.dropFirst(3))],
                                                                                           iface: "", firstSeen: Date(), lastSeen: Date()) : nil),
               store.inbound.values.contains(where: { d.ips.contains($0.remote) }) {
                Button("Clear Tries") { d.ips.forEach(store.forgetTries) }
            }
            if let why = store.blockRefusal(device: node.ref) {
                Button("Block This Device") {}.disabled(true)
                Text(why)
            } else if store.isBlocked(device: node.ref) {
                Button("Unblock This Device") { store.setBlocked(device: node.ref, false) }
            } else {
                Button("Block This Device") { store.setBlocked(device: node.ref, true) }
                Text("Nothing from it reaches this Mac, and nothing goes to it")
            }
        case .internet:
            Button("Clear Tries") { store.forgetTries(from: node.ref) }
            if store.blockedAddresses.contains(node.ref) {
                Button("Unblock \(node.ref)") { store.setBlocked(address: node.ref, false) }
            } else {
                Button("Block \(node.ref)") { store.setBlocked(address: node.ref, true) }
            }
        case .listener:
            if let port = Int(node.subtitle.dropFirst()) {
                if store.blockedPorts.contains(port) {
                    Button("Allow Other Machines to Port \(port)") { store.setBlocked(port: port, false) }
                } else {
                    Button("Block Other Machines from Port \(port)") { store.setBlocked(port: port, true) }
                    Text("This Mac can still reach it")
                }
            }
        case .program:
            if actions.programBlocked(node.ref) {
                Button("Allow \(node.title)’s Connections") { actions.blockProgram(node.ref, false) }
            } else {
                Button("Block \(node.title)’s Connections") { actions.blockProgram(node.ref, true) }
                firewallNote
            }
        case .destination:
            if let device = store.device(forIP: node.ref) {
                if store.isBlocked(device: device.mac) {
                    Button("Unblock This Device") { store.setBlocked(device: device.mac, false) }
                } else if store.blockRefusal(device: device.mac) == nil {
                    Button("Block This Device") { store.setBlocked(device: device.mac, true) }
                }
            } else if NetMapParse.ipv4(node.ref) != nil || node.ref.contains(":") {
                if store.blockedAddresses.contains(node.ref) {
                    Button("Unblock \(node.ref)") { store.setBlocked(address: node.ref, false) }
                } else {
                    Button("Block \(node.ref)") { store.setBlocked(address: node.ref, true) }
                }
            } else if actions.domainBlocked(node.ref) {
                Button("Unblock \(node.ref)") { actions.blockDomain(node.ref, false) }
            } else {
                Button("Block \(node.ref)") { actions.blockDomain(node.ref, true) }
                firewallNote
            }
        case .closedPorts:
            Button("Clear Refused Tries") { store.clearTries(refusedOnly: true) }
        case .wayOut:
            EmptyView()
        }
    }

    /// The process behind a program or a listening program.
    private var processEvent: ActivityEvent? {
        switch node.kind {
        case .program: return store.lastEvent(program: node.ref)
        case .listener: return store.listeners.first { "lis:\($0.proc)|\($0.port)" == node.id }.map(store.listenerEvent)
        default: return nil
        }
    }

    @ViewBuilder private var firewallNote: some View {
        if !actions.firewallStops() { Text("The firewall is not on Ask or Strict: it will only show what it would block") }
    }
}
