import SwiftUI

/// The map's right-click menu: block or unblock what was clicked, in the way that fits it. Devices and addresses are
/// blocked both ways by the collector, whatever the firewall does. A port refuses other machines. A program's or a
/// domain's block is the firewall's, so it stops connections in Ask and Strict.
struct NetworkMapMenu: View {
    let node: MapNode
    @ObservedObject var store: NetworkMapStore
    let actions: NetworkMapActions
    let select: () -> Void

    var body: some View {
        Button("Show Details") { select() }
        switch node.kind {
        case .device:
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
        case .wayOut, .closedPorts:
            EmptyView()
        }
    }

    @ViewBuilder private var firewallNote: some View {
        if !actions.firewallStops() { Text("The firewall is not on Ask or Strict: it will only show what it would block") }
    }
}
