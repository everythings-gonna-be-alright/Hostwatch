import Foundation

/// Devices that announce themselves on your network (Bonjour), by address: their name and model. It asks the local
/// network once every 15 minutes, as the Finder and AirPlay menus do, and nothing leaves the network.
@MainActor
final class BonjourDevices: NSObject, @preconcurrency NetServiceBrowserDelegate, @preconcurrency NetServiceDelegate {
    /// AirPlay, Apple devices' companion link, device info, AirPlay audio, Cast, printers, HomeKit.
    static let types = ["_airplay._tcp.", "_companion-link._tcp.", "_device-info._tcp.", "_raop._tcp.", "_googlecast._tcp.",
                        "_ipp._tcp.", "_printer._tcp.", "_hap._tcp."]

    private(set) var byAddress: [String: AnnouncedDevice] = [:]
    /// A service instance's name -> model, for records without addresses (device info) matched to the same name.
    private var modelByName: [String: String] = [:]
    private var browsers: [NetServiceBrowser] = []
    private var services: [NetService] = []
    private var timer: Timer?
    var onChange: (() -> Void)?

    func start() {
        browse()
        timer = Timer.scheduledTimer(withTimeInterval: 15 * 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.browse() }
        }
    }

    private func browse() {
        browsers.forEach { $0.stop() }
        services.forEach { $0.stop() }
        browsers = Self.types.map { type in
            let b = NetServiceBrowser()
            b.delegate = self
            b.searchForServices(ofType: type, inDomain: "local.")
            return b
        }
        services = []
        // Browsing runs until stopped: a minute is enough to hear everyone that answers.
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) { [weak self] in
            MainActor.assumeIsolated { self?.browsers.forEach { $0.stop() } }
        }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        guard services.count < 500 else { return }
        services.append(service)
        service.delegate = self
        service.resolve(withTimeout: 5)
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        let txt = sender.txtRecordData().map { NetService.dictionary(fromTXTRecord: $0) }?
            .compactMapValues { String(data: $0, encoding: .utf8) } ?? [:]
        var model = DeviceModels.model(txt: txt)
        let name = DeviceModels.name(service: sender.name, txt: txt)
        if model.isEmpty { model = modelByName[sender.name] ?? "" } else { modelByName[sender.name] = model }
        let ips = (sender.addresses ?? []).compactMap { NetAddress.text(sockaddr: $0) }.map(AgentParse.stripHost)
        var changed = false
        for ip in ips where !ip.hasPrefix("127.") && ip != "::1" {
            var d = byAddress[ip] ?? AnnouncedDevice()
            let before = d
            if d.name.isEmpty || sender.type != "_device-info._tcp." { d.name = name }
            if !model.isEmpty { d.model = model }
            byAddress[ip] = d
            changed = changed || d != before
        }
        // A device-info record names the model of the device whose other services share its name.
        if !model.isEmpty {
            for (ip, d) in byAddress where d.name == name && d.model.isEmpty { byAddress[ip]?.model = model; changed = true }
        }
        if changed { onChange?() }
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        // Device info has no address of its own: keep its model for the name, read from its TXT record.
        guard sender.type == "_device-info._tcp." else { return }
        sender.startMonitoring()
    }

    func netService(_ sender: NetService, didUpdateTXTRecord data: Data) {
        let txt = NetService.dictionary(fromTXTRecord: data).compactMapValues { String(data: $0, encoding: .utf8) }
        let model = DeviceModels.model(txt: txt)
        guard !model.isEmpty else { return }
        modelByName[sender.name] = model
        for (ip, d) in byAddress where d.name == sender.name && d.model.isEmpty { byAddress[ip]?.model = model }
        sender.stopMonitoring()
        onChange?()
    }
}
