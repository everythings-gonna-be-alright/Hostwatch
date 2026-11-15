import Foundation

// What a device on your network is: its maker from the hardware address (IEEE's public registry, shipped with the
// app as Resources/oui.tsv, never fetched) and its model and name from what it announces itself (Bonjour).
// source: docs/adr/0017-network-map.md

/// Hardware address prefix -> maker.
final class MakerTable: @unchecked Sendable {
    static let shared = MakerTable(url: Bundle.main.url(forResource: "oui", withExtension: "tsv"))

    private let lock = NSLock()
    private var table: [String: String]?
    private let load: () -> String

    init(url: URL?) { load = { url.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "" } }
    init(text: String) { load = { text } }

    /// The maker, nil for a private (made-up) address or an unknown prefix.
    func maker(for mac: String) -> String? {
        guard !NetMapParse.isRandom(mac) else { return nil }
        let key = mac.replacingOccurrences(of: ":", with: "").prefix(6).lowercased()
        lock.lock(); defer { lock.unlock() }
        if table == nil {
            var t: [String: String] = [:]
            for line in load().split(separator: "\n") {
                guard let tab = line.firstIndex(of: "\t") else { continue }
                t[String(line[..<tab])] = String(line[line.index(after: tab)...])
            }
            table = t
        }
        return table?[String(key)]
    }
}

/// What a device says about itself in its Bonjour announcements.
struct AnnouncedDevice: Equatable, Sendable {
    var name = ""
    var model = ""
}

enum DeviceModels {
    private static let apple: [(String, String)] = [
        ("MacBookPro", "MacBook Pro"), ("MacBookAir", "MacBook Air"), ("MacBook", "MacBook"), ("iMacPro", "iMac Pro"),
        ("iMac", "iMac"), ("Macmini", "Mac mini"), ("MacPro", "Mac Pro"), ("Mac", "Mac"), ("iPhone", "iPhone"),
        ("iPad", "iPad"), ("iPod", "iPod touch"), ("AppleTV", "Apple TV"), ("AudioAccessory", "HomePod"),
        ("Watch", "Apple Watch"), ("RealityDevice", "Apple Vision Pro"),
    ]

    /// "iPhone15,2" -> "iPhone", "AudioAccessory5,1" -> "HomePod"; anything else as it was announced.
    static func friendly(_ id: String) -> String {
        let t = id.trimmingCharacters(in: .whitespaces)
        for (prefix, name) in apple where t.hasPrefix(prefix) {
            let rest = t.dropFirst(prefix.count)
            if rest.isEmpty || rest.first?.isNumber == true { return name }
        }
        return t
    }

    /// The model a service's TXT record names, by the keys devices use (AirPlay, Companion, Cast, printers, HomeKit).
    static func model(txt: [String: String]) -> String {
        for key in ["model", "rpMd", "md", "am", "ty", "usb_MDL", "product"] {
            if let v = txt[key]?.trimmingCharacters(in: CharacterSet(charactersIn: " ()")), !v.isEmpty { return friendly(v) }
        }
        return ""
    }

    /// A service instance's name as the device's: "A1B2C3D4E5F6@Living Room" (AirPlay audio) -> "Living Room".
    static func name(service: String, txt: [String: String]) -> String {
        if let fn = txt["fn"], !fn.isEmpty { return fn }
        if let at = service.firstIndex(of: "@"), service[..<at].count == 12 { return String(service[service.index(after: at)...]) }
        return service
    }

    /// An SF Symbol for what the device is.
    static func symbol(model: String, maker: String) -> String {
        let m = model.lowercased()
        if m.hasPrefix("iphone") { return "iphone" }
        if m.hasPrefix("ipad") { return "ipad" }
        if m.hasPrefix("macbook") { return "laptopcomputer" }
        if m.hasPrefix("imac") || m.hasPrefix("mac") { return "desktopcomputer" }
        if m.hasPrefix("apple tv") || m.contains("chromecast") || m.contains("tv") { return "tv" }
        if m.hasPrefix("homepod") || m.contains("sonos") || m.contains("speaker") { return "hifispeaker" }
        if m.hasPrefix("apple watch") { return "applewatch" }
        if m.contains("printer") || m.contains("laserjet") || m.contains("deskjet") || m.contains("officejet") || m.contains("epson")
            || m.contains("brother") || m.contains("canon") { return "printer" }
        let k = maker.lowercased()
        if k.contains("espressif") || k.contains("tuya") || k.contains("shelly") { return "lightbulb" }
        if k.contains("raspberry") || k.contains("proxmox") || k.contains("synology") || k.contains("qnap") { return "server.rack" }
        return model.isEmpty && maker.isEmpty ? "questionmark.circle" : "desktopcomputer"
    }
}
