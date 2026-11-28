import Foundation

// The steps a story is made of, how much each weighs and how it reads.

enum StoryStage: String, Codable, CaseIterable, Comparable {
    case drop, unquarantine, runFromDrop, appShell, lolbin, encodedCommand, persistence, credential, network
    case unsignedCode, swappedBinary, newDomain, beaconing, rawIP, heavyUntrusted, knownBad, listed
    // The network map's: someone on your network trying this Mac (ADR 0017).
    case portScan, newDevice, routerChanged, largeUpload
    // A project's lockfile names a version on the malicious-package list (ADR 0024).
    case maliciousPackage

    static func < (a: StoryStage, b: StoryStage) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    var weight: Int {
        switch self {
        case .drop, .lolbin, .network, .newDevice: return 1
        case .runFromDrop, .newDomain, .rawIP: return 2
        case .unquarantine, .appShell, .encodedCommand, .credential, .unsignedCode, .beaconing, .heavyUntrusted, .listed: return 3
        case .persistence, .portScan, .routerChanged, .largeUpload: return 4
        case .swappedBinary: return 5
        case .knownBad, .maliciousPackage: return 8
        }
    }

    /// Strong enough to make activity started from your own terminal/IDE worth a story.
    var isStrong: Bool {
        [.unquarantine, .encodedCommand, .persistence, .credential, .unsignedCode, .swappedBinary, .beaconing, .heavyUntrusted, .knownBad, .listed, .maliciousPackage]
            .contains(self)
    }

    var title: String {
        switch self {
        case .drop: return "Download"
        case .unquarantine: return "Quarantine removed"
        case .runFromDrop: return "Ran downloaded/temp file"
        case .appShell: return "App spawned shell"
        case .lolbin: return "System tool"
        case .encodedCommand: return "Encoded/piped command"
        case .persistence: return "Autostart write"
        case .credential: return "Credential access"
        case .network: return "Outbound connection"
        case .unsignedCode: return "Unsigned download ran"
        case .swappedBinary: return "Binary replaced"
        case .newDomain: return "New domain"
        case .beaconing: return "Beaconing"
        case .rawIP: return "Raw-IP connection"
        case .heavyUntrusted: return "Heavy untrusted process"
        case .knownBad: return "Known malware"
        case .listed: return "On a blocklist"
        case .portScan: return "Port scan"
        case .newDevice: return "New device reached this Mac"
        case .routerChanged: return "Router changed"
        case .largeUpload: return "Large upload"
        case .maliciousPackage: return "Malicious package"
        }
    }

    var symbol: String {
        switch self {
        case .drop: return "arrow.down.circle"
        case .unquarantine: return "shield.slash"
        case .runFromDrop: return "play.circle"
        case .appShell: return "terminal"
        case .lolbin: return "wrench.and.screwdriver"
        case .encodedCommand: return "curlybraces"
        case .persistence: return "arrow.clockwise.circle"
        case .credential: return "key"
        case .network: return "network"
        case .unsignedCode: return "seal"
        case .swappedBinary: return "arrow.triangle.swap"
        case .newDomain: return "globe.badge.chevron.backward"
        case .beaconing: return "dot.radiowaves.right"
        case .rawIP: return "number"
        case .heavyUntrusted: return "flame"
        case .knownBad: return "xmark.octagon"
        case .listed: return "list.bullet.rectangle"
        case .portScan: return "dot.radiowaves.left.and.right"
        case .newDevice: return "questionmark.circle"
        case .routerChanged: return "wifi.exclamationmark"
        case .largeUpload: return "arrow.up.circle"
        case .maliciousPackage: return "shippingbox"
        }
    }
}
