// swift-tools-version: 5.9
import Foundation
import PackageDescription

// Command Line Tools keep the Swift Testing macro plugin in a subfolder the compiler does not always
// search; point the tests at it when present (Xcode toolchains find it on their own).
let cltTestingPlugins = "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing"
let testSettings: [SwiftSetting] = FileManager.default.fileExists(atPath: cltTestingPlugins)
    ? [.unsafeFlags(["-plugin-path", cltTestingPlugins])] : []

let package = Package(
    name: "Hostwatch",
    platforms: [.macOS("26.0")],
    products: [
        .executable(name: "Hostwatch", targets: ["Hostwatch"])
    ],
    targets: [
        // shm_open for the history write buffer (variadic in C, so not callable from Swift directly).
        .target(name: "HostwatchShim", path: "src/shim"),
        .executableTarget(name: "Hostwatch", dependencies: ["HostwatchShim"], path: "src/hostwatch"),
        .testTarget(name: "HostwatchTests", dependencies: ["Hostwatch"], path: "tests/swift",
                    swiftSettings: testSettings),
    ]
)
