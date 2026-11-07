import Foundation

let collectorLauncherFlag = "--collector-launcher"

/// Collector-launcher mode, run as root by launchd. It spawns the collector
/// (`Hostwatch --collector`) as a child and waits; it does not exec into it. The
/// collector and eslogger then inherit this process as their TCC "responsible
/// process", so Hostwatch.app's Full Disk Access grant applies.
func runCollectorLauncher(_ args: [String]) -> Never {
    guard let program = args.first else {
        FileHandle.standardError.write(Data("collector launcher: missing program\n".utf8))
        exit(64)
    }
    let child = Process()
    child.executableURL = URL(fileURLWithPath: program)
    child.arguments = Array(args.dropFirst())
    child.terminationHandler = { exit($0.terminationStatus) }
    do {
        try child.run()
    } catch {
        FileHandle.standardError.write(Data("collector launcher: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
    // Forward stop signals (e.g. `launchctl bootout`) so the agent shuts eslogger down cleanly.
    var sources: [DispatchSourceSignal] = []
    for sig in [SIGTERM, SIGINT, SIGHUP] {
        signal(sig, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        source.setEventHandler { child.terminate() }
        source.resume()
        sources.append(source)
    }
    withExtendedLifetime(sources) { dispatchMain() }
}
