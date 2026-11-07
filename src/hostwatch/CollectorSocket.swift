import Foundation
import Network

/// The collector's Unix socket, and the checks that make sure it really is the root collector:
/// it must sit in a root-owned folder nobody else can write (so only root could have created it),
/// belong to you and be closed to everyone else. The collector in turn only accepts this app.
enum CollectorSocket {
    static let defaultPath = "/var/run/hostwatch/collector.sock"
    /// HOSTWATCH_SOCKET points elsewhere for development; then the folder need not be root's.
    static var path: String { ProcessInfo.processInfo.environment["HOSTWATCH_SOCKET"] ?? defaultPath }
    static var endpoint: NWEndpoint { .unix(path: path) }

    enum Check: Equatable {
        case ok
        case missing                    // collector not running
        case unsafe(String)             // exists but cannot be trusted: never connect
    }

    static func check(path: String = path, uid: uid_t = getuid()) -> Check {
        var sock = stat(), folder = stat()
        let hasSocket = lstat(path, &sock) == 0
        let hasFolder = lstat((path as NSString).deletingLastPathComponent, &folder) == 0
        return evaluate(folder: hasFolder ? folder : nil, socket: hasSocket ? sock : nil, uid: uid,
                        requireRootFolder: path == defaultPath)
    }

    static func evaluate(folder: stat?, socket: stat?, uid: uid_t, requireRootFolder: Bool) -> Check {
        guard let socket else { return .missing }
        guard socket.st_mode & S_IFMT == S_IFSOCK else { return .unsafe("the collector path is not a socket") }
        guard socket.st_uid == uid else { return .unsafe("the socket belongs to user \(socket.st_uid), not you") }
        guard socket.st_mode & 0o077 == 0 else { return .unsafe("the socket is open to other users") }
        guard let folder, folder.st_mode & S_IFMT == S_IFDIR else { return .unsafe("the socket folder is missing or a link") }
        if requireRootFolder, folder.st_uid != 0 {
            return .unsafe("the socket folder is not owned by root, so it may not be the real collector")
        }
        guard folder.st_mode & 0o022 == 0 else { return .unsafe("the socket folder is writable by others") }
        return .ok
    }
}
