import Darwin
import Testing
@testable import Hostwatch

/// The app only talks to a collector socket that only root could have created, and only for you.
@Suite struct CollectorSocketTrust {
    let me: uid_t = 501

    func st(_ type: mode_t, _ perms: mode_t, owner: uid_t) -> stat {
        var s = stat()
        s.st_mode = type | perms
        s.st_uid = owner
        return s
    }

    var rootFolder: stat { st(S_IFDIR, 0o755, owner: 0) }
    var mySocket: stat { st(S_IFSOCK, 0o600, owner: me) }

    @Test func theRealCollectorIsTrusted() {
        #expect(CollectorSocket.evaluate(folder: rootFolder, socket: mySocket, uid: me, requireRootFolder: true) == .ok)
    }

    @Test func notRunningIsNotAnError() {
        #expect(CollectorSocket.evaluate(folder: rootFolder, socket: nil, uid: me, requireRootFolder: true) == .missing)
    }

    @Test func fakesAreRefused() {
        func refused(_ folder: stat?, _ socket: stat) -> Bool {
            if case .unsafe = CollectorSocket.evaluate(folder: folder, socket: socket, uid: me, requireRootFolder: true) {
                return true
            }
            return false
        }
        #expect(refused(st(S_IFDIR, 0o755, owner: me), mySocket))               // folder made by a non-root process
        #expect(refused(st(S_IFDIR, 0o777, owner: 0), mySocket))                // folder writable by anyone
        #expect(refused(st(S_IFLNK, 0o755, owner: 0), mySocket))                // folder is a symlink
        #expect(refused(nil, mySocket))                                          // folder missing
        #expect(refused(rootFolder, st(S_IFREG, 0o600, owner: me)))             // not a socket
        #expect(refused(rootFolder, st(S_IFSOCK, 0o600, owner: 502)))           // someone else's socket
        #expect(refused(rootFolder, st(S_IFSOCK, 0o666, owner: me)))            // open to other users
    }

    @Test func developmentPathSkipsOnlyTheRootFolderRule() {
        let myFolder = st(S_IFDIR, 0o755, owner: me)
        #expect(CollectorSocket.evaluate(folder: myFolder, socket: mySocket, uid: me, requireRootFolder: false) == .ok)
        #expect(CollectorSocket.evaluate(folder: st(S_IFDIR, 0o777, owner: me), socket: mySocket, uid: me,
                                         requireRootFolder: false) != .ok)
    }
}

/// Only Hostwatch's own code may talk to the real collector: the peer's code must satisfy our designated requirement.
@Suite struct CollectorPeerCode {
    @Test func theSameCodePasses() throws {
        var fds: [Int32] = [0, 0]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        #expect(AgentSocket.peerIsSameCode(fds[0]))                    // the other end is this very process
        #expect(AgentSocket.peerIsSameCode(fds[1]))
    }

    @Test func aPipeIsNotAPeer() throws {
        var fds: [Int32] = [0, 0]
        try #require(pipe(&fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        #expect(!AgentSocket.peerIsSameCode(fds[0]))                   // no audit token: refused
    }
}
