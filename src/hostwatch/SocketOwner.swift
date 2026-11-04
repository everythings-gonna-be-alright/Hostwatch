import Darwin
import Foundation

/// Which process has a TCP or UDP socket on a local port (the program behind a connection the firewall relays).
/// Reads every process's open sockets with libproc; as root it sees all of them, otherwise only yours.
enum SocketOwner {
    struct Owner: Equatable { var pid: Int32; var path: String }

    static func find(tcp: Bool, localPort: UInt16, skip: Int32 = getpid()) -> Owner? {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return nil }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        for pid in pids.prefix(max(0, n)) where pid > 0 && pid != skip {
            let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard bytes > 0 else { continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdSize + 16)
            let got = Int(proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * fdSize))) / fdSize
            for fd in fds.prefix(got) where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
                var info = socket_fdinfo()
                let size = Int32(MemoryLayout<socket_fdinfo>.size)
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, size) == size else { continue }
                let s = info.psi
                guard s.soi_family == AF_INET || s.soi_family == AF_INET6 else { continue }
                let isTCP = s.soi_kind == SOCKINFO_TCP
                guard isTCP == tcp, isTCP || s.soi_kind == SOCKINFO_IN else { continue }
                let lport = isTCP ? s.soi_proto.pri_tcp.tcpsi_ini.insi_lport : s.soi_proto.pri_in.insi_lport
                guard UInt16(truncatingIfNeeded: lport).bigEndian == localPort else { continue }
                var path = [CChar](repeating: 0, count: 4096)
                let len = proc_pidpath(pid, &path, UInt32(path.count))
                return Owner(pid: pid, path: len > 0 ? String(cString: path) : "")
            }
        }
        return nil
    }
}
