import Darwin
import Foundation

/// Every process's open TCP and UDP sockets, read with libproc (no lsof). As root it sees all of them, otherwise
/// only yours. Used for the program behind a connection the firewall relays, and for the connection list the
/// collector compares every second.
enum SocketOwner {
    struct Owner: Equatable { var pid: Int32; var path: String }

    /// Which process has a TCP or UDP socket on a local port.
    static func find(tcp: Bool, localPort: UInt16, skip: Int32 = getpid()) -> Owner? {
        var found: Owner?
        forEachSocket(skip: skip) { pid, s in
            let isTCP = s.soi_kind == SOCKINFO_TCP
            guard isTCP == tcp else { return true }
            let lport = isTCP ? s.soi_proto.pri_tcp.tcpsi_ini.insi_lport : s.soi_proto.pri_in.insi_lport
            guard UInt16(truncatingIfNeeded: lport).bigEndian == localPort else { return true }
            found = Owner(pid: pid, path: ProcessList.path(Int(pid)))
            return false
        }
        return found
    }

    /// Connected sockets (those with a remote end), like `lsof -nP -i`: {(pid, "TCP"/"UDP", local, remote): (ppid, name)}.
    /// Addresses read "1.2.3.4:443" or "[2a00::1]:443"; IPv4 on an IPv6 socket reads as IPv4.
    static func connections(skip: Int32 = getpid()) -> [LsofConnection: (ppid: Int, command: String)] {
        var out: [LsofConnection: (ppid: Int, command: String)] = [:]
        var names: [Int32: (Int, String)] = [:]
        forEachSocket(skip: skip) { pid, s in
            let isTCP = s.soi_kind == SOCKINFO_TCP
            let ini = isTCP ? s.soi_proto.pri_tcp.tcpsi_ini : s.soi_proto.pri_in
            guard let remote = endpoint(ini, foreign: true), let local = endpoint(ini, foreign: false) else { return true }
            let who = names[pid] ?? {
                var info = proc_bsdinfo()
                let size = Int32(MemoryLayout<proc_bsdinfo>.size)
                let ok = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size
                let name = ok ? withUnsafeBytes(of: info.pbi_name) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) } : ""
                let comm = ok ? withUnsafeBytes(of: info.pbi_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) } : ""
                let v = (ok ? Int(info.pbi_ppid) : 0, name.isEmpty ? comm : name)
                names[pid] = v
                return v
            }()
            out[LsofConnection(pid: Int(pid), proto: isTCP ? "TCP" : "UDP", local: local, remote: remote)] = who
            return true
        }
        return out
    }

    /// One end of a socket as text; nil when unset (listening, unconnected UDP).
    static func endpoint(_ ini: in_sockinfo, foreign: Bool) -> String? {
        let port = UInt16(truncatingIfNeeded: foreign ? ini.insi_fport : ini.insi_lport).bigEndian
        if ini.insi_vflag & UInt8(INI_IPV4) != 0 {
            let a = foreign ? ini.insi_faddr.ina_46.i46a_addr4 : ini.insi_laddr.ina_46.i46a_addr4
            guard !foreign || (a.s_addr != 0 && port != 0) else { return nil }
            return NetAddress.text(v4: a, port: port)
        }
        guard ini.insi_vflag & UInt8(INI_IPV6) != 0 else { return nil }
        let a = foreign ? ini.insi_faddr.ina_6 : ini.insi_laddr.ina_6
        let text = NetAddress.text(v6: a, port: port)
        guard !foreign || (port != 0 && !NetAddress.isUnspecified(text)) else { return nil }
        return text
    }

    /// Calls `body` for every IPv4/IPv6 TCP or UDP socket of every process but `skip`, until it returns false.
    private static func forEachSocket(skip: Int32, _ body: (Int32, socket_info) -> Bool) {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return }
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
                guard s.soi_family == AF_INET || s.soi_family == AF_INET6,
                      s.soi_kind == SOCKINFO_TCP || s.soi_kind == SOCKINFO_IN else { continue }
                if !body(pid, s) { return }
            }
        }
    }
}

/// Addresses as the collector writes them everywhere: "1.2.3.4:443", "[2a00::1]:443" (IPv4-mapped IPv6 as IPv4,
/// no scope), so the same connection seen by different sources has the same text.
enum NetAddress {
    static func text(v4 a: in_addr, port: UInt16) -> String {
        var a = a
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count))
        return "\(String(cString: buf)):\(port)"
    }

    static func text(v6 a: in6_addr, port: UInt16) -> String {
        let b = withUnsafeBytes(of: a) { Array($0) }
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {
            return "\(b[12]).\(b[13]).\(b[14]).\(b[15]):\(port)"
        }
        var a = a
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
        return "[\(String(cString: buf))]:\(port)"
    }

    /// A sockaddr (sockaddr_in / sockaddr_in6 bytes) as text; nil for other families or too short.
    static func text(sockaddr d: Data) -> String? {
        guard d.count >= 2 else { return nil }
        return d.withUnsafeBytes { raw -> String? in
            switch Int32(raw[1]) {
            case AF_INET where d.count >= MemoryLayout<sockaddr_in>.size:
                let sin = raw.loadUnaligned(as: sockaddr_in.self)
                return text(v4: sin.sin_addr, port: UInt16(bigEndian: sin.sin_port))
            case AF_INET6 where d.count >= MemoryLayout<sockaddr_in6>.size:
                let sin6 = raw.loadUnaligned(as: sockaddr_in6.self)
                return text(v6: sin6.sin6_addr, port: UInt16(bigEndian: sin6.sin6_port))
            default: return nil
            }
        }
    }

    static func isUnspecified(_ text: String) -> Bool {
        text.hasPrefix("0.0.0.0:") || text.hasPrefix("[::]:") || text.hasSuffix(":0")
    }

    /// Loopback and link-local: this Mac talking to itself or to the next hop, not to somewhere else.
    static func isLocalOnly(_ text: String) -> Bool {
        let ip = AgentParse.stripHost(text)
        return ip.hasPrefix("127.") || ip == "::1" || ip.hasPrefix("fe80:") || ip.hasPrefix("169.254.")
    }
}
