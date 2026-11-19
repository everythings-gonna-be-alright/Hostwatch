import Foundation

extension String {
    /// A C string from a buffer the system filled (proc_pidpath, getnameinfo, inet_ntop, an interface name): up to its
    /// terminating NUL, as UTF-8. `String(cString:)` on an array is deprecated for this.
    init(cBuffer buf: [CChar]) {
        self = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
