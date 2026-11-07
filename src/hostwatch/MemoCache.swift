import Foundation

/// A small thread-safe memo for pure functions; forgets everything when full (cheap, and the working set
/// refills in milliseconds).
final class MemoCache<Key: Hashable, Value>: @unchecked Sendable {
    private var store: [Key: Value] = [:]
    private let lock = NSLock()
    private let limit: Int

    init(limit: Int) { self.limit = limit }

    func get(_ key: Key) -> Value? {
        lock.lock(); defer { lock.unlock() }
        return store[key]
    }

    func set(_ key: Key, _ value: Value) {
        lock.lock(); defer { lock.unlock() }
        if store.count >= limit { store.removeAll(keepingCapacity: true) }
        store[key] = value
    }
}
