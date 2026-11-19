import CryptoKit
import Foundation
import Security

/// Everything on disk sealed with one data key (AES-256-GCM) kept in the Secure Enclave, else in a keychain item
/// that only Hostwatch's own code may read. A file or line without the marker is an older, plain one.
/// source: docs/adr/0009-encryption-at-rest.md
final class Vault: @unchecked Sendable {
    nonisolated(unsafe) static var shared = isTestProcess ? Vault(key: SymmetricKey(size: .bits256))
        : AppPaths.isDemo ? Vault(key: demoKey()) : Vault()

    /// The demo's own key, kept as a plain file in its folder: made-up data needs no protection, and reaching for
    /// the real key would put up a keychain dialog (the demo's code signature isn't the app's).
    private static func demoKey() -> SymmetricKey {
        #if DEMO
        if let root = Demo.root {
            let file = root.appendingPathComponent("demo-vault.key")
            if let data = try? Data(contentsOf: file), data.count == 32 { return SymmetricKey(data: data) }
            let fresh = SymmetricKey(size: .bits256)
            try? fresh.withUnsafeBytes { Data($0) }.write(to: file)
            return fresh
        }
        #endif
        return SymmetricKey(size: .bits256)
    }

    /// A test run: never the keychain or the Enclave (a key made by the test runner would lock the real app out).
    static var isTestProcess: Bool {
        let argv0 = CommandLine.arguments.first ?? ""
        return argv0.contains("swiftpm-testing-helper") || argv0.hasSuffix("xctest") || Bundle.main.bundlePath.hasSuffix(".xctest")
            || ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }

    private static let magic = Data("HWV1".utf8)
    private static let lineMagic = "HWV1:"
    // Variables only so a test can use names of its own: a test must never reach the real key.
    nonisolated(unsafe) static var keychainService = "tech.hostwatch.vault"
    static let keychainAccount = "data-key"
    nonisolated(unsafe) static var enclaveTag = Data("tech.hostwatch.vault.enclave".utf8)
    static let wrappedKeyFile = "vault.key"

    enum Backend: String { case enclave = "Secure Enclave", keychain = "keychain", memory = "in memory", none = "none" }

    private let lock = NSLock()
    private var loaded = false
    private var key: SymmetricKey?
    private(set) var backend: Backend = .none
    /// Why there is no key (shown in Settings when something is wrong).
    private(set) var problem: String?
    /// A key exists that this build can't open: nothing is read or written.
    private var locked = false
    /// Where `vault.key` lives (the support folder); tests point it elsewhere.
    var directory: URL

    init(key: SymmetricKey? = nil, directory: URL = AppPaths.support) {
        self.directory = directory
        if let key { self.key = key; backend = .memory; loaded = true }
    }

    // MARK: Sealing

    /// `data` sealed for disk: the marker, then the AES-GCM box (nonce, ciphertext, tag). Plain when there's no key.
    func seal(_ data: Data) -> Data {
        guard let key = currentKey() else { return data }
        guard let box = try? AES.GCM.seal(data, using: key), let combined = box.combined else { return data }
        return Self.magic + combined
    }

    /// What `seal` sealed; data without the marker is returned as it is (an older, plain file); nil when sealed
    /// data can't be opened (another key, or tampered with).
    func open(_ data: Data) -> Data? {
        guard data.starts(with: Self.magic) else { return data }
        guard let key = currentKey(), let box = try? AES.GCM.SealedBox(combined: data.dropFirst(Self.magic.count)),
              let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return plain
    }

    /// One line of an append-only file (a journal, a log): sealed and base64, with its marker; `\n` is appended.
    func sealLine(_ line: Data) -> Data {
        guard currentKey() != nil else { var l = line; l.append(0x0A); return l }
        return Data((Self.lineMagic + seal(line).base64EncodedString() + "\n").utf8)
    }

    /// A line as `sealLine` wrote it, or a plain line from an older version.
    func openLine(_ line: Data) -> Data? {
        guard line.starts(with: Data(Self.lineMagic.utf8)) else { return line }
        guard let sealed = Data(base64Encoded: line.dropFirst(Self.lineMagic.count)) else { return nil }
        return open(sealed)
    }

    func write(_ data: Data, to url: URL, options: Data.WritingOptions = .atomic) throws {
        try seal(data).write(to: url, options: options)
    }

    /// A file written before sealing (or by a build without a key): readable as it is, worth sealing on the next save.
    static func isPlainFile(_ url: URL) -> Bool {
        guard let h = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? h.close() }
        let head = (try? h.read(upToCount: magic.count)) ?? Data()
        return !head.isEmpty && head != magic
    }

    func read(_ url: URL) -> Data? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return open(data)
    }

    /// Appends one sealed line (creates the file with mode 0600).
    func appendLine(_ line: Data, to url: URL) {
        let out = sealLine(line)
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: out)
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: url.path, contents: out, attributes: [.posixPermissions: 0o600])
        }
    }

    /// The lines of an append-only file, opened (unreadable lines are skipped).
    func lines(of url: URL) -> [Data] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return data.split(separator: 0x0A).compactMap { openLine(Data($0)) }
    }

    var isSealed: Bool { currentKey() != nil }
    /// A key exists that this app can't use: nothing must be written (it would overwrite sealed files with plain).
    var isLocked: Bool { currentKey() == nil && (locked || problem?.contains("didn't let this app read it") == true) }

    // MARK: The key

    private func currentKey() -> SymmetricKey? {
        lock.lock(); defer { lock.unlock() }
        if !loaded { loaded = true; loadOrCreate() }
        return key
    }

    private func loadOrCreate() {
        // 1. The Enclave-wrapped key on disk.
        let wrapped = directory.appendingPathComponent(Self.wrappedKeyFile)
        if let blob = try? Data(contentsOf: wrapped) {
            // Every key with the tag: more than one can exist (a build with another keychain identity made its own).
            // Tried a few times: opening it with the Enclave can fail once and work a moment later (seen right after a
            // rebuild), and that one failure used to make a new key over the data.
            for attempt in 0..<4 {
                if attempt > 0 { Thread.sleep(forTimeInterval: 0.25) }
                for privateKey in Self.enclaveKeys() {
                    if let data = Self.unwrap(blob, with: privateKey) { key = SymmetricKey(data: data); backend = .enclave; return }
                }
            }
            // Never a new key over it: the old one may come back (another build, a keychain that wasn't ready), and a new
            // vault.key would make every sealed file unreadable for good. A keychain key that works (one a build with
            // another keychain identity made) is used instead, and this vault.key is kept beside it, never deleted.
            if Self.keychainRead() != nil {
                let aside = directory.appendingPathComponent("vault.key.unopened-\(Int(Date().timeIntervalSince1970))")
                if (try? FileManager.default.moveItem(at: wrapped, to: aside)) == nil {
                    key = Self.keychainRead().map { SymmetricKey(data: $0) }; backend = .keychain; return
                }
            } else {
                problem = "Hostwatch's data key (vault.key) can't be opened by this build of Hostwatch, so it opens nothing and writes nothing. Your data is untouched."
                locked = true
                return
            }
        }
        // 2. The keychain item (a Mac without an Enclave, or earlier versions). With an Enclave at hand the key moves
        //    into it: wrapped into vault.key, then the keychain item goes (a password alone no longer opens the data).
        if let data = Self.keychainRead() {
            key = SymmetricKey(data: data); backend = .keychain
            // The app's identity changed (0.13.0): the item's access list named the old one, so this read showed a
            // keychain dialog; re-stored, the next read is silent.
            if Migration.changedIdentity { _ = Self.keychainWrite(data) }
            if let privateKey = Self.enclaveKey(create: true), let publicKey = SecKeyCopyPublicKey(privateKey),
               let blob = Self.wrap(data, with: publicKey), (try? blob.write(to: wrapped, options: .atomic)) != nil {
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: wrapped.path)
                Self.keychainDelete()
                backend = .enclave
            }
            return
        }
        // An item that exists but couldn't be read (you pressed Deny, or a build this access list doesn't name):
        // never make a new key over it, the sealed files would become unreadable for good.
        if Self.keychainItemExists() {
            problem = "Hostwatch's data key is in your keychain but macOS didn't let this app read it. Reopen Hostwatch and choose Always Allow in the keychain dialog."
            return
        }
        // 3. New: make one.
        let fresh = SymmetricKey(size: .bits256)
        let raw = fresh.withUnsafeBytes { Data($0) }
        if let privateKey = Self.enclaveKey(create: true), let publicKey = SecKeyCopyPublicKey(privateKey),
           let blob = Self.wrap(raw, with: publicKey), (try? blob.write(to: wrapped, options: .atomic)) != nil {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: wrapped.path)
            key = fresh; backend = .enclave; return
        }
        if Self.keychainWrite(raw) { key = fresh; backend = .keychain; return }
        problem = (problem ?? "") + " No place to keep the data key: files stay readable."
    }

    // MARK: Secure Enclave

    private static func enclaveKey(create: Bool) -> SecKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: enclaveTag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecReturnRef as String: true]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item { return (item as! SecKey) }
        guard create else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           .privateKeyUsage, &error) else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                                            kSecAttrApplicationTag as String: enclaveTag,
                                            kSecAttrAccessControl as String: access],
        ]
        return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    }

    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    private static func wrap(_ data: Data, with publicKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else { return nil }
        return SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) as Data?
    }

    private static func unwrap(_ blob: Data, with privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        return SecKeyCreateDecryptedData(privateKey, algorithm, blob as CFData, &error) as Data?
    }

    // MARK: Keychain

    private static func keychainRead() -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: keychainService,
                                    kSecAttrAccount as String: keychainAccount,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    /// Whether the item is there at all (attributes only: no access-list check, so no dialog).
    private static func keychainItemExists() -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: keychainService, kSecAttrAccount as String: keychainAccount,
                                    kSecReturnAttributes as String: true]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
    }

    private static func keychainDelete() {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: keychainService, kSecAttrAccount as String: keychainAccount]
        SecItemDelete(query as CFDictionary)
    }

    /// Adds the item with an access list of one: this application (its code, by designated requirement). The two
    /// calls are deprecated (the file keychain), and stay: it holds the data key wherever the Secure Enclave can't
    /// (every build signed without an application identifier), and its warnings are the build's only ones.
    private static func keychainWrite(_ data: Data) -> Bool {
        var trusted: SecTrustedApplication?
        guard SecTrustedApplicationCreateFromPath(nil, &trusted) == errSecSuccess, let trusted else { return false }
        var access: SecAccess?
        guard SecAccessCreate("Hostwatch data key" as CFString, [trusted] as CFArray, &access) == errSecSuccess, let access
        else { return false }
        let attributes: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                         kSecAttrService as String: keychainService,
                                         kSecAttrAccount as String: keychainAccount,
                                         kSecAttrLabel as String: "Hostwatch data key",
                                         kSecAttrDescription as String: "Encrypts Hostwatch's patterns, stories and history",
                                         kSecAttrAccess as String: access,
                                         kSecValueData as String: data]
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // An item we can't read (made by another build, or its access list refused us): ours by name, replaced.
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                        kSecAttrService as String: keychainService, kSecAttrAccount as String: keychainAccount]
            SecItemDelete(query as CFDictionary)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        return status == errSecSuccess
    }
}

// MARK: Diagnosis

extension Vault {
    /// Every Secure Enclave key with the vault's tag this build can see, in both keychains macOS has.
    static func enclaveKeys() -> [SecKey] {
        var out: [SecKey] = []
        for dataProtection in [false, true] {
            var query: [String: Any] = [kSecClass as String: kSecClassKey,
                                        kSecAttrApplicationTag as String: enclaveTag,
                                        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                        kSecReturnRef as String: true,
                                        kSecMatchLimit as String: kSecMatchLimitAll]
            if dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            var items: CFTypeRef?
            if SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess, let refs = items as? [SecKey] {
                for r in refs where !out.contains(where: { CFEqual($0, r) }) { out.append(r) }
            }
        }
        return out
    }

    /// What this build sees of the data key, without creating or changing anything (`--vault-probe`).
    static func probe(directory: URL = AppPaths.support) -> String {
        var lines: [String] = []
        let blob = try? Data(contentsOf: directory.appendingPathComponent(wrappedKeyFile))
        lines.append("vault.key: \(blob.map { "\($0.count) bytes" } ?? "missing")")
        for dataProtection in [false, true] {
            var query: [String: Any] = [kSecClass as String: kSecClassKey,
                                        kSecAttrApplicationTag as String: enclaveTag,
                                        kSecReturnAttributes as String: true,
                                        kSecMatchLimit as String: kSecMatchLimitAll]
            if dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            var items: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &items)
            let groups = (items as? [[String: Any]] ?? []).map { ($0[kSecAttrAccessGroup as String] as? String ?? "?").replacingOccurrences(of: #"^[A-Z0-9]{10}\."#, with: "TEAM.", options: .regularExpression) }
            lines.append("enclave keys (\(dataProtection ? "data protection keychain" : "default search")): status \(status), \(groups.count) \(groups)")
        }
        let keys = enclaveKeys()
        let opens = blob.map { b in keys.filter { unwrap(b, with: $0) != nil }.count } ?? 0
        lines.append("keys seen: \(keys.count), opening vault.key: \(opens)")
        if let b = blob { for k in keys {
            var error: Unmanaged<CFError>?
            let ok = SecKeyCreateDecryptedData(k, algorithm, b as CFData, &error) != nil
            lines.append("  unwrap: \(ok ? "ok" : String(describing: error?.takeRetainedValue()))")
        } }
        lines.append("keychain item: \(keychainItemExists() ? (keychainRead() != nil ? "exists, opens" : "exists, can't be read") : "none")")
        return lines.joined(separator: "\n")
    }
}
