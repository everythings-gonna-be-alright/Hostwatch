import CryptoKit
import Foundation
import Security

/// Everything on disk sealed with one data key (AES-256-GCM) kept in the Secure Enclave, else in a keychain item
/// that only Hostwatch's own code may read. A file or line without the marker is an older, plain one.
/// source: docs/adr/0009-encryption-at-rest.md
final class Vault: @unchecked Sendable {
    nonisolated(unsafe) static var shared = isTestProcess ? Vault(key: SymmetricKey(size: .bits256)) : Vault()

    /// A test run: never the keychain or the Enclave (a key made by the test runner would lock the real app out).
    static var isTestProcess: Bool {
        let argv0 = CommandLine.arguments.first ?? ""
        return argv0.contains("swiftpm-testing-helper") || argv0.hasSuffix("xctest") || Bundle.main.bundlePath.hasSuffix(".xctest")
            || ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }

    private static let magic = Data("HWV1".utf8)
    private static let lineMagic = "HWV1:"
    static let keychainService = "tech.hostwatch.vault"
    static let keychainAccount = "data-key"
    static let enclaveTag = Data("tech.hostwatch.vault.enclave".utf8)
    static let wrappedKeyFile = "vault.key"

    enum Backend: String { case enclave = "Secure Enclave", keychain = "keychain", memory = "in memory", none = "none" }

    private let lock = NSLock()
    private var loaded = false
    private var key: SymmetricKey?
    private(set) var backend: Backend = .none
    /// Why there is no key (shown in Settings when something is wrong).
    private(set) var problem: String?
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
            if let privateKey = Self.enclaveKey(create: false), let data = Self.unwrap(blob, with: privateKey) {
                key = SymmetricKey(data: data); backend = .enclave; return
            }
            problem = "The Secure Enclave key for Hostwatch's data is gone (vault.key can't be opened)."
        }
        // 2. The keychain item (a Mac without an Enclave, or earlier versions).
        if let data = Self.keychainRead() { key = SymmetricKey(data: data); backend = .keychain; return }
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

    /// Adds the item with an access list of one: this application (its code, by designated requirement).
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
