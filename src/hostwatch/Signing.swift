import Darwin
import Foundation
import Security

// Who signed a binary, cached by path. Pattern risk uses it: unsigned code from a download is
// high-risk, Apple and trusted developers' everyday activity is routine, and a binary whose signer
// changes at a known path (swapped/replaced) raises an alert.

struct CodeIdentity: Codable, Equatable {
    var signed = false
    var adhoc = false
    var apple = false              // platform binary or signed by Apple ("Software Signing")
    var teamID: String?
    var organization: String?      // "Google LLC" from the leaf certificate
    var cdhash: String?            // identifies the exact build
    var quarantined = false
    var valid: Bool?               // full signature check (async); nil = not checked yet
    var missing = false            // file gone (deleted after running?)

    /// One word for tables: Apple / Google LLC / Unsigned / Ad-hoc …
    var label: String {
        if missing { return "Missing" }
        if valid == false { return "Invalid signature" }
        if !signed { return quarantined ? "Unsigned · quarantined" : "Unsigned" }
        if adhoc { return quarantined ? "Ad-hoc · quarantined" : "Ad-hoc" }
        if apple { return "Apple" }
        return organization ?? teamID ?? "Signed"
    }

    var untrustedCode: Bool { !missing && (!signed || adhoc) }

    /// Signer changed in a way an update would not explain.
    func swapped(from old: CodeIdentity) -> String? {
        guard old.signed, !old.adhoc, !missing else { return nil }
        if !signed || adhoc { return "was signed by \(old.label), now \(label.lowercased())" }
        if old.apple && !apple { return "was Apple-signed, now \(label)" }
        if let t = old.teamID, teamID != t { return "signer changed from \(old.label) to \(label)" }
        return nil
    }
}

/// What identifies a file's current contents cheaply.
struct FileStamp: Equatable {
    var inode: UInt64 = 0, size: Int64 = 0, mtime = timespec()

    init(_ path: String) {
        var st = stat()
        guard stat(path, &st) == 0 else { return }
        inode = UInt64(st.st_ino); size = Int64(st.st_size); mtime = st.st_mtimespec
    }

    static func == (a: FileStamp, b: FileStamp) -> Bool {
        a.inode == b.inode && a.size == b.size && a.mtime.tv_sec == b.mtime.tv_sec && a.mtime.tv_nsec == b.mtime.tv_nsec
    }
}

final class SigningCache: @unchecked Sendable {
    static let shared = SigningCache()

    private let lock = NSLock()
    private var identities: [String: CodeIdentity] = [:]   // this session, by raw path
    private var stamps: [String: FileStamp] = [:]          // file state when inspected
    private var known: [String: CodeIdentity] = [:]        // persisted: last identity per path
    private var swaps: [String: String] = [:]              // path -> why it looks swapped
    private var trusted: Set<String>                        // trusted Team IDs
    private let validation = DispatchQueue(label: "signing.validate", qos: .utility)
    private let fileURL: URL
    private var dirty = false

    /// Called on the main queue when a path's identity changes after the first look
    /// (signature turned out invalid, or the signer changed): views and risk re-evaluate.
    var onChange: ((String) -> Void)?
    /// Off in reports/replays: no background validation, no disk writes.
    var live = true
    /// Reports can turn the signing rules off (REPORT_NOSIGN=1) to measure their effect.
    var enabled = ProcessInfo.processInfo.environment["REPORT_NOSIGN"] == nil

    private init() {
        // HOSTWATCH_SIGNING_DB: separate database for tests (--signing-check).
        fileURL = ProcessInfo.processInfo.environment["HOSTWATCH_SIGNING_DB"].map { URL(fileURLWithPath: $0) }
            ?? AppPaths.support.appendingPathComponent("signing.json")
        trusted = Set(UserDefaults.standard.stringArray(forKey: "trustedTeams") ?? [])
        if let data = try? Data(contentsOf: fileURL),
           let stored = try? JSONDecoder().decode([String: CodeIdentity].self, from: data) {
            known = stored
        }
    }

    // MARK: Lookup

    /// Identity of the binary at `path` (quick facts, ~1 ms on first use). Re-inspected when the
    /// file changes (inode/size/mtime), so a binary replaced while running is noticed at once.
    func identity(_ path: String) -> CodeIdentity? {
        guard path.hasPrefix("/") else { return nil }
        let stamp = FileStamp(path)
        lock.lock()
        if let id = identities[path], stamps[path] == stamp { lock.unlock(); return id }
        lock.unlock()

        let id = Self.inspect(path)
        lock.lock()
        identities[path] = id
        stamps[path] = stamp
        if let old = known[path], let why = id.swapped(from: old) { swaps[path] = why }
        if !id.missing { known[path] = id; dirty = true }
        lock.unlock()
        if live, id.signed, !id.missing { validateLater(path) }
        return id
    }

    /// Cached identity only (for drawing tables), never touches the disk.
    func cached(_ path: String) -> CodeIdentity? {
        lock.lock(); defer { lock.unlock() }
        return identities[path] ?? known[path]
    }

    func swapReason(_ path: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return swaps[path]
    }

    // MARK: Trust

    func isTrusted(_ id: CodeIdentity) -> Bool {
        guard id.signed, !id.adhoc, id.valid != false, !id.missing else { return false }
        if id.apple { return true }
        lock.lock(); defer { lock.unlock() }
        return id.teamID.map(trusted.contains) ?? false
    }

    var trustedTeams: Set<String> { lock.lock(); defer { lock.unlock() }; return trusted }

    /// Optional (off by default): treat Homebrew-installed tools as trusted. Homebrew ad-hoc-signs
    /// what it builds, so signing cannot vouch for them; this trusts the install receipt instead.
    /// /opt/homebrew is writable by your user, so a planted binary there would be trusted too.
    var trustHomebrew: Bool = ProcessInfo.processInfo.environment["REPORT_TRUST_HOMEBREW"] != nil
        || UserDefaults.standard.bool(forKey: "trustHomebrewTools") {
        didSet { UserDefaults.standard.set(trustHomebrew, forKey: "trustHomebrewTools") }
    }

    static let homebrewCellars = ["/opt/homebrew/Cellar/", "/usr/local/Cellar/"]

    /// A binary inside <Cellar>/<formula>/<version>/ that has Homebrew's INSTALL_RECEIPT.json.
    static func homebrewManaged(_ path: String, cellars: [String] = homebrewCellars) -> Bool {
        for cellar in cellars where path.hasPrefix(cellar) {
            let rest = path.dropFirst(cellar.count).split(separator: "/", maxSplits: 2)
            guard rest.count == 3 else { return false }
            let receipt = cellar + rest[0] + "/" + rest[1] + "/INSTALL_RECEIPT.json"
            return FileManager.default.fileExists(atPath: receipt)
        }
        return false
    }

    /// Trust decision for a binary: Apple, a trusted developer, or (if enabled) a Homebrew tool.
    func trusts(_ path: String, _ id: CodeIdentity) -> Bool {
        if isTrusted(id) { return true }
        return trustHomebrew && id.valid != false && !id.missing && !id.quarantined && Self.homebrewManaged(path)
    }

    func setTrusted(_ team: String, _ on: Bool) {
        lock.lock()
        if on { trusted.insert(team) } else { trusted.remove(team) }
        let list = Array(trusted)
        lock.unlock()
        UserDefaults.standard.set(list, forKey: "trustedTeams")
    }

    /// First run: trust the developers of apps already installed in /Applications (signed with a
    /// Developer ID and not quarantined) — your current baseline. New vendors stay untrusted.
    func seedTrustFromInstalledApps(completion: @escaping @MainActor () -> Void) {
        guard !UserDefaults.standard.bool(forKey: "trustedTeamsSeeded") else { return }
        UserDefaults.standard.set(true, forKey: "trustedTeamsSeeded")
        DispatchQueue.global(qos: .utility).async {
            let teams = Self.installedAppTeams()
            self.lock.lock()
            self.trusted.formUnion(teams)
            let list = Array(self.trusted)
            self.lock.unlock()
            UserDefaults.standard.set(list, forKey: "trustedTeams")
            DispatchQueue.main.async { MainActor.assumeIsolated { completion() } }
        }
    }

    /// Team IDs of Developer ID–signed, non-quarantined apps in /Applications.
    static func installedAppTeams() -> Set<String> {
        let apps = (try? FileManager.default.contentsOfDirectory(atPath: "/Applications")) ?? []
        var teams = Set<String>()
        for app in apps where app.hasSuffix(".app") {
            let id = inspect("/Applications/" + app)
            if id.signed, !id.adhoc, !id.quarantined, let t = id.teamID { teams.insert(t) }
        }
        return teams
    }

    /// Tests: trust one Team ID for this process only.
    func trustInMemory(_ team: String) {
        lock.lock(); trusted.insert(team); lock.unlock()
    }

    /// Reports/replays: same baseline as the app's first run, in memory only.
    func trustInstalledAppsInMemory() {
        let teams = Self.installedAppTeams()
        lock.lock(); trusted.formUnion(teams); lock.unlock()
    }

    // MARK: Inspection

    static func inspect(_ path: String) -> CodeIdentity {
        var id = CodeIdentity()
        guard FileManager.default.fileExists(atPath: path) else { id.missing = true; return id }
        id.quarantined = isQuarantined(path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return id }
        var cfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else { return id }
        guard info[kSecCodeInfoIdentifier as String] != nil else { return id }   // unsigned
        id.signed = true
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        id.adhoc = flags & 0x2 != 0                                              // kSecCodeSignatureAdhoc
        id.teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        if let unique = info[kSecCodeInfoUnique as String] as? Data {
            id.cdhash = unique.map { String(format: "%02x", $0) }.joined()
        }
        let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        let leaf = certs.first.flatMap { SecCertificateCopySubjectSummary($0) as String? }
        id.apple = info[kSecCodeInfoPlatformIdentifier as String] != nil
            || (id.teamID == nil && leaf == "Software Signing")
        if let leaf, !id.apple {
            // "Developer ID Application: Google LLC (EQHXZ8M8AV)" -> "Google LLC"
            var name = leaf
            if let colon = name.firstIndex(of: ":") { name = String(name[name.index(after: colon)...]) }
            if let paren = name.range(of: " (", options: .backwards) { name = String(name[..<paren.lowerBound]) }
            id.organization = name.trimmingCharacters(in: .whitespaces)
        }
        return id
    }

    private static func isQuarantined(_ path: String) -> Bool {
        // The executable, or the .app bundle that contains it.
        var candidates = [path]
        if let r = path.range(of: ".app/") { candidates.append(String(path[..<r.lowerBound]) + ".app") }
        return candidates.contains { getxattr($0, "com.apple.quarantine", nil, 0, 0, 0) >= 0 }
    }

    /// Full signature check right now (for --signing-check and the MCP server): true when the
    /// binary still matches its signature, nil when it is unsigned or missing.
    static func validateNow(_ path: String) -> Bool? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil) == errSecSuccess
    }

    /// Full check that the binary still matches its signature (catches modified executables).
    private func validateLater(_ path: String) {
        validation.async { [weak self] in
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
                  let code else { return }
            let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil)
            let valid = status == errSecSuccess
            guard let self else { return }
            self.lock.lock()
            self.identities[path]?.valid = valid
            self.known[path]?.valid = valid
            self.dirty = true
            self.lock.unlock()
            if !valid { DispatchQueue.main.async { self.onChange?(path) } }
        }
    }

    func save() {
        lock.lock()
        guard dirty, live else { lock.unlock(); return }
        dirty = false
        let snapshot = known
        lock.unlock()
        if let data = try? JSONEncoder().encode(snapshot) { try? data.write(to: fileURL, options: .atomic) }
    }
}

/// `Hostwatch --signing-check <path>…`: prints each binary's identity, swap verdict and the trust
/// decision, and records it (set HOSTWATCH_SIGNING_DB to use a scratch database).
func runSigningCheck(_ paths: [String]) -> Never {
    let cache = SigningCache.shared
    cache.trustInstalledAppsInMemory()
    for path in paths {
        guard let id = cache.identity(path) else { print("\(path): not a path"); continue }
        print("\(path)")
        print("  signer: \(id.label)  team: \(id.teamID ?? "-")  adhoc: \(id.adhoc)  apple: \(id.apple)"
              + "  quarantined: \(id.quarantined)  trusted: \(cache.isTrusted(id))")
        if let why = cache.swapReason(path) { print("  SWAPPED: \(why)") }
    }
    cache.live = true
    cache.save()
    exit(0)
}
