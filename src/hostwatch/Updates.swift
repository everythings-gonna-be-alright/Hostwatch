import AppKit
import Foundation

/// A published release on GitHub.
struct Release: Equatable, Sendable {
    var version: String          // "0.4.0"
    var name: String             // "Hostwatch 0.4.0"
    var url: URL                 // the release page
    var notes: String
    var published: Date?

    /// Parses GitHub's `releases/latest` JSON.
    static func parse(_ data: Data) -> Release? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = json["tag_name"] as? String,
              let page = (json["html_url"] as? String).flatMap(URL.init(string:)),
              (json["draft"] as? Bool) != true, (json["prerelease"] as? Bool) != true else { return nil }
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        let published = (json["published_at"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
        return Release(version: version, name: json["name"] as? String ?? "Hostwatch \(version)", url: page,
                       notes: json["body"] as? String ?? "", published: published)
    }
}

enum Version {
    /// Numeric comparison of dotted versions: 0.10.0 > 0.9.2, 1.0 == 1.0.0.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        func parts(_ v: String) -> [Int] {
            v.split(separator: "-").first.map { $0.split(separator: ".").map { Int($0) ?? 0 } } ?? []
        }
        let a = parts(candidate), b = parts(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    /// This app's version (from Info.plist; "0.0.0" when run outside the bundle).
    static var current: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }
}

/// Checks GitHub for a newer release: on demand, and once a day if allowed. Sends one anonymous
/// request to api.github.com; nothing is downloaded or installed automatically.
@MainActor
final class UpdateChecker: ObservableObject {
    static let repository = "everythings-gonna-be-alright/Hostwatch"
    static let releasesPage = URL(string: "https://github.com/\(repository)/releases")!
    private static let latestAPI = URL(string: "https://api.github.com/repos/\(repository)/releases/latest")!
    private static let interval: TimeInterval = 24 * 3600

    @Published var automatic: Bool {
        didSet { UserDefaults.standard.set(automatic, forKey: "checkForUpdates"); schedule() }
    }
    /// A release newer than this app, once found.
    @Published private(set) var available: Release?
    @Published private(set) var checking = false
    @Published private(set) var lastChecked: Date?
    @Published private(set) var lastError: String?

    /// Called when an automatic check finds a new release (the app updates its menu).
    var onAvailable: (() -> Void)?
    /// Seam for tests.
    var fetch: @Sendable (URLRequest) async throws -> (Data, URLResponse) = { try await URLSession.shared.data(for: $0) }
    let currentVersion: String
    private var timer: Timer?

    init(currentVersion: String = Version.current, defaults: UserDefaults = .standard) {
        self.currentVersion = currentVersion
        automatic = defaults.object(forKey: "checkForUpdates") as? Bool ?? true
        lastChecked = defaults.object(forKey: "lastUpdateCheck") as? Date
    }

    var statusText: String {
        if checking { return "Checking…" }
        if let available { return "\(available.name) is available" }
        if let lastError { return "Couldn't check: \(lastError)" }
        guard let lastChecked else { return "Not checked yet" }
        return "Up to date · checked \(lastChecked.formatted(.relative(presentation: .named)))"
    }

    /// Starts daily checks (first one shortly after launch if a day has passed).
    func schedule() {
        timer?.invalidate()
        timer = nil
        guard automatic else { return }
        let due = lastChecked.map { $0.addingTimeInterval(Self.interval).timeIntervalSinceNow } ?? 0
        timer = Timer.scheduledTimer(withTimeInterval: max(30, due), repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.check(); self.schedule() }
            }
        }
    }

    /// Asks GitHub for the latest release. Returns it if newer than this app.
    @discardableResult
    func check() async -> Release? {
        guard !checking else { return available }
        checking = true
        defer { checking = false }
        var request = URLRequest(url: Self.latestAPI, timeoutInterval: 15)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Hostwatch/\(currentVersion)", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await fetch(request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 200
            guard status == 200 else { throw CheckError.http(status) }
            guard let release = Release.parse(data) else { throw CheckError.unreadable }
            lastError = nil
            lastChecked = Date()
            UserDefaults.standard.set(lastChecked, forKey: "lastUpdateCheck")
            let newer = Version.isNewer(release.version, than: currentVersion) ? release : nil
            let isNew = newer != nil && newer != available
            available = newer
            if isNew { onAvailable?() }
            return newer
        } catch {
            lastError = (error as? CheckError)?.text ?? error.localizedDescription
            return nil
        }
    }

    private enum CheckError: Error {
        case http(Int), unreadable
        var text: String {
            switch self {
            case .http(404): return "no release published"
            case .http(403), .http(429): return "GitHub rate limit, try later"
            case .http(let code): return "GitHub answered \(code)"
            case .unreadable: return "unexpected answer from GitHub"
            }
        }
    }

    // MARK: Asking you

    /// "Check for Updates…": always answers, even when up to date or offline.
    func checkAndReport() {
        Task {
            let newer = await check()
            NSApp.activate(ignoringOtherApps: true)
            if let newer { presentAvailable(newer); return }
            let alert = NSAlert()
            if let lastError {
                alert.messageText = "Couldn't check for updates"
                alert.informativeText = lastError.prefix(1).uppercased() + lastError.dropFirst() + "."
                alert.alertStyle = .warning
            } else {
                alert.messageText = "Hostwatch is up to date"
                alert.informativeText = "Version \(currentVersion) is the latest release."
            }
            alert.addButton(withTitle: "OK")
            alert.addButton(withTitle: "Open Releases Page")
            if alert.runModal() == .alertSecondButtonReturn { NSWorkspace.shared.open(Self.releasesPage) }
        }
    }

    /// The new version, its notes, and a way to get it.
    func presentAvailable(_ release: Release) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "\(release.name) is available"
        var info = "You have \(currentVersion)."
        if let date = release.published { info += " Released \(date.formatted(date: .abbreviated, time: .omitted))." }
        let notes = Self.plainNotes(release.notes)
        if !notes.isEmpty { info += "\n\n" + notes }
        alert.informativeText = info
        alert.addButton(withTitle: "Open Release Page")
        alert.addButton(withTitle: "Later")
        if alert.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(release.url) }
    }

    /// Release notes without Markdown markup, shortened for an alert.
    static func plainNotes(_ markdown: String, limit: Int = 600) -> String {
        var text = markdown.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "`", with: "")
        text = text.split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.hasPrefix("#") ? String($0.drop { $0 == "#" || $0 == " " }) : String($0) }
            .joined(separator: "\n")
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.count > limit ? String(text.prefix(limit)).trimmingCharacters(in: .whitespaces) + "…" : text
    }
}
