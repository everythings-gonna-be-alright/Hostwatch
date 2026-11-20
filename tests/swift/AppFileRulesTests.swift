import Foundation
import Testing
@testable import Hostwatch

/// Files per app (ADR 0021): the app's own places, then its Every protected place, then General.
@Suite struct AppFileRulesOrder {
    let home = "/Users/me"
    let cursor = "/Applications/Cursor.app"
    var cursorBin: String { cursor + "/Contents/MacOS/Cursor" }

    func decide(_ path: String, by actor: String, mode: String = "r", status: SignatureStatus = .unclassified,
                settings: [String: ProtectedGroupSetting] = [:], places: [CustomPlace] = [],
                apps: [AppFileRules]) -> ProtectionDecision? {
        let (pattern, risk, _) = SignatureBuilder.fileTarget(path, mode: mode, actor: actor)
        return ProtectionPolicy.decideFileAccess(path: path, actor: actor, pattern: pattern, status: status, risk: risk,
                                                 writes: mode.contains("w"), settings: settings, places: places, apps: apps,
                                                 home: home, hostwatch: "/hw")
    }

    @Test func theAppsOwnPlaceWinsTheMostSpecificFirst() {
        var r = AppFileRules(app: cursor)
        r.places = [AppPlace(place: home + "/Projects", verdict: .block), AppPlace(place: home + "/Projects/site", verdict: .allow)]
        #expect(decide(home + "/Projects/site/a.md", by: cursorBin, apps: [r])?.verdict == .allow)
        #expect(decide(home + "/Projects/other/a.md", by: cursorBin, apps: [r])?.verdict == .block)
        // Not protected in General: only Cursor is concerned.
        #expect(decide(home + "/Projects/other/a.md", by: "/usr/bin/vim", apps: [r]) == nil)
        #expect(decide(home + "/Documents/x", by: cursorBin, apps: [r]) == nil)
    }

    @Test func aBuiltInPlaceOnTheCardOutranksExpectedAndPatterns() {
        var r = AppFileRules(app: "/usr/bin/ssh")
        r.places = [AppPlace(place: AppPlace.group("ssh"), verdict: .block)]
        #expect(decide(home + "/.ssh/id_ed25519", by: "/usr/bin/ssh", status: .safe, apps: [r])?.verdict == .block)
        // SSH keys are deeper than a home-wide Allow on the same card.
        r.places.append(AppPlace(place: home, verdict: .allow))
        #expect(decide(home + "/.ssh/id_ed25519", by: "/usr/bin/ssh", apps: [r])?.verdict == .block)
        // Even with General's SSH card off.
        #expect(decide(home + "/.ssh/id_ed25519", by: "/usr/bin/ssh", settings: ["ssh": .init(on: false)], apps: [r])?.verdict == .block)
    }

    @Test func autostartIsAboutChangesOnly() {
        var r = AppFileRules(app: cursor)
        r.places = [AppPlace(place: AppPlace.group("autostart"), verdict: .block)]
        #expect(decide(home + "/Library/LaunchAgents/x.plist", by: cursorBin, mode: "r", apps: [r]) == nil)
        #expect(decide(home + "/Library/LaunchAgents/x.plist", by: cursorBin, mode: "w", apps: [r])?.verdict == .block)
    }

    @Test func everyProtectedPlaceCoversOnlyWhatGeneralProtects() {
        var r = AppFileRules(app: cursor, everywhere: .block)
        let secret = CustomPlace(path: home + "/secret", isFolder: true)
        #expect(decide(home + "/secret/a", by: cursorBin, places: [secret], apps: [r])?.verdict == .block)
        #expect(decide(home + "/Documents/a", by: cursorBin, places: [secret], apps: [r]) == nil)
        r.places = [AppPlace(place: home + "/secret/shared", verdict: .allow)]
        #expect(decide(home + "/secret/shared/a", by: cursorBin, places: [secret], apps: [r])?.verdict == .allow)
        r.everywhere = .allow
        r.places = []
        #expect(decide(home + "/secret/a", by: cursorBin, status: .dangerous, places: [secret], apps: [r])?.verdict == .allow)
        // Another program still meets General.
        #expect(decide(home + "/secret/a", by: "/tmp/x", places: [secret], apps: [r])?.verdict == .ask)
    }

    @Test func aSingleFileIsJustThatFile() {
        let r = AppFileRules(app: cursor, places: [AppPlace(place: home + "/.env", isFolder: false, verdict: .block)])
        #expect(decide(home + "/.env", by: cursorBin, apps: [r])?.verdict == .block)
        #expect(decide(home + "/.env/x", by: cursorBin, apps: [r]) == nil)
    }
}

/// The collector's places carry the cards: whole-place Allow and Block on its lists, an app's own folders held.
@Suite struct AppFileRulesForTheCollector {
    let home = "/Users/me"
    let cursor = "/Applications/Cursor.app"

    func card(_ cards: [[String: Any]], _ id: String) -> [String: Any]? { cards.first { $0["id"] as? String == id } }

    @Test func wholePlacesAreListedAndOwnRulesInsideAreLeftToTheApp() {
        let blocked = AppFileRules(app: cursor, everywhere: .block)
        let ssh = AppFileRules(app: "/opt/homebrew/bin/rclone", places: [AppPlace(place: AppPlace.group("ssh"), verdict: .allow)])
        let inside = AppFileRules(app: "/usr/bin/vim", everywhere: .block,
                                  places: [AppPlace(place: home + "/.ssh/config", isFolder: false, verdict: .allow)])
        let cards = FileHoldCards.cards(groups: [:], custom: [], apps: [blocked, ssh, inside], home: home)
        let s = card(cards, "ssh")
        #expect((s?["blocked"] as? [String]) == [cursor])
        #expect((s?["owners"] as? [String])?.contains("/opt/homebrew/bin/rclone") == true)
        #expect((s?["owners"] as? [String])?.contains("/usr/bin/vim") == false)
        // vim's own file: held, with the SSH card's lists around it and vim allowed.
        let own = card(cards, "app:" + home + "/.ssh/config")
        #expect((own?["owners"] as? [String])?.contains("/usr/bin/vim") == true && (own?["blocked"] as? [String]) == [cursor])
        #expect(own?["othersPass"] as? Bool == false)
    }

    @Test func aPlaceOnlyOneAppIsBlockedFromLetsOthersPass() {
        let r = AppFileRules(app: cursor, places: [AppPlace(place: home + "/taxes", verdict: .block),
                                                   AppPlace(place: AppPlace.group("ssh"), verdict: .block)])
        let cards = FileHoldCards.cards(groups: ["ssh": .init(on: false)], custom: [], apps: [r], home: home)
        let taxes = card(cards, "app:" + home + "/taxes")
        #expect((taxes?["blocked"] as? [String]) == [cursor] && taxes?["othersPass"] as? Bool == true)
        let ssh = card(cards, "ssh")
        #expect((ssh?["blocked"] as? [String]) == [cursor] && ssh?["othersPass"] as? Bool == true)
        let place = HoldPlace(ssh!)!
        let config = HoldConfig(files: true, places: [place])
        func open(_ program: String) -> HoldRequest {
            HoldRequest(what: .open, path: program, pid: 9, ppid: 8, file: home + "/.ssh/id_rsa", mode: "r", uid: 501, seconds: 30)
        }
        #expect(config.local(open(cursor + "/Contents/MacOS/Cursor"), userUID: 501, ours: { _ in false })?.allow == false)
        #expect(config.local(open("/tmp/x"), userUID: 501, ours: { _ in false })?.allow == true)
    }
}
