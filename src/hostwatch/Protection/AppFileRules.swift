import Foundation

// One app's own file rules, next to the general ones: the firewall's Apps, for files. source: docs/adr/0021-file-rules-per-app.md

/// What an app meets in every protected place, where none of its own places decides.
enum AppPlaceChoice: String, Codable, CaseIterable, Sendable { case decides, allow, block }

/// One place on an app's card: a built-in place ("group:ssh") or a folder or file of yours, Allow or Block. It needs no
/// protection in General: a folder only this app may not open is a rule of its own.
struct AppPlace: Codable, Identifiable, Equatable, Sendable {
    var id = UUID().uuidString
    var place: String                               // "group:<id>", or an absolute path
    var isFolder = true
    var verdict: ProtectionVerdict = .block         // .allow or .block
    var on = true

    static func group(_ id: String) -> String { "group:" + id }

    var group: ProtectedGroup? { place.hasPrefix("group:") ? ProtectedGroup.group(id: String(place.dropFirst(6))) : nil }
    var path: String? { place.hasPrefix("group:") ? nil : place }
    var title: String { group?.title ?? (place as NSString).lastPathComponent }

    /// How deep it covers this access (longer is more specific), nil when it doesn't. A built-in place matches by the
    /// pattern's label, as General's card does, or by its folders, and counts as deep as its own folder: SSH keys over
    /// your home folder.
    func depth(path file: String, group fileGroup: String?, writes: Bool, home: String) -> Int? {
        if let g = group {
            guard writes || !g.writesOnly else { return nil }
            let deepest = g.prefixes(home: home).filter { AccessRules.covers($0, file) }.map(\.count).max()
            guard deepest != nil || g.id == fileGroup else { return nil }
            return deepest ?? 1
        }
        guard let p = path else { return nil }
        let covers = isFolder ? AccessRules.covers(p, file) : AccessRules.covers(p, file) && !file.hasPrefix(p + "/")
        return covers ? p.count : nil
    }
}

/// An app's card on the Protected Files and Folders page.
struct AppFileRules: Codable, Identifiable, Equatable, Sendable {
    var app: String                                 // a path: a bundle covers every program inside it
    var everywhere: AppPlaceChoice = .decides
    var places: [AppPlace] = []

    var id: String { app }
    var name: String { PlaceExceptions.name(app) }
    var ruleCount: Int { (everywhere == .decides ? 0 : 1) + places.count }

    func runs(_ program: String) -> Bool { AccessRules.runs(app, program) }

    /// Its own place that decides this access: the most specific one that covers it.
    func decision(path: String, group: String?, writes: Bool, home: String) -> ProtectionDecision? {
        guard let p = places.filter({ $0.on && $0.verdict != .ask })
            .compactMap({ p in p.depth(path: path, group: group, writes: writes, home: home).map { (p, $0) } })
            .max(by: { $0.1 < $1.1 })?.0 else { return nil }
        return p.verdict == .allow ? .init(verdict: .allow, reason: "you allow \(name) in \(p.title)")
                                   : .init(verdict: .block, reason: "you block \(name) from \(p.title)")
    }
}

enum AppFileRulesList {
    /// The card that decides for a program: the most specific one that runs it (a program's own over its bundle's).
    static func rules(for program: String, in apps: [AppFileRules]) -> AppFileRules? {
        guard !program.isEmpty else { return nil }
        return apps.filter { $0.runs(program) }.max { $0.app.count < $1.app.count }
    }

    /// Adds a place's Allow or Block to a program's card (made when missing). On both lists, Block, as before.
    static func add(_ program: String, place: String, isFolder: Bool, _ verdict: ProtectionVerdict, to apps: inout [AppFileRules]) {
        let key = rules(for: program, in: apps)?.app ?? AppRulesList.app(of: program)
        if !apps.contains(where: { $0.app == key }) { apps.append(AppFileRules(app: key)) }
        guard let i = apps.firstIndex(where: { $0.app == key }) else { return }
        if let j = apps[i].places.firstIndex(where: { $0.place == place }) {
            if verdict == .block { apps[i].places[j].verdict = .block }
        } else {
            apps[i].places.append(AppPlace(place: place, isFolder: isFolder, verdict: verdict))
        }
    }

    /// Program chips from before cards existed, on the built-in places and yours, become places on the apps' cards.
    static func migrated(groups: [String: ProtectedGroupSetting], custom: [CustomPlace], into apps: [AppFileRules]) -> [AppFileRules] {
        var out = apps
        for (id, s) in groups.sorted(by: { $0.key < $1.key }) {
            for p in s.exceptions.allowed { add(p, place: AppPlace.group(id), isFolder: true, .allow, to: &out) }
            for p in s.exceptions.blocked { add(p, place: AppPlace.group(id), isFolder: true, .block, to: &out) }
        }
        for c in custom {
            for p in c.exceptions.allowed { add(p, place: c.path, isFolder: c.isFolder, .allow, to: &out) }
            for p in c.exceptions.blocked { add(p, place: c.path, isFolder: c.isFolder, .block, to: &out) }
        }
        return out
    }
}

/// The collector's places (`HoldPlace`), with the apps' cards in them: an app allowed or blocked in a whole place is on
/// its lists, so it's answered without the app. An app with its own rules inside a place isn't listed there: the app
/// decides. An app's own folders and files are held too, General's protection or not.
enum FileHoldCards {
    /// What one app's card says about a whole General place: allow, block, or nil (nothing, or rules of its own inside).
    static func verdict(_ app: AppFileRules, place: String, prefixes: [String], home: String) -> ProtectionVerdict? {
        let own = app.places.filter(\.on)
        if let exact = own.first(where: { $0.place == place }) { return exact.verdict }
        let inside = own.contains { p in
            let theirs = p.group?.prefixes(home: home) ?? [p.place]
            return theirs.contains { t in prefixes.contains { AccessRules.covers($0, t) } }
        }
        if inside { return nil }
        switch app.everywhere {
        case .allow: return .allow
        case .block: return .block
        case .decides: return nil
        }
    }

    static func cards(groups: [String: ProtectedGroupSetting], custom: [CustomPlace], apps: [AppFileRules],
                      home: String) -> [[String: Any]] {
        func listed(_ place: String, _ prefixes: [String]) -> (allowed: [String], blocked: [String]) {
            var out: ([String], [String]) = ([], [])
            for app in apps {
                switch verdict(app, place: place, prefixes: prefixes, home: home) {
                case .allow?: out.0.append(app.app)
                case .block?: out.1.append(app.app)
                default: break
                }
            }
            return out
        }
        var out: [[String: Any]] = []
        for g in ProtectedGroup.all {
            let s = groups[g.id] ?? ProtectedGroupSetting()
            let place = AppPlace.group(g.id)
            // Off in General: held only for the apps whose cards name it, everyone else passes.
            let named = apps.compactMap { a in a.places.first { $0.on && $0.place == place }.map { (a.app, $0.verdict) } }
            guard s.on || !named.isEmpty else { continue }
            let all = g.prefixes(home: home)
            let lists: (allowed: [String], blocked: [String]) = s.on ? listed(place, all)
                             : (named.filter { $0.1 == .allow }.map(\.0), named.filter { $0.1 == .block }.map(\.0))
            func card(_ prefixes: [String], names: [String] = []) -> [String: Any] {
                ["id": g.id, "prefixes": prefixes, "owners": (s.on ? g.owners : []) + lists.allowed, "blocked": lists.blocked,
                 "writesOnly": g.writesOnly, "names": names, "othersPass": !s.on]
            }
            // Browser profile folders hold far more than credentials: there, only the credential stores are held.
            let exact = Set(SignatureBuilder.sensitive.filter { g.labels.contains($0.label) }
                .map { $0.prefix.hasPrefix("~") ? home + $0.prefix.dropFirst() : $0.prefix })
            let byName = all.filter { !exact.contains($0) }
            guard g.labels.contains("browser credentials"), !byName.isEmpty else { out.append(card(all)); continue }
            out += [card(all.filter(exact.contains)), card(byName, names: Array(SignatureBuilder.credentialFiles).sorted())]
                .filter { !($0["prefixes"] as? [String] ?? []).isEmpty }
        }
        for c in custom where c.on {
            let lists = listed(c.path, [c.path])
            out.append(["id": c.groupID, "prefixes": [c.path], "owners": lists.allowed, "blocked": lists.blocked,
                        "writesOnly": false])
        }
        // An app's own folders and files: the place around it keeps its lists, the app is added to its own.
        var own: [String: (allowed: [String], blocked: [String])] = [:]
        for app in apps {
            for p in app.places where p.on {
                guard let path = p.path, !custom.contains(where: { $0.on && $0.path == path }) else { continue }
                if p.verdict == .allow { own[path, default: ([], [])].allowed.append(app.app) }
                else { own[path, default: ([], [])].blocked.append(app.app) }
            }
        }
        let general = out
        for (path, lists) in own.sorted(by: { $0.key < $1.key }) {
            func depth(_ c: [String: Any]) -> Int {
                (c["prefixes"] as? [String] ?? []).filter { AccessRules.covers($0, path) }.map(\.count).max() ?? -1
            }
            let around = general.filter { depth($0) >= 0 }.max { depth($0) < depth($1) }
            out.append(["id": "app:" + path, "prefixes": [path],
                        "owners": (around?["owners"] as? [String] ?? []) + lists.allowed,
                        "blocked": (around?["blocked"] as? [String] ?? []) + lists.blocked,
                        "writesOnly": around?["writesOnly"] as? Bool ?? false, "names": around?["names"] as? [String] ?? [],
                        "othersPass": around.map { $0["othersPass"] as? Bool ?? false } ?? true])
        }
        return out
    }
}
