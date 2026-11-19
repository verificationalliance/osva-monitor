import Foundation

/// Apps, the libraries bundled in them, and editor and browser extensions, matched on this Mac to the public index's
/// `A`, `C` and `M` lines, and turned into findings with the verified decision Homebrew's projects use.
///
/// Matching reads only this Mac's files and the downloaded index. What a scan may then ask about is the product keys
/// the index itself lists (`productKeys`) and the project a bundled Python is checked as (`projectSlugs`), and both
/// pass the privacy filter first. Bundle identifiers, paths and extension IDs stay here, and whether an extension is
/// malicious is decided here alone.
public struct BundleCheck: Sendable {
    public struct AppMatch: Hashable, Sendable {
        public var app: InstalledApp
        public var record: ProductIndex.App
        /// Nil when its Info.plist has no readable version.
        public var version: String?
    }

    public struct ComponentMatch: Hashable, Sendable {
        public var app: InstalledApp
        public var found: ComponentReader.Found
        /// For a bundled Python, the project it is checked as (cpython); nil for the others.
        public var project: String?
    }

    public struct MaliciousMatch: Hashable, Sendable {
        public var record: ProductIndex.MaliciousExtension
        /// The copies in one editor or browser (one per profile).
        public var copies: [InstalledExtension]
    }

    public var apps: [AppMatch] = []
    public var components: [ComponentMatch] = []
    public var malicious: [MaliciousMatch] = []

    public init(apps: [AppMatch] = [], components: [ComponentMatch] = [], malicious: [MaliciousMatch] = []) {
        self.apps = apps; self.components = components; self.malicious = malicious
    }

    // MARK: Matching (this Mac only)

    public static func match(_ inventory: Inventory, index: PublicIndex) -> BundleCheck {
        let products = index.products
        var out = BundleCheck()
        for app in inventory.apps {
            guard let id = app.bundleID, let record = products.apps[id] else { continue }
            out.apps.append(AppMatch(app: app, record: record, version: version(of: app, key: record.versionKey)))
        }
        if !products.components.isEmpty {
            let python = { (r: ProductIndex.Component) -> String? in
                guard r.kind == .python else { return nil }
                return [r.product, "cpython"].first { index.project(slug: $0) != nil }
            }
            for (app, found) in components(in: inventory.apps, records: products.components) {
                out.components.append(ComponentMatch(app: app, found: found, project: python(found.record)))
            }
        }
        out.malicious = malicious(inventory.extensions, in: products)
        return out
    }

    /// The version the product's advisories use: CFBundleShortVersionString, unless the `A` line asks for
    /// CFBundleVersion. A missing short version falls back to a dotted CFBundleVersion ("6.6.10.69071"), never to a
    /// bare build number ("453000292").
    static func version(of app: InstalledApp, key: String) -> String? {
        if key == "CFBundleVersion" { return app.bundleVersion.flatMap(VersionText.leading) }
        return app.shortVersion.flatMap(VersionText.leading)
            ?? app.bundleVersion.flatMap(VersionText.leading).flatMap { $0.contains(".") ? $0 : nil }
    }

    /// Every app's components, read side by side (most apps need a directory listing or two).
    static func components(in apps: [InstalledApp], records: [ProductIndex.Component]) -> [(InstalledApp, ComponentReader.Found)] {
        let results = Results(count: apps.count)
        DispatchQueue.concurrentPerform(iterations: apps.count) { i in
            results.set(i, ComponentReader.components(in: URL(fileURLWithPath: apps[i].path, isDirectory: true), records: records))
        }
        return apps.indices.flatMap { i in results.get(i).map { (apps[i], $0) } }
    }

    private final class Results: @unchecked Sendable {   // each slot is written once, by one iteration, under the lock
        private let lock = NSLock()
        private var slots: [[ComponentReader.Found]]
        init(count: Int) { slots = Array(repeating: [], count: count) }
        func set(_ i: Int, _ v: [ComponentReader.Found]) { lock.withLock { slots[i] = v } }
        func get(_ i: Int) -> [ComponentReader.Found] { lock.withLock { slots[i] } }
    }

    /// Extensions whose store lists them as malicious. Membership is the verified core's byte-for-byte test (the
    /// privacy filter's), against the `M` lines' keys; nothing is sent. One match per editor or browser.
    static func malicious(_ extensions: [InstalledExtension], in products: ProductIndex) -> [MaliciousMatch] {
        guard !extensions.isEmpty, products.maliciousKeys.count > 0 else { return [] }
        let mask = Core.shared.select(inventory: extensions.map(\.maliciousKey), index: products.maliciousKeys)
        var out: [MaliciousMatch] = [], at: [String: Int] = [:]
        for (e, hit) in zip(extensions, mask) where hit {
            guard let record = products.malicious[e.maliciousKey] else { continue }
            let key = e.maliciousKey + "\u{1F}" + e.host.rawValue
            if let i = at[key] { out[i].copies.append(e) } else { at[key] = out.count; out.append(MaliciousMatch(record: record, copies: [e])) }
        }
        return out
    }

    /// The product keys worth asking about: apps and libraries whose version could be read.
    public var productKeys: [String] {
        apps.filter { $0.version != nil }.map(\.record.product)
            + components.filter { $0.found.version != nil && $0.found.record.kind != .python }.map(\.found.record.product)
    }

    /// The projects bundled libraries are checked as (a bundled Python is cpython).
    public var projectSlugs: [String] { components.filter { $0.found.version != nil }.compactMap(\.project) }

    // MARK: Findings

    /// The advisories `installed` is affected by, weighed as Homebrew projects' are (critical, high, or exploited),
    /// each decided by the verified core, and the one upgrade that clears them: the newest of the nearest fixes.
    struct Decision {
        var advisories: [ProjectResponse.Advisory]
        var target: String?
        var exploited: Bool
        var severity: Severity?
    }

    static func decide(_ installed: String, _ recent: [ProjectResponse.Advisory]) -> Decision? {
        let core = Core.shared
        var hits: [(ProjectResponse.Advisory, String?)] = []
        for a in recent where FindingBuilder.weighed(a) {
            if core.affectedness(installed: installed, fixedVersions: a.fixedHint) == .affected {
                hits.append((a, core.nearestVersion(in: a.fixedHint, above: installed)))
            }
        }
        guard !hits.isEmpty else { return nil }
        return Decision(advisories: hits.map(\.0), target: core.newestVersion(hits.compactMap(\.1)), exploited: hits.contains { $0.0.kev },
                        severity: hits.compactMap { Severity(api: $0.0.severity) }.max())
    }

    /// A library's own version number (libavcodec 61.3.100) is compared with a record only when the record's fixed
    /// versions are numbered the same way (some share its major version); FFmpeg's releases (7.1.1) are not, and such
    /// a library is "not checked" rather than silently fine.
    static func comparable(_ found: ComponentReader.Found, _ version: String, _ recent: [ProjectResponse.Advisory]) -> Bool {
        guard found.isLibraryVersion else { return true }
        let major = ComponentReader.majorOf(version)
        return recent.contains { $0.fixedHint.contains { ComponentReader.majorOf($0) == major } }
    }

    public func findings(products: [String: ProductResponse], projects: [String: ProjectResponse]) -> [Finding] {
        var out: [Finding] = []
        func likely(_ d: Decision) -> String? { d.target.map { "Likely affected: the issuer names \($0) as fixed." } }

        // An app's own version, against its product record.
        for m in apps {
            guard let version = m.version, let record = products[m.record.product], let d = Self.decide(version, record.recent) else { continue }
            let advice = BundleAdvice.advice(for: m.app.origin, component: nil, malicious: false)
            out.append(Finding(
                id: "prod|\(m.app.path)|\(m.record.product)|\(version)", group: d.exploited ? .exploited : .criticalHigh,
                subject: .product(key: m.record.product, name: record.name), title: m.app.name, installedVersion: version,
                fixedVersion: d.target, severity: d.severity, advisoryIDs: d.advisories.map(\.id), flawCount: d.advisories.count,
                exploited: d.exploited, malicious: false, note: [likely(d), advice.note].compactMap { $0 }.joined(separator: " "),
                bigIssue: nil, origins: [m.app.origin], pageURL: record.sourceURL ?? SiteURL.home, upgradeCommand: advice.command,
                verification: .none, grade: nil))
        }

        // A library an app bundles: attributed to the app, since updating the app is what updates it. One finding per
        // app, product and version, however many of its files matched (libssl and libcrypto are one OpenSSL).
        var seen = Set<String>()
        for c in components {
            guard let version = c.found.version else { continue }
            let key = "\(c.app.path)|\(c.found.record.product)|\(version)"
            guard seen.insert(key).inserted else { continue }
            // The row's title is the app, so a bundled library's own grade and verification mark (CPython's) are not
            // shown beside it: they would read as the app's.
            let subject: Finding.Subject, recent: [ProjectResponse.Advisory], page: URL
            if let slug = c.project {
                guard let p = projects[slug] else { continue }
                (subject, recent, page) = (.project(slug: slug, name: p.name, installedAs: c.found.record.match), p.recent, SiteURL.projectPage(slug: slug))
            } else {
                guard let r = products[c.found.record.product] else { continue }
                (subject, recent, page) = (.product(key: c.found.record.product, name: r.name), r.recent, r.sourceURL ?? SiteURL.home)
            }
            guard Self.comparable(c.found, version, recent), let d = Self.decide(version, recent) else { continue }
            let advice = BundleAdvice.advice(for: c.app.origin, component: c.found.label, malicious: false)
            out.append(Finding(
                id: "comp|\(key)", group: d.exploited ? .exploited : .criticalHigh, subject: subject, title: c.app.name,
                component: c.found.label, installedVersion: version, fixedVersion: d.target, severity: d.severity,
                advisoryIDs: d.advisories.map(\.id), flawCount: d.advisories.count, exploited: d.exploited, malicious: false,
                note: [likely(d), advice.note].compactMap { $0 }.joined(separator: " "), bigIssue: nil, origins: [c.app.origin],
                pageURL: page, upgradeCommand: advice.command, verification: .none, grade: nil))
        }

        // An extension its store reported: malicious, removed with the editor's own command or in the browser.
        for m in malicious {
            let first = m.copies[0], host = first.host
            let store = ExtensionHost.storeTitle(m.record.store)
            let flagged = m.record.reason.isEmpty ? "Flagged as malicious by \(store)." : "Flagged by \(store): \(m.record.reason)."
            let advice = BundleAdvice.advice(for: first.origin, component: nil, malicious: true)
            let what: String
            if host.isEditor {
                what = "Remove it, then rotate every secret it could read."
            } else {
                let profiles = m.copies.compactMap(\.profile)
                what = BundleAdvice.removal(host: host, name: first.name, profiles: profiles) + " Its ID is \(first.id). Then rotate every secret it could read."
            }
            out.append(Finding(
                id: "ext|\(m.record.store)|\(m.record.id)|\(host.rawValue)", group: .malicious, subject: .addOn(store: m.record.store, id: m.record.id),
                title: first.name, installedVersion: first.version, fixedVersion: nil, severity: nil, advisoryIDs: [], flawCount: 0,
                exploited: false, malicious: true, note: flagged + " " + what, bigIssue: nil, origins: m.copies.map(\.origin),
                pageURL: m.record.source ?? SiteURL.home, upgradeCommand: advice.command, verification: .none, grade: nil))
        }
        return out
    }

    // MARK: What was not checked

    /// Apps this check accounts for, by name: checked against their product record, or listed under "no readable
    /// version". The rest of the apps that do not bundle Electron are "Apps with no product record".
    public func accountedApps(products: [String: ProductResponse]) -> Set<String> {
        Set(apps.filter { $0.version == nil || products[$0.record.product] != nil }.map(\.app.name))
    }

    public func notChecked(products: [String: ProductResponse], projects: [String: ProjectResponse]) -> [Coverage.Bucket] {
        var unreadable: [String] = [], noRecord: [String] = [], appVersions: [String] = [], otherNumbering: [String] = []
        for m in apps where m.version == nil { appVersions.append(m.app.name) }
        for c in components {
            if let v = c.found.version {
                let recent = c.project.map { projects[$0]?.recent } ?? products[c.found.record.product]?.recent
                if let recent {
                    if !Self.comparable(c.found, v, recent) { otherNumbering.append("\(c.found.label) \(v) in \(c.app.name)") }
                } else {
                    noRecord.append("\(c.found.label) \(v) in \(c.app.name)")
                }
            } else {
                unreadable.append("\(c.found.label) in \(c.app.name)")
            }
        }
        func unique(_ items: [String]) -> [String] {
            Array(Set(items)).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        }
        return [Coverage.Bucket(source: "Apps with no readable version", items: unique(appVersions)),
                Coverage.Bucket(source: "Bundled libraries with no readable version", items: unique(unreadable)),
                Coverage.Bucket(source: "Bundled libraries with no product record", items: unique(noRecord)),
                Coverage.Bucket(source: "Bundled libraries numbered unlike their advisories", items: unique(otherNumbering))].filter { !$0.items.isEmpty }
    }

    // MARK: Asking (only approved product keys)

    /// Each product's record: from the cache when it is fresh, else from the API. A product the server has no record
    /// of (404) is remembered as such and is "not checked", not a problem.
    static func records(_ approved: [ApprovedProduct], api: APIClient, cache: DiskCache, maxAge: TimeInterval,
                        progress: @Sendable (String) -> Void) async -> (records: [String: ProductResponse], fromCache: Int, problems: [String]) {
        var records: [String: ProductResponse] = [:], fromCache = 0, problems: [String] = []
        for p in approved {
            if let cached = cache.readJSON(CachedProduct.self, "product", p.key, maxAge: maxAge) {
                if let r = cached.record { records[p.key] = r }
                fromCache += 1
                continue
            }
            progress("Reading \(p.key)'s advisories…")
            do {
                let r = try await api.product(p)
                records[p.key] = r
                cache.writeJSON(CachedProduct(record: r), "product", p.key)
            } catch APIClient.APIError.http(404, _) {
                cache.writeJSON(CachedProduct(record: nil), "product", p.key)
            } catch {
                problems.append("Product \(p.key): \(error.localizedDescription)")
                if error as? APIClient.APIError == .keptRateLimiting { break }
            }
        }
        return (records, fromCache, problems)
    }

    struct CachedProduct: Codable { var record: ProductResponse? }
}

extension BundleAdvice {
    /// Where to remove a browser extension: "Remove it in Chrome: open chrome://extensions, in the profile “Work”,
    /// find Foo, and click Remove."
    static func removal(host: ExtensionHost, name: String, profiles: [String]) -> String {
        let page = host.extensionsPage ?? "the browser's extensions page"
        let unique = profiles.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        let quoted = unique.map { "“\($0)”" }
        let inProfiles = quoted.isEmpty ? "" : quoted.count == 1 ? ", in the profile \(quoted[0])" : ", in each of the profiles \(quoted.joined(separator: ", "))"
        return "Remove it in \(host.title): open \(page)\(inProfiles), find \(name), and click Remove."
    }
}

/// The order findings are shown in: by group, worst first, and an app's or an extension's findings together, where
/// its worst one is (Zoom's own flaws, then the Sparkle it bundles), so each thing to update reads as one.
public enum FindingOrder {
    public static func sorted(_ findings: [Finding]) -> [Finding] {
        func rank(_ f: Finding) -> Int { -(f.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1) }
        let base = findings.sorted { ($0.group, rank($0), $0.title.lowercased(), $0.id) < ($1.group, rank($1), $1.title.lowercased(), $1.id) }
        var out: [Finding] = []
        for group in Finding.Group.allCases {
            var clusters: [String: [Finding]] = [:], order: [String] = []
            for f in base where f.group == group {
                let k = f.clusterKey
                if clusters[k] == nil { order.append(k) }
                clusters[k, default: []].append(f)
            }
            out += order.flatMap { clusters[$0]! }
        }
        return out
    }
}

extension Finding {
    /// What the finding is updated through: the app's bundle, the extension's folder; else the finding itself.
    var clusterKey: String {
        if origins.count == 1 {
            switch origins[0] {
            case let .electronApp(_, path, _), let .application(_, path, _): return "app|" + path
            case let .addOn(_, _, _, _, path): return "ext|" + path
            default: break
            }
        }
        return "id|" + id
    }

    /// The words for the finding's link: the site, or the report's own host.
    public var pageLabel: String {
        let host = pageURL.host ?? ""
        return host == "verificationalliance.org" || host.isEmpty ? "Open on verificationalliance.org" : "Open the report on \(host)"
    }

    /// Whether it is about an extension (or a package inside one): removed or updated in its editor or browser.
    public var isExtension: Bool { origins.first?.kind == .extensions }
}
