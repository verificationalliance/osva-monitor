import Foundation

/// The apps no check here covers (no product record, no Electron), by who, if anyone, keeps them up to date: the
/// App Store, macOS, or the browser a web app runs in. Only the rest are "Apps with no security record". Each list
/// names apps the way the person knows them, never by bundle or app ID, and keeps each app's bundle for its icon.
public enum AppCoverage {
    public static let noRecord = "Apps with no security record"
    public static let appStore = "Kept up to date by the App Store"
    public static let macOS = "Kept up to date by macOS"
    public static func webApps(_ browser: String) -> String { "\(browser) web apps" }

    /// `names`: the apps left unchecked, as Finder names them (ElectronSource's `otherApps`); `apps`: what AppSource
    /// read about every app.
    public static func buckets(_ names: [String], apps: [InstalledApp]) -> (notChecked: Coverage.Bucket?, updatedElsewhere: [Coverage.Bucket]) {
        var byName: [String: InstalledApp] = [:]
        for a in apps where byName[a.name] == nil { byName[a.name] = a }
        var groups: [String: [(name: String, path: String)]] = [:], seen = Set<String>()
        for name in names {
            let app = byName[name]
            // The same app reached twice (a link to it, a copy of the list) is listed once.
            guard seen.insert(app.map { Paths.realPath($0.path) } ?? "name:" + name).inserted else { continue }
            let title: String
            switch app?.keeper {
            case .appStore?: title = appStore
            case .macOS?: title = macOS
            case let .browser(b)?: title = webApps(b)
            case nil: title = noRecord
            }
            groups[title, default: []].append((app?.shownName ?? name, app?.path ?? ""))
        }
        func bucket(_ title: String) -> Coverage.Bucket? {
            guard let items = groups[title]?.sorted(by: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }) else { return nil }
            return Coverage.Bucket(source: title, items: items.map(\.name), paths: items.map(\.path))
        }
        let browsers = groups.keys.filter { $0.hasSuffix(" web apps") }.sorted()
        return (bucket(noRecord), ([appStore, macOS] + browsers).compactMap(bucket))
    }
}
