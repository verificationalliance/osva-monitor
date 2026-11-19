import Foundation

/// Apps that bundle Electron, in /Applications and ~/Applications. Each is checked as the npm package `electron` at
/// the version it bundles, because Electron's advisories are published against that package.
public struct ElectronSource: Sendable {
    static let frameworkPlist = "Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

    let roots: [URL]
    let caskForApp: [String: String]

    public init(roots: [URL], caskForApp: [String: String] = [:]) {
        self.roots = roots; self.caskForApp = caskForApp
    }

    public static func defaultRoots(home: URL) -> [URL] {
        [URL(fileURLWithPath: "/Applications", isDirectory: true), home.appendingPathComponent("Applications", isDirectory: true)]
    }

    /// The apps that bundle Electron, and the names of those that do not (which nothing here checks).
    public func collect() -> (packages: [InstalledPackage], otherApps: [String], report: SourceReport) {
        var packages: [InstalledPackage] = [], others: [String] = []
        for app in appBundles() {
            guard let raw = Self.plistString(app.appendingPathComponent(Self.frameworkPlist), "CFBundleVersion"),
                  let version = Self.electronVersion(raw) else {
                others.append(app.deletingPathExtension().lastPathComponent)
                continue
            }
            // The name Finder shows (the bundle's file name): "Visual Studio Code", where CFBundleName says "Code".
            let name = app.deletingPathExtension().lastPathComponent
            packages.append(InstalledPackage(ecosystem: .npm, name: "electron", version: version,
                                             origin: .electronApp(name: name, bundlePath: app.path, caskToken: caskForApp[app.lastPathComponent])))
        }
        packages.sort { $0.origin.label.localizedCaseInsensitiveCompare($1.origin.label) == .orderedAscending }
        return (packages, others.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending },
                SourceReport(kind: .electron, available: true, count: packages.count, detail: packages.count == 1 ? "1 app" : "\(packages.count) apps"))
    }

    /// App bundles directly in each root, and one folder down ("/Applications/Utilities", vendor folders).
    func appBundles() -> [URL] {
        let fm = FileManager.default
        var out: [URL] = []
        for root in roots {
            guard let entries = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else { continue }
            for e in entries.sorted(by: { $0.path < $1.path }) {
                if e.pathExtension == "app" { out.append(e); continue }
                guard (try? e.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true,
                      let inner = try? fm.contentsOfDirectory(at: e, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { continue }
                out += inner.filter { $0.pathExtension == "app" }.sorted { $0.path < $1.path }
            }
        }
        return out
    }

    static func plistString(_ url: URL, _ key: String) -> String? {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let value = plist[key] as? String, !value.isEmpty else { return nil }
        return value
    }

    private static let release = Regex("^([0-9]+\\.[0-9]+\\.[0-9]+)(-(alpha|beta|nightly)\\.[0-9]+)?")

    /// The Electron release an app bundles. Vendors sometimes append their own build to it ("37.10.3-dropbox-75-…");
    /// such a build is based on the release before the suffix, which is what advisories name, so the suffix is dropped.
    /// Electron's own pre-releases ("-beta.3") are kept.
    public static func electronVersion(_ raw: String) -> String? {
        guard let m = release.firstMatch(raw), let base = m[1] else { return nil }
        return base + (m[2] ?? "")
    }
}
