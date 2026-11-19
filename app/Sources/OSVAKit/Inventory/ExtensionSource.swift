import Foundation

/// Editor and browser extensions:
///   - VS Code, VS Code Insiders, Cursor, VSCodium and Windsurf: each extension's package.json in the editor's
///     extensions folder (~/.vscode/extensions ...), and the npm packages it bundles in node_modules;
///   - Chrome, Brave, Edge, Arc and Vivaldi: <profile>/Extensions/<id>/<version>/manifest.json in every profile;
///   - Firefox: each profile's extensions.json.
/// The extensions are checked on this Mac against the index's list of malicious ones; nothing about them is sent. The
/// packages bundled in an editor's extensions are checked like any other installed npm package: only those in the
/// public index are named to the server.
public struct ExtensionSource: Sendable {
    public struct Limits: Sendable {
        public var extensionsPerFolder = 2000
        public var profiles = 64
        public var versionsPerExtension = 16
        /// node_modules inside node_modules, this deep.
        public var nesting = 4
        public var packagesPerExtension = 3000
        public var packagesInAll = 20_000
        public init() {}
    }

    static let maxManifest = 4 << 20
    static let maxMessages = 1 << 20
    static let maxPackageJSON = 1 << 20
    static let maxFirefoxList = 16 << 20
    static let maxLocalState = 8 << 20

    let home: URL
    let hosts: [ExtensionHost]
    let limits: Limits

    public init(home: URL, hosts: [ExtensionHost] = ExtensionHost.allCases, limits: Limits = Limits()) {
        self.home = home; self.hosts = hosts; self.limits = limits
    }

    public func collect() -> (extensions: [InstalledExtension], packages: [InstalledPackage], report: SourceReport) {
        var extensions: [InstalledExtension] = [], packages: [InstalledPackage] = [], present: [ExtensionHost] = []
        var editorExtensions: [InstalledExtension] = []
        for host in hosts {
            let folder = home.appendingPathComponent(host.folder)
            guard Directory.isDirectory(folder) else { continue }
            present.append(host)
            switch host {
            case .firefox:
                extensions += firefox(folder)
            case .chrome, .brave, .edge, .arc, .vivaldi:
                extensions += chromium(host, folder)
            default:
                let found = editor(host, folder).sorted { $0.path < $1.path }
                extensions += found
                editorExtensions += found
            }
        }
        packages = Self.bundledPackages(of: editorExtensions, limits: limits)
        extensions.sort { ($0.host.rawValue, $0.name.lowercased(), $0.path) < ($1.host.rawValue, $1.name.lowercased(), $1.path) }
        let n = extensions.count
        let detail = present.isEmpty ? "no editors or browsers with extensions"
            : "\(n == 1 ? "1 extension" : "\(n) extensions") in " + present.map(\.title).joined(separator: ", ")
        return (extensions, packages, SourceReport(kind: .extensions, available: !present.isEmpty, count: n, detail: detail))
    }

    // MARK: VS Code and its forks

    /// The editor's extensions. Its extensions.json, when there is one, says which folders are installed; folders
    /// listed in .obsolete are being removed and do not count. One copy per extension: the newest.
    func editor(_ host: ExtensionHost, _ folder: URL) -> [InstalledExtension] {
        let obsolete = Set(((Documents.json(folder.appendingPathComponent(".obsolete"), limit: Self.maxMessages) as? [String: Any]) ?? [:]).keys)
        var names = Directory.entries(folder, limit: limits.extensionsPerFolder)
        if let listed = Documents.json(folder.appendingPathComponent("extensions.json"), limit: Self.maxManifest) as? [[String: Any]] {
            let installed = Set(listed.prefix(limits.extensionsPerFolder).compactMap { $0["relativeLocation"] as? String })
            if !installed.isEmpty { names = names.filter { installed.contains($0) } }
        }
        var byID: [String: InstalledExtension] = [:]
        for name in names where !obsolete.contains(name) {
            let dir = folder.appendingPathComponent(name)
            guard let manifest = Documents.json(dir.appendingPathComponent("package.json"), limit: Self.maxManifest) as? [String: Any],
                  let publisher = manifest["publisher"] as? String, let extName = manifest["name"] as? String,
                  let id = ProductIndex.extensionID(publisher + "." + extName, store: host.store).map({ _ in publisher + "." + extName }),
                  let version = manifest["version"] as? String, PackageNames.isPlausibleVersion(version) else { continue }
            let title = Self.displayName(manifest["displayName"] as? String, nls: dir.appendingPathComponent("package.nls.json")) ?? id
            let e = InstalledExtension(host: host, id: id, name: title, version: version, profile: nil, path: dir.path)
            let key = id.lowercased()
            if let old = byID[key], Core.shared.compareVersions(old.version, version) >= 0 { continue }
            byID[key] = e
        }
        return Array(byID.values)
    }

    /// "%displayName%" names a string in package.nls.json.
    static func displayName(_ raw: String?, nls: URL) -> String? {
        guard let raw else { return nil }
        if raw.count > 2, raw.hasPrefix("%"), raw.hasSuffix("%") {
            let key = String(raw.dropFirst().dropLast())
            let table = Documents.json(nls, limit: maxMessages) as? [String: Any]
            let value = table?[key] as? String ?? (table?[key] as? [String: Any])?["message"] as? String
            return value.flatMap { ProductIndex.clean($0, max: 80) }
        }
        return ProductIndex.clean(raw, max: 80)
    }

    /// Every editor extension's bundled packages, read side by side, `packagesInAll` package.json files at most.
    static func bundledPackages(of extensions: [InstalledExtension], limits: Limits) -> [InstalledPackage] {
        let budget = Budget(limits.packagesInAll)
        let results = Slots(count: extensions.count)
        DispatchQueue.concurrentPerform(iterations: extensions.count) { i in
            let e = extensions[i]
            results.set(i, bundledPackages(in: URL(fileURLWithPath: e.path), origin: e.origin, limits: limits, budget: budget))
        }
        return (0..<extensions.count).flatMap { results.get($0) }
    }

    /// package.json files left to read, shared by the extensions read side by side.
    final class Budget: @unchecked Sendable {      // every access is under the lock
        private let lock = NSLock()
        private var left: Int
        init(_ n: Int) { left = n }
        /// Takes one, if any is left.
        func take() -> Bool { lock.withLock { if left > 0 { left -= 1; return true }; return false } }
        var remaining: Int { lock.withLock { left } }
    }

    private final class Slots: @unchecked Sendable {      // each slot is written once, by one iteration, under the lock
        private let lock = NSLock()
        private var slots: [[InstalledPackage]]
        init(count: Int) { slots = Array(repeating: [], count: count) }
        func set(_ i: Int, _ v: [InstalledPackage]) { lock.withLock { slots[i] = v } }
        func get(_ i: Int) -> [InstalledPackage] { lock.withLock { slots[i] } }
    }

    /// The npm packages an editor extension bundles: node_modules, and node_modules inside those, `nesting` deep, at
    /// most `packagesPerExtension` of them (and no more than the shared budget allows). Symbolic links are not
    /// followed. Each name and version once.
    static func bundledPackages(in ext: URL, origin: Origin, limits: Limits, budget: Budget) -> [InstalledPackage] {
        var out: [InstalledPackage] = [], seen = Set<String>(), read = 0
        var queue: [(URL, Int)] = [(ext.appendingPathComponent("node_modules"), 1)]
        while !queue.isEmpty, read < limits.packagesPerExtension {
            let (modules, depth) = queue.removeFirst()
            guard Directory.isDirectory(modules, noLinks: true) else { continue }
            var dirs: [URL] = []
            for name in Directory.entries(modules, limit: limits.packagesPerExtension) {
                let url = modules.appendingPathComponent(name)
                if name.hasPrefix("@") {
                    guard Directory.isDirectory(url, noLinks: true) else { continue }
                    dirs += Directory.entries(url, limit: limits.packagesPerExtension).map { url.appendingPathComponent($0) }
                } else {
                    dirs.append(url)
                }
            }
            for dir in dirs where Directory.isDirectory(dir, noLinks: true) {
                guard read < limits.packagesPerExtension, budget.take() else { return out }
                read += 1
                if let manifest = Documents.json(dir.appendingPathComponent("package.json"), limit: maxPackageJSON) as? [String: Any],
                   let name = manifest["name"] as? String, isPackageName(name),
                   let version = manifest["version"] as? String, PackageNames.isPlausibleVersion(version),
                   seen.insert(name + "@" + version).inserted {
                    out.append(InstalledPackage(ecosystem: .npm, name: name, version: version, origin: origin))
                }
                if depth < limits.nesting { queue.append((dir.appendingPathComponent("node_modules"), depth + 1)) }
            }
        }
        return out
    }

    /// npm's limits: at most 214 characters, printable, no spaces.
    static func isPackageName(_ s: String) -> Bool {
        !s.isEmpty && s.utf8.count <= 214 && s.unicodeScalars.allSatisfy { $0.value > 0x20 && $0.value < 0x7F }
    }

    // MARK: Chromium browsers

    func chromium(_ host: ExtensionHost, _ userData: URL) -> [InstalledExtension] {
        let names = Self.profileNames(userData.appendingPathComponent("Local State"))
        var out: [InstalledExtension] = [], profiles = 0
        for profile in Directory.entries(userData, limit: 512) {
            let extensions = userData.appendingPathComponent(profile).appendingPathComponent("Extensions")
            guard profiles < limits.profiles, Directory.isDirectory(extensions) else { continue }
            profiles += 1
            for id in Directory.entries(extensions, limit: limits.extensionsPerFolder) where ProductIndex.extensionID(id, store: "chrome") == id {
                let versions = Directory.entries(extensions.appendingPathComponent(id), limit: limits.versionsPerExtension)
                    .filter { Directory.isDirectory(extensions.appendingPathComponent(id).appendingPathComponent($0)) }
                guard let newest = Core.shared.newestVersion(versions.map(Self.chromiumFolderVersion)),
                      let folder = versions.first(where: { Self.chromiumFolderVersion($0) == newest }) else { continue }
                let dir = extensions.appendingPathComponent(id).appendingPathComponent(folder)
                guard let manifest = Documents.json(dir.appendingPathComponent("manifest.json"), limit: Self.maxManifest) as? [String: Any],
                      let version = manifest["version"] as? String, PackageNames.isPlausibleVersion(version) else { continue }
                let title = Self.localized(manifest["name"] as? String, defaultLocale: manifest["default_locale"] as? String, in: dir) ?? id
                out.append(InstalledExtension(host: host, id: id, name: title, version: version, profile: names[profile] ?? profile, path: dir.path))
            }
        }
        return out
    }

    /// "1.2.3_0", a version folder, is version 1.2.3 (the suffix counts installs of it).
    static func chromiumFolderVersion(_ folder: String) -> String {
        guard let underscore = folder.lastIndex(of: "_"), folder[folder.index(after: underscore)...].allSatisfy(\.isNumber) else { return folder }
        return String(folder[..<underscore])
    }

    /// Profile folder -> the name the person gave it, from the browser's Local State.
    static func profileNames(_ localState: URL) -> [String: String] {
        guard let root = Documents.json(localState, limit: maxLocalState) as? [String: Any],
              let cache = (root["profile"] as? [String: Any])?["info_cache"] as? [String: Any] else { return [:] }
        var out: [String: String] = [:]
        for (folder, info) in cache.prefix(256) {
            if let name = (info as? [String: Any])?["name"] as? String, let clean = ProductIndex.clean(name, max: 40) { out[folder] = clean }
        }
        return out
    }

    /// "__MSG_appName__" names a message in _locales/<default_locale>/messages.json (keys without regard to case).
    static func localized(_ raw: String?, defaultLocale: String?, in dir: URL) -> String? {
        guard let raw else { return nil }
        guard raw.hasPrefix("__MSG_"), raw.hasSuffix("__"), raw.count > 8 else { return ProductIndex.clean(raw, max: 80) }
        let key = raw.dropFirst(6).dropLast(2).lowercased()
        for locale in [defaultLocale, "en", "en_US"].compactMap({ $0 }) where !locale.contains("/") && !locale.contains("..") && locale.count <= 16 {
            guard let table = Documents.json(dir.appendingPathComponent("_locales").appendingPathComponent(locale).appendingPathComponent("messages.json"),
                                             limit: maxMessages) as? [String: Any] else { continue }
            for (k, v) in table where k.lowercased() == key {
                if let message = (v as? [String: Any])?["message"] as? String, let clean = ProductIndex.clean(message, max: 80) { return clean }
            }
        }
        return nil
    }

    // MARK: Firefox

    /// Locations of Firefox's own add-ons, which are not the person's.
    static let firefoxBuiltIn: Set<String> = ["app-builtin", "app-system-defaults", "app-system-addons"]

    func firefox(_ profiles: URL) -> [InstalledExtension] {
        var out: [InstalledExtension] = []
        for profile in Directory.entries(profiles, limit: 256).prefix(limits.profiles) {
            let dir = profiles.appendingPathComponent(profile)
            guard let root = Documents.json(dir.appendingPathComponent("extensions.json"), limit: Self.maxFirefoxList) as? [String: Any],
                  let addons = root["addons"] as? [[String: Any]] else { continue }
            // "abcd1234.default-release" is the profile Firefox calls "default-release".
            let label = profile.split(separator: ".", maxSplits: 1).last.map(String.init).flatMap { ProductIndex.clean($0, max: 40) } ?? profile
            for a in addons.prefix(limits.extensionsPerFolder) {
                guard (a["type"] as? String) == "extension", !Self.firefoxBuiltIn.contains(a["location"] as? String ?? ""),
                      let id = a["id"] as? String, ProductIndex.extensionID(id, store: "firefox") != nil,
                      let version = a["version"] as? String, PackageNames.isPlausibleVersion(version) else { continue }
                let name = ((a["defaultLocale"] as? [String: Any])?["name"] as? String).flatMap { ProductIndex.clean($0, max: 80) } ?? id
                out.append(InstalledExtension(host: .firefox, id: id, name: name, version: version, profile: label, path: dir.path))
            }
        }
        return out
    }
}
