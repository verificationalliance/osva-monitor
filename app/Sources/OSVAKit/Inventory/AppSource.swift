import Foundation

/// Every app in /Applications and ~/Applications (and one folder down), as its Info.plist describes it: its bundle
/// identifier, which the public index's `A` lines match to a product record, and its version.
public struct AppSource: Sendable {
    public static let maxApps = 2000
    public static let maxInfoPlist = 1 << 20

    let roots: [URL]
    let caskForApp: [String: String]

    public init(roots: [URL], caskForApp: [String: String] = [:]) { self.roots = roots; self.caskForApp = caskForApp }

    public func collect() -> (apps: [InstalledApp], report: SourceReport) {
        var bundles: [URL] = [], seen = Set<String>()
        for bundle in ElectronSource(roots: roots).appBundles().prefix(Self.maxApps) {
            // The same app reached twice (a link in ~/Applications to /Applications) is one app.
            if seen.insert(Paths.realPath(bundle.path)).inserted { bundles.append(bundle) }
        }
        // Side by side: an App Store app's signature takes a few milliseconds to check.
        let slots = Slots(count: bundles.count), casks = caskForApp
        DispatchQueue.concurrentPerform(iterations: bundles.count) { i in
            slots.set(i, Self.read(bundles[i], cask: casks[bundles[i].lastPathComponent]))
        }
        var apps = (0..<bundles.count).compactMap { slots.get($0) }
        apps.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return (apps, SourceReport(kind: .apps, available: true, count: apps.count, detail: apps.count == 1 ? "1 app" : "\(apps.count) apps"))
    }

    private final class Slots: @unchecked Sendable {      // each slot is written once, by one iteration, under the lock
        private let lock = NSLock()
        private var slots: [InstalledApp?]
        init(count: Int) { slots = Array(repeating: nil, count: count) }
        func set(_ i: Int, _ v: InstalledApp) { lock.withLock { slots[i] = v } }
        func get(_ i: Int) -> InstalledApp? { lock.withLock { slots[i] } }
    }

    /// One app bundle. An unreadable or garbage Info.plist leaves only the name.
    public static func read(_ bundle: URL, cask: String? = nil) -> InstalledApp {
        let plist = Documents.plist(bundle.appendingPathComponent("Contents/Info.plist"), limit: maxInfoPlist) ?? [:]
        let bundleID = Documents.string(plist, "CFBundleIdentifier", max: 255).flatMap(ProductIndex.bundleID)
        let kept = AppKeepers.keeper(of: bundle, plist: plist, bundleID: bundleID)
        return InstalledApp(name: bundle.deletingPathExtension().lastPathComponent, path: bundle.path, bundleID: bundleID,
                            shortVersion: Documents.string(plist, "CFBundleShortVersionString"),
                            bundleVersion: Documents.string(plist, "CFBundleVersion"), caskToken: cask, keeper: kept.keeper, displayName: kept.name)
    }
}

/// The libraries an app bundles, found by the public index's `C` lines, with the version each one is.
public enum ComponentReader {
    public struct Found: Hashable, Sendable {
        public var record: ProductIndex.Component
        /// What the finding calls it: the record's name ("OpenSSL"), or the file's prefix ("libavcodec") when the
        /// version is the library file's own rather than the product's release.
        public var label: String
        /// Nil when it is there but its version could not be read.
        public var version: String?
        /// Where, inside the bundle ("Contents/Frameworks/Sparkle.framework").
        public var path: String
        /// The version is the library file's own numbering (its install name's current_version), which a product's
        /// advisories may not use: libavcodec 61.3.100 is FFmpeg 7.0.
        public var isLibraryVersion = false
    }

    static let maxEntries = 2000
    static let maxNestedFrameworks = 256
    /// How much of a library is searched for its printed release.
    static let maxScan = 8 << 20

    /// Folders that hold an app's libraries.
    static let libraryFolders = ["Contents/Frameworks", "Contents/MacOS", "Contents/lib", "Contents/Libraries", "Contents/Resources/lib"]

    public static func components(in app: URL, records: [ProductIndex.Component]) -> [Found] {
        guard !records.isEmpty else { return [] }
        var out: [Found] = [], seen = Set<String>()
        func add(_ f: Found, file: URL) {
            if seen.insert(f.record.product + "\u{1F}" + Paths.realPath(file.path)).inserted { out.append(f) }
        }
        let byKind = Dictionary(grouping: records, by: \.kind)

        // Frameworks: Contents/Frameworks, and frameworks nested one level inside those.
        let frameworkRecords = (byKind[.framework] ?? []) + (byKind[.python] ?? [])
        if !frameworkRecords.isEmpty {
            for (folder, name) in frameworkDirectories(app) {
                // Electron is checked as the npm package it is, by ElectronSource.
                guard name != "Electron Framework.framework" else { continue }
                for r in frameworkRecords where r.match == name {
                    let url = folder.appendingPathComponent(name)
                    add(Found(record: r, label: r.name, version: frameworkVersion(url, record: r), path: relative(url, to: app)), file: url)
                }
            }
        }

        // Libraries by file-name prefix: "libssl" is libssl.3.dylib or libssl.dylib, not libssl_extra.dylib.
        if let dylibs = byKind[.dylib] {
            for folder in libraryFolders.map({ app.appendingPathComponent($0) }) {
                for name in Directory.entries(folder, limit: maxEntries) where name.hasSuffix(".dylib") {
                    for r in dylibs where hasPrefix(name, r.match) {
                        let url = folder.appendingPathComponent(name)
                        let (version, own) = dylibVersion(url, record: r)
                        add(Found(record: r, label: own ? r.match : r.name, version: version, path: relative(url, to: app), isLibraryVersion: own),
                            file: url)
                    }
                }
            }
        }

        // A bundled Java runtime, by its `release` file (the `C jre java` line; a vendor's own line is for the runtimes
        // installed on their own, JavaCheck).
        if let java = byKind[.jre]?.first(where: { $0.match == "java" }) {
            for url in javaReleases(app) {
                let version = BoundedFile.read(url, limit: 64 << 10).flatMap { JavaRelease.version(String(decoding: $0, as: UTF8.self)) }
                add(Found(record: java, label: java.name, version: version, path: relative(url.deletingLastPathComponent(), to: app)), file: url)
            }
        }
        return out
    }

    static func hasPrefix(_ name: String, _ prefix: String) -> Bool {
        guard name.hasPrefix(prefix), name.count > prefix.count else { return false }
        let next = name[name.index(name.startIndex, offsetBy: prefix.count)]
        return next == "." || next == "-"
    }

    static func relative(_ url: URL, to app: URL) -> String {
        url.path.hasPrefix(app.path + "/") ? String(url.path.dropFirst(app.path.count + 1)) : url.path
    }

    /// (folder, framework directory name) pairs, at most `maxNestedFrameworks` nested ones.
    static func frameworkDirectories(_ app: URL) -> [(URL, String)] {
        let top = app.appendingPathComponent("Contents/Frameworks")
        let names = Directory.entries(top, limit: maxEntries).filter { $0.hasSuffix(".framework") }
        var out = names.map { (top, $0) }, nested = 0
        for name in names where nested < maxNestedFrameworks {
            for inner in ["Versions/Current/Frameworks", "Frameworks"] {
                let folder = top.appendingPathComponent(name).appendingPathComponent(inner)
                let found = Directory.entries(folder, limit: maxEntries).filter { $0.hasSuffix(".framework") }.prefix(maxNestedFrameworks - nested)
                nested += found.count
                out += found.map { (folder, $0) }
                if !found.isEmpty { break }
            }
        }
        return out
    }

    // MARK: Versions

    /// A framework's version. Its Info.plist and its binary's install name can each be the one that is complete:
    /// Qt writes "6.10" and "6.10.1" in the plist and current_version 6.10.1 in the binary; Parallels' Qt writes
    /// CFBundleVersion "18"; Sparkle writes CFBundleVersion "2057" and the version in CFBundleShortVersionString. So
    /// the most specific of them that agrees with the short version wins. CEF is read from its version header, else
    /// its Info.plist ("151.3.18.0" is CEF 151.3.18).
    static func frameworkVersion(_ framework: URL, record: ProductIndex.Component) -> String? {
        let versions = Directory.entries(framework.appendingPathComponent("Versions"), limit: 16)
        let roots = [framework] + (["Current", "A"] + versions.filter { $0 != "Current" && $0 != "A" }).map {
            framework.appendingPathComponent("Versions").appendingPathComponent($0)
        }
        let plist = roots.lazy.compactMap { Documents.plist($0.appendingPathComponent("Resources/Info.plist")) }.first ?? [:]
        let short = Documents.string(plist, "CFBundleShortVersionString").flatMap(VersionText.leading)
        let bundle = Documents.string(plist, "CFBundleVersion").flatMap(VersionText.leading)

        if record.match.hasPrefix("Chromium Embedded Framework") {
            for root in roots {
                if let header = BoundedFile.read(root.appendingPathComponent("Headers/cef_version.h"), limit: 64 << 10),
                   let v = cefHeaderVersion(String(decoding: header, as: UTF8.self)) { return v }
            }
            return short.map { $0.split(separator: ".").prefix(3).joined(separator: ".") }
        }

        let executable = Documents.string(plist, "CFBundleExecutable", max: 255).flatMap { $0.contains("/") ? nil : $0 }
            ?? String(record.match.dropLast(".framework".count))
        let binary = roots.lazy.map { $0.appendingPathComponent(executable) }.first { BoundedFile.size($0) != nil }
        let info = binary.flatMap(MachO.read)
        return choose(short: short, bundle: bundle, current: info?.current, compatibility: info?.compatibility)
    }

    static func choose(short: String?, bundle: String?, current: UInt32?, compatibility: UInt32?) -> String? {
        // current_version equal to compatibility_version is the ABI's version, not the release (libssl.3: 3.0.0).
        let m = current.flatMap { c in c != 0 && c != compatibility ? VersionText.machO(c) : nil }
        func extends(_ x: String?, _ base: String?) -> Bool {
            guard let x, let base else { return false }
            return x == base || x.hasPrefix(base + ".")
        }
        if let m, extends(m, short) { return m }
        if let bundle, bundle != short, extends(bundle, short) { return bundle }
        if let short, short.contains(".") { return short }
        if let bundle, bundle.contains(".") { return bundle }
        return m
    }

    private static let cefDefine = Regex("#define\\s+CEF_VERSION\\s+\"([0-9]+\\.[0-9]+\\.[0-9]+)")

    static func cefHeaderVersion(_ text: String) -> String? { cefDefine.firstMatch(text)?[1] ?? nil }

    /// A library's version: the release it prints ("OpenSSL 3.6.2 7 Apr 2026", searched for in its C strings, at
    /// most `maxScan` bytes), else its install name's current_version, when that is not just its ABI's and agrees
    /// with the major version in the file's name (libavcodec.60.dylib, 60.23.100; libxml2.2.dylib says 15.3.0,
    /// libtool's numbering, which is no version of libxml2). The second value says the version is the file's own
    /// (libavcodec 61.3.100), not the product's release.
    static func dylibVersion(_ url: URL, record: ProductIndex.Component) -> (String?, own: Bool) {
        let needles = [record.name + " version ", record.name + " ", record.name + "/"]
        let info = MachO.read(url)
        if let v = printedRelease(url, info: info, needles: needles) { return (v, false) }
        // OpenSSL 3 prints its release in libcrypto only: libssl.3.dylib's is in libcrypto.3.dylib beside it.
        if url.lastPathComponent.hasPrefix("libssl") {
            let sibling = url.deletingLastPathComponent().appendingPathComponent("libcrypto" + url.lastPathComponent.dropFirst("libssl".count))
            if let v = printedRelease(sibling, info: MachO.read(sibling), needles: needles) { return (v, false) }
        }
        let m = info.flatMap { i in i.current.flatMap { c in c != 0 && c != i.compatibility ? VersionText.machO(c) : nil } }
            .flatMap { v in fileMajor(url.lastPathComponent, prefix: record.match).map { $0 == majorOf(v) } ?? true ? v : nil }
        return (m, m != nil)
    }

    /// "libavcodec.60.dylib" -> "60"; "libavcodec.dylib" -> nil.
    static func fileMajor(_ name: String, prefix: String) -> String? {
        let rest = name.dropFirst(prefix.count).dropLast(".dylib".count).drop { $0 == "." || $0 == "-" }
        let major = rest.prefix { $0.isNumber }
        return major.isEmpty ? nil : String(major)
    }

    static func majorOf(_ version: String) -> String { String(version.prefix { $0.isNumber }) }

    private static func printedRelease(_ url: URL, info: MachO.Info?, needles: [String]) -> String? {
        guard let size = BoundedFile.size(url) else { return nil }
        let range = info?.cstrings ?? 0..<min(size, maxScan)
        guard let data = BoundedFile.read(url, offset: range.lowerBound, length: min(range.count, maxScan)) else { return nil }
        return VersionText.embedded(in: data, needles: needles)
    }

    /// Where apps keep a Java runtime: jpackage's Contents/runtime, JetBrains' Contents/jbr, a JDK or JRE in PlugIns,
    /// Resources or Frameworks. At most a few dozen paths are looked at per app.
    static func javaReleases(_ app: URL) -> [URL] {
        let c = app.appendingPathComponent("Contents")
        var candidates = ["Home/release", "runtime/Contents/Home/release", "runtime/release", "jbr/Contents/Home/release",
                          "jre/Contents/Home/release", "jre/release", "jdk/Contents/Home/release", "jdk/release"].map { c.appendingPathComponent($0) }
        func javaLike(_ name: String) -> Bool {
            let n = name.lowercased()
            return n.contains("jre") || n.contains("jdk") || n.contains("java") || n.contains("runtime") || n.contains("jbr")
        }
        for folder in ["PlugIns", "Resources", "Frameworks"] {
            let dir = c.appendingPathComponent(folder)
            for name in Directory.entries(dir, limit: maxEntries).filter({ folder == "PlugIns" || javaLike($0) }).prefix(32) {
                candidates += [dir.appendingPathComponent(name).appendingPathComponent("Contents/Home/release"),
                               dir.appendingPathComponent(name).appendingPathComponent("release")]
            }
        }
        return candidates.filter { BoundedFile.size($0) != nil }
    }
}
