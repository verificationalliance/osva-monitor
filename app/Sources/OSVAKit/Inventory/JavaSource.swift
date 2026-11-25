import Foundation

/// Java runtimes installed on their own, wherever Java's installers and version managers put them, each read from its
/// `release` file (JAVA_VERSION, IMPLEMENTOR, JAVA_RUNTIME_VERSION …) and its bundle's Info.plist:
///   - /Library/Java/JavaVirtualMachines/*.jdk: the installers' (Oracle, Temurin, Zulu, Corretto …) and casks';
///   - ~/Library/Java/JavaVirtualMachines and ~/.jdks: IntelliJ IDEA's downloads;
///   - SDKMAN's, asdf's and mise's Java installs;
///   - Homebrew's openjdk formulae (opt/openjdk*/libexec/openjdk.jdk).
/// One runtime is one finding: a link to another (Homebrew's caveat links its keg into /Library/Java/JavaVirtualMachines;
/// SDKMAN's "current"; mise's "17" for "17.0.2") is the same runtime, by its real path. Every read is bounded, and a
/// runtime whose version cannot be read is listed as such, never guessed. The runtimes bundled inside apps are the
/// apps' components (ComponentReader), not these.
public struct JavaSource: Sendable {
    public static let maxPerFolder = 256
    /// Homebrew's opt folder has a link per installed formula, hundreds of them.
    public static let maxOpt = 8192
    public static let maxRelease = 64 << 10
    public static let maxPlist = 1 << 20
    public static let maxRuntimes = 512
    /// The "No record" heading of runtimes with no version the advisories could be compared with.
    public static let unreadable = "Java runtimes with no readable version"

    public struct Result: Sendable {
        public var runtimes: [JavaRuntime]
        public var unchecked: [UncheckedItem]
        public var report: SourceReport
    }

    let environment: ToolEnvironment
    let casks: [CaskFootprint]
    let homebrewPrefixes: [String]

    /// `casks`: the installed casks' footprints (HomebrewSource), to tell which JDK a cask installed.
    public init(environment: ToolEnvironment, casks: [CaskFootprint] = [], homebrewPrefixes: [String] = ["/opt/homebrew", "/usr/local"]) {
        self.environment = environment; self.casks = casks; self.homebrewPrefixes = homebrewPrefixes
    }

    /// A folder whose entries are runtimes.
    struct Root {
        var place: JavaRuntime.Place
        var folder: URL
    }

    /// Where runtimes are, in the order a runtime found twice is attributed: Homebrew's kegs first (the formula is what
    /// updates it), then the machine's folder, the person's own, and the version managers'.
    func roots() -> [Root] {
        let env = environment.base, home = environment.home
        func dir(_ variable: String, _ fallback: String) -> URL {
            if let v = env[variable], v.hasPrefix("/") { return URL(fileURLWithPath: v, isDirectory: true) }
            return home.appendingPathComponent(fallback, isDirectory: true)
        }
        let xdg = env["XDG_DATA_HOME"].flatMap { $0.hasPrefix("/") ? $0 + "/mise" : nil }
        let mise = env["MISE_DATA_DIR"].flatMap { $0.hasPrefix("/") ? $0 : nil } ?? xdg ?? home.appendingPathComponent(".local/share/mise").path
        return [Root(place: .system, folder: URL(fileURLWithPath: environment.system("/Library/Java/JavaVirtualMachines"), isDirectory: true)),
                Root(place: .user, folder: home.appendingPathComponent("Library/Java/JavaVirtualMachines", isDirectory: true)),
                Root(place: .intellij, folder: home.appendingPathComponent(".jdks", isDirectory: true)),
                Root(place: .sdkman, folder: dir("SDKMAN_DIR", ".sdkman").appendingPathComponent("candidates/java", isDirectory: true)),
                Root(place: .asdf, folder: dir("ASDF_DATA_DIR", ".asdf").appendingPathComponent("installs/java", isDirectory: true)),
                Root(place: .mise, folder: URL(fileURLWithPath: mise, isDirectory: true).appendingPathComponent("installs/java", isDirectory: true))]
    }

    /// One place to look: the bundle or folder, its Home, and its Info.plist when it is a bundle.
    struct Candidate {
        var place: JavaRuntime.Place
        var path: URL
        var home: URL
        var plist: URL?
        var formula: String?
    }

    /// Homebrew's opt folders, one per prefix: a link per installed formula, the openjdk ones among them.
    func optFolders() -> [URL] {
        homebrewPrefixes.map { URL(fileURLWithPath: environment.system($0 + "/opt"), isDirectory: true) }
    }

    func candidates() -> [Candidate] {
        var out: [Candidate] = []
        for opt in optFolders() {
            for name in Directory.entries(opt, limit: Self.maxOpt) where JavaVersion.isHomebrewFormula(name) && FixSafety.isSafeName(name) {
                let jdk = opt.appendingPathComponent(name).appendingPathComponent("libexec/openjdk.jdk", isDirectory: true)
                if let c = Self.layout(jdk) { out.append(Candidate(place: .homebrew, path: jdk, home: c.home, plist: c.plist, formula: name)) }
            }
        }
        for root in roots() {
            // folders before links, so a runtime reached both ways is named by its own folder (mise's 17.0.2, not "17")
            let names = Directory.entries(root.folder, limit: Self.maxPerFolder).filter { $0 != "current" }
            let isLink = Dictionary(uniqueKeysWithValues: names.map { ($0, !Directory.isDirectory(root.folder.appendingPathComponent($0), noLinks: true)) })
            for name in names.sorted(by: { isLink[$0]! == isLink[$1]! ? $0 < $1 : !isLink[$0]! }) {
                let entry = root.folder.appendingPathComponent(name, isDirectory: true)
                if let c = Self.layout(entry) { out.append(Candidate(place: root.place, path: entry, home: c.home, plist: c.plist)) }
            }
        }
        return out
    }

    /// A bundle (Contents/Home, Contents/Info.plist) or a plain folder (bin/, lib/, release). Nil when it is not a folder.
    static func layout(_ entry: URL) -> (home: URL, plist: URL?)? {
        let bundleHome = entry.appendingPathComponent("Contents/Home", isDirectory: true)
        if Directory.isDirectory(bundleHome) { return (bundleHome, entry.appendingPathComponent("Contents/Info.plist")) }
        guard Directory.isDirectory(entry) else { return nil }
        // a link to a bundle's Home (an SDKMAN or mise install made from a macOS bundle): the bundle's Info.plist
        let real = Paths.realPath(entry.path)
        if real.hasSuffix("/Contents/Home") {
            return (entry, URL(fileURLWithPath: (real as NSString).deletingLastPathComponent).appendingPathComponent("Info.plist"))
        }
        return (entry, nil)
    }

    public func collect() async -> Result {
        var runtimes: [JavaRuntime] = [], unchecked: [UncheckedItem] = [], seen = Set<String>()
        for c in candidates() {
            guard runtimes.count + unchecked.count < Self.maxRuntimes else { break }
            let real = Paths.realPath(c.home.path)
            guard seen.insert(real).inserted else { continue }
            switch Self.read(c, realPath: real) {
            case let .runtime(r)?: runtimes.append(r)
            case let .unreadable(text)?: unchecked.append(UncheckedItem(kind: .java, bucket: Self.unreadable, item: text, formula: c.formula))
            case nil: continue
            }
        }
        if !casks.isEmpty {
            let attribution = CaskAttribution(environment: environment, casks: casks)
            for i in runtimes.indices where runtimes[i].formula == nil {
                runtimes[i].cask = await attribution.cask(for: runtimes[i])
            }
        }
        let n = runtimes.count
        var detail = n == 1 ? "1 JDK" : "\(n) JDKs"
        if !unchecked.isEmpty { detail += ", \(unchecked.count) with no readable version" }
        return Result(runtimes: runtimes, unchecked: unchecked, report: SourceReport(kind: .java, available: true, count: n, detail: detail))
    }

    enum Read { case runtime(JavaRuntime), unreadable(String) }

    /// One candidate. Nil when it is no Java runtime at all (no release file, no Info.plist naming a Java VM, no
    /// bin/java); unreadable when it is one whose version cannot be read or is no Java version.
    static func read(_ c: Candidate, realPath: String) -> Read? {
        let releaseData = BoundedFile.read(c.home.appendingPathComponent("release"), limit: maxRelease)
        let release = releaseData.map { JavaRelease.fields(String(decoding: $0, as: UTF8.self)) } ?? [:]
        let plist = c.plist.flatMap { Documents.plist($0, limit: maxPlist) } ?? [:]
        let javaVM = plist["JavaVM"] as? [String: Any]
        let hasJava = BoundedFile.size(c.home.appendingPathComponent("bin/java")) != nil
        guard releaseData != nil || javaVM != nil || hasJava else { return nil }
        let name = c.path.lastPathComponent, shownName = ProductIndex.clean(name, max: 80) ?? "?"
        // JAVA_VERSION, else the bundle's own (Corretto 8 has no release file; its Info.plist says JVMVersion 1.8.0_514)
        let written = release["JAVA_VERSION"].flatMap(JavaRelease.plausible)
            ?? (javaVM?["JVMVersion"] as? String).flatMap { ProductIndex.clean($0, max: 40) }.flatMap(JavaRelease.plausible)
        guard let version = written else { return .unreadable(shownName) }
        let vendor = JavaVendor.identify(release: release, plist: plist, folder: name)
        guard let canonical = JavaVersion.canonical(version) else { return .unreadable("\(vendor.title) \(version) (\(shownName))") }
        let implementor = release["IMPLEMENTOR"] ?? (javaVM?["JVMVendor"] as? String).flatMap { ProductIndex.clean($0, max: 80) }
        let build = release["JAVA_RUNTIME_VERSION"] ?? release["IMPLEMENTOR_VERSION"]
        let image = release["IMAGE_TYPE"]?.uppercased() == "JRE" ? "JRE" : "JDK"
        var runtime = JavaRuntime(path: c.path.path, home: c.home.path, realPath: realPath, place: c.place, vendor: vendor, version: version,
                                  canonical: canonical, build: build, implementor: implementor, image: image, formula: c.formula)
        runtime.implementorVersion = release["IMPLEMENTOR_VERSION"]
        return .runtime(runtime)
    }
}

extension JavaRelease {
    /// A release file's `KEY="value"` lines (at most 200; keys of capitals, digits and "_"; the first of each key; values
    /// cleaned of control characters, at most 256 characters). GraalVM's COMMIT_INFO={json} is read as written.
    static func fields(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline).prefix(200) {
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            guard (1...40).contains(key.count), out[key] == nil,
                  key.unicodeScalars.allSatisfy({ (65...90).contains($0.value) || (48...57).contains($0.value) || $0 == "_" }) else { continue }
            var value = parts[1].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.first == "\"", value.last == "\"" { value = String(value.dropFirst().dropLast()) }
            out[key] = ProductIndex.clean(value, max: 256)
        }
        return out
    }

    /// A version as a runtime writes it: starts with a digit, at most 40 characters, nothing a registry would not have.
    static func plausible(_ v: String) -> String? {
        PackageNames.isPlausibleVersion(v) && v.first?.isNumber == true && v.count <= 40 ? v : nil
    }
}

/// Which installed cask put a JDK in place, by the cask's own record, not by its name: a cask that moves a folder there
/// (`artifact` target), or one whose installer package's receipt holds the JDK's bundle. pkgutil says which receipt a
/// path belongs to when the package installed at "/" (Temurin's); for one that installed into the JDKs' folder itself
/// (Corretto's), the receipt's own file list is read.
struct CaskAttribution {
    static let pkgutil = "/usr/sbin/pkgutil"
    static let maxPackages = 32

    let environment: ToolEnvironment
    let casks: [CaskFootprint]

    func cask(for runtime: JavaRuntime) async -> String? {
        let bundle = runtime.path, real = Paths.realPath(bundle)
        for c in casks {
            for t in c.targets {
                let target = environment.expand(t)
                if [target, environment.system(target)].contains(where: { $0 == bundle || Paths.realPath($0) == real }) { return c.token }
            }
        }
        // installer packages put JDKs in the machine's folder only
        guard runtime.place == .system, environment.isExecutable(Self.pkgutil) else { return nil }
        let owners = casks.flatMap { c in c.packages.filter(Self.isExactID).map { (id: $0, token: c.token) } }.prefix(Self.maxPackages)
        guard !owners.isEmpty else { return nil }
        if let info = await run(["--file-info", bundle]) {
            let ids = info.split(whereSeparator: \.isNewline).compactMap { line -> String? in
                let l = line.trimmingCharacters(in: .whitespaces)
                return l.hasPrefix("pkgid:") ? l.dropFirst("pkgid:".count).trimmingCharacters(in: .whitespaces) : nil
            }
            if let owner = owners.first(where: { ids.contains($0.id) }) { return owner.token }
        }
        let parent = (bundle as NSString).deletingLastPathComponent, name = (bundle as NSString).lastPathComponent
        for owner in owners {
            guard let plist = await run(["--pkg-info-plist", owner.id]),
                  let info = (try? PropertyListSerialization.propertyList(from: Data(plist.utf8), format: nil)) as? [String: Any],
                  let location = info["install-location"] as? String else { continue }
            let volume = (info["volume"] as? String) ?? "/"
            let installed = environment.system((("/" + volume + "/" + location) as NSString).standardizingPath)
            if installed == (bundle as NSString).standardizingPath { return owner.token }
            guard installed == (parent as NSString).standardizingPath, let files = await run(["--only-dirs", "--files", owner.id]) else { continue }
            if files.split(whereSeparator: \.isNewline).contains(where: { $0.split(separator: "/").first.map(String.init) == name }) { return owner.token }
        }
        return nil
    }

    /// A receipt identifier pkgutil can be asked about by name (not a pattern).
    static func isExactID(_ id: String) -> Bool {
        !id.isEmpty && id.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || ".-_".unicodeScalars.contains($0) } && !id.hasPrefix("-")
    }

    private func run(_ arguments: [String]) async -> String? {
        guard let r = try? await environment.run(Self.pkgutil, arguments, timeout: 20), r.status == 0, r.stdout.count <= 4 << 20 else { return nil }
        return String(decoding: r.stdout, as: UTF8.self)
    }
}
