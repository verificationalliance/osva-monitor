import Foundation

/// Installed Homebrew formulae and casks, from `brew info --json=v2 --installed`.
public struct HomebrewSource: Sendable {
    public static let brewCandidates = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]

    public struct Result: Sendable {
        public var items: [HomebrewItem]
        /// App bundle file name ("Visual Studio Code.app") -> the cask that installed it, for upgrade commands.
        public var caskForApp: [String: String]
        /// What each installed cask's record says it puts in place: the Java runtimes' source tells by these which
        /// JDK a cask installed.
        public var casks: [CaskFootprint] = []
        public var report: SourceReport
    }

    let environment: ToolEnvironment
    public init(environment: ToolEnvironment) { self.environment = environment }

    public func collect() async -> Result {
        guard let brew = environment.firstExecutable(Self.brewCandidates) else {
            return Result(items: [], caskForApp: [:], report: SourceReport(kind: .homebrew, available: false, count: 0, detail: "Homebrew not found"))
        }
        // Homebrew normally reads formula data from its downloaded API cache. When that cache cannot be refreshed
        // (another user owns the installation, or the Mac is offline), the local taps still answer.
        var lastError = ""
        for extra in [["HOMEBREW_API_AUTO_UPDATE_SECS": "604800"], ["HOMEBREW_NO_INSTALL_FROM_API": "1"]] {
            do {
                let r = try await environment.run(brew, ["info", "--json=v2", "--installed"], extra: extra, timeout: 180)
                if r.status == 0, let parsed = try? Self.parseInstalled(r.stdout) {
                    let formulae = parsed.items.filter { $0.kind == .formula }.count
                    return Result(items: parsed.items, caskForApp: parsed.caskForApp, casks: parsed.casks,
                                  report: SourceReport(kind: .homebrew, available: true, count: parsed.items.count,
                                                       detail: "\(formulae) formulae, \(parsed.items.count - formulae) casks"))
                }
                lastError = r.errorText.isEmpty ? "brew exited with \(r.status)" : r.errorText
            } catch {
                lastError = error.localizedDescription
            }
        }
        return Result(items: [], caskForApp: [:], report: SourceReport(kind: .homebrew, available: true, count: 0,
                      detail: "brew info failed", error: String(lastError.prefix(200))))
    }

    /// Reads `brew info --json=v2 --installed`.
    public static func parse(_ json: Data) throws -> (items: [HomebrewItem], caskForApp: [String: String]) {
        let parsed = try parseInstalled(json)
        return (parsed.items, parsed.caskForApp)
    }

    /// Reads `brew info --json=v2 --installed`, with each cask's footprint.
    public static func parseInstalled(_ json: Data) throws -> (items: [HomebrewItem], caskForApp: [String: String], casks: [CaskFootprint]) {
        guard let root = try JSONSerialization.jsonObject(with: json) as? [String: Any] else { throw CocoaError(.propertyListReadCorrupt) }
        var items: [HomebrewItem] = []
        for f in root["formulae"] as? [[String: Any]] ?? [] {
            guard let name = f["name"] as? String else { continue }
            let installed = (f["installed"] as? [[String: Any]] ?? []).compactMap { $0["version"] as? String }
            guard !installed.isEmpty else { continue }
            // The version in use is the linked keg; a keg-only formula's is its newest installed version.
            let linked = f["linked_keg"] as? String
            let pkgVersion = linked.flatMap { installed.contains($0) ? $0 : nil } ?? Core.shared.newestVersion(installed) ?? installed[0]
            let urls = f["urls"] as? [String: Any]
            let stable = (urls?["stable"] as? [String: Any])?["url"] as? String
            let head = (urls?["head"] as? [String: Any])?["url"] as? String
            items.append(HomebrewItem(kind: .formula, name: name, version: upstreamVersion(pkgVersion),
                                      urls: [f["homepage"] as? String, stable, head].compactMap { $0 }.filter { !$0.isEmpty }))
        }
        var caskForApp: [String: String] = [:], casks: [CaskFootprint] = []
        for c in root["casks"] as? [[String: Any]] ?? [] {
            guard let token = c["token"] as? String, let installed = c["installed"] as? String, !installed.isEmpty else { continue }
            // Cask versions may carry a build after a comma ("5.7.3,2320"); the first part is the version.
            let version = String(installed.split(separator: ",", maxSplits: 1).first ?? Substring(installed))
            items.append(HomebrewItem(kind: .cask, name: token, version: version,
                                      urls: [c["homepage"] as? String, c["url"] as? String].compactMap { $0 }.filter { !$0.isEmpty }))
            for artifact in c["artifacts"] as? [[String: Any]] ?? [] {
                for app in artifact["app"] as? [Any] ?? [] {
                    if let file = app as? String { caskForApp[file] = token }
                    else if let target = (app as? [String: Any])?["target"] as? String { caskForApp[(target as NSString).lastPathComponent] = token }
                }
            }
            if let footprint = CaskFootprint(token: token, artifacts: c["artifacts"] as? [Any] ?? []) { casks.append(footprint) }
        }
        return (items, caskForApp, casks)
    }

    private static let revisionSuffix = Regex("_[0-9]+$")

    /// Homebrew writes a rebuilt formula's version as `<version>_<revision>` ("3.6.8_1"); the upstream version is the
    /// part before. This is reading Homebrew's format, not comparing versions.
    public static func upstreamVersion(_ pkgVersion: String) -> String {
        revisionSuffix.replacing(in: pkgVersion, with: "")
    }
}

/// What a cask's record says it puts in place, beyond apps: the installer packages its uninstall removes by their
/// receipts (`uninstall pkgutil:`), and the folders it moves into place (`artifact` targets). A JDK cask is one or the
/// other: temurin@17 installs a package whose receipt is net.temurin.17.jdk, sapmachine-jdk moves its JDK to
/// /Library/Java/JavaVirtualMachines/sapmachine-jdk.jdk.
public struct CaskFootprint: Hashable, Codable, Sendable {
    public var token: String
    /// Receipt identifiers, exactly as written (a pattern like "com.oracle.jdk-*" is kept, and matched only exactly).
    public var packages: [String]
    /// Absolute targets ("~/" for the home folder).
    public var targets: [String]

    public init(token: String, packages: [String] = [], targets: [String] = []) {
        self.token = token; self.packages = packages; self.targets = targets
    }

    /// Nil when the record names neither.
    init?(token: String, artifacts: [Any]) {
        func strings(_ v: Any?) -> [String] { (v as? String).map { [$0] } ?? (v as? [Any])?.compactMap { $0 as? String } ?? [] }
        var packages: [String] = [], targets: [String] = []
        for case let entry as [String: Any] in artifacts {
            for step in (entry["uninstall"] as? [Any]) ?? [] {
                for id in strings((step as? [String: Any])?["pkgutil"]) where !packages.contains(id) && id.utf8.count <= 255 { packages.append(id) }
            }
            for item in (entry["artifact"] as? [Any]) ?? [] {
                if let target = (item as? [String: Any])?["target"] as? String, target.hasPrefix("/") || target.hasPrefix("~/") { targets.append(target) }
            }
        }
        guard !packages.isEmpty || !targets.isEmpty else { return nil }
        self.init(token: token, packages: Array(packages.prefix(16)), targets: Array(targets.prefix(16)))
    }
}
