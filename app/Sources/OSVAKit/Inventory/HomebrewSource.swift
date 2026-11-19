import Foundation

/// Installed Homebrew formulae and casks, from `brew info --json=v2 --installed`.
public struct HomebrewSource: Sendable {
    public static let brewCandidates = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]

    public struct Result: Sendable {
        public var items: [HomebrewItem]
        /// App bundle file name ("Visual Studio Code.app") -> the cask that installed it, for upgrade commands.
        public var caskForApp: [String: String]
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
                if r.status == 0, let parsed = try? Self.parse(r.stdout) {
                    let formulae = parsed.items.filter { $0.kind == .formula }.count
                    return Result(items: parsed.items, caskForApp: parsed.caskForApp,
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
        var caskForApp: [String: String] = [:]
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
        }
        return (items, caskForApp)
    }

    private static let revisionSuffix = Regex("_[0-9]+$")

    /// Homebrew writes a rebuilt formula's version as `<version>_<revision>` ("3.6.8_1"); the upstream version is the
    /// part before. This is reading Homebrew's format, not comparing versions.
    public static func upstreamVersion(_ pkgVersion: String) -> String {
        revisionSuffix.replacing(in: pkgVersion, with: "")
    }
}
