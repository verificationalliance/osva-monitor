import Foundation

/// Globally installed packages: npm, pip, cargo and RubyGems. A missing tool is not an error; the source says so.
public struct GlobalPackageSources: Sendable {
    let environment: ToolEnvironment
    public init(environment: ToolEnvironment) { self.environment = environment }

    // MARK: npm

    public static let npmCandidates = ["/opt/homebrew/bin/npm", "/usr/local/bin/npm", "~/.volta/bin/npm"]

    public func npm() async -> (packages: [InstalledPackage], report: SourceReport) {
        var tools = Self.npmCandidates.map(environment.expand)
        // Each Node installed with nvm has its own global packages.
        let nvm = environment.home.appendingPathComponent(".nvm/versions/node")
        if let versions = try? FileManager.default.contentsOfDirectory(atPath: nvm.path) {
            tools += versions.sorted().map { nvm.appendingPathComponent($0).appendingPathComponent("bin/npm").path }
        }
        tools = environment.distinctExecutables(tools)
        guard !tools.isEmpty else { return ([], SourceReport(kind: .npm, available: false, count: 0, detail: "npm not found")) }
        var packages: [InstalledPackage] = [], errors: [String] = []
        for npm in tools {
            do {
                // npm exits with 1 when the tree has problems (extraneous, missing) but still prints the list.
                let r = try await environment.run(npm, ["ls", "-g", "--json", "--depth=0"], timeout: 60)
                if let list = try? Self.parseNpmList(r.stdout) {
                    packages += list.map { InstalledPackage(ecosystem: .npm, name: $0.name, version: $0.version, origin: .npmGlobal(npm: npm)) }
                } else {
                    errors.append(r.errorText.isEmpty ? "\(npm) exited with \(r.status)" : r.errorText)
                }
            } catch { errors.append(error.localizedDescription) }
        }
        return (packages, SourceReport(kind: .npm, available: true, count: packages.count, detail: Self.count(packages.count, "global package"),
                                       error: errors.isEmpty ? nil : String(errors.joined(separator: "; ").prefix(200))))
    }

    /// `npm ls -g --json --depth=0`: {"dependencies": {"name": {"version": "1.2.3"}}}.
    public static func parseNpmList(_ data: Data) throws -> [(name: String, version: String)] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw CocoaError(.propertyListReadCorrupt) }
        let deps = root["dependencies"] as? [String: Any] ?? [:]
        return deps.keys.sorted().compactMap { name in
            guard let v = (deps[name] as? [String: Any])?["version"] as? String, !v.isEmpty else { return nil }
            return (name, v)
        }
    }

    // MARK: cargo

    public func cargo() -> (packages: [InstalledPackage], report: SourceReport) {
        let cargoHome = environment.base["CARGO_HOME"].map { URL(fileURLWithPath: $0) } ?? environment.home.appendingPathComponent(".cargo")
        let file = cargoHome.appendingPathComponent(".crates2.json")
        guard let data = try? Data(contentsOf: file) else {
            return ([], SourceReport(kind: .cargo, available: false, count: 0, detail: "no crates installed with cargo install"))
        }
        let crates = (try? Self.parseCrates2(data)) ?? []
        let packages = crates.map { InstalledPackage(ecosystem: .crates, name: $0.name, version: $0.version, origin: .cargoInstall) }
        return (packages, SourceReport(kind: .cargo, available: true, count: packages.count, detail: Self.count(packages.count, "crate")))
    }

    /// `~/.cargo/.crates2.json`: {"installs": {"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {...}}}.
    /// Only crates from crates.io; ones installed from git or a path are not registry packages.
    public static func parseCrates2(_ data: Data) throws -> [(name: String, version: String)] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw CocoaError(.propertyListReadCorrupt) }
        let installs = root["installs"] as? [String: Any] ?? [:]
        return installs.keys.sorted().compactMap { key in
            let parts = key.split(separator: " ", maxSplits: 2).map(String.init)
            guard parts.count == 3 else { return nil }
            let source = parts[2].trimmingCharacters(in: CharacterSet(charactersIn: "()"))
            guard source.hasPrefix("registry+https://github.com/rust-lang/crates.io-index") || source.hasPrefix("sparse+https://index.crates.io/") else { return nil }
            return (parts[0], parts[1])
        }
    }

    // MARK: RubyGems

    public static let gemCandidates = ["/opt/homebrew/opt/ruby/bin/gem", "/usr/local/opt/ruby/bin/gem", "/usr/bin/gem"]

    public func gem() async -> (packages: [InstalledPackage], report: SourceReport) {
        let gems = environment.distinctExecutables(Self.gemCandidates)
        guard !gems.isEmpty else { return ([], SourceReport(kind: .gem, available: false, count: 0, detail: "gem not found")) }
        var packages: [InstalledPackage] = [], errors: [String] = []
        for gem in gems {
            do {
                let r = try await environment.run(gem, ["list", "--local"], timeout: 60)
                guard r.status == 0 else { errors.append(r.errorText.isEmpty ? "\(gem) exited with \(r.status)" : r.errorText); continue }
                packages += Self.parseGemList(String(decoding: r.stdout, as: UTF8.self)).map {
                    InstalledPackage(ecosystem: .rubygems, name: $0.name, version: $0.version, origin: .gem(gem: gem))
                }
            } catch { errors.append(error.localizedDescription) }
        }
        return (packages, SourceReport(kind: .gem, available: true, count: packages.count, detail: Self.count(packages.count, "gem"),
                                       error: errors.isEmpty ? nil : String(errors.joined(separator: "; ").prefix(200))))
    }

    private static let gemLine = Regex("^([A-Za-z0-9_.-]+) \\((.+)\\)$")

    /// `gem list --local`: "nokogiri (1.13.8, 1.13.6)", "json (default: 2.1.0)", "ffi (1.15.5-arm64-darwin)".
    /// Every installed version is listed (any of them can be loaded); a platform suffix is not part of the version.
    public static func parseGemList(_ text: String) -> [(name: String, version: String)] {
        var out: [(String, String)] = []
        for line in text.split(whereSeparator: \.isNewline) {
            guard let m = gemLine.firstMatch(String(line)), let name = m[1], let versions = m[2] else { continue }
            for entry in versions.components(separatedBy: ", ") {
                var v = entry.trimmingCharacters(in: .whitespaces)
                if v.hasPrefix("default: ") { v.removeFirst("default: ".count) }
                v = String(v.split(separator: " ").first ?? "")                  // "1.2.3 x86_64-linux" (older RubyGems)
                v = String(v.split(separator: "-", maxSplits: 1).first ?? "")     // RubyGems versions never contain "-"
                if !v.isEmpty { out.append((name, v)) }
            }
        }
        return out
    }

    // MARK: helpers

    static func count(_ n: Int, _ noun: String) -> String { n == 1 ? "1 \(noun)" : "\(n) \(noun)s" }
}
