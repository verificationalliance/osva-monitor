import Foundation

/// Command-line tools installed with pipx or uv, each in a virtual environment of its own. Read from the files alone:
/// the environment's pyvenv.cfg gives its Python version (so fix plans respect Requires-Python), each package's
/// dist-info METADATA its name and version. The tools' Pythons are never run.
public struct PythonToolSource: Sendable {
    static let maxTools = 500
    static let maxDistributions = 5000
    static let maxMetadataHead = 64 * 1024

    let environment: ToolEnvironment
    let pipxFolders: [String]
    let uvFolders: [String]

    /// The folders default to where pipx and uv put tools, and where their settings ($PIPX_HOME, $UV_TOOL_DIR,
    /// $XDG_DATA_HOME) say.
    public init(environment: ToolEnvironment, pipxFolders: [String]? = nil, uvFolders: [String]? = nil) {
        self.environment = environment
        self.pipxFolders = pipxFolders ?? Self.pipxVenvFolders(environment)
        self.uvFolders = uvFolders ?? Self.uvToolFolders(environment)
    }

    static func pipxVenvFolders(_ environment: ToolEnvironment) -> [String] {
        let env = environment.base, home = environment.home.path
        var out: [String] = []
        if let h = env["PIPX_HOME"], h.hasPrefix("/") { out.append(h + "/venvs") }
        out += [home + "/.local/pipx/venvs", home + "/.local/share/pipx/venvs", home + "/Library/Application Support/pipx/venvs"]
        if let g = env["PIPX_GLOBAL_HOME"], g.hasPrefix("/") { out.append(g + "/venvs") }
        out.append("/opt/pipx/venvs")
        return unique(out)
    }

    static func uvToolFolders(_ environment: ToolEnvironment) -> [String] {
        let env = environment.base, home = environment.home.path
        var out: [String] = []
        if let d = env["UV_TOOL_DIR"], d.hasPrefix("/") { out.append(d) }
        if let x = env["XDG_DATA_HOME"], x.hasPrefix("/") { out.append(x + "/uv/tools") }
        out.append(home + "/.local/share/uv/tools")
        return unique(out)
    }

    static func unique(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.filter { seen.insert(Paths.realPath(($0 as NSString).standardizingPath)).inserted }
    }

    public func collect() -> (packages: [InstalledPackage], reports: [SourceReport]) {
        let clock = ContinuousClock()
        var packages: [InstalledPackage] = [], reports: [SourceReport] = []
        for (manager, folders) in [(PythonTool.Manager.pipx, pipxFolders), (.uv, uvFolders)] {
            let t0 = clock.now
            var tools = 0, found = false, own: [InstalledPackage] = []
            for folder in folders {
                guard let names = try? FileManager.default.contentsOfDirectory(atPath: folder) else { continue }
                found = true
                for name in names.sorted().prefix(Self.maxTools) where !name.hasPrefix(".") {
                    let venv = folder + "/" + name
                    guard let read = readTool(manager: manager, name: name, venv: venv) else { continue }
                    tools += 1
                    own += read
                }
            }
            packages += own
            let noun = manager == .pipx ? "pipx tool" : "uv tool"
            let detail = tools == 0 ? "no \(noun)s" : "\(GlobalPackageSources.count(tools, "tool")), \(GlobalPackageSources.count(own.count, "package"))"
            reports.append(SourceReport(kind: manager == .pipx ? .pipx : .uv, available: found, count: own.count, detail: detail,
                                        seconds: (clock.now - t0).seconds))
        }
        return (packages, reports)
    }

    /// One tool's packages, or nil when the folder is not a tool's environment.
    func readTool(manager: PythonTool.Manager, name: String, venv: String) -> [InstalledPackage]? {
        guard environment.isExecutable(venv + "/bin/python") || environment.isExecutable(venv + "/bin/python3"),
              let cfg = Self.readHead(venv + "/pyvenv.cfg", max: 16 * 1024) else { return nil }
        let python = Self.pythonVersion(fromPyvenvCfg: String(decoding: cfg, as: UTF8.self))
        let dists = Self.distributions(inVenv: venv)
        let main = PackageNames.indexName(mainPackage(manager: manager, name: name, venv: venv), in: .pypi)
        let version = dists.first { PackageNames.indexName($0.name, in: .pypi) == main }?.version
        let tool = PythonTool(manager: manager, name: name, mainPackage: main, version: version, venv: venv, python: python)
        return dists.map { InstalledPackage(ecosystem: .pypi, name: $0.name, version: $0.version, origin: .pythonTool(tool)) }
    }

    /// The package the tool was installed from: pipx's pipx_metadata.json says, uv's uv-receipt.toml lists it first;
    /// both name the environment after it.
    func mainPackage(manager: PythonTool.Manager, name: String, venv: String) -> String {
        switch manager {
        case .pipx:
            if let data = Self.readHead(venv + "/pipx_metadata.json", max: 1 << 20),
               let json = try? JSONSerialization.jsonObject(with: Data(data)) as? [String: Any],
               let main = (json["main_package"] as? [String: Any])?["package"] as? String, !main.isEmpty {
                return main
            }
        case .uv:
            if let data = Self.readHead(venv + "/uv-receipt.toml", max: 256 * 1024),
               let m = Self.receiptRequirement.firstMatch(String(decoding: data, as: UTF8.self)), let main = m[1], !main.isEmpty {
                return main
            }
        }
        return name
    }

    private static let receiptRequirement = Regex(#"requirements\s*=\s*\[\s*\{\s*name\s*=\s*"([^"]+)""#)
    private static let versionValue = Regex(#"^([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#)

    /// `version = 3.12.4` (venv), `version_info = 3.12.4` (uv) or `version_info = 3.12.4.final.0` (virtualenv).
    public static func pythonVersion(fromPyvenvCfg text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, parts[0] == "version" || parts[0] == "version_info",
                  let m = versionValue.firstMatch(parts[1]), let v = m[1] else { continue }
            return v
        }
        return nil
    }

    /// Every distribution in the environment's site-packages: its METADATA's Name and Version, or, without a readable
    /// METADATA, the dist-info folder's name ("black-24.1.0.dist-info").
    static func distributions(inVenv venv: String) -> [(name: String, version: String)] {
        let lib = venv + "/lib"
        let pythons = ((try? FileManager.default.contentsOfDirectory(atPath: lib)) ?? []).filter { $0.hasPrefix("python") }.sorted()
        var out: [(String, String)] = [], seen = Set<String>()
        for py in pythons {
            let site = "\(lib)/\(py)/site-packages"
            let entries = ((try? FileManager.default.contentsOfDirectory(atPath: site)) ?? []).filter { $0.hasSuffix(".dist-info") }.sorted()
            for entry in entries.prefix(maxDistributions) {
                let fromMetadata = readHead("\(site)/\(entry)/METADATA", max: maxMetadataHead).flatMap { metadataNameAndVersion($0) }
                guard let d = fromMetadata ?? distInfoNameAndVersion(entry), PackageNames.isPlausibleVersion(d.version),
                      seen.insert(PackageNames.indexName(d.name, in: .pypi) + "\u{1F}" + d.version).inserted else { continue }
                out.append(d)
            }
        }
        return out
    }

    /// Name and Version from a METADATA file's header (it ends at the first empty line).
    public static func metadataNameAndVersion(_ bytes: [UInt8]) -> (name: String, version: String)? {
        var name: String?, version: String?
        // "\r\n" is one Character in Swift: split on newlines of any kind, keeping the empty line that ends the header.
        for l in String(decoding: bytes, as: UTF8.self).split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            if l.isEmpty { break }
            if name == nil, l.hasPrefix("Name:") { name = l.dropFirst(5).trimmingCharacters(in: .whitespaces) }
            else if version == nil, l.hasPrefix("Version:") { version = l.dropFirst(8).trimmingCharacters(in: .whitespaces) }
            if name != nil && version != nil { break }
        }
        guard let name, let version, !name.isEmpty, !version.isEmpty else { return nil }
        return (name, version)
    }

    /// "black-24.1.0.dist-info": the name never contains "-" (it is escaped as "_"), so the first "-" ends it.
    static func distInfoNameAndVersion(_ folder: String) -> (name: String, version: String)? {
        let stem = folder.dropLast(".dist-info".count)
        guard let dash = stem.firstIndex(of: "-") else { return nil }
        let name = String(stem[..<dash]), version = String(stem[stem.index(after: dash)...])
        return name.isEmpty || version.isEmpty ? nil : (name, version)
    }

    static func readHead(_ path: String, max: Int) -> [UInt8]? { ReadOnlyFile.head(path, max: max) }
}
