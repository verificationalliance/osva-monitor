import Foundation

/// Python packages, per interpreter: for each Python on this Mac, its version and kind (Apple's, Homebrew's,
/// python.org's, a virtual environment), whether it is externally managed (PEP 668), and for each package whether it
/// sits in the per-user site and whether a Homebrew formula installed it. That is what decides the upgrade command.
public struct PythonSource: Sendable {
    let environment: ToolEnvironment
    public init(environment: ToolEnvironment) { self.environment = environment }

    /// Prints what the app needs to know about an interpreter, as JSON.
    static let describeScript = """
    import json, platform, site, sys, sysconfig
    print(json.dumps({"version": platform.python_version(), "executable": sys.executable, "prefix": sys.prefix,
                      "base_prefix": getattr(sys, "base_prefix", sys.prefix), "stdlib": sysconfig.get_path("stdlib"),
                      "usersite": site.getusersitepackages() if hasattr(site, "getusersitepackages") else None}))
    """

    /// The interpreters to look at, each real file once: Homebrew's python3 and python3.x, python.org's, a
    /// /usr/local one, and Apple's /usr/bin/python3 (only when the developer tools are present: without them it is
    /// a stub that asks to install them).
    /// Machine-wide paths, under `ToolEnvironment.systemRoot` ("" in the app; a test's own folder in tests).
    func interpreters() -> [String] {
        let sys = environment.system
        var candidates = [sys("/opt/homebrew/bin/python3"), sys("/usr/local/bin/python3")]
        for dir in [sys("/opt/homebrew/bin"), sys("/usr/local/bin")] {
            let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
            candidates += names.filter { $0.range(of: #"^python3\.[0-9]+$"#, options: .regularExpression) != nil }
                .sorted { $0.localizedStandardCompare($1) == .orderedDescending }.map { "\(dir)/\($0)" }
        }
        let frameworks = sys("/Library/Frameworks/Python.framework/Versions")
        let versions = (try? FileManager.default.contentsOfDirectory(atPath: frameworks)) ?? []
        candidates += versions.filter { $0 != "Current" }.sorted().reversed().map { "\(frameworks)/\($0)/bin/python3" }
        if environment.isExecutable(sys("/Library/Developer/CommandLineTools/usr/bin/python3"))
            || environment.isExecutable(sys("/Applications/Xcode.app/Contents/Developer/usr/bin/python3")) {
            candidates.append(sys("/usr/bin/python3"))
        }
        return environment.distinctExecutables(candidates)
    }

    public func collect() async -> (packages: [InstalledPackage], report: SourceReport) {
        let pythons = interpreters()
        guard !pythons.isEmpty else { return ([], SourceReport(kind: .pip, available: false, count: 0, detail: "python3 not found")) }
        var packages: [InstalledPackage] = [], errors: [String] = [], described = 0
        for exe in pythons {
            guard let python = await describe(exe) else { errors.append("\(exe): could not run"); continue }
            described += 1
            do {
                let list = try await environment.run(exe, ["-m", "pip", "list", "-v", "--format=json", "--disable-pip-version-check"], timeout: 60)
                guard list.status == 0, let entries = try? Self.parsePipList(list.stdout) else {
                    if !list.errorText.contains("No module named pip") { errors.append("\(python.label): pip did not answer") }
                    continue
                }
                // pip without per-package locations (very old): ask for the user site separately.
                var userKeys: Set<String>?
                if entries.contains(where: { $0.location == nil }) {
                    let user = try? await environment.run(exe, ["-m", "pip", "list", "--user", "--format=json", "--disable-pip-version-check"], timeout: 60)
                    userKeys = Set((user.flatMap { $0.status == 0 ? try? Self.parsePipList($0.stdout) : nil } ?? []).map { "\($0.name)\u{1F}\($0.version)" })
                }
                for e in entries {
                    let user = userKeys.map { $0.contains("\(e.name)\u{1F}\(e.version)") }
                        ?? (python.userSite.map { Self.samePath(e.location ?? "", $0) } ?? false)
                    let formula = e.installer == "brew" ? (e.location.flatMap { Self.homebrewFormula(of: e.name, in: $0) } ?? "") : nil
                    packages.append(InstalledPackage(ecosystem: .pypi, name: e.name, version: e.version,
                                                     origin: .pip(python: python, user: user, formula: formula),
                                                     provenance: e.location.map { Provenance(path: $0) }))
                }
            } catch { errors.append("\(python.label): \(error.localizedDescription)") }
        }
        let detail = "\(GlobalPackageSources.count(packages.count, "package")) in \(GlobalPackageSources.count(described, "Python"))"
        return (packages, SourceReport(kind: .pip, available: true, count: packages.count, detail: detail,
                                       error: errors.isEmpty ? nil : String(errors.joined(separator: "; ").prefix(200))))
    }

    /// Runs the interpreter once to learn what it is.
    func describe(_ exe: String) async -> PythonEnvironment? {
        guard let r = try? await environment.run(exe, ["-c", Self.describeScript], timeout: 30), r.status == 0,
              let info = try? JSONSerialization.jsonObject(with: r.stdout) as? [String: Any] else { return nil }
        return Self.classify(executable: exe, info: info, fileExists: { FileManager.default.fileExists(atPath: $0) })
    }

    /// What kind of Python this is, from where it lives.
    public static func classify(executable: String, info: [String: Any], fileExists: (String) -> Bool) -> PythonEnvironment? {
        guard let version = info["version"] as? String, !version.isEmpty else { return nil }
        let prefix = info["prefix"] as? String ?? "", base = info["base_prefix"] as? String ?? prefix
        let stdlib = info["stdlib"] as? String
        let kind: PythonEnvironment.Kind
        var formula: String?
        if prefix != base {
            kind = .virtualEnv
        } else if executable == "/usr/bin/python3" || prefix.contains("/Library/Developer/CommandLineTools/") || prefix.contains(".app/Contents/Developer/") {
            kind = .apple
        } else if prefix.hasPrefix("/opt/homebrew/") || prefix.hasPrefix("/usr/local/Cellar/") || prefix.hasPrefix("/usr/local/opt/") {
            kind = .homebrew
            formula = prefix.range(of: #"/(?:opt|Cellar)/(python(?:@[0-9.]+)?)/"#, options: .regularExpression)
                .map { String(prefix[$0]).split(separator: "/")[1] }.map(String.init)
        } else if prefix.hasPrefix("/Library/Frameworks/Python.framework/") {
            kind = .pythonOrg
        } else {
            kind = .other
        }
        return PythonEnvironment(executable: executable, version: version, kind: kind,
                                 externallyManaged: stdlib.map { fileExists(($0 as NSString).appendingPathComponent("EXTERNALLY-MANAGED")) } ?? false,
                                 userSite: info["usersite"] as? String, formula: formula)
    }

    public struct PipEntry: Sendable, Equatable {
        public var name: String, version: String, location: String?, installer: String?
    }

    /// `python -m pip list -v --format=json`: [{"name", "version", "location", "installer"}]; older pip omits the last two.
    public static func parsePipList(_ data: Data) throws -> [PipEntry] {
        guard let list = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { throw CocoaError(.propertyListReadCorrupt) }
        return list.compactMap { e in
            guard let n = e["name"] as? String, let v = e["version"] as? String, !n.isEmpty, !v.isEmpty else { return nil }
            return PipEntry(name: n, version: v, location: e["location"] as? String, installer: (e["installer"] as? String).map { $0.lowercased() })
        }
    }

    /// The Homebrew formula whose Cellar a package's files link into: Homebrew installs a formula's Python packages in
    /// its Cellar and links them into site-packages, so the package's METADATA resolves to .../Cellar/<formula>/...
    public static func homebrewFormula(of name: String, in location: String) -> String? {
        let wanted = PackageNames.indexName(name, in: .pypi)
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: location),
              let distInfo = entries.first(where: { e in
                  guard e.hasSuffix(".dist-info"), let dash = e.dropLast(10).lastIndex(of: "-") else { return false }
                  return PackageNames.indexName(String(e[..<dash]), in: .pypi) == wanted
              }) else { return nil }
        let real = Paths.realPath((location as NSString).appendingPathComponent(distInfo + "/METADATA"))
        guard let cellar = real.range(of: "/Cellar/") else { return nil }
        return real[cellar.upperBound...].split(separator: "/").first.map(String.init)
    }

    static func samePath(_ a: String, _ b: String) -> Bool {
        func clean(_ p: String) -> String { (p as NSString).standardizingPath }
        return !a.isEmpty && clean(a) == clean(b)
    }
}
