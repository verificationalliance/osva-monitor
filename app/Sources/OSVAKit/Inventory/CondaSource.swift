import Foundation

/// conda environments (Miniconda, Anaconda, Miniforge, mamba, micromamba): each package's record in the environment's
/// conda-meta folder. Only a Python package that PyPI knows under the same name can be checked as a PyPI package (the
/// record's files include its dist-info, which names the distribution); every other package is matched to the
/// projects the site grades through the index, or listed as not checked.
public struct CondaSource: Sendable {
    static let maxEnvironments = 200
    static let maxRecords = 5000
    static let maxRecordSize = 32 << 20

    public struct Result: Sendable {
        /// Python packages with the same name on PyPI, checked as PyPI packages.
        public var packages: [InstalledPackage]
        /// The rest, for the index's `R conda` lines.
        public var managed: [ManagedPackage]
        public var unchecked: [UncheckedItem]
        public var report: SourceReport
    }

    let environment: ToolEnvironment
    let roots: [String]

    /// `roots` defaults to where the installers put conda (and where $CONDA_EXE, $CONDA_ROOT and $MAMBA_ROOT_PREFIX say).
    public init(environment: ToolEnvironment, roots: [String]? = nil) {
        self.environment = environment
        self.roots = roots ?? Self.defaultRoots(environment)
    }

    static func defaultRoots(_ environment: ToolEnvironment) -> [String] {
        let home = environment.home.path, env = environment.base
        var out: [String] = []
        if let exe = env["CONDA_EXE"], exe.hasPrefix("/") {
            out.append(((exe as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent)
        }
        for key in ["CONDA_ROOT", "MAMBA_ROOT_PREFIX"] { if let v = env[key], v.hasPrefix("/") { out.append(v) } }
        out += ["miniconda3", "miniconda", "anaconda3", "anaconda", "miniforge3", "miniforge", "mambaforge", "micromamba",
                ".local/share/mamba", "opt/anaconda3", "opt/miniconda3"].map { home + "/" + $0 }
        out += ["/opt/anaconda3", "/opt/miniconda3", "/opt/miniforge3", "/opt/homebrew/anaconda3", "/opt/homebrew/Caskroom/miniconda/base",
                "/opt/homebrew/Caskroom/miniforge/base", "/usr/local/anaconda3", "/usr/local/miniconda3",
                "/usr/local/Caskroom/miniconda/base", "/usr/local/Caskroom/miniforge/base"]
        return out
    }

    /// micromamba is a single binary outside the environments it manages.
    func micromamba() -> Bool {
        environment.firstExecutable(["~/.local/bin/micromamba", "/opt/homebrew/bin/micromamba", "/usr/local/bin/micromamba", "~/bin/micromamba"]) != nil
    }

    /// The command that manages an installation: conda (also Miniforge's; conda uses mamba's solver now), else mamba,
    /// else micromamba. Nil when none is there to run.
    func tool(forRoot root: String) -> CondaEnvironment.Tool? {
        if environment.isExecutable(root + "/bin/conda") || environment.isExecutable(root + "/condabin/conda") { return .conda }
        if environment.isExecutable(root + "/bin/mamba") { return .mamba }
        if environment.isExecutable(root + "/bin/micromamba") || micromamba() { return .micromamba }
        return nil
    }

    static func isEnvironment(_ path: String) -> Bool {
        var dir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path + "/conda-meta", isDirectory: &dir) && dir.boolValue
    }

    /// Every environment: each installation's root ("base") and its envs folder, and those listed in
    /// ~/.conda/environments.txt (where `conda create -p` records environments made elsewhere).
    func environments() -> [(prefix: String, name: String, named: Bool, tool: CondaEnvironment.Tool)] {
        var out: [(String, String, Bool, CondaEnvironment.Tool)] = [], seen = Set<String>()
        var known: [(root: String, tool: CondaEnvironment.Tool)] = []
        func add(_ prefix: String, _ name: String, _ named: Bool, _ tool: CondaEnvironment.Tool) {
            guard out.count < Self.maxEnvironments, seen.insert(Paths.realPath(prefix)).inserted else { return }
            out.append((prefix, name, named, tool))
        }
        for root in roots where Self.isEnvironment(root) {
            guard let tool = tool(forRoot: root), !known.contains(where: { Paths.realPath($0.root) == Paths.realPath(root) }) else { continue }
            known.append((root, tool))
            add(root, "base", true, tool)
            for env in ((try? FileManager.default.contentsOfDirectory(atPath: root + "/envs")) ?? []).sorted() where !env.hasPrefix(".") {
                if Self.isEnvironment(root + "/envs/" + env) { add(root + "/envs/" + env, env, true, tool) }
            }
        }
        if let list = ReadOnlyFile.head(environment.home.path + "/.conda/environments.txt", max: 256 * 1024), let first = known.first {
            for line in String(decoding: list, as: UTF8.self).split(whereSeparator: \.isNewline).prefix(Self.maxEnvironments) {
                let prefix = line.trimmingCharacters(in: .whitespaces)
                guard prefix.hasPrefix("/"), Self.isEnvironment(prefix) else { continue }
                if let k = known.first(where: { prefix.hasPrefix($0.root + "/envs/") }) {
                    add(prefix, (prefix as NSString).lastPathComponent, true, k.tool)
                } else {
                    add(prefix, (prefix as NSString).lastPathComponent, false, first.tool)
                }
            }
        }
        return out
    }

    public func collect() -> Result {
        let clock = ContinuousClock(), start = clock.now
        let envs = environments()
        guard !envs.isEmpty else {
            return Result(packages: [], managed: [], unchecked: [], report: SourceReport(kind: .conda, available: false, count: 0,
                          detail: "conda not found", seconds: (clock.now - start).seconds))
        }
        var packages: [InstalledPackage] = [], managed: [ManagedPackage] = [], unchecked: [UncheckedItem] = []
        for e in envs {
            let records = Self.records(in: e.prefix)
            let python = records.first { $0.name == "python" }?.version
            let env = CondaEnvironment(prefix: e.prefix, name: e.name, named: e.named, tool: e.tool, python: python)
            for r in records {
                switch r.classification {
                case let .pypi(name, version):
                    packages.append(InstalledPackage(ecosystem: .pypi, name: name, version: version, origin: .conda(env: env)))
                case let .differentPyPIName(pypi):
                    unchecked.append(UncheckedItem(kind: .conda, bucket: "conda packages named differently on PyPI",
                                                   item: "\(r.name) \(r.version) (PyPI: \(pypi))"))
                case .pythonWithoutMetadata:
                    unchecked.append(UncheckedItem(kind: .conda, bucket: "conda Python packages without PyPI metadata", item: "\(r.name) \(r.version)"))
                case .other:
                    managed.append(ManagedPackage(manager: .conda, name: r.name, version: r.version, origin: .conda(env: env)))
                }
            }
        }
        let detail = "\(GlobalPackageSources.count(envs.count, "environment")), "
            + "\(GlobalPackageSources.count(packages.count + managed.count + unchecked.count, "package")) (\(packages.count) on PyPI)"
        return Result(packages: packages, managed: managed, unchecked: unchecked,
                      report: SourceReport(kind: .conda, available: true, count: packages.count + managed.count, detail: detail,
                                           seconds: (clock.now - start).seconds))
    }

    public struct Record: Equatable, Sendable {
        public enum Classification: Equatable, Sendable {
            /// A Python package whose distribution has the conda package's name: checked as this PyPI package.
            case pypi(name: String, version: String)
            /// A Python package published on PyPI under another name ("pytorch" is "torch"): not checked.
            case differentPyPIName(String)
            /// `noarch: python` without a dist-info to name it.
            case pythonWithoutMetadata
            /// Not a Python package (openssl, libcurl, python itself).
            case other
        }
        public var name: String
        public var version: String
        public var classification: Classification
    }

    /// The package records in an environment's conda-meta folder.
    static func records(in prefix: String) -> [Record] {
        let meta = prefix + "/conda-meta"
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: meta)) ?? []).filter { $0.hasSuffix(".json") }.sorted()
        return files.prefix(maxRecords).compactMap { f in
            ReadOnlyFile.head(meta + "/" + f, max: maxRecordSize).flatMap { record(from: $0) }
        }
    }

    private static let distInfo = Regex(#"(?:^|/)site-packages/([^/]+)\.(dist-info|egg-info)(?:/|$)"#)

    /// One conda-meta record: {"name", "version", "noarch", "files": [...]}.
    public static func record(from bytes: [UInt8]) -> Record? {
        guard let json = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any],
              let name = json["name"] as? String, let version = json["version"] as? String, !name.isEmpty, !version.isEmpty else { return nil }
        let noarch = (json["noarch"] as? String) ?? ((json["noarch"] as? [String: Any])?["type"] as? String)
        let files = (json["files"] as? [Any] ?? []).compactMap { $0 as? String }
        var dist: (name: String, version: String)?
        for file in files where file.contains("site-packages/") {
            guard let m = distInfo.firstMatch(file), let stem = m[1] else { continue }
            dist = distribution(stem, egg: m[2] == "egg-info")
            if dist != nil { break }
        }
        let classification: Record.Classification
        if let dist {
            classification = PackageNames.indexName(dist.name, in: .pypi) == PackageNames.indexName(name, in: .pypi)
                ? .pypi(name: name, version: dist.version) : .differentPyPIName(dist.name)
        } else if noarch == "python" {
            classification = .pythonWithoutMetadata
        } else {
            classification = .other
        }
        return Record(name: name, version: version, classification: classification)
    }

    /// "PyYAML-6.0.1" (dist-info) or "PyYAML-6.0.1-py3.11" (egg-info): the name, and its version as PyPI writes it.
    static func distribution(_ stem: String, egg: Bool) -> (name: String, version: String)? {
        let parts = stem.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        return (parts[0], parts[1])
    }
}
