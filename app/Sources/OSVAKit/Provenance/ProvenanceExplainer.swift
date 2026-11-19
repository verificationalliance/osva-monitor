import Foundation

/// Explains each finding's copies: where each is on disk and why it is there, from this Mac's files only (see
/// `Provenance`). Runs after the findings are made, on their copies alone, and reads each site-packages, Homebrew
/// Cellar, lockfile and gem path at most once per scan. Nothing it reads goes into any request: the API's requests
/// are made before this, from `ApprovedPackage` values that carry no paths.
public struct ProvenanceExplainer: Sendable {
    let tools: ToolEnvironment
    let timeZone: TimeZone
    let home: String
    /// Where Homebrew is ("/opt/homebrew"): by default, wherever its brew is.
    let homebrewPrefixes: [String]

    public init(tools: ToolEnvironment = ToolEnvironment(), timeZone: TimeZone = .current, homebrewPrefixes: [String]? = nil) {
        self.tools = tools; self.timeZone = timeZone; home = tools.home.path
        self.homebrewPrefixes = homebrewPrefixes ?? HomebrewSource.brewCandidates.filter(tools.isExecutable)
            .map { (($0 as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent }
    }

    /// The findings, each with `provenance` set for the copies it stands for (nil when nothing could be told).
    public func explain(_ findings: [Finding], inventory: Inventory) async -> [Finding] {
        let context = Context(explainer: self, inventory: inventory)
        var byKey: [String: [InstalledPackage]] = [:]
        for p in inventory.packages { byKey[Self.key(p.ecosystem, p.name, p.version), default: []].append(p) }
        // Where each RubyGems keeps its gems is asked of it (`gem env gempath`, a Ruby start-up), while the rest is read.
        let gemTools = Set(findings.flatMap(\.origins).compactMap { o -> String? in if case let .gem(g) = o { return g } else { return nil } })
        let tools = self.tools
        let gemPaths = Task { await Self.gemPaths(Array(gemTools), tools: tools) }
        var out = findings
        // the gems last, when their paths are known
        let order = out.indices.filter { !out[$0].origins.contains { $0.kind == .gem } } + out.indices.filter { out[$0].origins.contains { $0.kind == .gem } }
        for i in order {
            if context.gemPaths == nil, out[i].origins.contains(where: { $0.kind == .gem }) { context.gemPaths = await gemPaths.value }
            let f = out[i]
            var copies: [Provenance] = []
            switch f.subject {
            case let .package(ecosystem, name):
                let installs = byKey[Self.key(ecosystem, name, f.installedVersion)] ?? []
                for origin in f.origins {
                    guard let install = installs.first(where: { $0.origin == origin }) else { continue }
                    if let p = context.explain(install), p != Provenance() { copies.append(p) }
                }
            case .project:
                for origin in f.origins {
                    if let p = context.homebrew(origin, version: f.installedVersion), p != Provenance() { copies.append(p) }
                }
            case .product, .addOn:
                for origin in f.origins {
                    if let p = context.bundled(origin), p != Provenance() { copies.append(p) }
                }
            }
            out[i].provenance = copies.isEmpty ? nil : copies
        }
        return out
    }

    /// Each gem tool's `gem env gempath`, asked side by side.
    static func gemPaths(_ gems: [String], tools: ToolEnvironment) async -> [String: [String]] {
        await withTaskGroup(of: (String, [String]).self) { group in
            for gem in gems {
                group.addTask {
                    let r = try? await tools.run(gem, ["env", "gempath"], timeout: 30)
                    let paths = r.flatMap { $0.status == 0 ? String(decoding: $0.stdout.prefix(16 * 1024), as: UTF8.self) : nil }?
                        .trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ":").map(String.init).filter { $0.hasPrefix("/") } ?? []
                    return (gem, Array(paths.prefix(8)))
                }
            }
            var out: [String: [String]] = [:]
            for await (gem, paths) in group { out[gem] = paths }
            return out
        }
    }

    static func key(_ ecosystem: Ecosystem, _ name: String, _ version: String) -> String {
        "\(ecosystem)\u{1F}\(PackageNames.indexName(name, in: ecosystem))\u{1F}\(version)"
    }

    func short(_ path: String) -> String { Paths.abbreviatingHome(path, home: home) }
    func day(_ date: Date) -> String { ProvenanceText.day(date, timeZone: timeZone) }

    /// The caches of one explanation pass.
    final class Context {
        let explainer: ProvenanceExplainer
        let inventory: Inventory
        var sites: [String: SitePackages] = [:]
        var receipts: [String: HomebrewReceipts] = [:]
        var graphs: [String: LockfileGraph?] = [:]
        var gemSpecs: [String: GemSpecs] = [:]
        var gemPaths: [String: [String]]?

        init(explainer: ProvenanceExplainer, inventory: Inventory) { self.explainer = explainer; self.inventory = inventory }

        func explain(_ p: InstalledPackage) -> Provenance? {
            if let given = p.provenance, given.why != nil { return given }          // a source that knew already
            switch p.origin {
            case let .pip(python, user, formula): return pip(p, python: python, user: user, formula: formula)
            case let .electronApp(name, bundlePath, cask): return electron(name, bundlePath, cask)
            case let .npmGlobal(npm): return npmGlobal(p, npm: npm)
            case let .gem(gem): return self.gem(p, tool: gem)
            case .cargoInstall: return cargo(p)
            case let .folder(_, lockfile, direct): return folder(p, lockfile: lockfile, direct: direct)
            case .homebrewFormula, .homebrewCask: return homebrew(p.origin, version: p.version)
            case .application, .addOn: return bundled(p.origin)
            }
        }

        /// An app checked by its product record, or an extension: where it is, and who installed it when that is known.
        func bundled(_ origin: Origin) -> Provenance? {
            switch origin {
            case let .application(name, bundlePath, cask):
                var out = Provenance(path: bundlePath)
                if let cask, let prefix = explainer.homebrewPrefixes.first(where: { LocalFiles.isDirectory($0 + "/Caskroom/" + cask) }) {
                    let installed = HomebrewReceipts.cask(cask, prefix: prefix)?.installed
                    out.why = "Homebrew installed \(name)" + (installed.map { " on \(explainer.day($0))" } ?? "") + " (cask \(cask))"
                }
                return out
            case let .addOn(host, _, _, profile, path):
                return Provenance(path: path, why: "An extension in \(host.title)" + (profile.map { ", profile \($0)" } ?? ""))
            default:
                return nil
            }
        }

        // MARK: pip

        func siteIndex(for python: PythonEnvironment) -> SitePackages {
            if let s = sites[python.executable] { return s }
            let s = SitePackages(sites: ReverseDependencies.sitePackages(of: python, in: inventory))
            sites[python.executable] = s
            return s
        }

        func pip(_ p: InstalledPackage, python: PythonEnvironment, user: Bool, formula: String?) -> Provenance? {
            let index = siteIndex(for: python)
            guard let d = index.distribution(p.name, version: p.version) else { return p.provenance }
            let e = explainer
            var out = Provenance(path: index.location(of: d))
            // One line per dependent: a dependent listing the package twice (under two markers) shows both ranges.
            var order: [String] = [], merged: [String: Provenance.Dependent] = [:], ranges: [String: [String]] = [:]
            for (dep, req) in index.dependents(of: d.name) {
                if merged[dep.key] == nil {
                    order.append(dep.key)
                    merged[dep.key] = .init(name: dep.name, version: dep.version, specifier: nil, requested: dep.isProject ? true : dep.requested)
                }
                if !(ranges[dep.key] ?? []).contains(req.specifier) { ranges[dep.key, default: []].append(req.specifier) }
            }
            for k in order {
                let r = ranges[k] ?? []
                merged[k]?.specifier = r.contains("") ? "" : r.joined(separator: " or ")
            }
            out.dependents = order.compactMap { merged[$0] }
            let installedLine = ProvenanceText.installed(on: ProvenanceText.plausible(d.installed), by: Self.tool(d.installer), timeZone: e.timeZone)

            if let formula {
                out.why = "Comes with Homebrew's \(formula)"
            } else if python.kind == .apple && !user {
                out.why = "Comes with Apple's Python, part of Xcode"
            } else if d.isProject {
                out.why = "Your own project" + (d.projectFolder.map { ", from \(e.short($0))" } ?? "")
            } else if let (chain, top) = index.chainToTop(of: d.name) {
                let names = chain.map(\.name)
                let alike = out.dependents.filter { $0.requested == true && (top != .project || index.distribution($0.name)?.isProject == true) }
                out.why = ProvenanceText.neededBy(chain: names, top: top, direct: out.dependents.map(\.name), directLikeTop: alike.map(\.name))
                if top != .unknown, let t = chain.last {
                    if top == .project, let folder = t.projectFolder { out.details.append("\(t.name) is your project, from \(e.short(folder))") }
                    if top == .requested, let date = ProvenanceText.plausible(t.installed) { out.details.append("You installed \(t.name) on \(e.day(date))") }
                }
                if top != .unknown, chain.count > ProvenanceText.maxShownChain { out.details.append("Needed by " + names.joined(separator: " → ")) }
                if d.requested == true {
                    out.details.append("You also installed it by name" + (ProvenanceText.plausible(d.installed).map { " on \(e.day($0))" } ?? ""))
                } else if let installedLine {
                    out.details.append(installedLine)
                }
            } else if d.requested == true {
                out.why = ProvenanceText.installedByYou(on: ProvenanceText.plausible(d.installed),
                                                        with: d.source == .vcs ? "git" : Self.tool(d.installer).flatMap { $0 == "pip" ? nil : $0 },
                                                        timeZone: e.timeZone)
            } else if d.requested == false {
                out.why = "Installed" + (ProvenanceText.plausible(d.installed).map { " on \(e.day($0))" } ?? "") + " for another package"
                let bootstrap: Set<String> = ["pip", "setuptools", "wheel", "distribute"]
                // Only when every metadata file was read and no extra names it (pip does not record the extras asked for).
                if index.complete, !bootstrap.contains(d.key), !index.isNamedByAnExtra(d.name) { out.advice = ProvenanceText.unused }
            } else {
                out.why = installedLine
            }
            if out.why?.hasPrefix("Comes with") == true || d.isProject, let installedLine { out.details.append(installedLine) }
            return out
        }

        /// INSTALLER's tool, as a person would name it: "Poetry 2.3.2" -> "Poetry", "brew" -> "Homebrew".
        static func tool(_ installer: String?) -> String? {
            guard let first = installer?.split(separator: " ").first.map(String.init), !first.isEmpty, first.count <= 30 else { return nil }
            return first.lowercased() == "brew" ? "Homebrew" : first
        }

        // MARK: Homebrew

        func homebrew(_ origin: Origin, version: String) -> Provenance? {
            let e = explainer
            switch origin {
            case let .homebrewFormula(name):
                guard let prefix = e.homebrewPrefixes.first(where: { LocalFiles.isDirectory($0 + "/Cellar/" + name) }) else { return nil }
                if receipts[prefix] == nil { receipts[prefix] = HomebrewReceipts(prefix: prefix) }
                guard let r = receipts[prefix], let keg = r.kegs[name] else { return Provenance(path: prefix + "/Cellar/" + name) }
                var out = Provenance(path: keg.path)
                out.dependents = r.dependents(of: name).map { Provenance.Dependent(name: $0, requested: r.kegs[$0]?.onRequest) }
                let date = keg.installed.map { e.day($0) }
                if let (chain, top) = r.chainToTop(of: name) {
                    out.why = ProvenanceText.neededBy(chain: chain, top: top, direct: out.dependents.map(\.name),
                                                      directLikeTop: out.dependents.filter { $0.requested == true }.map(\.name))
                    if top == .requested, chain.count > ProvenanceText.maxShownChain { out.details.append("Needed by " + chain.joined(separator: " → ")) }
                    if top == .requested, let t = chain.last, let d = r.kegs[t]?.installed { out.details.append("You installed \(t) on \(e.day(d))") }
                    if keg.onRequest == true { out.details.append("You also installed it yourself" + (date.map { " on \($0)" } ?? "")) }
                    else if let date { out.details.append("Installed on \(date)") }
                } else if keg.onRequest == true {
                    out.why = ProvenanceText.installedByYou(on: keg.installed, timeZone: e.timeZone)
                } else if keg.onRequest == false {
                    out.why = "Installed" + (date.map { " on \($0)" } ?? "") + " for another formula"
                    if r.complete {
                        out.advice = "Nothing else from Homebrew uses it — if you don't either, removing it may be better than upgrading it."
                    }
                } else {
                    out.why = ProvenanceText.installed(on: keg.installed, timeZone: e.timeZone)
                }
                return out
            case let .homebrewCask(token):
                guard let prefix = e.homebrewPrefixes.first(where: { LocalFiles.isDirectory($0 + "/Caskroom/" + token) }),
                      let cask = HomebrewReceipts.cask(token, version: version, prefix: prefix) else { return nil }
                return Provenance(path: cask.app ?? cask.path,
                                  why: ProvenanceText.installedByYou(on: cask.installed, with: "Homebrew", timeZone: e.timeZone))
            default:
                return nil
            }
        }

        // MARK: Apps, npm, gems, cargo

        func electron(_ name: String, _ bundlePath: String, _ cask: String?) -> Provenance {
            var out = Provenance(path: bundlePath, why: "Inside \(name), which ships its own Electron")
            if let cask, let prefix = explainer.homebrewPrefixes.first(where: { LocalFiles.isDirectory($0 + "/Caskroom/" + cask) }) {
                let installed = HomebrewReceipts.cask(cask, prefix: prefix)?.installed
                out.details.append("Homebrew installed \(name)" + (installed.map { " on \(explainer.day($0))" } ?? "") + " (cask \(cask))")
            }
            return out
        }

        /// A global npm's packages folder: npm lives at <prefix>/lib/node_modules/npm, the packages beside it.
        func npmGlobal(_ p: InstalledPackage, npm: String) -> Provenance? {
            let real = Paths.realPath(npm)
            guard let r = real.range(of: "/lib/node_modules/") else { return nil }
            let root = String(real[..<r.upperBound].dropLast())
            let path = root + "/" + p.name
            guard LocalFiles.exists(path) else { return nil }
            var out = Provenance(path: path)
            if let parent = Self.npmParent(of: path, root: root) {
                out.why = "Inside \(parent), installed with npm -g"
            } else if p.name == "npm" || p.name == "corepack" {
                out.why = root.contains("/Cellar/node/") || HomebrewReceipts.prefix(of: root) != nil ? "Comes with Homebrew's node" : "Comes with Node.js"
            } else {
                out.why = ProvenanceText.installedByYou(on: ProvenanceText.plausible(LocalFiles.modified(path)), with: "npm -g", timeZone: explainer.timeZone)
            }
            return out
        }

        /// "…/node_modules/eslint/node_modules/debug" is inside eslint.
        static func npmParent(of path: String, root: String) -> String? {
            guard path.hasPrefix(root + "/") else { return nil }
            let parts = path.dropFirst(root.count + 1).components(separatedBy: "/node_modules/")
            guard parts.count > 1, let first = parts.first, !first.isEmpty else { return nil }
            return first
        }

        func gem(_ p: InstalledPackage, tool: String) -> Provenance? {
            if gemSpecs[tool] == nil { gemSpecs[tool] = GemSpecs(paths: gemPaths?[tool] ?? []) }
            guard let specs = gemSpecs[tool], let g = specs.gem(p.name, version: p.version) else { return nil }
            let e = explainer
            var out = Provenance(path: g.path)
            out.dependents = specs.dependents(of: g.name).map { Provenance.Dependent(name: $0.gem.name, version: $0.gem.version, specifier: $0.specifier) }
            if g.path.hasPrefix("/System/") || (g.isDefault && tool.hasPrefix("/usr/bin/")) {
                out.why = "Comes with macOS's Ruby"
            } else if g.isDefault {
                out.why = "Comes with Ruby itself (a default gem)"
            } else if !out.dependents.isEmpty {
                // RubyGems does not record who asked for what: the gems that need it, not a guessed chain.
                out.why = ProvenanceText.neededBy(names: out.dependents.map(\.name), top: .unknown)
                if let date = g.installed { out.details.append("Installed on \(e.day(date))") }
            } else {
                out.why = "Installed" + (g.installed.map { " on \(e.day($0))" } ?? "") + "; no other gem needs it"
            }
            return out
        }

        func cargo(_ p: InstalledPackage) -> Provenance? {
            let e = explainer
            let cargoHome = e.tools.base["CARGO_HOME"] ?? (e.home + "/.cargo")
            let programs = CargoInstalls.programs(of: p.name, version: p.version, cargoHome: cargoHome)
            let program = programs.lazy.map { cargoHome + "/bin/" + $0 }.first(where: LocalFiles.exists)
            var out = Provenance(path: program ?? cargoHome + "/bin",
                                 why: ProvenanceText.installedByYou(on: program.flatMap { ProvenanceText.plausible(LocalFiles.modified($0)) },
                                                                    with: "cargo install", timeZone: e.timeZone))
            if !programs.isEmpty { out.details.append("It gives you " + programs.joined(separator: ", ")) }
            return out
        }

        // MARK: Lockfiles

        func folder(_ p: InstalledPackage, lockfile: String, direct: Bool?) -> Provenance {
            let file = URL(fileURLWithPath: lockfile)
            let dir = file.deletingLastPathComponent().path
            let manifest = Self.manifest(for: file.lastPathComponent)
            if graphs[lockfile] == nil {
                var graph: LockfileGraph?
                if let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= FolderSource.maxFileSize,
                   let data = LocalFiles.read(lockfile, limit: FolderSource.maxFileSize, within: LocalFiles.roots([dir])) {
                    graph = LockfileGraph.read(String(decoding: data, as: UTF8.self), filename: file.lastPathComponent,
                                               direct: Manifests.directNames(forLockfile: file))
                }
                graphs[lockfile] = .some(graph)
            }
            let graph = graphs[lockfile] ?? nil
            // Where: the installed copy when the project has it (package-lock.json says where; otherwise the top
            // node_modules folder, if it holds this version), else the project's folder.
            var out = Provenance(path: dir)
            if let installed = graph?.installPath(of: p.name, version: p.version), LocalFiles.exists(dir + "/" + installed) {
                out.path = dir + "/" + installed
            } else if p.ecosystem == .npm, !p.name.contains(".."), Self.npmVersion(at: dir + "/node_modules/" + p.name, within: dir) == p.version {
                out.path = dir + "/node_modules/" + p.name
            }
            let chain = graph?.chain(to: p.name, version: p.version)
            if direct == true || (direct == nil && chain == []) {
                out.why = "Named in your \(manifest)"
            } else if let chain, !chain.isEmpty {
                out.why = ProvenanceText.neededBy(chain: chain.reversed(), top: .manifest(manifest))
                out.details.append(([manifest] + chain + [p.name]).joined(separator: " → "))
            } else if direct == false {
                out.why = "Needed by another of the project's dependencies"
            }
            return out
        }

        /// The version in an installed npm package's package.json.
        static func npmVersion(at folder: String, within root: String) -> String? {
            guard let data = LocalFiles.read(folder + "/package.json", limit: 1024 * 1024, within: LocalFiles.roots([root])),
                  let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
            return j["version"] as? String
        }

        /// The file a lockfile's project names its own dependencies in.
        static func manifest(for lockfile: String) -> String {
            switch lockfile {
            case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml": return "package.json"
            case "poetry.lock": return "pyproject.toml"
            case "Pipfile.lock": return "Pipfile"
            case "Cargo.lock": return "Cargo.toml"
            case "go.sum": return "go.mod"
            case "Gemfile.lock": return "Gemfile"
            case "composer.lock": return "composer.json"
            default: return lockfile
            }
        }
    }
}
