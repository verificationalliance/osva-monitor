import Foundation

/// A Python interpreter on this Mac, and what kind it is: that decides how a package installed in it can be upgraded.
public struct PythonEnvironment: Hashable, Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        /// /usr/bin/python3: Apple's, part of Xcode or the Command Line Tools.
        case apple
        /// Homebrew's python@3.x: externally managed (PEP 668), pip refuses to change it.
        case homebrew
        /// The python.org installer's framework build.
        case pythonOrg
        case virtualEnv
        case other
    }

    /// The command that runs it ("/usr/bin/python3", "/opt/homebrew/bin/python3.12").
    public var executable: String
    /// "3.9.6", sent with each of its PyPI packages so the plan only names versions it can install.
    public var version: String
    public var kind: Kind
    /// Its standard library carries an EXTERNALLY-MANAGED marker (PEP 668): pip will not install into it, not even
    /// with --user, unless told to break that.
    public var externallyManaged: Bool
    /// Its per-user site-packages directory.
    public var userSite: String?
    /// For Homebrew's: the formula ("python@3.12").
    public var formula: String?

    public init(executable: String, version: String, kind: Kind, externallyManaged: Bool, userSite: String?, formula: String?) {
        self.executable = executable; self.version = version; self.kind = kind
        self.externallyManaged = externallyManaged; self.userSite = userSite; self.formula = formula
    }

    /// "3.9" from "3.9.6".
    public var minorVersion: String { version.split(separator: ".").prefix(2).joined(separator: ".") }

    public var label: String {
        switch kind {
        case .apple: return "Apple's Python \(version) (part of Xcode)"
        case .homebrew: return "Homebrew Python \(version)"
        case .pythonOrg: return "Python \(version) (python.org)"
        case .virtualEnv: return "virtual environment, Python \(version)"
        case .other: return "Python \(version)"
        }
    }
}

/// Where an installed thing was found. Shown on every finding, and used to write its upgrade command.
public enum Origin: Hashable, Codable, Sendable {
    case homebrewFormula(name: String)
    case homebrewCask(token: String)
    /// An app that bundles Electron. `caskToken` is set when Homebrew installed the app.
    case electronApp(name: String, bundlePath: String, caskToken: String?)
    case npmGlobal(npm: String)
    /// A package in a Python's site-packages: the per-user site or the interpreter's own, and the Homebrew formula
    /// that installed it, if one did.
    case pip(python: PythonEnvironment, user: Bool, formula: String?)
    case cargoInstall
    case gem(gem: String)
    /// A lockfile inside a folder the person asked us to watch. `direct` is whether the project's manifest names the
    /// package itself (nil when there is no manifest to tell).
    case folder(root: String, lockfile: String, direct: Bool?)
    /// A module or crate a Go or Rust program was built with (or its toolchain's standard library).
    case program(BuiltProgram)
    /// A package in a pipx or uv tool's environment.
    case pythonTool(PythonTool)
    /// A package in a conda environment.
    case conda(env: CondaEnvironment)
    /// A MacPorts port.
    case macports(port: String)
    /// A package in a Nix profile; `element` is what its upgrade command names.
    case nix(profile: NixProfile, element: String)
    /// An app checked by its own product record or by a library bundled inside it. `caskToken` is set when Homebrew
    /// installed the app.
    case application(name: String, bundlePath: String, caskToken: String?)
    /// An editor or browser extension, or a package bundled inside one.
    case addOn(host: ExtensionHost, id: String, name: String, profile: String?, path: String)
    /// A Java runtime (a JDK or a JRE) installed on its own: in /Library/Java/JavaVirtualMachines, IntelliJ IDEA's
    /// folders, SDKMAN's, asdf's or mise's, or a Homebrew formula's keg.
    case javaRuntime(JavaRuntime)

    /// A short human description: "Homebrew", "Slack", "global npm", "~/code/site/package-lock.json".
    public var label: String {
        switch self {
        case .homebrewFormula: return "Homebrew"
        case .homebrewCask: return "Homebrew cask"
        case let .electronApp(name, _, _): return name
        case .npmGlobal: return "global npm"
        case let .pip(python, user, formula):
            if let formula { return "\(python.label) · from Homebrew's \(formula)" }
            return user ? "\(python.label) · your user site" : python.label
        case .cargoInstall: return "cargo install"
        case let .gem(gem): return gem.hasPrefix("/usr/bin/") ? "RubyGems (system Ruby)" : "RubyGems"
        case let .folder(_, lockfile, direct):
            let path = Paths.abbreviatingHome(lockfile)
            switch direct { case true?: return path; case false?: return "\(path) · indirect"; case nil: return path }
        case let .program(p): return p.originLabel
        case let .pythonTool(t): return (t.manager == .pipx ? "pipx" : "uv tool") + (t.python.map { " · Python \($0)" } ?? "")
        case let .conda(env):
            let place = env.named ? "conda env \(env.name)" : "conda env \(Paths.abbreviatingHome(env.prefix))"
            return place + (env.python.map { " · Python \($0)" } ?? "")
        case let .macports(port): return "MacPorts \(port)"
        case let .nix(profile, element): return "Nix \(element) · \(Paths.abbreviatingHome(profile.path))"
        case let .application(name, _, _): return name
        case let .addOn(host, _, name, _, _): return "\(name) (\(host.title))"
        case let .javaRuntime(r): return r.location
        }
    }

    /// Where, for the line under a finding: the app's bundle for an Electron app (its name is the finding's title),
    /// otherwise the label.
    public var location: String {
        if case let .electronApp(_, path, cask) = self {
            let folder = Paths.abbreviatingHome((path as NSString).deletingLastPathComponent)
            return "App in \(folder)" + (cask != nil ? " · Homebrew cask" : "")
        }
        if case let .application(_, path, cask) = self {
            let folder = Paths.abbreviatingHome((path as NSString).deletingLastPathComponent)
            return "App in \(folder)" + (cask != nil ? " · Homebrew cask" : "")
        }
        if case let .addOn(host, id, _, profile, _) = self {
            return "\(host.title) extension · " + (host.isEditor ? id : (profile ?? "default profile"))
        }
        return label
    }

    /// The Python version a pip package is installed with.
    public var pythonVersion: String? {
        if case let .pip(python, _, _) = self { return python.version }
        if case let .pythonTool(tool) = self { return tool.python }
        if case let .conda(env) = self { return env.python }
        return nil
    }

    /// Whether two origins are the same place, as a fix sees it: the same Python (an upgrade with --user moves a
    /// package from Apple's read-only site to the user site), the same lockfile, the same app bundle; otherwise equal.
    public func samePlace(as other: Origin) -> Bool {
        switch (self, other) {
        case let (.pip(a, _, _), .pip(b, _, _)): return a.executable == b.executable
        case let (.folder(_, a, _), .folder(_, b, _)): return a == b
        case let (.electronApp(_, a, _), .electronApp(_, b, _)): return a == b
        // A program is the same file, or the same formula's program of that name after an upgrade moved its keg.
        case let (.program(a), .program(b)): return a.path == b.path || (a.formula != nil && a.formula == b.formula && a.name == b.name)
        case let (.pythonTool(a), .pythonTool(b)): return a.venv == b.venv
        case let (.conda(a), .conda(b)): return a.prefix == b.prefix
        case let (.nix(a, _), .nix(b, _)): return a.path == b.path
        // the same runtime, whatever version an update put there
        case let (.javaRuntime(a), .javaRuntime(b)): return a.realPath == b.realPath
        default: return self == other
        }
    }

    public var kind: SourceKind {
        switch self {
        case .homebrewFormula, .homebrewCask: return .homebrew
        case .electronApp: return .electron
        case .npmGlobal: return .npm
        case .pip: return .pip
        case .cargoInstall: return .cargo
        case .gem: return .gem
        case .folder: return .folders
        case let .program(p): return p.language == .go ? .go : .rust
        case let .pythonTool(t): return t.manager == .pipx ? .pipx : .uv
        case .conda: return .conda
        case .macports: return .macports
        case .nix: return .nix
        case .application: return .apps
        case .addOn: return .extensions
        case .javaRuntime: return .java
        }
    }
}

/// The places OSVA Monitor looks.
public enum SourceKind: String, Codable, Sendable, CaseIterable, Comparable {
    case homebrew, macports, nix, electron, apps, extensions, java, go, rust, npm, pip, pipx, uv, conda, cargo, gem, folders

    public var title: String {
        switch self {
        case .homebrew: return "Homebrew"
        case .electron: return "Electron apps"
        case .apps: return "Apps"
        case .extensions: return "Extensions"
        case .java: return "Java"
        case .npm: return "npm"
        case .pip: return "pip"
        case .cargo: return "cargo"
        case .gem: return "RubyGems"
        case .folders: return "Folders"
        case .macports: return "MacPorts"
        case .nix: return "Nix"
        case .go: return "Go programs"
        case .rust: return "Rust programs"
        case .pipx: return "pipx"
        case .uv: return "uv tools"
        case .conda: return "conda"
        }
    }

    public static func < (a: SourceKind, b: SourceKind) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }
}

/// One installed package of a registry, as found on this Mac. Electron apps appear as npm `electron`.
public struct InstalledPackage: Hashable, Codable, Sendable {
    public var ecosystem: Ecosystem
    public var name: String
    public var version: String
    public var origin: Origin
    /// Where it is and why, as far as its source could tell cheaply (pip: the site-packages directory pip reported).
    /// Stays on this Mac; `ProvenanceExplainer` completes it for the copies behind findings.
    public var provenance: Provenance?

    public init(ecosystem: Ecosystem, name: String, version: String, origin: Origin, provenance: Provenance? = nil) {
        self.ecosystem = ecosystem; self.name = name; self.version = version; self.origin = origin; self.provenance = provenance
    }
}

/// A Homebrew formula or cask. These are matched to the projects our site grades, not to registry packages.
public struct HomebrewItem: Hashable, Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case formula, cask }
    public var kind: Kind
    /// The formula name or cask token.
    public var name: String
    /// The upstream version (Homebrew's `_<revision>` suffix removed).
    public var version: String
    /// The homepage and download URLs, from which the project's repository is derived.
    public var urls: [String]

    public init(kind: Kind, name: String, version: String, urls: [String]) {
        self.kind = kind; self.name = name; self.version = version; self.urls = urls
    }

    public var origin: Origin { kind == .formula ? .homebrewFormula(name: name) : .homebrewCask(token: name) }
}

/// What one source found, or why it found nothing.
public struct SourceReport: Hashable, Codable, Sendable {
    public var kind: SourceKind
    /// False when the tool is not installed (no brew, no npm ...).
    public var available: Bool
    public var count: Int
    /// "338 formulae, 69 casks", "npm not found", "2 folders, 7 lockfiles".
    public var detail: String
    public var error: String?
    /// How long the source took, in seconds (nil in reports saved before it was measured).
    public var seconds: Double?

    public init(kind: SourceKind, available: Bool, count: Int, detail: String, error: String? = nil, seconds: Double? = nil) {
        self.kind = kind; self.available = available; self.count = count; self.detail = detail; self.error = error
        self.seconds = seconds
    }
}

/// Everything found on this Mac in one scan. Stays on this Mac.
public struct Inventory: Codable, Sendable, Hashable {
    public var packages: [InstalledPackage] = []
    public var homebrew: [HomebrewItem] = []
    /// Apps in /Applications and ~/Applications that do not bundle Electron: not checked.
    public var otherApps: [String] = []
    public var reports: [SourceReport] = []
    /// MacPorts ports, Nix packages and conda's non-PyPI packages: matched to graded projects through the index.
    public var managed: [ManagedPackage] = []
    /// What the sources found and could not check at all.
    public var unchecked: [UncheckedItem] = []
    /// Every app in /Applications and ~/Applications, for its product record and the libraries it bundles.
    public var apps: [InstalledApp] = []
    /// Editor and browser extensions (the packages bundled inside them are in `packages`).
    public var extensions: [InstalledExtension] = []
    /// Java runtimes installed on their own (JavaSource); the ones bundled inside apps are the apps' components.
    public var javaRuntimes: [JavaRuntime] = []

    public init(packages: [InstalledPackage] = [], homebrew: [HomebrewItem] = [], otherApps: [String] = [], reports: [SourceReport] = [],
                apps: [InstalledApp] = [], extensions: [InstalledExtension] = [], javaRuntimes: [JavaRuntime] = []) {
        self.packages = packages; self.homebrew = homebrew; self.otherApps = otherApps; self.reports = reports
        self.apps = apps; self.extensions = extensions; self.javaRuntimes = javaRuntimes
    }

    public init(from decoder: Decoder) throws {                  // reports saved before otherApps existed
        let c = try decoder.container(keyedBy: CodingKeys.self)
        packages = try c.decode([InstalledPackage].self, forKey: .packages)
        homebrew = try c.decode([HomebrewItem].self, forKey: .homebrew)
        otherApps = try c.decodeIfPresent([String].self, forKey: .otherApps) ?? []
        reports = try c.decode([SourceReport].self, forKey: .reports)
        managed = try c.decodeIfPresent([ManagedPackage].self, forKey: .managed) ?? []          // reports saved before these
        unchecked = try c.decodeIfPresent([UncheckedItem].self, forKey: .unchecked) ?? []
        apps = try c.decodeIfPresent([InstalledApp].self, forKey: .apps) ?? []
        extensions = try c.decodeIfPresent([InstalledExtension].self, forKey: .extensions) ?? []
        javaRuntimes = try c.decodeIfPresent([JavaRuntime].self, forKey: .javaRuntimes) ?? []
    }

    /// This inventory with the given sources replaced by `other`'s.
    public func replacing(_ kinds: Set<SourceKind>, with other: Inventory) -> Inventory {
        var out = Inventory()
        out.packages = packages.filter { !kinds.contains($0.origin.kind) } + other.packages.filter { kinds.contains($0.origin.kind) }
        out.homebrew = kinds.contains(.homebrew) ? other.homebrew : homebrew
        out.otherApps = kinds.contains(.electron) ? other.otherApps : otherApps
        out.managed = managed.filter { !kinds.contains($0.origin.kind) } + other.managed.filter { kinds.contains($0.origin.kind) }
        out.unchecked = unchecked.filter { !kinds.contains($0.kind) } + other.unchecked.filter { kinds.contains($0.kind) }
        out.apps = kinds.contains(.apps) ? other.apps : apps
        out.extensions = kinds.contains(.extensions) ? other.extensions : extensions
        out.javaRuntimes = kinds.contains(.java) ? other.javaRuntimes : javaRuntimes
        out.reports = (reports.filter { !kinds.contains($0.kind) } + other.reports.filter { kinds.contains($0.kind) }).sorted { $0.kind < $1.kind }
        return out
    }
}
