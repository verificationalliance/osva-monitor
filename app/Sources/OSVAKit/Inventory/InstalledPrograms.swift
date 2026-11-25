import Foundation

/// A Go or Rust program that carries the list of what it was built from: Go writes its modules and toolchain into
/// every binary (the build info), and cargo-auditable writes the crates into a `.dep-v0` section. Its packages are
/// checked as that registry's packages, and a finding belongs to the program, because the program is what is updated.
public struct BuiltProgram: Hashable, Codable, Sendable {
    public enum Language: String, Codable, Sendable { case go, rust }

    /// How it got here, which decides how it is updated.
    public enum Place: String, Codable, Sendable {
        /// In a Homebrew formula's Cellar (`formula` names it).
        case homebrew
        /// In Go's bin directory: `go install` put it there.
        case goInstall
        /// In cargo's bin directory: `cargo install` put it there.
        case cargoInstall
        /// Inside an app bundle (Docker.app's docker, linked onto PATH): the app is what is updated.
        case app
        /// Anywhere else on the PATH: updated wherever it came from.
        case other
    }

    public var language: Language
    /// The file, where it was found ("/opt/homebrew/bin/gh").
    public var path: String
    /// The file name ("gh").
    public var name: String
    /// The program's own version, when known: the main module's or root crate's, else the Homebrew keg's.
    public var version: String?
    public var place: Place
    /// The Homebrew formula whose Cellar holds the file.
    public var formula: String?
    /// Go: the main package's import path ("github.com/cli/cli/v2/cmd/gh"), for `go install`. Rust: the root crate,
    /// when it is published on crates.io, for `cargo install`.
    public var package: String?
    /// Go: the main module ("github.com/cli/cli/v2"). Rust: the root crate.
    public var module: String?
    /// Go: the toolchain it was built with, as OSV writes the Go standard library's versions ("1.22.3").
    public var toolchain: String?
    /// The app bundle that ships it ("Docker"), and the Homebrew cask that installed the app.
    public var app: String?
    public var cask: String?

    public init(language: Language, path: String, name: String, version: String?, place: Place, formula: String?,
                package: String?, module: String? = nil, toolchain: String?, app: String? = nil, cask: String? = nil) {
        self.language = language; self.path = path; self.name = name; self.version = version; self.place = place
        self.formula = formula; self.package = package; self.module = module; self.toolchain = toolchain
        self.app = app; self.cask = cask
    }

    /// "gh 2.62.0", or "gh" when its version is not known.
    public var nameAndVersion: String { version.map { "\(name) \($0)" } ?? name }
}

/// A command-line tool installed with pipx or uv into a virtual environment of its own.
public struct PythonTool: Hashable, Codable, Sendable {
    public enum Manager: String, Codable, Sendable { case pipx, uv }

    public var manager: Manager
    /// The tool's name, as its manager knows it (its environment's folder name): "black".
    public var name: String
    /// The package the tool was installed from ("black"), as PyPI's index writes it.
    public var mainPackage: String
    /// The main package's version.
    public var version: String?
    /// The tool's virtual environment.
    public var venv: String
    /// The environment's Python version, from its pyvenv.cfg ("3.12.4"). Sent with each of its packages, so the plan
    /// only names versions that Python can install.
    public var python: String?

    public init(manager: Manager, name: String, mainPackage: String, version: String?, venv: String, python: String?) {
        self.manager = manager; self.name = name; self.mainPackage = mainPackage; self.version = version; self.venv = venv
        self.python = python
    }
}

/// A conda environment: a base installation (Miniconda, Anaconda, Miniforge, micromamba's root) or one of its envs.
public struct CondaEnvironment: Hashable, Codable, Sendable {
    /// The command that manages it.
    public enum Tool: String, Codable, Sendable { case conda, mamba, micromamba }

    /// The environment's folder.
    public var prefix: String
    /// "base" for an installation's root, the folder name for one of its envs.
    public var name: String
    /// Whether `-n <name>` reaches it (the root, or an env in the installation's envs folder); otherwise `-p <prefix>`.
    public var named: Bool
    public var tool: Tool
    /// The version of the `python` package installed in it, if any.
    public var python: String?

    public init(prefix: String, name: String, named: Bool, tool: Tool, python: String?) {
        self.prefix = prefix; self.name = name; self.named = named; self.tool = tool; self.python = python
    }
}

/// A package of a system package manager (MacPorts, Nix, and conda's packages that are not PyPI packages). These are
/// matched to the projects the site grades through the index's `R` lines, never sent themselves.
public struct ManagedPackage: Hashable, Codable, Sendable {
    public enum Manager: String, Codable, Sendable, CaseIterable { case macports, nix, conda }

    public var manager: Manager
    /// The name in that manager ("openssl3", "python3", "libcurl").
    public var name: String
    /// The upstream version (MacPorts' revision and Nix's output name are not part of it).
    public var version: String
    public var origin: Origin

    public init(manager: Manager, name: String, version: String, origin: Origin) {
        self.manager = manager; self.name = name; self.version = version; self.origin = origin
    }
}

/// Something a source found and could not check at all (a Rust program without a dependency list, a conda package
/// whose PyPI name differs from its own). Listed under "No record", never counted as clean.
public struct UncheckedItem: Hashable, Codable, Sendable {
    public var kind: SourceKind
    /// The heading it is listed under: "Rust programs without a dependency list".
    public var bucket: String
    /// "rav1e 0.8.1".
    public var item: String
    /// The Homebrew formula it belongs to, if any: a formula with no graded project is listed once, under Homebrew.
    public var formula: String?

    public init(kind: SourceKind, bucket: String, item: String, formula: String? = nil) {
        self.kind = kind; self.bucket = bucket; self.item = item; self.formula = formula
    }
}

/// A Nix profile's place, which decides the upgrade command.
public struct NixProfile: Hashable, Codable, Sendable {
    /// `nix profile` (manifest.json) or `nix-env` (manifest.nix).
    public enum Style: String, Codable, Sendable { case profile, env }

    /// The profile ("~/.nix-profile", "/nix/var/nix/profiles/default").
    public var path: String
    public var style: Style
    /// The machine-wide default profile, which only root changes.
    public var shared: Bool

    public init(path: String, style: Style, shared: Bool) { self.path = path; self.style = style; self.shared = shared }
}

extension BuiltProgram {
    /// Where it is, for the line under a finding: "Homebrew gh · Go program", "~/go/bin · go install".
    var originLabel: String {
        let kind = language == .go ? "Go program" : "Rust program"
        let folder = Paths.abbreviatingHome((path as NSString).deletingLastPathComponent)
        switch place {
        case .homebrew: return "Homebrew \(formula ?? name) · \(kind)"
        case .goInstall: return "\(folder) · go install"
        case .cargoInstall: return "\(folder) · cargo install"
        case .app: return "\(app ?? name).app · \(kind)" + (cask != nil ? " · Homebrew cask" : "")
        case .other: return "\(folder) · \(kind)"
        }
    }
}
