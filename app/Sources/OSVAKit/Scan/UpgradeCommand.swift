import Foundation

/// What to do about one finding where the package actually lives: the command to paste into Terminal (when there is
/// one that works there), and a note when the place needs explaining. The target is the server plan's version, the
/// lowest that fixes what can be fixed with this package's Python on this Mac, not simply the newest fix.
///
/// Names, versions and paths come from this Mac's files, so every one is shell-quoted unless it is plainly safe.
public enum UpgradeCommand {
    public struct Advice: Equatable, Sendable {
        public var command: String?
        public var note: String?
        public init(command: String?, note: String? = nil) { self.command = command; self.note = note }
    }

    /// What a command is made from: where the package lives, its name as this Mac spells it, the version to go to,
    /// and whether it is to be removed. A finding keeps these, so the Fix button can make the command again from them
    /// and run only a command that is exactly the one shown.
    public struct Inputs: Hashable, Codable, Sendable {
        public var origin: Origin
        public var name: String
        public var ecosystem: Ecosystem?
        public var target: String?
        public var malicious: Bool
        public init(origin: Origin, name: String, ecosystem: Ecosystem?, target: String?, malicious: Bool) {
            self.origin = origin; self.name = name; self.ecosystem = ecosystem; self.target = target; self.malicious = malicious
        }
    }

    public static func advice(_ i: Inputs, home: String = NSHomeDirectory()) -> Advice {
        advice(for: i.origin, name: i.name, ecosystem: i.ecosystem, target: i.target, malicious: i.malicious, home: home)
    }

    public static func command(for origin: Origin, name: String, ecosystem: Ecosystem?, fixed: String?, malicious: Bool,
                               home: String = NSHomeDirectory()) -> String? {
        advice(for: origin, name: name, ecosystem: ecosystem, target: fixed, malicious: malicious, home: home).command
    }

    public static func advice(for origin: Origin, name: String, ecosystem: Ecosystem?, target: String?, malicious: Bool,
                              home: String = NSHomeDirectory()) -> Advice {
        let n = quote(name)
        switch origin {
        case let .homebrewFormula(formula):
            return Advice(command: "brew upgrade \(quote(formula))")
        case let .homebrewCask(token):
            return Advice(command: "brew upgrade --cask \(quote(token))")
        case let .electronApp(name, _, cask):
            if let cask { return Advice(command: "brew upgrade --cask \(quote(cask))") }
            return Advice(command: nil, note: "Update \(name) from its own menu or its website: it ships its own Electron.")
        case let .npmGlobal(npm):
            let tool = npm.hasPrefix("/opt/homebrew/") || npm.hasPrefix("/usr/local/") ? "npm" : quote(npm)
            if malicious { return Advice(command: "\(tool) uninstall -g \(n)") }
            return Advice(command: "\(tool) install -g \(quote(name + "@" + (target ?? "latest")))")
        case let .pip(python, user, formula):
            return pip(python: python, user: user, formula: formula, name: name, target: target, malicious: malicious)
        case .cargoInstall:
            if malicious { return Advice(command: "cargo uninstall \(n)") }
            return Advice(command: "cargo install \(target.map { quote("\(name)@\($0)") } ?? n)")
        case let .gem(gem):
            // The system Ruby's gems are read-only: upgrades go to the user's gem directory.
            let system = gem == "/usr/bin/gem"
            let tool = system ? "gem" : quote(gem)
            let into = system ? " --user-install" : ""
            if malicious { return Advice(command: "\(tool) uninstall \(n)") }
            return Advice(command: target.map { "\(tool) install\(into) \(n) -v \(quote($0))" } ?? "\(tool) update\(into) \(n)")
        case let .folder(root, lockfile, direct):
            let folder = (lockfile as NSString).deletingLastPathComponent
            var a = inFolder(lockfile: (lockfile as NSString).lastPathComponent, name: name, ecosystem: ecosystem, target: target,
                             malicious: malicious, direct: direct)
            if let c = a.command { a.command = "cd \(folderArgument(folder.isEmpty ? root : folder, home: home)) && \(c)" }
            return a
        case .application, .addOn:
            return BundleAdvice.advice(for: origin, component: name, malicious: malicious)
        }
    }

    // MARK: Python

    /// pip, where the package lives:
    ///   - installed by a Homebrew formula: upgrade the formula;
    ///   - in the user site of a Python that allows it: pip --user;
    ///   - in Apple's Python (part of Xcode, read-only): a newer copy in the user site, which Python loads first;
    ///   - in an externally managed Python (Homebrew's, PEP 668): pip will not change it; a venv or pipx instead;
    ///   - in a virtual environment or python.org's Python: pip in place.
    static func pip(python: PythonEnvironment, user: Bool, formula: String?, name: String, target: String?, malicious: Bool) -> Advice {
        let py = quote(python.executable)
        // Exactly the fixed version: ">=" let pip take the newest release, which broke a package that needed an older
        // one (starlette 1.10 under fastapi 0.120, 0.2.0).
        let requirement = quote(target.map { "\(name)==\($0)" } ?? name)
        let appleNote = "For development, a current Python (python.org or Homebrew) is better than Apple's, which is part of Xcode."
        if let formula {
            if malicious { return Advice(command: formula.isEmpty ? nil : "brew uninstall \(quote(formula))") }
            return formula.isEmpty
                ? Advice(command: "brew upgrade", note: "A Homebrew formula installed it; upgrading Homebrew's formulae updates it.")
                : Advice(command: "brew upgrade \(quote(formula))")
        }
        // pip, setuptools and wheel inside Homebrew's Python come with the formula itself.
        if python.kind == .homebrew, !user, ["pip", "setuptools", "wheel"].contains(PackageNames.indexName(name, in: .pypi)), let f = python.formula {
            return malicious ? Advice(command: nil) : Advice(command: "brew upgrade \(quote(f))")
        }
        if python.externallyManaged {
            return Advice(command: nil, note: "\(python.label) is externally managed (PEP 668): pip will not change it. "
                          + "Install what you need in a virtual environment (python3 -m venv), or a command-line tool with pipx.")
        }
        if malicious { return Advice(command: "\(py) -m pip uninstall -y \(quote(name))") }      // -y: pip asks otherwise
        guard target != nil else { return Advice(command: nil) }
        switch (python.kind, user) {
        case (.apple, false):
            return Advice(command: "\(py) -m pip install --user --upgrade \(requirement)",
                          note: "Apple's Python keeps its own packages read-only; this installs a newer copy in your user site, which Python loads first. " + appleNote)
        case (.apple, true):
            return Advice(command: "\(py) -m pip install --user --upgrade \(requirement)", note: appleNote)
        case (_, true):
            return Advice(command: "\(py) -m pip install --user --upgrade \(requirement)")
        default:
            return Advice(command: "\(py) -m pip install --upgrade \(requirement)")
        }
    }

    // MARK: Lockfiles

    /// In the project's folder: a direct dependency is asked for at the fixed version; an indirect one is updated
    /// within its parent's range, or overridden when the parent pins an older one.
    private static func inFolder(lockfile: String, name: String, ecosystem: Ecosystem?, target: String?, malicious: Bool, direct: Bool?) -> Advice {
        let n = quote(name)
        let isDirect = direct ?? true
        let caret = target.map { quote("\(name)@^\($0)") } ?? n
        switch lockfile {
        case "package-lock.json", "npm-shrinkwrap.json":
            if malicious { return isDirect ? Advice(command: "npm uninstall \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "npm install \(caret)")
                : Advice(command: "npm update \(n)", note: override(name, target, field: "\"overrides\""))
        case "yarn.lock":
            if malicious { return isDirect ? Advice(command: "yarn remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "yarn add \(caret)")
                : Advice(command: nil, note: override(name, target, field: "\"resolutions\"", alone: true))
        case "pnpm-lock.yaml":
            if malicious { return isDirect ? Advice(command: "pnpm remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "pnpm add \(caret)")
                : Advice(command: "pnpm update --recursive \(n)", note: override(name, target, field: "\"pnpm\": { \"overrides\" }"))
        case "poetry.lock":
            if malicious { return isDirect ? Advice(command: "poetry remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "poetry add \(target.map { quote("\(name)>=\($0)") } ?? n)") : Advice(command: "poetry update \(n)")
        case "Pipfile.lock":
            if malicious { return isDirect ? Advice(command: "pipenv uninstall \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "pipenv install \(target.map { quote("\(name)>=\($0)") } ?? n)") : Advice(command: "pipenv update \(n)")
        case "Cargo.lock":
            if malicious { return isDirect ? Advice(command: "cargo remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            if isDirect, let target { return Advice(command: "cargo add \(quote("\(name)@\(target)"))") }
            return Advice(command: "cargo update -p \(n)\(target.map { " --precise \(quote($0))" } ?? "")")
        case "go.sum":
            return Advice(command: "go get \(quote(name + "@" + (target.map { $0.hasPrefix("v") ? $0 : "v" + $0 } ?? "latest")))")
        case "Gemfile.lock":
            if malicious { return isDirect ? Advice(command: "bundle remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return Advice(command: isDirect ? "bundle update \(n)" : "bundle update --conservative \(n)")
        case "composer.lock":
            if malicious { return isDirect ? Advice(command: "composer remove \(n)") : Advice(command: nil, note: removeIndirect(name)) }
            return isDirect ? Advice(command: "composer require \(target.map { quote("\(name):^\($0)") } ?? n)")
                : Advice(command: "composer update \(n) --with-dependencies")
        default:
            guard ecosystem == .pypi, !malicious, let target else { return Advice(command: nil) }      // requirements*.txt
            return Advice(command: "python3 -m pip install \(quote("\(name)==\(target)"))",
                          note: "Run it in the project's environment, then pin \(name)==\(target) in \(lockfile).")
        }
    }

    private static func removeIndirect(_ name: String) -> String {
        "\(name) is not in your manifest: another dependency brings it in. Remove or replace that dependency."
    }

    private static func override(_ name: String, _ target: String?, field: String, alone: Bool = false) -> String? {
        guard let target else { return nil }
        return (alone ? "Another dependency brings \(name) in: " : "If another dependency pins an older \(name), ")
            + "set \(field) to { \"\(name)\": \"^\(target)\" } in package.json."
    }

    // MARK: Shell

    /// A folder for `cd`, written from the home directory when it is inside it ("~/code/shop", "~/'My Project'"):
    /// shorter to read, and the shell expands the unquoted "~/".
    static func folderArgument(_ folder: String, home: String) -> String {
        guard !home.isEmpty, home != "/", folder.hasPrefix(home + "/") else { return quote(folder) }
        return "~/" + quote(String(folder.dropFirst(home.count + 1)))
    }

    private static let plain = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-")

    /// POSIX shell quoting: plainly safe words stay as they are, everything else goes in single quotes. A word that
    /// starts with "-" or "=" is quoted too (zsh, the macOS default, expands a leading "=word" to a command's path).
    public static func quote(_ s: String) -> String {
        if !s.isEmpty, s.unicodeScalars.allSatisfy({ plain.contains($0) }), !s.hasPrefix("-"), !s.hasPrefix("=") { return s }
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
