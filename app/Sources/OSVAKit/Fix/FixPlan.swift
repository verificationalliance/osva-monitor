import Foundation

/// A command the app offers to run in a Terminal window, and what the confirmation says about it.
///
/// The command is never taken from the report as text: it is made again by `UpgradeCommand` from the inputs the
/// finding recorded, and offered only if that gives exactly the command shown. So what runs is what the person read,
/// it comes from `UpgradeCommand`'s tools only, and every name, version and path in it went through its quoting and
/// through `FixSafety`.
public struct FixPlan: Hashable, Sendable {
    public enum Action: String, Hashable, Sendable { case upgrade, removal }

    /// What a Homebrew command upgrades, for the availability check (`HomebrewAvailability`).
    public struct Homebrew: Hashable, Sendable {
        public var brew: String
        /// The formula name or cask token.
        public var name: String
        public var cask: Bool
        /// True when the finding's fixed version is this formula's or cask's own version (nginx 1.30.7). False when
        /// the formula or cask only carries the vulnerable thing (the Electron inside Slack, a Python package that
        /// came with a formula): then a newer formula is all Homebrew can tell, and the check after the run says the rest.
        public var versionIsTheFix: Bool
        /// What the person knows it as ("Slack", "jupyterlab").
        public var label: String
    }

    public var findingID: String
    /// The finding's name ("nginx", "Slack").
    public var title: String
    /// Exactly the command shown in the row.
    public var command: String
    public var action: Action
    /// The tool the command starts, as found on this Mac ("/opt/homebrew/bin/brew", "/usr/bin/python3").
    public var toolPath: String
    /// The tool's short name ("brew", "pip", "npm").
    public var toolName: String
    /// Where it runs and what it changes: "Homebrew in /opt/homebrew", "Apple's Python 3.9.6 (part of Xcode), your
    /// user site", "~/code/storefront".
    public var place: String
    /// True for a project folder: the command runs with the tool the person's shell finds there, as when pasted.
    public var inProjectFolder: Bool
    /// The installed version as the row shows it ("1.30.2", "Electron 18.3.15").
    public var installed: String
    public var target: String?
    public var homebrew: Homebrew?
    /// Put first on PATH in the script, so a bare `brew` or `npm` runs the copy the app found.
    public var pathFirst: String?
    /// A Python package, for pip's dry run: the interpreter, the requirement and whether it goes to the user site.
    public var pip: Pip?
    /// "A major version, 1 to 2: …", when the upgrade crosses one.
    public var majorUpgrade: String?
    /// For a project folder: its lockfile changes, and its tests should run.
    public var lockfileNote: String?

    public struct Pip: Hashable, Sendable {
        public var python: String
        public var requirement: String
        public var user: Bool
    }

    /// Why a finding gets no Fix button.
    public enum Refusal: Error, Equatable, Sendable {
        case noCommand
        /// The inputs do not give exactly the command shown (an old report, or one changed on disk).
        case notReproducible
        case unsafeVersion
        case unsafeName
        case unsafePath
        /// `brew upgrade` with no name upgrades everything Homebrew installed.
        case tooBroad
        /// requirements.txt: pip must run in the project's own environment, which a new Terminal window does not have.
        case needsProjectEnvironment
        case toolNotFound(String)
        /// Upgrading one package where others depend on it (a Python's site-packages, a Ruby's gems, a project's
        /// lockfile) can break them: pip only warns, after installing. Not run until the app checks those dependents.
        case sharedEnvironment(String)

        /// What the row says, when it says anything: most refusals only mean the command is there to read and copy.
        public var explanation: String? {
            switch self {
            case let .toolNotFound(tool): return "\(tool) was not found on this Mac, so the app cannot run this for you."
            case let .sharedEnvironment(why): return why
            default: return nil
            }
        }
    }

    /// The plan for a finding, or why there is none.
    public static func make(for finding: Finding, tools: ToolEnvironment, home: String = NSHomeDirectory()) -> Result<FixPlan, Refusal> {
        guard let command = finding.upgradeCommand else { return .failure(.noCommand) }
        guard let inputs = finding.commandInputs, UpgradeCommand.advice(inputs, home: home).command == command else {
            return .failure(.notReproducible)
        }
        guard FixSafety.isPrintable(command) else { return .failure(.unsafePath) }
        if let t = inputs.target, !FixSafety.isSafeVersion(t) { return .failure(.unsafeVersion) }
        if !finding.malicious, let f = finding.fixedVersion, !FixSafety.isSafeVersion(f) { return .failure(.unsafeVersion) }
        guard FixSafety.isSafeName(inputs.name) else { return .failure(.unsafeName) }

        let action: Action = inputs.malicious ? .removal : .upgrade
        var plan = FixPlan(findingID: finding.id, title: finding.title, command: command, action: action, toolPath: "", toolName: "",
                           place: "", inProjectFolder: false, installed: finding.installedLabel, target: finding.malicious ? nil : finding.fixedVersion)
        let brew = { tools.firstExecutable(HomebrewSource.brewCandidates) }
        func homebrewPlace(_ path: String) -> String {
            "Homebrew in " + (path as NSString).deletingLastPathComponent.replacingOccurrences(of: "/bin", with: "", options: .anchored.union(.backwards))
        }

        switch inputs.origin {
        case let .homebrewFormula(name), let .homebrewCask(name):
            guard FixSafety.isSafeName(name) else { return .failure(.unsafeName) }
            guard let b = brew() else { return .failure(.toolNotFound("Homebrew")) }
            let cask: Bool
            if case .homebrewCask = inputs.origin { cask = true } else { cask = false }
            plan.use(tool: b, name: "brew", pathFirst: true)
            plan.place = homebrewPlace(b) + (cask ? ", the \(name) cask" : "")
            plan.homebrew = Homebrew(brew: b, name: name, cask: cask, versionIsTheFix: true, label: name)

        case let .electronApp(appName, bundlePath, cask):
            guard let cask else { return .failure(.noCommand) }
            guard FixSafety.isSafeName(cask), FixSafety.isSafePath(bundlePath) else { return .failure(.unsafeName) }
            guard let b = brew() else { return .failure(.toolNotFound("Homebrew")) }
            plan.use(tool: b, name: "brew", pathFirst: true)
            plan.place = homebrewPlace(b) + ", the \(cask) cask: \(appName) in " + Paths.abbreviatingHome((bundlePath as NSString).deletingLastPathComponent, home: home)
            plan.homebrew = Homebrew(brew: b, name: cask, cask: true, versionIsTheFix: false, label: appName)

        case let .npmGlobal(npm):
            guard FixSafety.isSafePath(npm), tools.isExecutable(npm) else { return .failure(.toolNotFound("npm")) }
            plan.use(tool: npm, name: "npm", pathFirst: true)
            plan.place = "Global npm packages"

        case let .pip(python, user, formula):
            guard FixSafety.isSafePath(python.executable) else { return .failure(.unsafePath) }
            if command == "brew upgrade" { return .failure(.tooBroad) }
            if command.hasPrefix("brew ") {
                // Installed by a formula (or part of Homebrew's Python): the formula is what upgrades.
                let f = formula.flatMap { $0.isEmpty ? nil : $0 } ?? python.formula ?? ""
                guard FixSafety.isSafeName(f) else { return .failure(.unsafeName) }
                guard let b = brew() else { return .failure(.toolNotFound("Homebrew")) }
                plan.use(tool: b, name: "brew", pathFirst: true)
                plan.place = homebrewPlace(b) + ", the \(f) formula, which brings \(inputs.name) into \(python.label)"
                if action == .upgrade { plan.homebrew = Homebrew(brew: b, name: f, cask: false, versionIsTheFix: false, label: f) }
            } else {
                guard tools.isExecutable(python.executable) else { return .failure(.toolNotFound(python.label)) }
                if action == .upgrade {
                    return .failure(.sharedEnvironment("Not run for you: other packages in \(python.label) may depend on this one, and pip upgrades it even when that breaks them. Update it where it is used, then check that still works."))
                }
                plan.use(tool: python.executable, name: "pip", pathFirst: false)
                let toUser = command.contains(" --user ")
                plan.place = python.label + (toUser || user ? ", your user site" : "")
                if action == .upgrade, let t = inputs.target {
                    plan.pip = Pip(python: python.executable, requirement: "\(inputs.name)>=\(t)", user: toUser)
                }
            }

        case .cargoInstall:
            guard let cargo = tools.firstExecutable(["~/.cargo/bin/cargo", "/opt/homebrew/bin/cargo", "/usr/local/bin/cargo"]) else {
                return .failure(.toolNotFound("cargo"))
            }
            plan.use(tool: cargo, name: "cargo", pathFirst: true)
            plan.place = "Programs installed with cargo install"

        case let .gem(gem):
            guard FixSafety.isSafePath(gem), tools.isExecutable(gem) else { return .failure(.toolNotFound("gem")) }
            if action == .upgrade {
                return .failure(.sharedEnvironment("Not run for you: other gems may depend on this one, and upgrading it alone can break them."))
            }
            plan.use(tool: gem, name: "gem", pathFirst: gem == "/usr/bin/gem")
            plan.place = gem == "/usr/bin/gem" ? "Your user gem directory (the system Ruby's own gems are read-only)" : "RubyGems"

        case let .folder(root, lockfile, _):
            guard FixSafety.isSafePath(root), FixSafety.isSafePath(lockfile) else { return .failure(.unsafePath) }
            let file = (lockfile as NSString).lastPathComponent
            guard let tool = projectTool[file] else { return .failure(.needsProjectEnvironment) }
            guard let path = tools.firstExecutable(projectToolLocations(tool, tools: tools)) else { return .failure(.toolNotFound(tool)) }
            if action == .upgrade {
                return .failure(.sharedEnvironment("Not run for you: it changes the project's dependencies. Run it in the project, then run its tests."))
            }
            plan.use(tool: path, name: tool, pathFirst: false)
            let folder = (lockfile as NSString).deletingLastPathComponent
            plan.place = Paths.abbreviatingHome(folder.isEmpty ? root : folder, home: home)
            plan.inProjectFolder = true
            plan.lockfileNote = "The project's \(file) changes. Run its tests before you commit it."
        }

        if action == .upgrade, let target = plan.target, plan.homebrew?.versionIsTheFix ?? true, finding.component == nil {
            plan.majorUpgrade = majorUpgrade(from: finding.installedVersion, to: target, name: finding.title)
        }
        return .success(plan)
    }

    private mutating func use(tool path: String, name: String, pathFirst first: Bool) {
        toolPath = path; toolName = name
        pathFirst = first ? (path as NSString).deletingLastPathComponent : nil
    }

    /// The tool each lockfile's command starts with. requirements*.txt is not here: its pip has to run in the project's
    /// own environment.
    static let projectTool: [String: String] = [
        "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
        "poetry.lock": "poetry", "Pipfile.lock": "pipenv", "Cargo.lock": "cargo", "go.sum": "go", "Gemfile.lock": "bundle",
        "composer.lock": "composer",
    ]

    /// Where installers put a project tool. The Terminal window uses the one the person's shell finds first, as when
    /// the command is pasted; this only checks that one exists on this Mac.
    static func projectToolLocations(_ tool: String, tools: ToolEnvironment) -> [String] {
        var dirs = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "~/.volta/bin", "~/.cargo/bin", "~/.local/bin", "~/go/bin",
                    "/usr/local/go/bin", "~/.bun/bin", "~/Library/pnpm", "~/.yarn/bin", "~/.composer/vendor/bin",
                    "~/.pyenv/shims", "~/.rbenv/shims", "~/.asdf/shims", "~/.local/share/mise/shims"]
        let nvm = tools.home.appendingPathComponent(".nvm/versions/node")
        if let versions = try? FileManager.default.contentsOfDirectory(atPath: nvm.path) {
            dirs += versions.sorted().reversed().map { nvm.appendingPathComponent($0).appendingPathComponent("bin").path }
        }
        return dirs.map { $0 + "/" + tool }
    }

    /// The first number of a version ("v2.8.0" is 2), when it starts with one.
    static func major(_ v: String) -> Int? {
        let digits = v.drop { $0 == "v" || $0 == "V" }.prefix { $0.isASCII && $0.isNumber }
        return digits.isEmpty ? nil : Int(digits)
    }

    /// Said when the first number of the version changes, which for most projects means behaviour may change.
    static func majorUpgrade(from installed: String, to target: String, name: String) -> String? {
        guard let a = major(installed), let b = major(target), a != b else { return nil }
        return "A major version, \(a) to \(b): it may change how \(name) behaves. Check what uses it afterwards."
    }
}
