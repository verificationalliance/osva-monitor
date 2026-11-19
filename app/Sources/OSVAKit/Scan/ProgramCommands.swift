import Foundation

/// Upgrade commands for the places the program sources find: a program is updated where it came from, a pipx or uv
/// tool with its manager, a conda package in its environment, a port with MacPorts, a Nix package in its profile.
/// Every name and path is shell-quoted unless it is plainly safe.
extension UpgradeCommand {
    static let removeNote = "Remove it, then rotate every secret it could read."

    /// A Go or Rust program: Homebrew's formula, `go install` again, `cargo install` again, or wherever it came from.
    /// `rebuildOnly` says the program's own code is fine and only what it was built with needs newer versions.
    static func program(_ p: BuiltProgram, rebuildOnly: Bool, malicious: Bool) -> Advice {
        switch p.place {
        case .homebrew where p.formula != nil:
            let f = p.formula!
            if malicious { return Advice(command: "brew uninstall \(quote(f))", note: removeNote) }
            return Advice(command: "brew upgrade \(quote(f))",
                          note: rebuildOnly ? "If brew says \(f) is up to date, the fix waits for Homebrew's next build of it." : nil)
        case .goInstall where p.package != nil && !malicious:
            return Advice(command: "go install \(quote(p.package! + "@latest"))",
                          note: "Builds \(p.name) again from its newest release, with the Go you have.")
        case .cargoInstall where p.package != nil:
            if malicious { return Advice(command: "cargo uninstall \(quote(p.package!))", note: removeNote) }
            return Advice(command: "cargo install --force \(quote(p.package!))",
                          note: "Builds \(p.name) again from its newest release, with the newest compatible crates.")
        case .app:
            let app = p.app ?? p.name
            if let cask = p.cask {
                if malicious { return Advice(command: "brew uninstall --cask \(quote(cask))", note: removeNote) }
                return Advice(command: "brew upgrade --cask \(quote(cask))", note: "\(app) ships \(p.name).")
            }
            if malicious { return Advice(command: nil, note: "\(app) ships \(p.name), built with a malicious package. " + removeNote) }
            return Advice(command: nil, note: "Update \(app) from its own menu or its website: it ships \(p.name).")
        default:
            if malicious { return Advice(command: nil, note: "\(p.name) was built with a malicious package. " + removeNote) }
            return Advice(command: nil, note: "Update \(p.name) where it came from: it carries its own copy of what it was built with.")
        }
    }

    /// A pipx or uv tool. uv upgrades everything in the tool's environment within the versions the tool allows. pipx
    /// upgrades the tool itself; for its dependencies, pip is asked for the fixed versions together with the tool, so
    /// pip keeps within what the tool requires (and changes nothing if they conflict).
    static func pythonTool(_ t: PythonTool, upgrades: [(name: String, target: String?)], malicious: Bool) -> Advice {
        let tool = quote(t.name)
        switch t.manager {
        case .uv:
            if malicious { return Advice(command: "uv tool uninstall \(tool)", note: removeNote) }
            return Advice(command: "uv tool upgrade \(tool)")
        case .pipx:
            if malicious { return Advice(command: "pipx uninstall \(tool)", note: removeNote) }
            func isMain(_ name: String) -> Bool { PackageNames.indexName(name, in: .pypi) == t.mainPackage }
            let deps = upgrades.filter { !isMain($0.name) && $0.target != nil }
            guard !deps.isEmpty else { return Advice(command: "pipx upgrade \(tool)") }
            // exact pins (never ">=", which let pip take a newer release than the fix and break what needed an older one)
            let main = upgrades.first { isMain($0.name) }?.target.map { "\(t.mainPackage)==\($0)" } ?? t.mainPackage
            let requirements = [main] + deps.map { "\($0.name)==\($0.target!)" }
            return Advice(command: "pipx runpip \(tool) install --upgrade " + requirements.map(quote).joined(separator: " "),
                          note: "pip upgrades them together with \(t.mainPackage), within the versions it allows; if they conflict, pip changes nothing.")
        }
    }

    /// A package in a conda environment, named or by its folder.
    static func conda(_ env: CondaEnvironment, name: String, target: String?, malicious: Bool) -> Advice {
        let place = env.named ? "-n \(quote(env.name))" : "-p \(quote(env.prefix))"
        let tool = env.tool.rawValue
        if malicious { return Advice(command: "\(tool) remove \(place) \(quote(name))", note: removeNote) }
        return Advice(command: "\(tool) update \(place) \(quote(name))",
                      note: target.map { "Needs \(name) \($0) or later in the environment's channels." })
    }

    /// A MacPorts port: the person runs it, with their password.
    static func macports(_ port: String) -> Advice {
        Advice(command: "sudo port upgrade \(quote(port))", note: "Run sudo port selfupdate first, so MacPorts knows the newest version.")
    }

    /// A package in a Nix profile: `nix profile` for a new-style profile, `nix-env` for an old one; root changes the
    /// machine's default profile.
    static func nix(_ profile: NixProfile, element: String) -> Advice {
        let e = quote(element)
        switch (profile.style, profile.shared) {
        case (.profile, false): return Advice(command: "nix profile upgrade \(e)")
        case (.profile, true): return Advice(command: "sudo nix profile upgrade --profile \(quote(profile.path)) \(e)")
        case (.env, false): return Advice(command: "nix-env -u \(e)", note: "Run nix-channel --update first, so nix-env sees the newest version.")
        case (.env, true):
            return Advice(command: "sudo nix-env --profile \(quote(profile.path)) -u \(e)",
                          note: "Run sudo nix-channel --update first, so nix-env sees the newest version.")
        }
    }
}
