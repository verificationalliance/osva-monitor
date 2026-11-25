import Foundation

/// Upgrade commands for the places the program sources find: a program is updated where it came from, a pipx or uv
/// tool with its manager, a conda package in its environment, a port with MacPorts, a Nix package in its profile.
/// Every name and path is shell-quoted unless it is plainly safe.
extension UpgradeCommand {
    static let removeNote = "Remove it, then rotate every secret it could read."

    /// A program's command, with the versions the core checked: for its own module or crate (`own`), and for Go's
    /// standard library it was built with (`toolchain`). What ProgramFindings offers, and the preview fixtures show.
    public static func rebuild(_ p: BuiltProgram, rebuildOnly: Bool, own: CheckedUpgrade?, toolchain: CheckedUpgrade?, malicious: Bool) -> Advice {
        program(p, rebuildOnly: rebuildOnly, own: own?.version, toolchain: toolchain?.displayed(.program).display, malicious: malicious)
    }

    /// A pipx or uv tool's command, with the versions the core checked for its packages.
    public static func tool(_ t: PythonTool, upgrades: [(name: String, upgrade: CheckedUpgrade?)], malicious: Bool) -> Advice {
        pythonTool(t, upgrades: upgrades.map { ($0.name, $0.upgrade?.version) }, malicious: malicious)
    }

    /// A Go or Rust program: Homebrew's formula, `go install` or `cargo install` again, or wherever it came from.
    /// `rebuildOnly` says the program's own code is fine and only what it was built with needs newer versions. A rebuild
    /// names the version it builds, never `@latest`: `own`, the version the core checked for the program's own module or
    /// crate, else the one installed (built again, with what it is built with brought up to date where the tool can:
    /// cargo's newest compatible crates; for Go only the standard library, from the Go you have). `toolchain`: the Go
    /// release the core checked as the standard library's fix. `go install` builds with the Go on this Mac, which the app
    /// does not read, so the note says which Go the fix needs; and a same-version rebuild, which changes nothing else, is
    /// offered only with one. Without a version that reads as one, no command.
    static func program(_ p: BuiltProgram, rebuildOnly: Bool, own: String? = nil, toolchain: String? = nil, malicious: Bool) -> Advice {
        switch p.place {
        case .homebrew where p.formula != nil:
            let f = p.formula!
            if malicious { return Advice(command: "brew uninstall \(quote(f))", note: removeNote) }
            return Advice(command: "brew upgrade \(quote(f))",
                          note: rebuildOnly ? "If brew says \(f) is up to date, the fix waits for Homebrew's next build of it." : nil)
        case .goInstall where p.package != nil && !malicious:
            func tag(_ v: String) -> String { quote(p.package! + "@" + (v.hasPrefix("v") ? v : "v" + v)) }
            let needs = toolchain.map { "its standard library's fix needs Go \($0) or later" }
            if let own {
                return Advice(command: "go install \(tag(own))",
                              note: "Builds \(p.name) \(FindingBuilder.Component.shown(own)) with the Go you have" + (needs.map { "; \($0)." } ?? "."))
            }
            guard let needs else {
                return Advice(command: nil, note: "The modules \(p.name) was built with change only in a newer release of it: update it where it came from.")
            }
            guard let v = p.version, FixSafety.isSafeVersion(v) else { return Advice(command: nil, note: versionUnknown(p.name)) }
            return Advice(command: "go install \(tag(v))",
                          note: "Builds \(p.name) \(FindingBuilder.Component.shown(v)) again with the Go you have; \(needs), "
                              + "and the modules it was built with change only in a newer release.")
        case .cargoInstall where p.package != nil:
            if malicious { return Advice(command: "cargo uninstall \(quote(p.package!))", note: removeNote) }
            guard let v = own ?? p.version, FixSafety.isSafeVersion(v) else { return Advice(command: nil, note: versionUnknown(p.name)) }
            return Advice(command: "cargo install --force \(quote(p.package!)) --version \(quote(v))",
                          note: "Builds \(p.name) \(v)\(own == nil ? " again" : ""), with the newest compatible crates.")
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

    /// A pipx or uv tool, its own package at the version the core checked for it (in `upgrades`), else where it is
    /// (`t.version`): never a release of it the core did not check, and never one a registry picks. uv installs the tool
    /// again at that version, with the newest versions it allows of what it uses. pipx's pip is asked for the fixed
    /// versions together with the tool's package pinned, so pip keeps within what the tool requires (and changes nothing
    /// if they conflict). Not knowing the tool's version, no command, and the note says why.
    static func pythonTool(_ t: PythonTool, upgrades: [(name: String, target: String?)], malicious: Bool) -> Advice {
        let tool = quote(t.name)
        func isMain(_ name: String) -> Bool { PackageNames.indexName(name, in: .pypi) == t.mainPackage }
        let checked = upgrades.first { isMain($0.name) }?.target
        switch t.manager {
        case .uv:
            if malicious { return Advice(command: "uv tool uninstall \(tool)", note: removeNote) }
            guard let v = checked ?? t.version, FixSafety.isSafeVersion(v) else { return Advice(command: nil, note: versionUnknown(t.mainPackage)) }
            return Advice(command: "uv tool install --force \(quote("\(t.mainPackage)==\(v)"))",
                          note: "uv installs \(t.mainPackage) \(v)\(checked == nil ? " again" : ""), with the newest versions it allows of what it uses.")
        case .pipx:
            if malicious { return Advice(command: "pipx uninstall \(tool)", note: removeNote) }
            let deps = upgrades.filter { !isMain($0.name) && $0.target != nil }
            guard checked != nil || !deps.isEmpty else { return Advice(command: nil) }          // nothing checked to move
            // exact pins (never ">=", which let pip take a newer release than the fix and break what needed an older one)
            guard let main = checked ?? t.version, FixSafety.isSafeVersion(main) else { return Advice(command: nil, note: versionUnknown(t.mainPackage)) }
            let requirements = ["\(t.mainPackage)==\(main)"] + deps.map { "\($0.name)==\($0.target!)" }
            let note: String? = deps.isEmpty ? nil : checked == nil
                ? "pip keeps \(t.mainPackage) at \(main) and upgrades them within the versions it allows; if they conflict, pip changes nothing."
                : "pip upgrades them together with \(t.mainPackage), within the versions it allows; if they conflict, pip changes nothing."
            return Advice(command: "pipx runpip \(tool) install --upgrade " + requirements.map(quote).joined(separator: " "), note: note)
        }
    }

    /// Why a program or tool whose version the app could not read gets no command: every command names the version.
    static func versionUnknown(_ name: String) -> String {
        "No command: the app could not read which version of \(name) is installed, and every command here names one."
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
