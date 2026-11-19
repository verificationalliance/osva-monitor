import Foundation

/// Where and why for the program sources and Java runtimes: a Go or Rust program (its file, and the formula, app, `go install` or `cargo
/// install` it came from), a pipx or uv tool's environment, a conda environment, a MacPorts port, a Nix profile. Read
/// from what the sources already found, and Homebrew's receipts for a formula's programs.
extension ProvenanceExplainer.Context {
    func located(_ origin: Origin) -> Provenance? {
        let e = explainer
        func date(_ path: String) -> Date? { ProvenanceText.plausible(LocalFiles.modified(path)) }
        switch origin {
        case let .program(p):
            var out = Provenance(path: p.path)
            // A link onto PATH (/opt/homebrew/bin/gh -> ../Cellar/gh/2.62.0/bin/gh): the file it names.
            let link = (try? FileManager.default.destinationOfSymbolicLink(atPath: p.path)).map { dest in
                dest.hasPrefix("/") ? dest : (((p.path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(dest) as NSString).standardizingPath
            }
            let real = link ?? p.path
            switch p.place {
            case .homebrew:
                let formula = p.formula ?? p.name
                out.why = "Part of Homebrew's \(formula)"
                if let keg = homebrew(.homebrewFormula(name: formula), version: p.version ?? "") {
                    if let why = keg.why { out.details.append("\(formula): \(why)") }
                    out.details += keg.details
                    out.dependents = keg.dependents
                    out.advice = keg.advice
                }
            case .goInstall:
                out.why = ProvenanceText.installedByYou(on: date(real), with: "go install", timeZone: e.timeZone)
            case .cargoInstall:
                out.why = ProvenanceText.installedByYou(on: date(real), with: "cargo install", timeZone: e.timeZone)
            case .app:
                out.why = "Ships inside \(p.app ?? p.name)" + (p.cask.map { " (Homebrew cask \($0))" } ?? "")
            case .other:
                out.why = "On your PATH, installed by hand or by its own installer"
            }
            if let link { out.details.append("Links to \(e.short(link))") }
            if let package = p.package { out.details.append("Built from \(package)") }
            if let go = p.toolchain { out.details.append("Built with Go \(go)") }
            return out
        case let .pythonTool(t):
            return Provenance(path: t.venv,
                              why: ProvenanceText.installedByYou(on: date(t.venv), with: t.manager == .pipx ? "pipx" : "uv tool install",
                                                                 timeZone: e.timeZone),
                              details: ["Its own environment" + (t.python.map { ", Python \($0)" } ?? "")])
        case let .conda(env):
            return Provenance(path: env.prefix, why: env.named ? "In the conda environment \(env.name)" : "In a conda environment made with -p",
                              details: ["Managed with \(env.tool.rawValue)"])
        case let .macports(port):
            return Provenance(path: "/opt/local", why: "Installed with MacPorts (the port \(port))")
        case let .nix(profile, element):
            return Provenance(path: profile.path,
                              why: (profile.shared ? "In this Mac's default Nix profile" : "In your Nix profile") + " (\(element))",
                              details: [profile.style == .profile ? "Installed with nix profile install" : "Installed with nix-env"])
        case let .javaRuntime(r):
            return java(r)
        default:
            return nil
        }
    }

    /// A Java runtime: who put it there (its cask, its formula, an installer, IntelliJ IDEA, SDKMAN, asdf, mise), who
    /// built it, and where a link leads.
    func java(_ r: JavaRuntime) -> Provenance {
        let e = explainer
        let installed = ProvenanceText.plausible(LocalFiles.modified(r.path))
        var out = Provenance(path: r.path)
        if let cask = r.cask {
            let prefix = e.homebrewPrefixes.first { LocalFiles.isDirectory($0 + "/Caskroom/" + cask) }
            let date = prefix.flatMap { HomebrewReceipts.cask(cask, prefix: $0)?.installed }
            out.why = "Homebrew installed it" + (date.map { " on \(e.day($0))" } ?? "") + " (cask \(cask))"
        } else if let formula = r.formula {
            out.why = "Part of Homebrew's \(formula)"
        } else {
            switch r.place {
            case .system: out.why = "Installed for everyone on this Mac" + (installed.map { ", on \(e.day($0))" } ?? "")
            case .user: out.why = "In your own Java folder, where IntelliJ IDEA puts the JDKs it downloads"
            case .intellij: out.why = "Downloaded by IntelliJ IDEA" + (installed.map { " on \(e.day($0))" } ?? "")
            case .sdkman: out.why = ProvenanceText.installedByYou(on: installed, with: "SDKMAN", timeZone: e.timeZone)
            case .asdf: out.why = ProvenanceText.installedByYou(on: installed, with: "asdf", timeZone: e.timeZone)
            case .mise: out.why = ProvenanceText.installedByYou(on: installed, with: "mise", timeZone: e.timeZone)
            case .homebrew: out.why = "In Homebrew's folder"
            }
        }
        if let who = r.implementor { out.details.append("Built by \(who)" + (r.build.map { ", \($0)" } ?? "")) }
        if r.version != r.shownVersion { out.details.append("Its version, \(r.version), is Java \(r.shownVersion)") }
        if (try? FileManager.default.destinationOfSymbolicLink(atPath: r.path)) != nil { out.details.append("Links to \(e.short(Paths.realPath(r.path)))") }
        return out
    }
}
