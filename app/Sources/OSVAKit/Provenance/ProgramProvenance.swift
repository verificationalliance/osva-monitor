import Foundation

/// Where and why for the program sources: a Go or Rust program (its file, and the formula, app, `go install` or `cargo
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
        default:
            return nil
        }
    }
}
