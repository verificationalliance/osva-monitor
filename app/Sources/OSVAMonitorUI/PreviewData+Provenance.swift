import Foundation
import OSVAKit

/// Fixture findings with where each copy is and why (`osva-render`'s provenance views): the owner's starlette, and one
/// of each kind of place, with the sentences `ProvenanceExplainer` writes for them.
extension PreviewData {
    public enum ProvenanceID {
        public static let starlette = "pkg|PyPI|starlette|0.48.0|py3.11.18"
        public static let urllib3 = "pkg|PyPI|urllib3|1.26.5"
        public static let openmtp = "app|/Applications/OpenMTP.app|18.3.15"
        public static let nginx = "brew|nginx|1.30.2"
        public static let setuptools = "pkg|PyPI|setuptools|58.0.4|py3.9.6"
        public static let time = "pkg|crates.io|time|0.1.43"
        public static let minimist = "pkg|npm|minimist|0.0.8"
    }

    static let homebrewPython311 = PythonEnvironment(executable: "/opt/homebrew/bin/python3.11", version: "3.11.18", kind: .homebrew,
                                                     externallyManaged: true, userSite: nil, formula: "python@3.11")

    /// The owner's finding: starlette in Homebrew's Python 3.11, there because fastapi needs it, for their project.
    public static let starletteProvenance = Provenance(
        path: "/opt/homebrew/lib/python3.11/site-packages/starlette",
        why: "Needed by fastapi → blooper-backend (your project)",
        dependents: [.init(name: "fastapi", version: "0.120.0", specifier: "<0.49.0,>=0.40.0", requested: true),
                     .init(name: "prometheus-fastapi-instrumentator", version: "7.1.0", specifier: "<1.0.0,>=0.30.0", requested: false)],
        details: ["blooper-backend is your project, from ~/code/blooper/backend", "You also installed it by name on 19 Nov 2026"])

    public static var provenanceFindings: [Finding] {
        let home = NSHomeDirectory()
        let starlette = finding(ProvenanceID.starlette, .exploited, .package(ecosystem: .pypi, name: "starlette"), "starlette", "0.48.0", "0.49.1",
                                .high, flaws: 2, exploited: true,
                                note: "Homebrew Python 3.11.18 is externally managed (PEP 668): pip will not change it. "
                                    + "Install what you need in a virtual environment (python3 -m venv), or a command-line tool with pipx.",
                                origins: [.pip(python: homebrewPython311, user: false, formula: nil)],
                                page: SiteURL.packagePage(.pypi, "starlette", version: "0.48.0"), ecosystem: .pypi, runnable: false)
        let minimist = finding(ProvenanceID.minimist, .criticalHigh, .package(ecosystem: .npm, name: "minimist"), "minimist", "0.0.8", "0.2.4",
                               .critical, flaws: 2,
                               origins: [.folder(root: home + "/code/storefront", lockfile: home + "/code/storefront/package-lock.json", direct: false),
                                         .folder(root: home + "/code/tools", lockfile: home + "/code/tools/web/yarn.lock", direct: false)],
                               page: SiteURL.packagePage(.npm, "minimist", version: "0.0.8"), ecosystem: .npm)
        let explained: [String: [Provenance]] = [
            ProvenanceID.starlette: [starletteProvenance],
            ProvenanceID.urllib3: [Provenance(path: "/opt/homebrew/lib/python3.15/site-packages/urllib3",
                                              why: "Installed on 12 Jan 2026 for another package", advice: ProvenanceText.unused)],
            ProvenanceID.openmtp: [Provenance(path: "/Applications/OpenMTP.app", why: "Inside OpenMTP, which ships its own Electron",
                                              details: ["Homebrew installed OpenMTP on 8 Apr 2026 (cask openmtp)"])],
            ProvenanceID.nginx: [Provenance(path: "/opt/homebrew/Cellar/nginx/1.30.2", why: "You installed it on 3 Mar 2026",
                                            dependents: [.init(name: "nginx-full", requested: true)])],
            ProvenanceID.setuptools: [Provenance(path: "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages/setuptools",
                                                 why: "Comes with Apple's Python, part of Xcode")],
            ProvenanceID.time: [Provenance(path: home + "/code/tools/cli", why: "Needed by chrono → notify-rust (in Cargo.toml)",
                                           details: ["Cargo.toml → notify-rust → chrono → time"])],
            ProvenanceID.minimist: [Provenance(path: home + "/code/storefront/node_modules/mkdirp/node_modules/minimist",
                                               why: "Needed by mkdirp → mocha (in package.json)",
                                               details: ["package.json → mocha → mkdirp → minimist"]),
                                    Provenance(path: home + "/code/tools/web", why: "Needed by optimist → handlebars (in package.json)",
                                               details: ["package.json → handlebars → optimist → minimist"])],
        ]
        return ([starlette, minimist] + findings).compactMap { f in
            guard let p = explained[f.id] else { return nil }
            var f = f
            f.provenance = p
            return f
        }
    }
}
