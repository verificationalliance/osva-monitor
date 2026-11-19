import Foundation
import OSVAKit

/// Fixture data for the program sources (Go and Rust programs, pipx and uv tools, conda, MacPorts, Nix), for
/// `osva-render`: a Mac with each of them, the findings worded as FindingBuilder words them.
extension PreviewData {
    public static let programReports: [SourceReport] = [
        SourceReport(kind: .homebrew, available: true, count: 407, detail: "338 formulae, 69 casks", seconds: 17.2),
        SourceReport(kind: .macports, available: true, count: 41, detail: "41 ports", seconds: 0.01),
        SourceReport(kind: .nix, available: true, count: 23, detail: "23 packages in 1 profile", seconds: 0.01),
        SourceReport(kind: .electron, available: true, count: 15, detail: "15 apps", seconds: 0.03),
        SourceReport(kind: .go, available: true, count: 669, detail: "16 programs, 529 module versions", seconds: 0.21),
        SourceReport(kind: .rust, available: true, count: 212, detail: "3 programs, 212 crates, 21 without a crate list", seconds: 0.21),
        SourceReport(kind: .npm, available: true, count: 1, detail: "1 global package", seconds: 0.6),
        SourceReport(kind: .pip, available: true, count: 495, detail: "495 packages in 8 Pythons", seconds: 3.9),
        SourceReport(kind: .pipx, available: true, count: 64, detail: "4 tools, 64 packages", seconds: 0.02),
        SourceReport(kind: .uv, available: true, count: 12, detail: "2 tools, 12 packages", seconds: 0.01),
        SourceReport(kind: .conda, available: true, count: 312, detail: "2 environments, 312 packages (118 on PyPI)", seconds: 0.4),
        SourceReport(kind: .gem, available: true, count: 48, detail: "48 gems", seconds: 0.2),
        SourceReport(kind: .folders, available: true, count: 212, detail: "2 folders, 5 lockfiles", seconds: 0.01),
    ]

    public static let programCoverage = Coverage(
        notInIndex: [.init(source: "Go programs", items: ["github.com/charlievieth/fastwalk v1.0.14", "github.com/mattn/go-isatty v0.0.24",
                                                          "github.com/rivo/uniseg v0.4.7"]),
                     .init(source: "pipx", items: ["mypy-extensions 1.0.0", "pathspec 0.12.1"])],
        notChecked: [.init(source: "Homebrew packages with no graded project", items: ["abseil 20260817.0", "ack 3.10.0", "aom 3.15.3"]),
                     .init(source: "MacPorts ports with no graded project", items: ["gettext 0.22.5", "libiconv 1.17", "ncurses 6.5"]),
                     .init(source: "conda packages with no graded project", items: ["libffi 3.4.4", "tk 8.6.13", "xz 5.4.6"]),
                     .init(source: "Rust programs without a crate list", items: ["biome 2.6.8", "fd 10.5.2", "rav1e 0.8.1", "xplr 1.1.0"])])

    public static let programFindings: [Finding] = {
        let home = NSHomeDirectory()
        let gh = BuiltProgram(language: .go, path: "/opt/homebrew/bin/gh", name: "gh", version: "2.62.0", place: .homebrew, formula: "gh",
                              package: "github.com/cli/cli/v2/cmd/gh", module: "github.com/cli/cli/v2", toolchain: "1.22.3")
        let gopls = BuiltProgram(language: .go, path: home + "/go/bin/gopls", name: "gopls", version: "0.16.1", place: .goInstall, formula: nil,
                                 package: "golang.org/x/tools/gopls", module: "golang.org/x/tools/gopls", toolchain: "1.23.0")
        let docker = BuiltProgram(language: .go, path: "/usr/local/bin/docker", name: "docker", version: nil, place: .app, formula: nil,
                                  package: nil, toolchain: "1.23.8", app: "Docker", cask: "docker-desktop")
        let rg = BuiltProgram(language: .rust, path: home + "/.cargo/bin/rg", name: "rg", version: "13.0.0", place: .cargoInstall, formula: nil,
                              package: "ripgrep", module: "ripgrep", toolchain: nil)
        let black = PythonTool(manager: .pipx, name: "black", mainPackage: "black", version: "24.1.0", venv: home + "/.local/pipx/venvs/black",
                               python: "3.12.4")
        let base = CondaEnvironment(prefix: home + "/miniforge3", name: "base", named: true, tool: .conda, python: "3.11.5")
        let profile = NixProfile(path: home + "/.nix-profile", style: .profile, shared: false)
        let brewNote = "If brew says gh is up to date, the fix waits for Homebrew's next build of it."
        return [
            programFinding("prog|brew|gh|2.62.0", .criticalHigh, .package(ecosystem: .go, name: "golang.org/x/net"), "gh", component: "golang.org/x/net",
                    "0.23.0", "0.33.0", .critical, flaws: 24,
                    note: "gh 2.62.0 was built with golang.org/x/net 0.23.0 — fixed in 0.33.0 · built with Go 1.22.3, whose stdlib has 4 known flaws. "
                        + brewNote,
                    origins: [.program(gh)], page: SiteURL.packagePage(.go, "golang.org/x/net", version: "v0.23.0"),
                    inputs: UpgradeCommand.Inputs(origin: .program(gh), name: "gh", ecosystem: nil, target: nil, malicious: false)),
            programFinding("prog|app|Docker", .criticalHigh, .package(ecosystem: .go, name: "stdlib"), "Docker", component: "Go", "1.21.9", "1.26.11",
                    .critical, flaws: 81,
                    note: "Docker’s 6 programs were built with golang.org/x/crypto 0.14.0 to 0.37.0 — fixed in 0.56.0 · built with Go 1.21.9 to 1.23.8, "
                        + "whose stdlib has up to 74 known flaws. Docker ships them.",
                    origins: [.program(docker)], page: SiteURL.packagePage(.go, "stdlib", version: "1.21.9"),
                    command: "brew upgrade --cask docker-desktop"),
            programFinding("brew|nginx|1.30.2", .criticalHigh, .project(slug: "nginx", name: "nginx", installedAs: "nginx"), "nginx", "1.30.2", "1.30.7",
                    .critical, flaws: 6, note: "Likely affected: the issuer names 1.30.7 as fixed. Run sudo port selfupdate first, so MacPorts knows the newest version.",
                    bigIssue: "On the site's “patch these first” list", origins: [.macports(port: "nginx")],
                    page: SiteURL.projectPage(slug: "nginx"), command: "sudo port upgrade nginx", grade: "C"),
            programFinding("tool|pipx|black", .criticalHigh, .package(ecosystem: .pypi, name: "black"), "black", "24.1.0", "26.10.1", .critical, flaws: 8,
                    note: "black 24.1.0 has 4 known flaws — fixed in 26.10.1 · uses requests 2.25.0 — fixed in 2.33.0. "
                        + "pip upgrades them together with black, within the versions it allows; if they conflict, pip changes nothing.",
                    origins: [.pythonTool(black)], page: SiteURL.packagePage(.pypi, "black", version: "24.1.0"),
                    command: "pipx runpip black install --upgrade 'black>=26.10.1' 'requests>=2.33.0'"),
            programFinding("pkg|PyPI|pyyaml|5.3|py3.11.5", .criticalHigh, .package(ecosystem: .pypi, name: "pyyaml"), "pyyaml", "5.3", "5.4", .critical,
                    flaws: 2, note: "Needs pyyaml 5.4 or later in the environment's channels.", origins: [.conda(env: base)],
                    page: SiteURL.packagePage(.pypi, "pyyaml", version: "5.3"),
                    inputs: UpgradeCommand.Inputs(origin: .conda(env: base), name: "pyyaml", ecosystem: .pypi, target: "5.4", malicious: false)),
            programFinding("prog|" + gopls.path, .other, .package(ecosystem: .go, name: "stdlib"), "gopls", component: "Go", "1.23.0", "1.23.11", .moderate,
                    flaws: 3, note: "gopls 0.16.1 was built with Go 1.23.0, whose stdlib has 3 known flaws. "
                        + "Builds gopls again from its newest release, with the Go you have.",
                    origins: [.program(gopls)], page: SiteURL.packagePage(.go, "stdlib", version: "1.23.0"),
                    command: "go install golang.org/x/tools/gopls@latest"),
            programFinding("prog|" + rg.path, .other, .package(ecosystem: .crates, name: "regex"), "rg", component: "regex", "1.5.4", "1.5.5", .moderate,
                    flaws: 1, note: "rg 13.0.0 was built with regex 1.5.4 — fixed in 1.5.5. Builds rg again from its newest release, with the newest compatible crates.",
                    origins: [.program(rg)], page: SiteURL.packagePage(.crates, "regex", version: "1.5.4"), command: "cargo install --force ripgrep"),
            programFinding("nix|openssl|3.0.12|" + profile.path, .other, .project(slug: "openssl", name: "OpenSSL", installedAs: "openssl"), "OpenSSL",
                    "3.0.12", "3.0.15", .moderate, flaws: 1, note: "Likely affected: the issuer names 3.0.15 as fixed.",
                    origins: [.nix(profile: profile, element: "openssl")], page: SiteURL.projectPage(slug: "openssl"),
                    command: "nix profile upgrade openssl", grade: "B"),
        ]
    }()

    public enum ProgramID {
        public static let gh = "prog|brew|gh|2.62.0", docker = "prog|app|Docker", black = "tool|pipx|black"
        public static let pyyaml = "pkg|PyPI|pyyaml|5.3|py3.11.5", nginx = "brew|nginx|1.30.2"
    }

    /// A finding as ProgramFindings words it: the command shown, and the inputs it is made from where a scan records
    /// them (a Homebrew formula's program, a conda package), so the Fix button is decided as the app decides it.
    static func programFinding(_ id: String, _ group: Finding.Group, _ subject: Finding.Subject, _ title: String, component: String? = nil,
                               _ installed: String, _ fixed: String?, _ severity: Severity?, flaws: Int, note: String? = nil,
                               bigIssue: String? = nil, origins: [Origin], page: URL, command: String? = nil,
                               inputs: UpgradeCommand.Inputs? = nil, grade: String? = nil) -> Finding {
        Finding(id: id, group: group, subject: subject, title: title, component: component, installedVersion: installed, fixedVersion: fixed,
                severity: severity, advisoryIDs: [], flawCount: flaws, exploited: false, malicious: false, note: note, bigIssue: bigIssue,
                origins: origins, pageURL: page, upgradeCommand: inputs.flatMap { UpgradeCommand.advice($0).command } ?? command,
                verification: .none, grade: grade, commandInputs: inputs)
    }

    /// The rows opened: gh's Fix button (a Homebrew formula's program: brew upgrade, checked against Homebrew's
    /// data), and why conda's upgrade is not run for you. The others are commands to read and copy.
    public static var programFixes: [String: FixRowState] {
        var out: [String: FixRowState] = [:]
        for f in programFindings {
            switch FixPlan.make(for: f, tools: fixtureTools) {
            case let .success(plan):
                let line = plan.homebrew.map { h -> String in
                    switch HomebrewAvailability.decide(HomebrewInfo(name: h.name, stable: "2.63.0", installed: "2.62.0"), for: h, fixedVersion: f.fixedVersion) {
                    case let .available(line), let .unavailable(line), let .unknown(line), let .needsPassword(line): return line
                    }
                }
                out[f.id] = FixRowState(availability: .offered(FixOffer(plan: plan, homebrew: line)))
            case let .failure(refusal):
                if let why = refusal.explanation { out[f.id] = FixRowState(availability: .withheld(why)) }
            }
        }
        return out
    }

    public static func programReport(findings: [Finding] = programFindings) -> ScanReport {
        ScanReport(startedAt: now.addingTimeInterval(-300), finishedAt: now.addingTimeInterval(-240),
                   inventory: Inventory(reports: programReports), findings: findings, sent: sent,
                   indexGeneratedAt: "2026-11-19T01:32:46Z", problems: [], coverage: programCoverage)
    }
}
