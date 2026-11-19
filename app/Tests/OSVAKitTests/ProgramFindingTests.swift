import Foundation
import Testing
@testable import OSVAKit

/// Findings for programs, tools and managed packages, from a live answer recorded on 2026-11-19 (Go stdlib 1.22.3,
/// golang.org/x/net v0.23.0, golang.org/x/text v0.3.7, time 0.1.43, black, requests and pyyaml).
@Suite struct ProgramFindingTests {
    static let index = PublicIndex(generatedAt: "T", packages: [
        (.go, "golang.org/x/net"), (.go, "golang.org/x/text"), (.go, "stdlib"), (.crates, "time"),
        (.pypi, "black"), (.pypi, "requests"), (.pypi, "pyyaml"), (.pypi, "click"),
    ], projects: Fixture.index.projects, managed: [("macports", "nginx", "nginx"), ("nix", "nginx", "nginx"), ("conda", "openssl", "openssl")])
    static let batch = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-programs-live-2026-11-19.json"))
    static let nginx = try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-nginx.json"))

    static let gh = BuiltProgram(language: .go, path: "/opt/homebrew/bin/gh", name: "gh", version: "2.62.0", place: .homebrew, formula: "gh",
                                 package: "github.com/cli/cli/v2/cmd/gh", module: "github.com/cli/cli/v2", toolchain: "1.22.3")
    static let black = PythonTool(manager: .pipx, name: "black", mainPackage: "black", version: "24.1.0",
                                  venv: "/Users/ana/.local/pipx/venvs/black", python: "3.12.4")

    /// Approves through the real privacy filter and answers from the recorded batch.
    func findings(_ installed: [InstalledPackage], brew: [FindingBuilder.BrewMatch] = [], projects: [String: ProjectResponse] = [:],
                  managed: [FindingBuilder.ManagedMatch] = [], bigIssues: [StateResponse.BigIssue] = []) -> [Finding] {
        let selection = PrivacyFilter(index: Self.index).approve(installed)
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in
            Self.batch.packages.first { $0.ecosystem == a.ecosystem.rawValue && $0.name == a.name && $0.version == a.version }.map { (a, $0) }
        })
        return FindingBuilder(index: Self.index).findings(approved: selection.approved, verdicts: verdicts, brew: brew, projects: projects,
                                                          bigIssues: bigIssues, managed: managed)
    }

    func program(_ p: BuiltProgram, _ modules: [(String, String)]) -> [InstalledPackage] {
        modules.map { InstalledPackage(ecosystem: p.language == .go ? .go : .crates, name: $0.0, version: $0.1, origin: .program(p)) }
    }

    @Test func aProgramIsOneFinding() throws {
        let f = findings(program(Self.gh, [("golang.org/x/net", "v0.23.0"), ("golang.org/x/text", "v0.3.7"), ("stdlib", "1.22.3"),
                                           ("golang.org/x/sys", "v0.35.0")]))
        #expect(f.count == 1)
        let gh = try #require(f.first)
        #expect(gh.title == "gh" && gh.group == .criticalHigh && gh.severity == .critical)
        #expect(gh.shownVersions == "golang.org/x/net 0.23.0 → 0.62.0")             // the worst part, versions as people write them
        #expect(gh.note == "gh 2.62.0 was built with golang.org/x/net 0.23.0 — fixed in 0.62.0 · built with golang.org/x/text 0.3.7 — fixed in 0.41.0"
                + " · built with Go 1.22.3, whose stdlib has 74 known flaws. If brew says gh is up to date, the fix waits for Homebrew's next build of it.")
        #expect(gh.flawCount == 20 + 3 + 74)                                       // 40 listed stdlib flaws, 2 Windows-only, 36 unlisted
        #expect(gh.upgradeCommand == "brew upgrade gh")
        #expect(gh.originSummary == "Homebrew gh · Go program")
        #expect(gh.unresolved.isEmpty)                                             // its Windows-only flaws do not affect this Mac
        #expect(gh.pageURL.absoluteString == "https://verificationalliance.org/#/check/pkg/Go/golang.org%2Fx%2Fnet@v0.23.0")
    }

    @Test func aFormulaThatIsAProjectFindingTakesItsProgramsIn() throws {
        let item = HomebrewItem(kind: .formula, name: "nginx", version: "1.30.2", urls: [])
        let prog = BuiltProgram(language: .go, path: "/opt/homebrew/bin/nginx-exporter", name: "nginx-exporter", version: "1.30.2", place: .homebrew,
                                formula: "nginx", package: nil, toolchain: "1.22.3")
        let f = findings(program(prog, [("stdlib", "1.22.3")]), brew: [.init(item: item, project: Self.index.project(slug: "nginx")!)],
                         projects: ["nginx": Self.nginx])
        #expect(f.map(\.id) == ["brew|nginx|1.30.2"])                             // one finding for the formula
        let n = try #require(f.first)
        #expect(n.note == "Likely affected: the issuer names 1.30.7 as fixed. nginx-exporter 1.30.2 was built with Go 1.22.3, whose stdlib has 74 known flaws.")
        #expect(n.flawCount == 10 + 74 && n.upgradeCommand == "brew upgrade nginx")
    }

    @Test func severalProgramsOfOneAppAreOneFinding() throws {
        func docker(_ name: String) -> BuiltProgram {
            BuiltProgram(language: .go, path: "/usr/local/bin/\(name)", name: name, version: nil, place: .app, formula: nil, package: nil,
                         toolchain: nil, app: "Docker", cask: nil)
        }
        let f = findings(program(docker("docker"), [("stdlib", "1.22.3"), ("golang.org/x/net", "v0.23.0")])
                         + program(docker("kubectl"), [("golang.org/x/net", "v0.23.0"), ("golang.org/x/text", "v0.3.7")]))
        let d = try #require(f.first)
        #expect(f.count == 1 && d.title == "Docker" && d.upgradeCommand == nil)
        #expect(d.note == "docker and kubectl were built with golang.org/x/net 0.23.0 — fixed in 0.62.0 · built with golang.org/x/text 0.3.7 — fixed in 0.41.0"
                + " · built with Go 1.22.3, whose stdlib has 74 known flaws. Update Docker from its own menu or its website: it ships them.")
        #expect(d.originSummary == "Docker.app · Go program")
    }

    @Test func aRustProgram() throws {
        let fd = BuiltProgram(language: .rust, path: "/Users/ana/.cargo/bin/fd", name: "fd", version: "10.5.2", place: .cargoInstall, formula: nil,
                              package: "fd-find", module: "fd-find", toolchain: nil)
        let f = try #require(findings(program(fd, [("time", "0.1.43"), ("libc", "0.2.191")])).first)
        #expect(f.title == "fd" && f.shownVersions == "time 0.1.43 → 0.2.0" && f.group == .other)
        #expect(f.note == "fd 10.5.2 was built with time 0.1.43 — fixed in 0.2.0. Builds fd again from its newest release, with the newest compatible crates.")
        #expect(f.upgradeCommand == "cargo install --force fd-find" && f.fixesCount == 1)
    }

    @Test func aPipxToolAndItsDependencies() throws {
        let installed = [("black", "24.1.0"), ("requests", "2.25.0"), ("click", "8.1.3"), ("my-private-lib", "1.0")].map {
            InstalledPackage(ecosystem: .pypi, name: $0.0, version: $0.1, origin: .pythonTool(Self.black))
        }
        let f = try #require(findings(installed).first)
        #expect(f.title == "black" && f.component == nil && f.shownVersions == "24.1.0 → 26.10.1" && f.severity == .critical)
        #expect(f.note == "black 24.1.0 has 4 known flaws — fixed in 26.10.1 · uses requests 2.25.0 — fixed in 2.33.0."
                + " pip upgrades them together with black, within the versions it allows; if they conflict, pip changes nothing.")
        #expect(f.upgradeCommand == "pipx runpip black install --upgrade black==26.10.1 requests==2.33.0")
        #expect(f.originSummary == "pipx · Python 3.12.4")
        var uv = Self.black; uv.manager = .uv; uv.venv = "/Users/ana/.local/share/uv/tools/black"
        let u = try #require(findings(installed.map { InstalledPackage(ecosystem: $0.ecosystem, name: $0.name, version: $0.version, origin: .pythonTool(uv)) }).first)
        #expect(u.upgradeCommand == "uv tool upgrade black" && u.originSummary == "uv tool · Python 3.12.4")
    }

    @Test func aToolsOwnPackageOnlyIsUpgradedWithPipx() {
        let a = UpgradeCommand.pythonTool(Self.black, upgrades: [("black", "26.10.1")], malicious: false)
        #expect(a.command == "pipx upgrade black" && a.note == nil)
        #expect(UpgradeCommand.pythonTool(Self.black, upgrades: [("requests", nil)], malicious: false).command == "pipx upgrade black")
        #expect(UpgradeCommand.pythonTool(Self.black, upgrades: [("evil", nil)], malicious: true).command == "pipx uninstall black")
    }

    @Test func condaPackagesAreCheckedWhereTheyLive() throws {
        let env = CondaEnvironment(prefix: "/Users/ana/miniforge3", name: "base", named: true, tool: .conda, python: "3.11.5")
        let f = try #require(findings([InstalledPackage(ecosystem: .pypi, name: "pyyaml", version: "5.3", origin: .conda(env: env))]).first)
        #expect(f.title == "pyyaml" && f.fixedVersion == "5.4" && f.upgradeCommand == "conda update -n base pyyaml")
        #expect(f.originSummary == "conda env base · Python 3.11.5")
        #expect(f.note == "Needs pyyaml 5.4 or later in the environment's channels.")
    }

    @Test func managedPackagesFollowTheProjectPath() throws {
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.30.2", origin: .macports(port: "nginx"))
        let profile = NixProfile(path: "/Users/ana/.nix-profile", style: .profile, shared: false)
        let nix = ManagedPackage(manager: .nix, name: "nginx", version: "1.31.8", origin: .nix(profile: profile, element: "nginx"))
        let patched = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.9", origin: .macports(port: "nginx"))
        let project = Self.index.project(manager: "macports", package: "nginx")!
        let state = try JSONDecoder().decode(StateResponse.self, from: Fixture.data("api/state.json"))
        let f = findings([], projects: ["nginx": Self.nginx], managed: [port, nix, patched].map { .init(package: $0, project: project) },
                         bigIssues: state.bigIssues)
        #expect(f.count == 2)                                                          // 1.31.9 is at its branch's fix
        let mp = try #require(f.first { $0.origins == [.macports(port: "nginx")] })
        #expect(mp.title == "nginx" && mp.fixedVersion == "1.30.7" && mp.upgradeCommand == "sudo port upgrade nginx")
        #expect(mp.note == "Likely affected: the issuer names 1.30.7 as fixed. Run sudo port selfupdate first, so MacPorts knows the newest version.")
        #expect(mp.bigIssue != nil && mp.originSummary == "MacPorts nginx")
        let n = try #require(f.first { $0.origins.first?.kind == .nix })
        #expect(n.fixedVersion == "1.31.9" && n.upgradeCommand == "nix profile upgrade nginx")
    }
}

@Suite struct ProgramCommandTests {
    func program(_ place: BuiltProgram.Place, package: String? = nil, formula: String? = nil, app: String? = nil, cask: String? = nil) -> BuiltProgram {
        BuiltProgram(language: .go, path: "/x/tool", name: "tool", version: nil, place: place, formula: formula, package: package, toolchain: nil,
                     app: app, cask: cask)
    }

    @Test func programs() {
        #expect(UpgradeCommand.program(program(.homebrew, formula: "gh"), rebuildOnly: false, malicious: false).command == "brew upgrade gh")
        #expect(UpgradeCommand.program(program(.homebrew, formula: "gh"), rebuildOnly: false, malicious: true).command == "brew uninstall gh")
        #expect(UpgradeCommand.program(program(.goInstall, package: "golang.org/x/tools/gopls"), rebuildOnly: true, malicious: false).command
                == "go install golang.org/x/tools/gopls@latest")
        #expect(UpgradeCommand.program(program(.goInstall, package: nil), rebuildOnly: true, malicious: false).command == nil)
        #expect(UpgradeCommand.program(program(.cargoInstall, package: "ripgrep"), rebuildOnly: true, malicious: false).command == "cargo install --force ripgrep")
        #expect(UpgradeCommand.program(program(.app, app: "Docker", cask: "docker-desktop"), rebuildOnly: true, malicious: false).command
                == "brew upgrade --cask docker-desktop")
        let other = UpgradeCommand.program(program(.other), rebuildOnly: true, malicious: false)
        #expect(other.command == nil && other.note == "Update tool where it came from: it carries its own copy of what it was built with.")
    }

    @Test func hostileNamesStayOneWord() {
        #expect(UpgradeCommand.program(program(.goInstall, package: "example.com/x;rm -rf ~/cmd"), rebuildOnly: true, malicious: false).command
                == "go install 'example.com/x;rm -rf ~/cmd@latest'")
        #expect(UpgradeCommand.program(program(.cargoInstall, package: "evil$(curl x)"), rebuildOnly: true, malicious: false).command
                == "cargo install --force 'evil$(curl x)'")
        #expect(UpgradeCommand.program(program(.homebrew, formula: "-rf"), rebuildOnly: true, malicious: false).command == "brew upgrade '-rf'")
        let tool = PythonTool(manager: .pipx, name: "my tool", mainPackage: "my-tool", version: nil, venv: "/v", python: nil)
        #expect(UpgradeCommand.pythonTool(tool, upgrades: [("it's", "2.0")], malicious: false).command
                == "pipx runpip 'my tool' install --upgrade my-tool 'it'\\''s==2.0'")
        #expect(UpgradeCommand.macports("a;b").command == "sudo port upgrade 'a;b'")
    }

    @Test func condaEnvironments() {
        func c(_ named: Bool, _ name: String, _ prefix: String, _ tool: CondaEnvironment.Tool, malicious: Bool = false) -> String? {
            UpgradeCommand.advice(for: .conda(env: CondaEnvironment(prefix: prefix, name: name, named: named, tool: tool, python: nil)), name: "requests",
                                  ecosystem: .pypi, target: "2.33.0", malicious: malicious).command
        }
        #expect(c(true, "base", "/m", .conda) == "conda update -n base requests")
        #expect(c(true, "my env", "/m/envs/my env", .mamba) == "mamba update -n 'my env' requests")
        #expect(c(false, ".env", "/Users/ana/x y/.env", .micromamba) == "micromamba update -p '/Users/ana/x y/.env' requests")
        #expect(c(true, "base", "/m", .conda, malicious: true) == "conda remove -n base requests")
    }

    @Test func nixProfiles() {
        func c(_ style: NixProfile.Style, _ shared: Bool) -> String? {
            UpgradeCommand.nix(NixProfile(path: shared ? "/nix/var/nix/profiles/default" : "/Users/ana/.nix-profile", style: style, shared: shared),
                               element: "openssl").command
        }
        #expect(c(.profile, false) == "nix profile upgrade openssl")
        #expect(c(.profile, true) == "sudo nix profile upgrade --profile /nix/var/nix/profiles/default openssl")
        #expect(c(.env, false) == "nix-env -u openssl")
        #expect(c(.env, true) == "sudo nix-env --profile /nix/var/nix/profiles/default -u openssl")
    }
}

@Suite struct ProgramScanTests {
    /// A whole scan of a home with a Go program, a pipx tool, a conda installation and a Nix profile: only names in
    /// the index leave the Mac, and what cannot be checked is said.
    @Test func onlyIndexNamesLeaveTheMac() async throws {
        let home = temporaryDirectory()
        let gobin = home.appendingPathComponent("gobin")
        try FileManager.default.createDirectory(at: gobin, withIntermediateDirectories: true)
        try Data(Binaries.goInline).write(to: gobin.appendingPathComponent("secret-tool"))
        ManagerFiles.venv(home.appendingPathComponent(".local/pipx/venvs/black"), cfg: "version = 3.12.4\n", python: "3.12",
                          dists: [("black", "24.1.0", true), ("requests", "2.25.0", true), ("internal-private-lib", "1.0", true)])
        let conda = home.appendingPathComponent("miniforge3")
        ManagerFiles.condaEnv(conda, [
            ("python", ManagerFiles.record("python", "3.11.5")),
            ("pyyaml", ManagerFiles.record("pyyaml", "5.3", files: ["lib/python3.11/site-packages/PyYAML-5.3.dist-info/METADATA"])),
            ("openssl", ManagerFiles.record("openssl", "3.0.12")),
            ("secret-corp-pkg", ManagerFiles.record("secret-corp-pkg", "1.0")),
        ])
        let hash = String(repeating: "b", count: 32)
        write(#"{"version": 3, "elements": {"nginx": {"storePaths": ["/nix/store/\#(hash)-nginx-1.30.2"]}, "private": {"storePaths": ["/nix/store/\#(hash)-private-thing-1.0"]}}}"#,
              to: home.appendingPathComponent(".nix-profile/manifest.json"))

        let index = "#osva-app-index\t1\tT\t5\t2\nP\tnginx\tnginx\tgithub.com/nginx/nginx\nP\topenssl\tOpenSSL\tgithub.com/openssl/openssl\n"
            + "K\tGo\tgolang.org/x/net\nK\tGo\tstdlib\nK\tPyPI\tblack\nK\tPyPI\trequests\nK\tPyPI\tpyyaml\n"
            + "R\tnix\tnginx\tnginx\nR\tconda\topenssl\topenssl\n"
        let transport = RecordedTransport { request, _ in
            switch request.url!.path {
            case "/data/app-index.tsv": return .init(status: 200, body: Data(index.utf8))
            case "/api/v1/check/batch": return .init(status: 200, body: Fixture.data("api/check-batch-programs-live-2026-11-19.json"))
            case "/api/v1/state": return .init(status: 200, body: Fixture.data("api/state.json"))
            case "/api/v1/project/nginx": return .init(status: 200, body: Fixture.data("api/project-nginx.json"))
            case "/api/v1/project/openssl": return .init(status: 200, body: Fixture.data("api/project-openssl.json"))
            default: return .init(status: 404, body: Data())
            }
        }
        var tools = ToolEnvironment(home: home, base: ["GOBIN": gobin.path], runner: RecordedRunner(outputs: [:]),
                                    isExecutable: { p in
                                        p.hasPrefix(home.path) && (p.hasPrefix(gobin.path) || ["/bin/python", "/bin/conda", "/bin/nix-env"].contains { p.hasSuffix($0) })
                                    })
        tools.systemRoot = home.appendingPathComponent("system-root").path   // not this Mac's own /nix (the Mac server has Nix)
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: home.appendingPathComponent("support")), tools: tools,
                                                               folders: [], applicationRoots: [home.appendingPathComponent("Applications")]),
                              transport: transport, pause: { _ in })
        let report = await scanner.scan()
        #expect(report.problems.isEmpty, "\(report.problems)")

        #expect(Set(report.sent.distinctItems) == ["Go golang.org/x/net v0.23.0 · macOS", "Go stdlib 1.27.4 · macOS",
                                                    "PyPI black 24.1.0 · Python 3.12.4 · macOS", "PyPI requests 2.25.0 · Python 3.12.4 · macOS",
                                                    "PyPI pyyaml 5.3 · Python 3.11.5 · macOS", "project nginx", "project openssl"])
        for r in transport.requests {
            let wire = (r.url?.absoluteString ?? "") + String(decoding: r.httpBody ?? Data(), as: UTF8.self)
            for secret in ["secret-tool", "internal-private-lib", "secret-corp-pkg", "private-thing", "example.com/osva", "golang.org/x/text",
                           "miniforge3", "pipx", ".nix-profile", home.path, "gobin"] {
                #expect(!wire.contains(secret), "\(secret) left the Mac in \(wire)")
            }
        }

        #expect(Set(report.findings.map(\.title)) == ["black", "secret-tool", "pyyaml", "nginx"])
        let tool = try #require(report.findings.first { $0.title == "secret-tool" })
        #expect(tool.upgradeCommand == "go install example.com/osva/gofixture@latest" && tool.shownVersions == "golang.org/x/net 0.23.0 → 0.62.0")
        #expect(report.findings.first { $0.title == "nginx" }?.upgradeCommand == "nix profile upgrade nginx")
        #expect(report.coverage.notChecked.contains(.init(source: "Nix packages with no graded project", items: ["private-thing 1.0"])))
        #expect(report.coverage.notChecked.contains(.init(source: "conda packages with no graded project", items: ["python 3.11.5", "secret-corp-pkg 1.0"])))
        #expect(report.coverage.notInIndex.contains(.init(source: "pipx", items: ["internal-private-lib 1.0"])))
        let kinds = Dictionary(uniqueKeysWithValues: report.inventory.reports.map { ($0.kind, $0) })
        #expect(kinds[.go]?.detail == "1 program, 2 module versions" && kinds[.pipx]?.detail == "1 tool, 3 packages")
        #expect(kinds[.conda]?.available == true && kinds[.nix]?.detail == "2 packages in 1 profile")
        #expect(report.inventory.reports.allSatisfy { $0.seconds != nil })
    }
}

private extension Finding {
    /// The row's version line, as the popover writes it: "golang.org/x/net 0.23.0 → 0.62.0".
    var shownVersions: String { (component.map { "\($0) " } ?? "") + installedVersion + (fixedVersion.map { " → \($0)" } ?? "") }
}

@Suite struct ProgramRowTests {
    typealias C = FindingBuilder.Component

    @Test("versions as people write them", arguments: [
        ("v0.23.0", "0.23.0"), ("v25.0.6+incompatible", "25.0.6"), ("v0.40.16+dirty", "0.40.16"), ("2.1.0+cpu", "2.1.0+cpu"), ("v0.0.0-20210226172049-e18ecbb05110", "0.0.0-20210226"),
        ("v1.2.4-0.20240101120000-abcdefabcdef", "1.2.4-20240101"), ("1.22.3", "1.22.3"), ("version", "version"),
    ])
    func shown(_ raw: String, _ expected: String) { #expect(C.shown(raw) == expected) }

    @Test func longModulePathsAreShortenedToFit() {
        #expect(C.rowLabel("golang.org/x/net", installed: "0.23.0", fixed: "0.62.0") == "golang.org/x/net")
        #expect(C.rowLabel("github.com/hashicorp/go-retryablehttp", installed: "0.7.1", fixed: "0.7.7") == "hashicorp/go-retryablehttp")
        #expect(C.rowLabel("github.com/hashicorp/go-retryablehttp", installed: "0.0.0-20210226", fixed: "0.7.7") == "go-retryablehttp")
        #expect(C.rowLabel(nil, installed: "1", fixed: nil) == nil)
        let line = { (l: String?, i: String, f: String?) in (l.map { $0 + " " } ?? "") + i + (f.map { " → " + $0 } ?? "") }
        for (label, i, f) in [("github.com/docker/docker", "25.0.6", "25.0.13"), ("github.com/aws/aws-sdk-go-v2/service/ecr", "1.20.2", "1.45.0")] {
            #expect(line(C.rowLabel(label, installed: i, fixed: f), i, f).count <= 44)
        }
    }
}

/// The Fix button and "where and why" for the program sources.
@Suite struct ProgramFixAndProvenanceTests {
    let tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: RecordedRunner(outputs: [:]),
                                isExecutable: { $0 == "/opt/homebrew/bin/brew" })

    func gh(_ place: BuiltProgram.Place = .homebrew) -> BuiltProgram {
        BuiltProgram(language: .go, path: "/opt/homebrew/bin/gh", name: "gh", version: "2.62.0", place: place, formula: place == .homebrew ? "gh" : nil,
                     package: "github.com/cli/cli/v2/cmd/gh", module: "github.com/cli/cli/v2", toolchain: "1.22.3")
    }

    func finding(_ origin: Origin, inputs: UpgradeCommand.Inputs?) -> Finding {
        let command = inputs.flatMap { UpgradeCommand.advice($0).command } ?? UpgradeCommand.advice(for: origin, name: "x", ecosystem: nil, target: nil, malicious: false).command
        return Finding(id: "f", group: .criticalHigh, subject: .package(ecosystem: .go, name: "golang.org/x/net"), title: "gh", component: "golang.org/x/net",
                       installedVersion: "0.23.0", fixedVersion: "0.33.0", severity: .critical, advisoryIDs: [], flawCount: 1, exploited: false,
                       malicious: false, note: nil, bigIssue: nil, origins: [origin], pageURL: SiteURL.home, upgradeCommand: command,
                       verification: .none, grade: nil, commandInputs: inputs)
    }

    @Test func aHomebrewProgramGetsBrewUpgradeChecked() throws {
        let origin = Origin.program(gh())
        let f = finding(origin, inputs: FindingBuilder.inputs(origin: origin, malicious: false))
        guard case let .success(plan) = FixPlan.make(for: f, tools: tools) else { Issue.record("no plan"); return }
        #expect(plan.command == "brew upgrade gh" && plan.toolName == "brew")
        let homebrew = try #require(plan.homebrew)
        // the formula only carries the module: Homebrew can tell whether there is a newer gh, the check after says the rest
        #expect(!homebrew.versionIsTheFix && homebrew.name == "gh")
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "gh", stable: "2.62.0", installed: "2.62.0"), for: homebrew, fixedVersion: "0.33.0")
                == .unavailable("Homebrew has no newer gh than 2.62.0, the one installed."))
    }

    @Test func otherProgramsAndManagersAreCopyOnly() {
        #expect(FindingBuilder.inputs(origin: .program(gh(.goInstall)), malicious: false) == nil)
        let goInstall = finding(.program(gh(.goInstall)), inputs: UpgradeCommand.Inputs(origin: .program(gh(.goInstall)), name: "gh", ecosystem: nil,
                                                                                        target: nil, malicious: false))
        #expect(FixPlan.make(for: goInstall, tools: tools) == .failure(.noCommand))
        let env = CondaEnvironment(prefix: "/Users/ana/miniforge3", name: "base", named: true, tool: .conda, python: "3.11.5")
        let conda = finding(.conda(env: env), inputs: UpgradeCommand.Inputs(origin: .conda(env: env), name: "pyyaml", ecosystem: .pypi, target: "5.4",
                                                                            malicious: false))
        guard case let .failure(.sharedEnvironment(why)) = FixPlan.make(for: conda, tools: tools) else { Issue.record("conda ran"); return }
        #expect(why.hasPrefix("Not run for you"))
        for origin in [Origin.macports(port: "nginx"), .nix(profile: NixProfile(path: "/Users/ana/.nix-profile", style: .profile, shared: false), element: "nginx")] {
            #expect(FixPlan.make(for: finding(origin, inputs: UpgradeCommand.Inputs(origin: origin, name: "nginx", ecosystem: nil, target: nil, malicious: false)),
                                 tools: tools) == .failure(.noCommand))
        }
    }

    @Test func aProgramAfterAnUpgradeIsTheSamePlace() {
        var newer = gh(); newer.version = "2.63.0"; newer.path = "/opt/homebrew/Cellar/gh/2.63.0/bin/gh"
        #expect(Origin.program(gh()).samePlace(as: .program(newer)))
        var other = gh(.other); other.path = "/usr/local/bin/gh"
        #expect(!Origin.program(gh()).samePlace(as: .program(other)))
    }

    @Test func whereAndWhy() async {
        let home = temporaryDirectory()
        write("x", to: home.appendingPathComponent("go/bin/gopls"))
        let gopls = BuiltProgram(language: .go, path: home.path + "/go/bin/gopls", name: "gopls", version: "0.16.1", place: .goInstall, formula: nil,
                                 package: "golang.org/x/tools/gopls", toolchain: "1.23.0")
        let docker = BuiltProgram(language: .go, path: "/usr/local/bin/docker", name: "docker", version: nil, place: .app, formula: nil, package: nil,
                                  toolchain: "1.23.8", app: "Docker", cask: "docker-desktop")
        let tool = PythonTool(manager: .pipx, name: "black", mainPackage: "black", version: "24.1.0", venv: home.path + "/venvs/black", python: "3.12.4")
        let findings = [Origin.program(gopls), .program(docker), .pythonTool(tool), .macports(port: "nginx")].enumerated().map { i, o in
            var f = finding(o, inputs: nil); f.id = "f\(i)"; return f
        }
        let explained = await ProvenanceExplainer(tools: ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false }))
            .explain(findings, inventory: Inventory())
        let why = explained.map { $0.provenance?.first?.why }
        #expect(why[0]?.hasPrefix("You installed it with go install on ") == true)
        #expect(explained[0].provenance?.first?.details == ["Built from golang.org/x/tools/gopls", "Built with Go 1.23.0"])
        #expect(why[1] == "Ships inside Docker (Homebrew cask docker-desktop)")
        #expect(why[2] == "You installed it with pipx" && explained[2].provenance?.first?.path == tool.venv)
        #expect(why[3] == "Installed with MacPorts (the port nginx)")
    }
}

extension ProgramFixAndProvenanceTests {
    @Test func aLinkOntoPathSaysWhatItNames() async throws {
        let home = temporaryDirectory()
        write("x", to: home.appendingPathComponent("Cellar/gh/2.62.0/bin/gh"))
        try FileManager.default.createDirectory(at: home.appendingPathComponent("bin"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: home.path + "/bin/gh", withDestinationPath: "../Cellar/gh/2.62.0/bin/gh")
        var p = gh(.other); p.path = home.path + "/bin/gh"
        let explained = await ProvenanceExplainer(tools: ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false }))
            .explain([finding(.program(p), inputs: nil)], inventory: Inventory())
        #expect(explained[0].provenance?.first?.details.first == "Links to " + Paths.abbreviatingHome(home.path + "/Cellar/gh/2.62.0/bin/gh", home: home.path))
    }
}

extension ProgramFindingTests {
    @Test func anAppThatIsAFindingTakesItsProgramsIn() throws {
        func docker(_ name: String) -> BuiltProgram {
            BuiltProgram(language: .go, path: "/usr/local/bin/\(name)", name: name, version: nil, place: .app, formula: nil, package: nil,
                         toolchain: nil, app: "Docker", cask: nil)
        }
        let programs = findings(program(docker("docker"), [("stdlib", "1.22.3")]) + program(docker("kubectl"), [("golang.org/x/net", "v0.23.0")]))
        let app = Finding(id: "product|docker|4.41.2", group: .criticalHigh, subject: .product(key: "docker", name: "Docker"),
                          title: "Docker", installedVersion: "4.41.2", fixedVersion: "4.86.0", severity: .high, advisoryIDs: ["CVE-1"], flawCount: 6,
                          exploited: false, malicious: false, note: "Likely affected: the issuer names 4.86.0 as fixed.", bigIssue: nil,
                          origins: [.application(name: "Docker", bundlePath: "/Applications/Docker.app", caskToken: nil)], pageURL: SiteURL.home,
                          upgradeCommand: nil, verification: .none, grade: nil)
        let other = Finding(id: "x", group: .other, subject: .package(ecosystem: .npm, name: "x"), title: "x", installedVersion: "1", fixedVersion: nil,
                            severity: nil, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil, bigIssue: nil,
                            origins: [.npmGlobal(npm: "npm")], pageURL: SiteURL.home, upgradeCommand: nil, verification: .none, grade: nil)
        let folded = FindingBuilder.foldingProgramsIntoApps(programs + [app, other])
        #expect(folded.map(\.id) == ["product|docker|4.41.2", "x"])
        let d = try #require(folded.first)
        #expect(d.note == "Likely affected: the issuer names 4.86.0 as fixed. docker and kubectl were built with golang.org/x/net 0.23.0 — fixed in 0.62.0"
                + " · built with Go 1.22.3, whose stdlib has 74 known flaws.")
        #expect(d.severity == .critical && d.flawCount == 6 + 20 + 74 && d.fixedVersion == "4.86.0")
        // without the app's own finding, the programs stay a finding
        #expect(FindingBuilder.foldingProgramsIntoApps(programs).map(\.title) == ["Docker"])
    }
}
