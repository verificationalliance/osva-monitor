import Foundation
import Testing
@testable import OSVAKit

@Suite struct HomebrewTests {
    @Test func readsFormulaeAndCasks() throws {
        let (items, caskForApp) = try HomebrewSource.parse(Fixture.data("brew/brew-info-installed.json"))
        func item(_ name: String) -> HomebrewItem? { items.first { $0.name == name } }
        #expect(item("openssl@3")?.version == "3.5.9")                  // keg-only, not linked: its installed version
        #expect(item("node")?.version == "26.13.1")                     // "26.13.1_2": Homebrew's revision is not upstream's
        #expect(item("imagemagick")?.version == "7.1.2-36")             // a dash is part of the upstream version
        #expect(item("git")?.urls.contains("https://git-scm.com") == true)
        #expect(item("berkeley-db") != nil)                             // keg-only, not linked: still installed
        #expect(item("alfred")?.version == "5.7.3")                     // cask "5.7.3,2320"
        #expect(item("alfred")?.kind == .cask)
        #expect(caskForApp["Visual Studio Code.app"] == "visual-studio-code")
        #expect(caskForApp["qBittorrent.app"] == "qbittorrent")         // an app renamed by its cask ("target")
    }

    @Test func revisionSuffix() {
        #expect(HomebrewSource.upstreamVersion("3.6.8_1") == "3.6.8")
        #expect(HomebrewSource.upstreamVersion("10.2p1") == "10.2p1")
        #expect(HomebrewSource.upstreamVersion("2026-11-05") == "2026-11-05")
    }

    @Test func runsBrewWithoutUpdatingAndFallsBackToLocalTaps() async {
        let brew = "/opt/homebrew/bin/brew"
        let tools = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: FailingFirstBrew(json: Fixture.data("brew/brew-info-installed.json")),
                                    isExecutable: { $0 == brew })
        let r = await HomebrewSource(environment: tools).collect()
        #expect(r.items.count == 19)
        #expect(r.report.detail == "13 formulae, 6 casks")
        #expect(tools.environment(for: brew)["HOMEBREW_NO_AUTO_UPDATE"] == "1")
    }

    @Test func noHomebrew() async {
        let r = await HomebrewSource(environment: ToolEnvironment(base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })).collect()
        #expect(r.report.available == false)
        #expect(r.report.detail == "Homebrew not found")
    }

    /// The first `brew info` fails as when the API cache cannot be refreshed; the retry reads local taps.
    struct FailingFirstBrew: CommandRunner {
        let json: Data
        func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
            environment["HOMEBREW_NO_INSTALL_FROM_API"] == "1"
                ? CommandResult(status: 0, stdout: json, stderr: Data())
                : CommandResult(status: 1, stdout: Data(), stderr: Data("Error: Permission denied @ rb_sysopen".utf8))
        }
    }
}

@Suite struct ProjectMatcherTests {
    let index = Fixture.index

    @Test("by repository", arguments: [
        ("https://github.com/curl/curl/releases/download/curl-8_11_0/curl-8.11.0.tar.xz", "curl"),
        ("https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.6/openmp-23.1.6.src.tar.xz", "llvm"),
        ("https://gitlab.freedesktop.org/poppler/poppler/-/archive/25.01.0/poppler-25.01.0.tar.gz", "poppler"),
        ("https://github.com/FFmpeg/FFmpeg.git", "ffmpeg"),
        ("https://www.github.com/OpenSSL/openssl", "openssl"),
    ])
    func byRepository(_ url: String, _ slug: String) {
        let item = HomebrewItem(kind: .formula, name: "something-else", version: "1.0", urls: ["https://example.org", url])
        #expect(ProjectMatcher.project(for: item, in: index)?.slug == slug)
    }

    @Test func byName() {
        func slug(_ name: String) -> String? {
            ProjectMatcher.project(for: HomebrewItem(kind: .formula, name: name, version: "1", urls: ["https://example.org/x.tar.gz"]), in: index)?.slug
        }
        #expect(slug("python@3.14") == "cpython")
        #expect(slug("openssl@1.1") == "openssl")
        #expect(slug("postgresql@16") == "postgres")
        #expect(slug("node") == "node")
        #expect(slug("libgcrypt") == nil)              // deliberately not mapped: its versions are not GnuPG's
        #expect(slug("abseil") == nil)
    }

    @Test func everyFallbackNameIsAProjectInTheIndex() {
        for (name, slug) in ProjectMatcher.fallbackNames {
            #expect(index.project(slug: slug) != nil, "\(name) -> \(slug) is not a project in the recorded index")
        }
    }

    @Test func recordedHomebrewMatches() throws {
        let (items, _) = try HomebrewSource.parse(Fixture.data("brew/brew-info-installed.json"))
        let matched = Dictionary(uniqueKeysWithValues: items.compactMap { i in ProjectMatcher.project(for: i, in: index).map { (i.name, $0.slug) } })
        #expect(matched == ["git": "git", "go": "go", "imagemagick": "imagemagick", "libomp": "llvm", "node": "node", "openssl@1.1": "openssl",
                            "openssl@3": "openssl", "postgresql@16": "postgres", "python@3.14": "cpython", "sqlite": "sqlite", "xz": "xz"])
    }

    @Test func repositoryKeys() {
        #expect(ProjectMatcher.repositoryKeys(of: "https://github.com/a/b.git") == ["github.com/a/b", "github.com/a"])
        #expect(ProjectMatcher.repositoryKeys(of: "ftp://example.org/a") == [])
        #expect(ProjectMatcher.repositoryKeys(of: "not a url") == [])
    }
}

@Suite struct GlobalPackageTests {
    @Test func npm() throws {
        let real = try GlobalPackageSources.parseNpmList(Fixture.data("tools/npm-ls-global.json"))
        #expect(real.map(\.name) == ["npm"] && real.map(\.version) == ["11.20.0"])
        let withProblems = try GlobalPackageSources.parseNpmList(Fixture.data("tools/npm-ls-global-problems.json"))
        #expect(withProblems.map(\.name) == ["@anthropic-ai/claude-code", "corepack", "event-stream", "left-pad", "npm"])   // a link without a version is skipped
    }

    @Test func cargo() throws {
        let crates = try GlobalPackageSources.parseCrates2(Fixture.data("tools/crates2.json"))
        #expect(crates.map { "\($0.name) \($0.version)" } == ["cargo-audit 0.18.3", "ripgrep 14.1.0"])   // path and git installs are not crates.io's

        let home = temporaryDirectory()
        write(Fixture.text("tools/crates2.json"), to: home.appendingPathComponent(".cargo/.crates2.json"))
        let r = GlobalPackageSources(environment: ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]))).cargo()
        #expect(r.packages.count == 2 && r.packages.allSatisfy { $0.ecosystem == .crates })
    }

    @Test func gem() {
        let gems = GlobalPackageSources.parseGemList(Fixture.text("tools/gem-list-local.txt"))
        #expect(gems.contains { $0.name == "nokogiri" && $0.version == "1.13.8" })
        #expect(gems.contains { $0.name == "json" && $0.version == "2.1.0" })              // "json (default: 2.1.0)"
        let more = GlobalPackageSources.parseGemList("ffi (1.15.5-arm64-darwin, 1.15.4)\nrake (13.0.6 ruby)\n\n*** LOCAL GEMS ***\n")
        #expect(more.map { "\($0.name) \($0.version)" } == ["ffi 1.15.5", "ffi 1.15.4", "rake 13.0.6"])
    }

    @Test func missingToolsAreNotErrors() async {
        let none = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        let g = GlobalPackageSources(environment: none)
        let (npm, pip, gem, cargo) = (await g.npm(), await PythonSource(environment: none).collect(), await g.gem(), g.cargo())
        for r in [npm.report, pip.report, gem.report, cargo.report] {
            #expect(r.available == false && r.error == nil)
        }
    }

    @Test func toolsRunWithTheirUpdateChecksOff() {
        let env = ToolEnvironment(base: ["PATH": "/usr/bin"]).environment(for: "/opt/homebrew/bin/npm")
        #expect(env["PATH"]!.hasPrefix("/opt/homebrew/bin:"))
        #expect(env["NPM_CONFIG_UPDATE_NOTIFIER"] == "false")
        #expect(env["PIP_DISABLE_PIP_VERSION_CHECK"] == "1")
        #expect(env["HOMEBREW_NO_AUTO_UPDATE"] == "1")
    }
}

@Suite struct ElectronTests {
    func app(_ root: URL, _ name: String, electron: String?) {
        let bundle = root.appendingPathComponent(name + ".app")
        write("x", to: bundle.appendingPathComponent("Contents/MacOS/x"))
        if let electron {
            let plist = try! PropertyListSerialization.data(fromPropertyList: ["CFBundleVersion": electron], format: .xml, options: 0)
            try! FileManager.default.createDirectory(at: bundle.appendingPathComponent(ElectronSource.frameworkPlist).deletingLastPathComponent(), withIntermediateDirectories: true)
            try! plist.write(to: bundle.appendingPathComponent(ElectronSource.frameworkPlist))
        }
    }

    @Test func findsAppsThatBundleElectron() {
        let root = temporaryDirectory()
        app(root, "Visual Studio Code", electron: "42.10.0")
        app(root, "Dropbox", electron: "37.10.3-dropbox-75-20261021-204309.0")
        app(root, "Native", electron: nil)
        app(root.appendingPathComponent("Vendor"), "Nested", electron: "30.0.0-beta.3")
        let r = ElectronSource(roots: [root, root.appendingPathComponent("missing")], caskForApp: ["Visual Studio Code.app": "visual-studio-code"]).collect()
        #expect(r.packages.map(\.origin.label) == ["Dropbox", "Nested", "Visual Studio Code"])
        #expect(r.packages.map(\.version) == ["37.10.3", "30.0.0-beta.3", "42.10.0"])
        #expect(r.packages.allSatisfy { $0.ecosystem == .npm && $0.name == "electron" })
        guard case let .electronApp(_, _, cask) = r.packages[2].origin else { Issue.record("not an app"); return }
        #expect(cask == "visual-studio-code")
    }

    @Test func versions() {
        #expect(ElectronSource.electronVersion("45.3.2") == "45.3.2")
        #expect(ElectronSource.electronVersion("not a version") == nil)
    }
}

@Suite struct PythonTests {
    func info(_ fixture: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Fixture.data("tools/\(fixture)")) as? [String: Any])
    }

    @Test func applesPython() throws {
        let p = try #require(PythonSource.classify(executable: "/usr/bin/python3", info: info("python-describe-apple.json"), fileExists: { _ in false }))
        #expect(p.kind == .apple && p.version == "3.9.6" && !p.externallyManaged && p.minorVersion == "3.9")
        #expect(p.userSite == "/Users/ana/Library/Python/3.9/lib/python/site-packages")
        #expect(p.label == "Apple's Python 3.9.6 (part of Xcode)")
    }

    @Test func homebrewsPythonIsExternallyManaged() throws {
        // The PEP 668 marker is a file in the standard library directory.
        let stdlib = "/opt/homebrew/opt/python@3.15/Frameworks/Python.framework/Versions/3.15/lib/python3.15"
        let p = try #require(PythonSource.classify(executable: "/opt/homebrew/bin/python3", info: info("python-describe-homebrew.json"),
                                                   fileExists: { $0 == stdlib + "/EXTERNALLY-MANAGED" }))
        #expect(p.kind == .homebrew && p.formula == "python@3.15" && p.externallyManaged && p.version == "3.15.2")
        let unmarked = try #require(PythonSource.classify(executable: "/opt/homebrew/bin/python3", info: info("python-describe-homebrew.json"), fileExists: { _ in false }))
        #expect(!unmarked.externallyManaged)
    }

    @Test func otherKinds() throws {
        let venv: [String: Any] = ["version": "3.12.4", "prefix": "/Users/ana/proj/.venv", "base_prefix": "/opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12"]
        #expect(PythonSource.classify(executable: "/Users/ana/proj/.venv/bin/python", info: venv, fileExists: { _ in true })?.kind == .virtualEnv)
        let org: [String: Any] = ["version": "3.13.1", "prefix": "/Library/Frameworks/Python.framework/Versions/3.13"]
        #expect(PythonSource.classify(executable: "/usr/local/bin/python3", info: org, fileExists: { _ in false })?.kind == .pythonOrg)
        #expect(PythonSource.classify(executable: "/x", info: [:], fileExists: { _ in false }) == nil)
    }

    @Test func verbosePipListsSayWhereAndWho() throws {
        let apple = try PythonSource.parsePipList(Fixture.data("tools/pip-list-verbose-apple.json"))
        #expect(apple.contains { $0.name == "setuptools" && $0.version == "58.0.4" && $0.installer == "pip" && $0.location?.contains("Xcode.app") == true })
        let brew = try PythonSource.parsePipList(Fixture.data("tools/pip-list-verbose-homebrew.json"))
        #expect(brew.allSatisfy { $0.installer == "brew" })
        let old = try PythonSource.parsePipList(Data(#"[{"name": "six", "version": "1.15.0"}]"#.utf8))
        #expect(old == [PythonSource.PipEntry(name: "six", version: "1.15.0", location: nil, installer: nil)])
    }

    @Test func theFormulaIsWhereTheFilesLink() throws {
        let root = temporaryDirectory()
        let cellar = root.appendingPathComponent("Cellar/certifi/2026.10.23/lib/python3.15/site-packages/certifi-2026.10.23.dist-info")
        write("Metadata-Version: 2.1", to: cellar.appendingPathComponent("METADATA"))
        let site = root.appendingPathComponent("lib/python3.15/site-packages/certifi-2026.10.23.dist-info")
        try FileManager.default.createDirectory(at: site, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: site.appendingPathComponent("METADATA"), withDestinationURL: cellar.appendingPathComponent("METADATA"))
        #expect(PythonSource.homebrewFormula(of: "Certifi", in: site.deletingLastPathComponent().path) == "certifi")
        #expect(PythonSource.homebrewFormula(of: "other", in: site.deletingLastPathComponent().path) == nil)
    }

    @Test func eachInterpreterIsAskedWhatItIs() async throws {
        let exe = "/usr/bin/python3"
        let runner = RecordedRunner(outputs: [
            "\(exe) -c \(PythonSource.describeScript)": CommandResult(status: 0, stdout: Fixture.data("tools/python-describe-apple.json"), stderr: Data()),
            "\(exe) -m pip list -v --format=json --disable-pip-version-check": CommandResult(status: 0, stdout: Data(#"""
                [{"name": "setuptools", "version": "58.0.4", "location": "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages", "installer": "pip"},
                 {"name": "requests", "version": "2.25.0", "location": "/Users/ana/Library/Python/3.9/lib/python/site-packages", "installer": "pip"}]
                """#.utf8), stderr: Data()),
        ])
        let tools = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: runner,
                                    isExecutable: { $0 == exe || $0 == "/Applications/Xcode.app/Contents/Developer/usr/bin/python3" })
        let r = await PythonSource(environment: tools).collect()
        #expect(r.report.detail == "2 packages in 1 Python")
        let user = r.packages.map { p -> Bool in if case let .pip(_, u, _) = p.origin { return u }; return false }
        #expect(user == [false, true])
        #expect(r.packages.allSatisfy { $0.origin.pythonVersion == "3.9.6" })
    }
}
