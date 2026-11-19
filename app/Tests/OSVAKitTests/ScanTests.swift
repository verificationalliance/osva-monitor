import Foundation
import Testing
@testable import OSVAKit

@Suite struct FindingBuilderTests {
    let index = Fixture.index
    var nginx: ProjectResponse { try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-nginx.json")) }
    var state: StateResponse { try! JSONDecoder().decode(StateResponse.self, from: Fixture.data("api/state.json")) }

    func brew(_ name: String, _ version: String, _ slug: String) -> FindingBuilder.BrewMatch {
        .init(item: HomebrewItem(kind: .formula, name: name, version: version, urls: []), project: index.project(slug: slug)!)
    }

    @Test func aHomebrewProjectBelowItsBranchFixIsLikelyAffected() throws {
        let f = FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [brew("nginx", "1.30.2", "nginx")],
                                                      projects: ["nginx": nginx], bigIssues: [])
        let finding = try #require(f.first)
        #expect(finding.group == .criticalHigh)
        #expect(finding.severity == .critical)
        #expect(finding.fixedVersion == "1.30.7")                    // the fix on its own branch, not the newest branch's
        #expect(finding.note == "Likely affected: the issuer names 1.30.7 as fixed.")
        #expect(finding.upgradeCommand == "brew upgrade nginx")
        #expect(finding.pageURL.absoluteString == "https://verificationalliance.org/#/project/nginx")
        #expect(finding.originSummary == "Homebrew nginx")
    }

    @Test func atItsBranchFixItIsNot() {
        let f = FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [brew("nginx", "1.30.7", "nginx")],
                                                      projects: ["nginx": nginx], bigIssues: [])
        #expect(f.isEmpty)
    }

    @Test func patchTheseFirstMarksAndPromotes() throws {
        let f = FindingBuilder(index: index).findings(approved: [:], verdicts: [:],
                                                      brew: [brew("nginx", "1.30.2", "nginx"), brew("openssh", "10.6p1", "openssh")],
                                                      projects: ["nginx": nginx], bigIssues: state.bigIssues)
        let n = try #require(f.first { $0.title == "nginx" })
        #expect(n.bigIssue?.hasPrefix("On the site's “patch these first” list") == true)
        let ssh = try #require(f.first { $0.id == "brew|openssh|10.6p1" })   // only in the big-issues list (no project answer)
        #expect(ssh.group == .exploited && ssh.exploited && ssh.fixedVersion == "10.6p2")
        #expect(f.first?.id == ssh.id)                                        // exploited sorts first
        #expect(ssh.deservesNotification && n.deservesNotification)
    }

    func findings(_ installed: [InstalledPackage], batch: String = "api/check-batch-plan.json") throws -> [Finding] {
        let response = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data(batch))
        let selection = PrivacyFilter(index: index).approve(installed)
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in
            response.packages.first { $0.name == a.name && $0.version == a.version }.map { (a, $0) }
        })
        return FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: [])
    }

    @Test func thePlanDecidesTheVersionAndTheGroup() throws {
        let f = try findings([
            InstalledPackage(ecosystem: .npm, name: "axios", version: "1.14.1", origin: .folder(root: "/w", lockfile: "/w/app/package-lock.json", direct: true)),
            InstalledPackage(ecosystem: .pypi, name: "setuptools", version: "58.0.4", origin: .pip(python: Fixture.applePython, user: false, formula: nil)),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .npmGlobal(npm: "/opt/homebrew/bin/npm")),
            InstalledPackage(ecosystem: .pypi, name: "Pygments", version: "2.14.0", origin: .pip(python: Fixture.homebrewPython, user: false, formula: "pygments")),
        ])
        #expect(f.map(\.title) == ["axios", "lodash", "setuptools", "Pygments"])
        #expect(f.map(\.group) == [.malicious, .criticalHigh, .criticalHigh, .other])
        let axios = f[0]
        #expect(axios.fixedVersion == nil && axios.severity == nil && axios.upgradeCommand == "cd /w/app && npm uninstall axios")

        // setuptools on Apple's Python 3.9.6: the plan's 78.1.1, not 84.1.0, the newest fix (which needs Python 3.10)
        let setuptools = f[2]
        #expect(setuptools.fixedVersion == "78.1.1" && setuptools.fixesCount == 3)
        #expect(setuptools.upgradeCommand == "/usr/bin/python3 -m pip install --user --upgrade 'setuptools>=78.1.1'")
        #expect(setuptools.note?.contains("current Python") == true)
        #expect(setuptools.flawCount == 4)                                    // the Windows-only one does not count here
        #expect(setuptools.unresolved.map(\.explanation) == [
            "Fixed in 83.0.0, which needs Python ≥3.10; this Python is 3.9.6",
            "Windows only, does not affect this Mac",
        ])
        #expect(f[1].upgradeCommand == "npm install -g lodash@4.17.21")

        // A flaw only on Windows makes an installed package "Other": listed, not counted in the menu bar.
        let pygments = f[3]
        #expect(pygments.group == .other && !pygments.group.needsAction && pygments.fixedVersion == nil)
        #expect(pygments.upgradeCommand == nil)                                // nothing to do for this Mac
        #expect(pygments.unresolved.first?.explanation == "Windows only, does not affect this Mac")
    }

    @Test func aProjectsDependencyCountsEveryPlatform() throws {
        // The same Windows-only flaw in a project folder: the project may be deployed anywhere, so it is not set aside.
        let f = try findings([InstalledPackage(ecosystem: .pypi, name: "pygments", version: "2.14.0",
                                               origin: .folder(root: "/w", lockfile: "/w/requirements.txt", direct: true))])
        #expect(f.first?.group == .criticalHigh)
        #expect(f.first?.unresolved.first?.explanation == "Windows only")
    }

    @Test func theLiveAnswerForAppleSetuptools() throws {
        // Recorded from production on 2026-11-19: setuptools 58.0.4 with Python 3.9.6 on macOS.
        let f = try findings([
            InstalledPackage(ecosystem: .pypi, name: "setuptools", version: "58.0.4", origin: .pip(python: Fixture.applePython, user: false, formula: nil)),
            InstalledPackage(ecosystem: .npm, name: "minimist", version: "0.0.8", origin: .folder(root: "/w", lockfile: "/w/package-lock.json", direct: false)),
        ], batch: "api/check-batch-live-2026-11-19.json")
        let setuptools = try #require(f.first { $0.title == "setuptools" })
        #expect(setuptools.fixedVersion == "78.1.1" && setuptools.fixesCount == 3 && setuptools.flawCount == 4)
        #expect(setuptools.upgradeCommand == "/usr/bin/python3 -m pip install --user --upgrade 'setuptools>=78.1.1'")
        #expect(Set(setuptools.unresolved.map(\.explanation)) == ["Fixed in 83.0.0, which needs Python ≥3.10; this Python is 3.9.6",
                                                                   "Windows only, does not affect this Mac"])
        let minimist = try #require(f.first { $0.title == "minimist" })
        #expect(minimist.fixedVersion == "0.2.4" && minimist.group == .criticalHigh && minimist.upgradeCommand == "cd /w && npm update minimist")
    }

    @Test func anOldAnswerWithoutAPlanStillGivesFindings() throws {
        let f = try findings([InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .npmGlobal(npm: "npm"))],
                             batch: "api/check-batch-malicious.json")
        #expect(f.first?.group == .criticalHigh && f.first?.fixedVersion == nil && f.first?.flawCount == 4)
    }

    @Test func eachElectronAppIsItsOwnFinding() throws {
        let batch = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch.json"))
        let installed = [
            InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0", origin: .electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack")),
            InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0", origin: .electronApp(name: "Notion", bundlePath: "/Applications/Notion.app", caskToken: nil)),
        ]
        let selection = PrivacyFilter(index: index).approve(installed)
        #expect(selection.approved.count == 1)                                 // one question to the server...
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.map { a in (a, batch.packages.first { $0.name == "electron" }!) })
        let f = FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: [])
        #expect(f.map(\.title) == ["Notion", "Slack"])                         // ...and one finding per app
        #expect(f.allSatisfy { $0.component == "Electron" && $0.installedVersion == "28.1.0" })
        #expect(f.map(\.upgradeCommand) == [nil, "brew upgrade --cask slack"])
        #expect(f.map(\.originSummary) == ["App in /Applications", "App in /Applications · Homebrew cask"])   // not the title again
    }
}

@Suite struct UpgradeCommandTests {
    @Test func quoting() {
        #expect(UpgradeCommand.quote("lodash@4.17.21") == "lodash@4.17.21")
        #expect(UpgradeCommand.quote("evil; rm -rf ~") == "'evil; rm -rf ~'")
        #expect(UpgradeCommand.quote("it's") == "'it'\\''s'")
        #expect(UpgradeCommand.quote("-rf") == "'-rf'")
        #expect(UpgradeCommand.quote("=ls") == "'=ls'")         // zsh would expand an unquoted =ls to /bin/ls
        #expect(UpgradeCommand.quote("") == "''")
    }

    @Test func aHostileNameCannotBreakOut() {
        let cmd = UpgradeCommand.command(for: .folder(root: "/p", lockfile: "/p/My Project/package-lock.json", direct: true), name: "x$(curl evil)",
                                         ecosystem: .npm, fixed: "1.0.0", malicious: false)
        #expect(cmd == "cd '/p/My Project' && npm install 'x$(curl evil)@^1.0.0'")
    }

    @Test func foldersInHomeAreWrittenFromTilde() {
        func c(_ lockfile: String) -> String? {
            UpgradeCommand.command(for: .folder(root: "/Users/ana/code", lockfile: lockfile, direct: true), name: "lodash", ecosystem: .npm, fixed: "4.18.1",
                                   malicious: false, home: "/Users/ana")
        }
        #expect(c("/Users/ana/code/shop/package-lock.json") == "cd ~/code/shop && npm install 'lodash@^4.18.1'")
        #expect(c("/Users/ana/My Project/package-lock.json") == "cd ~/'My Project' && npm install 'lodash@^4.18.1'")
        #expect(c("/Users/anabel/x/package-lock.json") == "cd /Users/anabel/x && npm install 'lodash@^4.18.1'")   // not inside the home
    }

    @Test func perOrigin() {
        func c(_ o: Origin, _ name: String = "pkg", _ eco: Ecosystem? = nil, fixed: String? = "2.0.0", malicious: Bool = false) -> String? {
            UpgradeCommand.command(for: o, name: name, ecosystem: eco, fixed: fixed, malicious: malicious)
        }
        #expect(c(.homebrewFormula(name: "openssl@3")) == "brew upgrade openssl@3")
        #expect(c(.homebrewCask(token: "slack")) == "brew upgrade --cask slack")
        #expect(c(.electronApp(name: "Notion", bundlePath: "/Applications/Notion.app", caskToken: nil)) == nil)
        #expect(c(.gem(gem: "/usr/bin/gem"), "nokogiri") == "gem install --user-install nokogiri -v 2.0.0")
        #expect(c(.cargoInstall, "ripgrep") == "cargo install ripgrep@2.0.0")
        #expect(c(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "eslint") == "npm install -g eslint@2.0.0")
    }

    @Test("pip, where the package lives", arguments: [
        // Apple's Python, its own (read-only) packages: a newer copy in the user site
        (Fixture.applePython, false, nil, "/usr/bin/python3 -m pip install --user --upgrade 'six>=2.0.0'", true),
        (Fixture.applePython, true, nil, "/usr/bin/python3 -m pip install --user --upgrade 'six>=2.0.0'", true),
        // Homebrew's: a formula's package is upgraded with the formula; anything else pip will not touch (PEP 668)
        (Fixture.homebrewPython, false, "python-six", "brew upgrade python-six", false),
        (Fixture.homebrewPython, false, nil, nil, true),
        (Fixture.homebrewPython, true, nil, nil, true),
        // a virtual environment and python.org's: pip in place
        (PythonEnvironment(executable: "/Users/ana/venv/bin/python", version: "3.12.4", kind: .virtualEnv, externallyManaged: false, userSite: nil, formula: nil),
         false, nil, "/Users/ana/venv/bin/python -m pip install --upgrade 'six>=2.0.0'", false),
        (PythonEnvironment(executable: "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3", version: "3.13.1", kind: .pythonOrg,
                           externallyManaged: false, userSite: nil, formula: nil),
         true, nil, "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m pip install --user --upgrade 'six>=2.0.0'", false),
    ] as [(PythonEnvironment, Bool, String?, String?, Bool)])
    func pip(_ python: PythonEnvironment, _ user: Bool, _ formula: String?, _ command: String?, _ hasNote: Bool) {
        let a = UpgradeCommand.advice(for: .pip(python: python, user: user, formula: formula), name: "six", ecosystem: .pypi, target: "2.0.0", malicious: false)
        #expect(a.command == command)
        #expect((a.note != nil) == hasNote, "\(a.note ?? "no note")")
        #expect(!(a.command ?? "").contains("--break-system-packages"))
    }

    @Test func homebrewsOwnPipComesWithItsFormula() {
        let a = UpgradeCommand.advice(for: .pip(python: Fixture.homebrewPython, user: false, formula: nil), name: "setuptools", ecosystem: .pypi,
                                      target: "78.1.1", malicious: false)
        #expect(a.command == "brew upgrade python@3.15")
        #expect(PythonEnvironment(executable: "/usr/bin/python3", version: "3.9.6", kind: .apple, externallyManaged: false, userSite: nil, formula: nil)
            .label == "Apple's Python 3.9.6 (part of Xcode)")
    }

    @Test func lockfilesDirectAndIndirect() {
        func a(_ lockfile: String, _ name: String, _ eco: Ecosystem, direct: Bool?, target: String? = "2.0.0", malicious: Bool = false) -> UpgradeCommand.Advice {
            UpgradeCommand.advice(for: .folder(root: "/p", lockfile: "/p/" + lockfile, direct: direct), name: name, ecosystem: eco, target: target,
                                  malicious: malicious, home: "/Users/ana")
        }
        #expect(a("package-lock.json", "lodash", .npm, direct: true).command == "cd /p && npm install 'lodash@^2.0.0'")
        let indirect = a("package-lock.json", "minimist", .npm, direct: false)
        #expect(indirect.command == "cd /p && npm update minimist")
        #expect(indirect.note?.contains(#""overrides""#) == true)
        #expect(a("yarn.lock", "axios", .npm, direct: true).command == "cd /p && yarn add 'axios@^2.0.0'")
        #expect(a("yarn.lock", "axios", .npm, direct: false).note?.contains("resolutions") == true)
        #expect(a("yarn.lock", "axios", .npm, direct: true, malicious: true).command == "cd /p && yarn remove axios")
        #expect(a("pnpm-lock.yaml", "x", .npm, direct: false).command == "cd /p && pnpm update --recursive x")
        #expect(a("poetry.lock", "requests", .pypi, direct: true).command == "cd /p && poetry add 'requests>=2.0.0'")
        #expect(a("poetry.lock", "idna", .pypi, direct: false).command == "cd /p && poetry update idna")
        #expect(a("Cargo.lock", "time", .crates, direct: true).command == "cd /p && cargo add time@2.0.0")
        #expect(a("Cargo.lock", "time", .crates, direct: false).command == "cd /p && cargo update -p time --precise 2.0.0")
        #expect(a("go.sum", "golang.org/x/net", .go, direct: false, target: "v0.33.0").command == "cd /p && go get golang.org/x/net@v0.33.0")
        #expect(a("Gemfile.lock", "rack", .rubygems, direct: false).command == "cd /p && bundle update --conservative rack")
        #expect(a("composer.lock", "guzzlehttp/guzzle", .packagist, direct: true).command == "cd /p && composer require 'guzzlehttp/guzzle:^2.0.0'")
        #expect(a("requirements.txt", "django", .pypi, direct: true).command == "cd /p && python3 -m pip install 'django>=2.0.0'")
        #expect(a("package-lock.json", "lodash", .npm, direct: nil).command == "cd /p && npm install 'lodash@^2.0.0'")   // unknown: as direct
    }
}

@Suite struct ScannerTests {
    /// A whole scan against recorded tools and recorded API answers.
    @Test func endToEnd() async throws {
        let home = temporaryDirectory()
        let support = home.appendingPathComponent("support")
        let project = home.appendingPathComponent("code/shop")
        write(#"{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/left-pad":{"version":"1.3.0"},"node_modules/our-internal-ui":{"version":"3.0.0"}}}"#,
              to: project.appendingPathComponent("package-lock.json"))
        let brew = "/opt/homebrew/bin/brew"
        let brewJSON = #"{"formulae":[{"name":"nginx","installed":[{"version":"1.30.2"}],"linked_keg":"1.30.2","homepage":"https://nginx.org/","urls":{"stable":{"url":"https://nginx.org/download/nginx-1.30.2.tar.gz"}}},{"name":"our-internal-tool","installed":[{"version":"1.0"}],"homepage":"https://git.example.com/x"}],"casks":[]}"#
        let tools = ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [
            "\(brew) info --json=v2 --installed": CommandResult(status: 0, stdout: Data(brewJSON.utf8), stderr: Data()),
        ]), isExecutable: { $0 == brew })
        let transport = RecordedTransport.site(batch: "api/check-batch-malicious.json")
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: support), tools: tools, folders: [project],
                                                               applicationRoots: [home.appendingPathComponent("Applications")]),
                              transport: transport, pause: { _ in })
        let report = await scanner.scan()

        #expect(report.problems.isEmpty, "\(report.problems)")
        #expect(report.findings.map(\.title) == ["axios", "nginx", "lodash"])
        #expect(report.findings[0].group == .malicious)
        #expect(report.findings[1].bigIssue != nil && report.findings[1].fixedVersion == "1.30.7")

        // What left the Mac: index entries only. The internal package and tool, left-pad (not in the index) and the
        // folder's path never did.
        let sent = report.sent.distinctItems
        #expect(sent == ["npm axios 1.14.1", "npm lodash 4.17.20", "project nginx"])
        #expect(report.sent.withheldCount == 3)
        // and the names that stayed here are kept, by where they were found, for Settings to show
        #expect(report.sent.withheld == [Coverage.Bucket(source: "Homebrew", items: ["our-internal-tool 1.0"]),
                                         Coverage.Bucket(source: "Folders", items: ["left-pad 1.3.0", "our-internal-ui 3.0.0"])])
        #expect(report.sent.cached.isEmpty && report.sent.answeredFromCache == 0)
        // and what was not vouched for is said, not counted as clean
        #expect(report.coverage.notInIndex == [Coverage.Bucket(source: "Folders", items: ["left-pad 1.3.0", "our-internal-ui 3.0.0"])])
        #expect(report.coverage.notChecked == [Coverage.Bucket(source: "Homebrew packages with no graded project", items: ["our-internal-tool 1.0"])])
        for r in transport.requests {
            let wire = (r.url?.absoluteString ?? "") + String(decoding: r.httpBody ?? Data(), as: UTF8.self)
            for secret in ["our-internal", "left-pad", "shop", home.path] { #expect(!wire.contains(secret), "\(secret) left the Mac in \(wire)") }
        }

        // A second scan right away answers from the cache and sends nothing new.
        let before = transport.requests.count
        let again = await scanner.scan(previous: report)
        #expect(again.findings.map(\.id) == report.findings.map(\.id))
        #expect(again.sent.requests.isEmpty)
        #expect(transport.requests.count == before)
        // and says what the cache answered, as it was sent the first time
        #expect(again.sent.cached == ["npm axios 1.14.1", "npm lodash 4.17.20", "project nginx"])
        #expect(again.sent.answeredFromCache == 3)
        #expect(again.sent.withheld == report.sent.withheld)
    }

    /// Each name once per source, sources in their usual order, Homebrew's unmatched formulae under Homebrew.
    @Test func withheldByWhereItWasFound() {
        let folder = Origin.folder(root: "/r", lockfile: "/r/package-lock.json", direct: true)
        let other = Origin.folder(root: "/s", lockfile: "/s/package-lock.json", direct: false)
        let packages = [InstalledPackage(ecosystem: .npm, name: "left-pad", version: "1.3.0", origin: folder),
                        InstalledPackage(ecosystem: .npm, name: "left-pad", version: "1.3.0", origin: other),
                        InstalledPackage(ecosystem: .npm, name: "Zeta", version: "1.0.0", origin: folder),
                        InstalledPackage(ecosystem: .pypi, name: "six", version: "1.15.0", origin: .pip(python: Fixture.applePython, user: false, formula: nil))]
        let brew = [HomebrewItem(kind: .formula, name: "jq", version: "1.8.1", urls: []), HomebrewItem(kind: .cask, name: "slack", version: "4.51", urls: [])]
        #expect(Scanner.withheld(packages, unmatchedBrew: brew) == [
            .init(source: "Homebrew", items: ["jq 1.8.1", "slack 4.51"]),
            .init(source: "pip", items: ["six 1.15.0"]),
            .init(source: "Folders", items: ["left-pad 1.3.0", "Zeta 1.0.0"]),
        ])
    }

    /// The lists are kept to SentRecord.listLimit names, the counts stay exact, and the cut survives saving.
    @Test func sentListsAreBounded() throws {
        let limit = SentRecord.listLimit
        let cached = (0..<(limit + 7)).map { "npm p\($0) 1.0.0" }
        let withheld = [Coverage.Bucket(source: "pip", items: (0..<(limit - 2)).map { "a\($0) 1" }),
                        Coverage.Bucket(source: "Folders", items: (0..<5).map { "b\($0) 1" }),
                        Coverage.Bucket(source: "RubyGems", items: ["c 1"])]
        let record = SentRecord(withheldCount: limit + 4, answeredFromCache: cached.count, cached: cached, withheld: withheld)
        #expect(record.cached.count == limit && record.cached.last == "npm p\(limit - 1) 1.0.0")
        #expect(record.withheld.map(\.source) == ["pip", "Folders"])
        #expect(record.withheld.map(\.items.count) == [limit - 2, 2])
        #expect(record.answeredFromCache == limit + 7 && record.withheldCount == limit + 4)
        let data = try JSONEncoder().encode(record)
        #expect(try JSONDecoder().decode(SentRecord.self, from: data) == record)
    }

    /// A report saved by 0.1.0, before the lists were kept, still opens: the counts without names.
    @Test func reportsFromBeforeTheListsStillLoad() throws {
        let old = #"{"requests":[{"endpoint":"GET api/v1/project","items":["project openssh"]}],"withheldCount":760,"answeredFromCache":245}"#
        let record = try JSONDecoder().decode(SentRecord.self, from: Data(old.utf8))
        #expect(record.withheldCount == 760 && record.answeredFromCache == 245)
        #expect(record.cached.isEmpty && record.withheld.isEmpty)
    }

    @Test func withoutTheIndexNothingIsSent() async {
        let home = temporaryDirectory()
        let transport = RecordedTransport { _, _ in .init(status: 503, body: Data()) }
        let tools = ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: home), tools: tools, folders: [], applicationRoots: []),
                              transport: transport, pause: { _ in })
        let report = await scanner.scan()
        #expect(report.findings.isEmpty)
        #expect(report.problems.contains { $0.hasPrefix("Could not download the public index") })
        #expect(transport.requests.allSatisfy { $0.url == SiteURL.index })
    }

    @Test func reportsSurviveARestart() throws {
        let dir = temporaryDirectory()
        let finding = Finding(id: "x", group: .exploited, subject: .project(slug: "openssh", name: "OpenSSH", installedAs: "openssh"), title: "OpenSSH",
                              installedVersion: "10.6p1", fixedVersion: "10.6p2", severity: .high, advisoryIDs: ["CVE-1"], flawCount: 1,
                              exploited: true, malicious: false, note: nil, bigIssue: nil, origins: [.homebrewFormula(name: "openssh")],
                              pageURL: SiteURL.projectPage(slug: "openssh"), upgradeCommand: "brew upgrade openssh", verification: .parts, grade: "U")
        let report = ScanReport(startedAt: Date(timeIntervalSince1970: 1_800_000_000), finishedAt: Date(timeIntervalSince1970: 1_800_000_060),
                                inventory: Inventory(), findings: [finding],
                                sent: SentRecord(requests: [SentRequest(endpoint: "GET api/v1/project", items: ["project openssh"])], withheldCount: 2,
                                                 answeredFromCache: 1, cached: ["npm axios 1.14.1"],
                                                 withheld: [Coverage.Bucket(source: "pip", items: ["six 1.15.0", "mlx 0.32.4"])]),
                                indexGeneratedAt: "2026-11-19T01:32:46Z", problems: [])
        let storage = Storage(directory: dir)
        storage.save(report)
        #expect(storage.loadLastReport() == report)
        var settings = MonitorSettings(); settings.watchedFolders = ["/Users/ana/code"]; settings.scanIntervalHours = 3
        storage.save(settings)
        #expect(storage.loadSettings() == settings)
    }
}
