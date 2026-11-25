import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// The whole loop of a fix, as the app runs it: the button opens the review, Update runs the command inside the app
/// (a real process, no shell), the row shows its steps and its log, the app checks the finding again, and the row
/// says what happened. The tools are stand-ins in a temporary home: an npm that records what it was asked and changes
/// the version it reports, and a Python whose pip installs into a folder of METADATA files.
@MainActor @Suite(.serialized) struct FixLoopTests {
    /// Runs a Terminal fallback script as Terminal would, minus the window and the key.
    struct ScriptRunner: TerminalOpener {
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) {
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = script
                p.environment = ["PATH": "/usr/bin:/bin", FixScript.noWaitVariable: "1"]
                p.standardInput = FileHandle.nullDevice
                p.standardOutput = FileHandle.nullDevice
                p.standardError = FileHandle.nullDevice
                do { try p.run(); completion(nil) } catch { completion(error.localizedDescription) }
            }
        }
    }

    struct Refused: TerminalOpener {
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) { completion("Terminal is not on this Mac") }
    }

    /// The site: an index that lists the packages, and a batch answer that has lodash 4.17.20 and chalk 4.0.0
    /// vulnerable (fixed in 4.17.21 and 4.1.2) and nothing to report about any other version.
    final class Site: HTTPTransport, @unchecked Sendable {
        let lock = NSLock()
        var bodies: [String] = []
        let index: String
        init(index: String = "K\tnpm\tlodash\nK\tnpm\tchalk\n") { self.index = index }
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let body: Data
            switch request.url!.path {
            case "/data/app-index.tsv": body = Data(("#osva-app-index\t1\t2026-11-19T03:00:00Z\t1\t0\n" + index).utf8)
            case "/api/v1/check/batch":
                let asked = String(decoding: request.httpBody ?? Data(), as: UTF8.self)
                lock.withLock { bodies.append(asked) }
                var packages: [String] = []
                for (name, version, fixed) in [("lodash", "4.17.20", "4.17.21"), ("chalk", "4.0.0", "4.1.2")]
                where asked.contains(#""name":"\#(name)","platform":"macos","version":"\#(version)""#) {
                    packages.append(#"{"ecosystem":"npm","name":"\#(name)","version":"\#(version)","malicious":false,"distinct_flaws":1,"worst_severity":"HIGH","advisories":["GHSA-x"],"flaws":[{"id":"GHSA-x","severity":"HIGH","fixed_in":["\#(fixed)"],"ranges":[{"fixed":"\#(fixed)"}]}],"plan":{"target":"\#(fixed)","fixes":["GHSA-x"],"remaining":[]}}"#)
                }
                body = Data(#"{"checked":1,"packages":[\#(packages.joined(separator: ","))]}"#.utf8)
            default: body = Data("{}".utf8)
            }
            return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
        }
    }

    struct Quiet: Notifier {
        var isAvailable: Bool { false }
        func requestPermission() async {}
        func post(_ findings: [Finding]) async {}
    }

    struct Home {
        var model: AppModel
        var findings: [Finding]
        var bin: URL
        var site: Site
        var finding: Finding { findings[0] }
    }

    /// A temporary home with a stand-in npm in ~/.volta/bin, and a last scan that found lodash 4.17.20 (and chalk
    /// 4.0.0) there. `mode` in the folder makes npm fail once, or fail asking for a password inside the app (CI=1)
    /// while it works in Terminal.
    func setUp(terminal: any TerminalOpener = ScriptRunner(), mode: String = "ok") throws -> Home {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("osva-fixloop-\(UUID().uuidString)", isDirectory: true)
        let bin = home.appendingPathComponent(".volta/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try Data(mode.utf8).write(to: bin.appendingPathComponent("mode"))
        let npm = bin.appendingPathComponent("npm")
        try Data("""
        #!/bin/sh
        here="$(dirname "$0")"
        state="$here/lodash-version"
        case "$1" in
          install)
            mode="$(cat "$here/mode")"
            if [ "$mode" = "password" ] && [ -n "$CI" ]; then
              echo "==> Running installer with sudo; the password may be necessary."
              echo "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper" >&2
              exit 1
            fi
            if [ "$mode" = "fail-once" ]; then echo ok > "$here/mode"; echo "npm ERR! code ECONNRESET" >&2; exit 1; fi
            printf '%s\\0' "$@" > "$here/argv"; echo "${3##*@}" > "$state"
            printf '\\033[32madded\\033[0m 1 package\\n'; echo "changed 1 package" ;;
          ls) printf '{"dependencies":{"lodash":{"version":"%s"},"chalk":{"version":"4.0.0"}}}' "$(cat "$state" 2>/dev/null || echo 4.17.20)" ;;
        esac

        """.utf8).write(to: npm)
        chmod(npm.path, 0o755)
        let tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(),
                                    isExecutable: { $0.hasPrefix(home.path) && FileManager.default.isExecutableFile(atPath: $0) })
        func make(_ name: String, _ installed: String, _ fixed: String) -> (Finding, InstalledPackage) {
            let inputs = UpgradeCommand.Inputs(origin: .npmGlobal(npm: npm.path), name: name, ecosystem: .npm, target: PreviewData.fix(fixed, above: installed),
                                               malicious: false)
            let f = Finding(id: "pkg|npm|\(name)|\(installed)", group: .criticalHigh, subject: .package(ecosystem: .npm, name: name), title: name,
                            installedVersion: installed, fixedVersion: fixed, severity: .high, advisoryIDs: ["GHSA-x"], flawCount: 1,
                            exploited: false, malicious: false, note: nil, bigIssue: nil, origins: [inputs.origin],
                            pageURL: SiteURL.packagePage(.npm, name, version: installed), upgradeCommand: UpgradeCommand.advice(inputs).command,
                            verification: .none, grade: nil, commandInputs: inputs)
            return (f, InstalledPackage(ecosystem: .npm, name: name, version: installed, origin: inputs.origin))
        }
        let lodash = make("lodash", "4.17.20", "4.17.21"), chalk = make("chalk", "4.0.0", "4.1.2")
        let storage = Storage(directory: home.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: [lodash.1, chalk.1]),
                                findings: [lodash.0, chalk.0], sent: SentRecord(), indexGeneratedAt: nil, problems: []))
        let site = Site()
        let model = AppModel(storage: storage, notifier: Quiet(), tools: tools, transport: site)
        model.terminal = terminal
        return Home(model: model, findings: [lodash.0, chalk.0], bin: bin, site: site)
    }

    func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0..<400 where !condition() { try await Task.sleep(for: .milliseconds(50)) }
    }

    func finished(_ model: AppModel, _ id: String) -> Bool {
        if case .finished? = model.fixes[id]?.progress { true } else { false }
    }

    /// Offer, review, Update: the row is ready to run.
    func review(_ h: Home, _ f: Finding) async throws {
        h.model.assessFix(f)
        try await waitUntil { h.model.fixes[f.id]?.availability != .checking }
        h.model.beginFix(f)
        try await waitUntil { h.model.fixes[f.id]?.preview != .loading }
    }

    @Test func aFixRunsInTheAppAndTheRowSaysFixed() async throws {
        let h = try setUp()
        let (model, finding) = (h.model, h.finding)
        model.assessFix(finding)
        guard case let .offered(offer)? = model.fixes[finding.id]?.availability else { Issue.record("no button"); return }
        #expect(offer.plan.command == "\(h.bin.path)/npm install -g lodash@4.17.21" && offer.plan.actionTitle == "Update to 4.17.21")
        #expect(offer.plan.invocation.argv == ["\(h.bin.path)/npm", "install", "-g", "lodash@4.17.21"])

        model.beginFix(finding)
        try await waitUntil { model.fixes[finding.id]?.preview != .loading }
        #expect(model.fixes[finding.id]?.preview == .ready(.none("npm has no dry run the app uses: the log shows what changes.")))

        model.runFix(finding)
        #expect(model.fixes[finding.id]?.progress == .running && model.fixes[finding.id]?.preview == nil)
        #expect(model.fixes[finding.id]?.run?.step == .preparing && model.activeFix == finding.id)
        #expect(model.initiallyExpanded.contains(finding.id))                       // a panel opened again shows the run
        try await waitUntil { finished(model, finding.id) }

        #expect(model.fixes[finding.id]?.progress == .finished(.fixed(now: "4.17.21")))
        let argv = try String(contentsOf: h.bin.appendingPathComponent("argv"), encoding: .utf8).split(separator: "\0").map(String.init)
        #expect(argv == ["install", "-g", "lodash@4.17.21"])                                // what ran is what was shown
        let run = try #require(model.fixes[finding.id]?.run)
        #expect(run.log.lines == ["added 1 package", "changed 1 package"])             // its output, without the colour codes
        #expect(run.step == .checking && run.endedAt != nil)
        #expect(h.site.lock.withLock { h.site.bodies } == [#"{"packages":[{"ecosystem":"npm","name":"lodash","platform":"macos","version":"4.17.21"}]}"#])
        #expect(model.report?.findings.map(\.id) == [h.findings[1].id] && model.resolved.map(\.id) == [finding.id])
        #expect(model.activeFix == nil)
        // nothing went near Terminal: no script was written
        let scripts = h.bin.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("support/fixes")
        #expect(((try? FileManager.default.contentsOfDirectory(atPath: scripts.path)) ?? []).isEmpty)
    }

    @Test func nothingRunsWithoutTheReview() throws {
        let h = try setUp()
        h.model.assessFix(h.finding)
        h.model.runFix(h.finding)                                                   // Update without the review first: ignored
        #expect(h.model.fixes[h.finding.id]?.progress == nil)
        h.model.runFixInTerminal(h.finding)                                         // Terminal only after a password prompt
        #expect(h.model.fixes[h.finding.id]?.progress == nil)
        #expect(!FileManager.default.fileExists(atPath: h.bin.appendingPathComponent("argv").path))
    }

    @Test func aFailedRunKeepsItsLogAndRetryRunsItAgain() async throws {
        let h = try setUp(mode: "fail-once")
        try await review(h, h.finding)
        h.model.runFix(h.finding)
        try await waitUntil { finished(h.model, h.finding.id) }
        #expect(h.model.fixes[h.finding.id]?.outcome == .exitedWithError(1))
        #expect(h.model.fixes[h.finding.id]?.run?.log.lines == ["npm ERR! code ECONNRESET"])
        try await waitUntil { if case .offered? = h.model.fixes[h.finding.id]?.availability { true } else { false } }

        h.model.retryFix(h.finding)
        #expect(h.model.fixes[h.finding.id]?.progress == .running)
        try await waitUntil { finished(h.model, h.finding.id) }
        #expect(h.model.fixes[h.finding.id]?.progress == .finished(.fixed(now: "4.17.21")))
    }

    @Test func theRowFollowsTheRunStepByStep() async throws {
        let h = try setUp()
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await review(h, h.finding)
        h.model.runFix(h.finding)
        try await waitUntil { !launcher.runs.isEmpty }
        let run = launcher.runs[0]
        #expect(run.invocation.argv == ["\(h.bin.path)/npm", "install", "-g", "lodash@4.17.21"])
        #expect(h.model.fixes[h.finding.id]?.run?.step == .running)
        run.print("one\n")
        try await waitUntil { h.model.fixes[h.finding.id]?.run?.log.lines == ["one"] }
        run.print("\u{1B}[1mtwo\u{1B}[0m\nthr")
        try await waitUntil { h.model.fixes[h.finding.id]?.run?.log.partial == "thr" }
        #expect(h.model.fixes[h.finding.id]?.run?.log.lines == ["one", "two"])
        #expect(h.model.fixes[h.finding.id]?.isBusy == true)
        run.end(.exited(0))
        try await waitUntil { finished(h.model, h.finding.id) }
        // the fake changed nothing, and the check says so
        #expect(h.model.fixes[h.finding.id]?.outcome == .stillAffected("still 4.17.20; the command did not change it"))
    }

    @Test func oneFixAtATime() async throws {
        let h = try setUp()
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        let (lodash, chalk) = (h.findings[0], h.findings[1])
        try await review(h, lodash)
        try await review(h, chalk)
        h.model.runFix(lodash)
        try await waitUntil { launcher.runs.count == 1 }
        h.model.runFix(chalk)                                                     // waits: nothing starts
        h.model.retryFix(chalk)
        #expect(launcher.runs.count == 1 && h.model.fixes[chalk.id]?.progress == nil)
        #expect(h.model.rowFixes[chalk.id]?.waitingFor == "lodash" && h.model.rowFixes[lodash.id]?.waitingFor == nil)
        launcher.runs[0].end(.exited(0))
        try await waitUntil { finished(h.model, lodash.id) }
        #expect(h.model.rowFixes[chalk.id]?.waitingFor == nil)
        h.model.runFix(chalk)
        try await waitUntil { launcher.runs.count == 2 }
        #expect(launcher.runs[1].invocation.arguments == ["install", "-g", "chalk@4.1.2"])
        launcher.runs[1].end(.exited(0))
        try await waitUntil { finished(h.model, chalk.id) }
    }

    @Test func stopIsHonest() async throws {
        let h = try setUp()
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await review(h, h.finding)
        h.model.runFix(h.finding)
        try await waitUntil { !launcher.runs.isEmpty }
        launcher.runs[0].print("working\n")
        h.model.stopFix(h.finding)
        #expect(launcher.runs[0].stopAsked)
        try await waitUntil { finished(h.model, h.finding.id) }
        #expect(h.model.fixes[h.finding.id]?.outcome == .stopped("still 4.17.20"))
        #expect(h.model.fixes[h.finding.id]?.outcome?.text == "Stopped — still 4.17.20")
    }

    /// The tool asks for an administrator password: the run stops cleanly, the row says why, and only then offers
    /// Terminal, whose script (the 0.2.0 path, kept for this) runs it where a password can be typed.
    @Test func aPasswordPromptOffersTerminalAndOnlyThen() async throws {
        let h = try setUp(mode: "password")
        try await review(h, h.finding)
        h.model.runFix(h.finding)
        try await waitUntil { finished(h.model, h.finding.id) }
        #expect(h.model.fixes[h.finding.id]?.outcome == .needsPassword)
        #expect(h.model.fixes[h.finding.id]?.run?.log.lines.last?.hasPrefix("sudo: a terminal is required") == true)

        h.model.assessFix(h.findings[1])
        h.model.runFixInTerminal(h.finding)
        #expect(h.model.fixes[h.finding.id]?.progress == .running && h.model.fixes[h.finding.id]?.run == nil)   // "Running in Terminal…"
        #expect(h.model.rowFixes[h.findings[1].id]?.waitingFor == "lodash")       // one at a time, Terminal too
        try await waitUntil { finished(h.model, h.finding.id) }
        #expect(h.model.fixes[h.finding.id]?.progress == .finished(.fixed(now: "4.17.21")))
        let support = h.bin.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("support")
        #expect((try FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("fixes").path)).isEmpty)
        #expect((try FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("fix-results").path)).isEmpty)
    }

    @Test func whenTerminalCannotOpenTheRowSaysSo() async throws {
        let h = try setUp(terminal: Refused(), mode: "password")
        try await review(h, h.finding)
        h.model.runFix(h.finding)
        try await waitUntil { finished(h.model, h.finding.id) }
        h.model.runFixInTerminal(h.finding)
        try await waitUntil { if case .finished(.couldNotOpen)? = h.model.fixes[h.finding.id]?.progress { true } else { false } }
        #expect(h.model.fixes[h.finding.id]?.progress == .finished(.couldNotOpen("Terminal is not on this Mac")))
        #expect(h.model.report?.findings.map(\.id).contains(h.finding.id) == true)     // nothing changed
    }

    // MARK: pip

    /// A Python in a temporary home whose pip installs into `site/` as METADATA files, and marks what its command line
    /// names REQUESTED, as pip does. Its dry run names starlette alone (or, with `reveal`, anyio 5 too); the real
    /// install also brings anyio 5, which httpx (which needs anyio < 5) then lacks; `--no-deps` puts versions back.
    func setUpPip(withFastapi: Bool = false) throws -> (AppModel, Finding, URL) {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("osva-fixloop-pip-\(UUID().uuidString)", isDirectory: true)
        let bin = home.appendingPathComponent("bin", isDirectory: true), site = home.appendingPathComponent("site", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let python = bin.appendingPathComponent("python")
        try Data(#"""
        #!/bin/sh
        here="$(cd "$(dirname "$0")" && pwd)"
        site="$here/../site"
        put() {
          name="$1"; version="$2"; shift 2
          rm -rf "$site/$name"-*.dist-info
          d="$site/$name-$version.dist-info"; mkdir -p "$d"
          { printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$name" "$version"; for r in "$@"; do printf 'Requires-Dist: %s\n' "$r"; done; } > "$d/METADATA"
        }
        if [ "$1" = "--setup" ]; then
          put starlette 0.48.0 "anyio<5,>=3.6.2"; put anyio 4.0.0; put httpx 0.27.0 "anyio<5"
          [ -n "$2" ] && put fastapi 0.120.0 "starlette<0.49.0,>=0.40.0"
          exit 0
        fi
        if [ "$1" = "-c" ]; then printf '{"path":["%s"],"markers":{"python_version":"3.11","sys_platform":"darwin"}}\n' "$site"; exit 0; fi
        [ "$1" = "-m" ] && [ "$2" = "pip" ] || exit 2
        shift 2
        case "$1" in
          --version) echo "pip 24.0 from $here (python 3.11)" ;;
          check) if [ -f "$here/broken" ]; then echo "httpx 0.27.0 has requirement anyio<5, but you have anyio 5.0.0."; exit 1; fi
                 echo "No broken requirements found." ;;
          install)
            case " $* " in
              *" --dry-run "*) if [ -f "$here/reveal" ]; then echo "Would install anyio-5.0.0 starlette-1.3.1"; else echo "Would install starlette-1.3.1"; fi
                               exit 0 ;;
            esac
            for a in "$@"; do printf '%s\0' "$a"; done >> "$here/installs"; echo >> "$here/installs"
            case " $* " in
              *" --no-deps "*) for a in "$@"; do case "$a" in *==*) put "${a%%==*}" "${a#*==}"; touch "$site/${a%%==*}-${a#*==}.dist-info/REQUESTED" ;; esac; done
                               rm -f "$here/broken"; echo "Successfully installed (put back)" ;;
              *) echo "Collecting starlette==1.3.1"; put starlette 1.3.1 "anyio>=5"; touch "$site/starlette-1.3.1.dist-info/REQUESTED"; put anyio 5.0.0
                 touch "$here/broken"; echo "Successfully installed anyio-5.0.0 starlette-1.3.1" ;;
            esac ;;
          *) exit 2 ;;
        esac

        """#.utf8).write(to: python)
        chmod(python.path, 0o755)
        let setup = Process()
        setup.executableURL = python
        setup.arguments = ["--setup"] + (withFastapi ? ["fastapi"] : [])
        try setup.run(); setup.waitUntilExit()
        _ = site

        let tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(),
                                    isExecutable: { $0.hasPrefix(home.path) && FileManager.default.isExecutableFile(atPath: $0) })
        let env = PythonEnvironment(executable: python.path, version: "3.11.14", kind: .virtualEnv, externallyManaged: false, userSite: nil, formula: nil)
        let inputs = UpgradeCommand.Inputs(origin: .pip(python: env, user: false, formula: nil), name: "starlette", ecosystem: .pypi,
                                           target: PreviewData.fix("1.3.1", above: "0.48.0"), malicious: false)
        let finding = Finding(id: "pkg|PyPI|starlette|0.48.0", group: .exploited, subject: .package(ecosystem: .pypi, name: "starlette"), title: "starlette",
                              installedVersion: "0.48.0", fixedVersion: "1.3.1", severity: .high, advisoryIDs: ["GHSA-x"], flawCount: 6,
                              exploited: true, malicious: false, note: nil, bigIssue: nil, origins: [inputs.origin],
                              pageURL: SiteURL.packagePage(.pypi, "starlette", version: "0.48.0"), upgradeCommand: UpgradeCommand.advice(inputs).command,
                              verification: .none, grade: nil, commandInputs: inputs)
        let storage = Storage(directory: home.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: [
            InstalledPackage(ecosystem: .pypi, name: "starlette", version: "0.48.0", origin: inputs.origin)]), findings: [finding], sent: SentRecord(),
                                indexGeneratedAt: nil, problems: []))
        let model = AppModel(storage: storage, notifier: Quiet(), tools: tools, transport: Site(index: "K\tPyPI\tstarlette\n"))
        return (model, finding, bin)
    }

    func installs(_ bin: URL) -> [[String]] {
        let text = (try? String(contentsOf: bin.appendingPathComponent("installs"), encoding: .utf8)) ?? ""
        return text.split(separator: "\n").map { $0.split(separator: "\0").map(String.init) }
    }

    /// The starlette case from the owner's Mac, with fastapi 0.120.0 installed: no button, and why in one line.
    @Test func anUpgradeThatWouldBreakADependentIsNotOffered() async throws {
        let (model, finding, bin) = try setUpPip(withFastapi: true)
        model.assessFix(finding)
        #expect(model.fixes[finding.id]?.availability == .checking)
        try await waitUntil { model.fixes[finding.id]?.availability != .checking }
        // nothing else needs fastapi and nobody asked for it, so the line says what would clear the way
        #expect(model.fixes[finding.id]?.availability
            == .withheld("fastapi 0.120.0 needs starlette < 0.49.0 — nothing installed needs fastapi: removing it would clear the way."))
        model.beginFix(finding); model.runFix(finding)
        #expect(installs(bin).isEmpty && model.fixes[finding.id]?.progress == nil)
    }

    /// Rule A-R4: the dry run comes first, and what it would also install is checked like the package itself.
    @Test func whatTheDryRunRevealsBlocksTheRun() async throws {
        let (model, finding, bin) = try setUpPip()
        try Data().write(to: bin.appendingPathComponent("reveal"))
        model.assessFix(finding)
        try await waitUntil { model.fixes[finding.id]?.availability != .checking }
        model.beginFix(finding)
        try await waitUntil { model.fixes[finding.id]?.preview != .loading }
        guard case let .ready(p)? = model.fixes[finding.id]?.preview else { Issue.record("no review"); return }
        #expect(p.installs == ["starlette": "1.3.1", "anyio": "5.0.0"])
        #expect(p.blocked == "httpx 0.27.0 needs anyio < 5 — nothing installed needs httpx: removing it would clear the way" && p.pins.isEmpty)
        model.runFix(finding)                                                      // Update is not there: nothing runs
        #expect(installs(bin).isEmpty && model.fixes[finding.id]?.progress == nil)
    }

    /// One it could not see coming (pip also brought anyio 5, which httpx cannot take): "Updated, but it broke httpx",
    /// never "Fixed", and Undo puts back exactly the versions that changed.
    @Test func anUpgradeThatBrokeSomethingSaysSoAndUndoes() async throws {
        let (model, finding, bin) = try setUpPip()
        model.assessFix(finding)
        try await waitUntil { model.fixes[finding.id]?.availability != .checking }
        guard case let .offered(offer)? = model.fixes[finding.id]?.availability else { Issue.record("\(String(describing: model.fixes[finding.id]))"); return }
        #expect(offer.plan.command.hasSuffix("-m pip install --upgrade starlette==1.3.1"))
        model.beginFix(finding)
        try await waitUntil { model.fixes[finding.id]?.preview != .loading }
        model.runFix(finding)
        try await waitUntil { finished(model, finding.id) }

        #expect(model.fixes[finding.id]?.outcome == .broke("httpx 0.27.0"))
        #expect(model.fixes[finding.id]?.isResolved == false)
        // pip marked starlette REQUESTED; it was not before, so the mark is gone (rule A-R6)
        let siteDir = bin.deletingLastPathComponent().appendingPathComponent("site")
        #expect(!FileManager.default.fileExists(atPath: siteDir.appendingPathComponent("starlette-1.3.1.dist-info/REQUESTED").path))
        let undo = try #require(model.fixes[finding.id]?.run?.undo)
        #expect(undo.invocation.arguments == ["-m", "pip", "install", "--no-deps", "--disable-pip-version-check", "anyio==4.0.0", "starlette==0.48.0"])
        #expect(installs(bin) == [["install", "--upgrade", "starlette==1.3.1"]])
        #expect(model.resolved.map(\.id) == [finding.id] || model.report?.findings.contains { $0.id == finding.id } == true)   // the row stays

        model.undoFix(finding)
        #expect(model.fixes[finding.id]?.run?.doing == "Undoing")
        try await waitUntil { finished(model, finding.id) }
        #expect(model.fixes[finding.id]?.outcome == .undone("anyio 4.0.0, starlette 0.48.0"))
        #expect(installs(bin).last == ["install", "--no-deps", "--disable-pip-version-check", "anyio==4.0.0", "starlette==0.48.0"])
        let site = PythonSite.scan(folders: [siteDir.path])
        #expect(Dictionary(uniqueKeysWithValues: site.map { ($0.key, $0.version) }) == ["starlette": "0.48.0", "anyio": "4.0.0", "httpx": "0.27.0"])
        #expect(site.allSatisfy { !$0.requested })                                    // and the undo's marks too
    }
}

/// Starts nothing: each launch is a run the test prints into and ends.
final class FakeLauncher: FixLaunching, @unchecked Sendable {
    private let lock = NSLock()
    private var _runs: [FakeRun] = []
    var runs: [FakeRun] { lock.withLock { _runs } }

    func launch(_ invocation: FixInvocation, environment: [String: String], limits: FixLimits,
                update: @escaping @Sendable (FixLog) -> Void) -> any FixRunning {
        let r = FakeRun(invocation: invocation, update: update)
        lock.withLock { _runs.append(r) }
        return r
    }
}

final class FakeRun: FixRunning, @unchecked Sendable {
    let invocation: FixInvocation
    private let update: @Sendable (FixLog) -> Void
    private let lock = NSLock()
    private var text = TerminalText()
    private var result: (FixEnding, FixLog)?
    private var waiters: [CheckedContinuation<(FixEnding, FixLog), Never>] = []
    private var _stopAsked = false
    var stopAsked: Bool { lock.withLock { _stopAsked } }

    init(invocation: FixInvocation, update: @escaping @Sendable (FixLog) -> Void) { self.invocation = invocation; self.update = update }

    func print(_ s: String) {
        let log = lock.withLock { text.feed(Array(s.utf8)); return text.log }
        update(log)
    }

    func end(_ e: FixEnding) {
        let (log, waiting): (FixLog, [CheckedContinuation<(FixEnding, FixLog), Never>]) = lock.withLock {
            text.finish()
            result = (e, text.log)
            defer { waiters = [] }
            return (text.log, waiters)
        }
        waiting.forEach { $0.resume(returning: (e, log)) }
    }

    func stop() {
        lock.withLock { _stopAsked = true }
        end(.stopped)
    }

    func ending() async -> (FixEnding, FixLog) {
        await withCheckedContinuation { c in
            let done: (FixEnding, FixLog)? = lock.withLock {
                if let result { return result }
                waiters.append(c)
                return nil
            }
            if let done { c.resume(returning: done) }
        }
    }
}
