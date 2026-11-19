import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// Fix all, as the app runs it: one review, then the rows' own fixes one at a time, through the single-fix loop. The
/// tools are stand-ins in a temporary home: an npm that keeps each package's version in a file (and can bring another
/// package along, fail, or ask for a password), and a Python whose pip installs into a folder of METADATA files.
/// FakeLauncher (FixLoopTests) holds a command until the test ends it.
@MainActor @Suite(.serialized) struct FixAllTests {
    /// One npm package on the stand-in's list: vulnerable at `installed`, fixed in `fixed`.
    struct Package {
        var name: String, installed: String, fixed: String
        var group: Finding.Group = .criticalHigh, severity: Severity = .high, exploited = false
    }

    /// The site: an index that lists every package, and a batch answer that has each package vulnerable at its
    /// installed version (starlette 0.48.0 too) and nothing to report about any other version.
    final class Site: HTTPTransport, @unchecked Sendable {
        let vulnerable: [(ecosystem: String, name: String, version: String, fixed: String)]
        init(_ vulnerable: [(String, String, String, String)]) { self.vulnerable = vulnerable.map { ($0.0, $0.1, $0.2, $0.3) } }
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let body: Data
            switch request.url!.path {
            case "/data/app-index.tsv":
                body = Data(("#osva-app-index\t1\t2026-11-19T03:00:00Z\t1\t0\n" + vulnerable.map { "K\t\($0.ecosystem)\t\($0.name)\n" }.joined()).utf8)
            case "/api/v1/check/batch":
                let asked = String(decoding: request.httpBody ?? Data(), as: UTF8.self)
                let packages = vulnerable.filter { asked.contains(#""name":"\#($0.name)","platform":"macos","version":"\#($0.version)""#) }.map { v in
                    #"{"ecosystem":"\#(v.ecosystem)","name":"\#(v.name)","version":"\#(v.version)","malicious":false,"distinct_flaws":1,"worst_severity":"HIGH","advisories":["GHSA-x"],"flaws":[{"id":"GHSA-x","severity":"HIGH","fixed_in":["\#(v.fixed)"]}],"plan":{"target":"\#(v.fixed)","fixes":["GHSA-x"],"remaining":[]}}"#
                }
                body = Data(#"{"checked":1,"packages":[\#(packages.joined(separator: ","))]}"#.utf8)
            default: body = Data("{}".utf8)
            }
            return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
        }
    }

    /// Opens nothing: counts how often it was asked.
    final class CountingTerminal: TerminalOpener, @unchecked Sendable {
        let lock = NSLock()
        var opened = 0
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) { lock.withLock { opened += 1 }; completion("not here") }
    }

    struct Home {
        var model: AppModel
        var findings: [Finding]
        var npm: URL
        var python: URL?
        func finding(_ name: String) -> Finding { findings.first { $0.title == name }! }
        func id(_ name: String) -> String { finding(name).id }
        /// What a command would have done, for a FakeLauncher run: the package at this version now.
        func installed(_ name: String, _ version: String) throws {
            try Data(version.utf8).write(to: npm.deletingLastPathComponent().appendingPathComponent("v-\(name)"))
        }
        /// The npm installs that really ran, in order.
        var npmInstalls: [String] {
            ((try? String(contentsOf: npm.deletingLastPathComponent().appendingPathComponent("installs"), encoding: .utf8)) ?? "")
                .split(separator: "\n").map(String.init)
        }
    }

    static let npmScript = """
    #!/bin/sh
    here="$(dirname "$0")"
    case "$1" in
      install)
        if [ "$(cat "$here/mode")" = "password" ] && [ -n "$CI" ]; then
          echo "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper" >&2
          exit 1
        fi
        spec="$3"; name="${spec%@*}"
        echo "$spec" >> "$here/installs"
        echo "${spec##*@}" > "$here/v-$name"
        if [ -f "$here/also-$name" ]; then other="$(cat "$here/also-$name")"; echo "${other##*@}" > "$here/v-${other%@*}"; fi
        echo "changed 1 package" ;;
      ls)
        printf '{"dependencies":{'; sep=""
        for f in "$here"/v-*; do n="${f##*/v-}"; printf '%s"%s":{"version":"%s"}' "$sep" "$n" "$(cat "$f")"; sep=","; done
        printf '}}' ;;
    esac

    """

    /// The pip stand-in of FixLoopTests' starlette case: its upgrade also brings anyio 5, which httpx cannot take.
    static let pythonScript = #"""
    #!/bin/sh
    here="$(cd "$(dirname "$0")" && pwd)"
    site="$here/../site"
    put() {
      name="$1"; version="$2"; shift 2
      rm -rf "$site/$name"-*.dist-info
      d="$site/$name-$version.dist-info"; mkdir -p "$d"
      { printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$name" "$version"; for r in "$@"; do printf 'Requires-Dist: %s\n' "$r"; done; } > "$d/METADATA"
    }
    if [ "$1" = "--setup" ]; then put starlette 0.48.0 "anyio<5,>=3.6.2"; put anyio 4.0.0; put httpx 0.27.0 "anyio<5"; exit 0; fi
    if [ "$1" = "-c" ]; then printf '{"path":["%s"],"markers":{"python_version":"3.11","sys_platform":"darwin"}}\n' "$site"; exit 0; fi
    [ "$1" = "-m" ] && [ "$2" = "pip" ] || exit 2
    shift 2
    case "$1" in
      --version) echo "pip 24.0 from $here (python 3.11)" ;;
      check) if [ -f "$here/broken" ]; then echo "httpx 0.27.0 has requirement anyio<5, but you have anyio 5.0.0."; exit 1; fi
             echo "No broken requirements found." ;;
      install)
        case " $* " in *" --dry-run "*) echo "Would install starlette-1.3.1"; exit 0 ;; esac
        for a in "$@"; do printf '%s\0' "$a"; done >> "$here/installs"; echo >> "$here/installs"
        case " $* " in
          *" --no-deps "*) for a in "$@"; do case "$a" in *==*) put "${a%%==*}" "${a#*==}" ;; esac; done
                           rm -f "$here/broken"; echo "Successfully installed (put back)" ;;
          *) put starlette 1.3.1 "anyio>=5"; put anyio 5.0.0; touch "$here/broken"; echo "Successfully installed anyio-5.0.0 starlette-1.3.1" ;;
        esac ;;
      *) exit 2 ;;
    esac

    """#

    /// A temporary home with the stand-in npm in ~/.volta/bin and these packages at their installed versions, and a
    /// last scan that found each of them (and, with `starlette`, the pip case). `refused` adds a finding whose npm is
    /// not on this Mac, so its row gets no button and says why.
    /// `twin`: a second lodash finding with the same command (as several of a formula's packages share its upgrade).
    func setUp(_ packages: [Package], starlette: Bool = false, refused: Bool = false, twin: Bool = false, mode: String = "ok",
               terminal: any TerminalOpener = CountingTerminal()) throws -> Home {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("osva-fixall-\(UUID().uuidString)", isDirectory: true)
        let bin = home.appendingPathComponent(".volta/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try Data(mode.utf8).write(to: bin.appendingPathComponent("mode"))
        let npm = bin.appendingPathComponent("npm")
        try Data(Self.npmScript.utf8).write(to: npm)
        chmod(npm.path, 0o755)
        for p in packages { try Data(p.installed.utf8).write(to: bin.appendingPathComponent("v-\(p.name)")) }

        var findings: [Finding] = [], inventory: [InstalledPackage] = []
        func add(_ origin: Origin, _ ecosystem: Ecosystem, _ name: String, _ installed: String, _ fixed: String, _ group: Finding.Group,
                 _ severity: Severity, _ exploited: Bool, id: String? = nil) {
            let inputs = UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: ecosystem, target: fixed, malicious: false)
            findings.append(Finding(id: id ?? "pkg|\(ecosystem.rawValue)|\(name)|\(installed)", group: group, subject: .package(ecosystem: ecosystem, name: name),
                                    title: name, installedVersion: installed, fixedVersion: fixed, severity: severity, advisoryIDs: ["GHSA-x"],
                                    flawCount: 1, exploited: exploited, malicious: false, note: nil, bigIssue: nil, origins: [origin],
                                    pageURL: SiteURL.packagePage(ecosystem, name, version: installed), upgradeCommand: UpgradeCommand.advice(inputs).command,
                                    verification: .none, grade: nil, commandInputs: inputs))
            inventory.append(InstalledPackage(ecosystem: ecosystem, name: name, version: installed, origin: origin))
        }
        for p in packages { add(.npmGlobal(npm: npm.path), .npm, p.name, p.installed, p.fixed, p.group, p.severity, p.exploited) }
        if refused { add(.npmGlobal(npm: home.appendingPathComponent("gone/npm").path), .npm, "left-pad", "1.0.0", "1.3.0", .criticalHigh, .high, false) }
        if twin, let p = packages.first {
            add(.npmGlobal(npm: npm.path), .npm, p.name, p.installed, p.fixed, p.group, p.severity, p.exploited, id: "pkg|npm|\(p.name)|\(p.installed)|twin")
            inventory.removeLast()
        }

        var python: URL?
        if starlette {
            let pbin = home.appendingPathComponent("bin", isDirectory: true)
            try FileManager.default.createDirectory(at: pbin, withIntermediateDirectories: true)
            let py = pbin.appendingPathComponent("python")
            try Data(Self.pythonScript.utf8).write(to: py)
            chmod(py.path, 0o755)
            let setup = Process()
            setup.executableURL = py
            setup.arguments = ["--setup"]
            try setup.run(); setup.waitUntilExit()
            let env = PythonEnvironment(executable: py.path, version: "3.11.14", kind: .virtualEnv, externallyManaged: false, userSite: nil, formula: nil)
            add(.pip(python: env, user: false, formula: nil), .pypi, "starlette", "0.48.0", "1.3.1", .exploited, .high, true)
            python = py
        }

        let tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(),
                                    isExecutable: { $0.hasPrefix(home.path) && FileManager.default.isExecutableFile(atPath: $0) })
        let storage = Storage(directory: home.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: inventory),
                                findings: FindingOrder.sorted(findings), sent: SentRecord(), indexGeneratedAt: nil, problems: []))
        let site = Site(packages.map { ("npm", $0.name, $0.installed, $0.fixed) } + (starlette ? [("PyPI", "starlette", "0.48.0", "1.3.1")] : []))
        let model = AppModel(storage: storage, notifier: FixLoopTests.Quiet(), tools: tools, transport: site)
        model.terminal = terminal
        return Home(model: model, findings: findings, npm: npm, python: python)
    }

    func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0..<400 where !condition() { try await Task.sleep(for: .milliseconds(50)) }
    }

    /// Every row decided (pip's are read in the background).
    func assessed(_ h: Home) async throws {
        h.model.assessAllFixes()
        try await waitUntil { !h.model.fixAllPanel.checking }
    }

    func done(_ h: Home) -> Bool { h.model.fixAll?.phase == .done }

    /// lodash high, chalk critical, debug moderate, minimist exploited: four npm findings of four ranks.
    static let four = [Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21"),
                       Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2", severity: .critical),
                       Package(name: "debug", installed: "2.6.8", fixed: "2.6.9", group: .other, severity: .moderate),
                       Package(name: "minimist", installed: "1.2.5", fixed: "1.2.6", group: .exploited, exploited: true)]

    // MARK: The count and the review

    /// N is exactly the rows that offer a fix: a refused row is not counted, a row that needs a password is not (it
    /// offers Terminal), a row whose run failed is (it offers Retry).
    @Test func theCountIsExactlyTheRowsThatOfferAFix() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21"),
                           Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2")], refused: true)
        try await assessed(h)
        let rowsThatOffer = { h.model.report!.findings.filter { h.model.rowFixes[$0.id]?.offeredFix != nil }.map(\.id) }
        #expect(h.model.fixAllPanel.count == 2 && Set(rowsThatOffer()) == [h.id("lodash"), h.id("chalk")])
        #expect(h.model.fixes[h.id("left-pad")]?.availability == .withheld("npm was not found on this Mac, so the app cannot run this for you."))
        h.model.openFixAll()
        #expect(Set(h.model.fixAll?.steps.map(\.id) ?? []) == [h.id("lodash"), h.id("chalk")])
        #expect(h.model.fixAll?.skipped == [FixAllState.Skip(finding: h.finding("left-pad"),
                                                              reason: "npm was not found on this Mac, so the app cannot run this for you.")])
        h.model.closeFixAll()

        // lodash fails once (Retry: still counted), then needs a password (Terminal only: not counted)
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        h.model.beginFix(h.finding("lodash"))
        try await waitUntil { h.model.fixes[h.id("lodash")]?.preview != .loading }
        h.model.runFix(h.finding("lodash"))
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].end(.exited(1))
        try await waitUntil { h.model.fixes[h.id("lodash")]?.outcome == .exitedWithError(1) && h.model.activeFix == nil }
        try await waitUntil { h.model.fixes[h.id("lodash")]?.availability != .checking }
        #expect(h.model.fixAllPanel.count == 2 && rowsThatOffer().count == 2)
        h.model.retryFix(h.finding("lodash"))
        try await waitUntil { launcher.runs.count == 2 }
        launcher.runs[1].end(.needsPassword)
        try await waitUntil { h.model.fixes[h.id("lodash")]?.outcome == .needsPassword && h.model.activeFix == nil }
        #expect(h.model.fixAllPanel.count == 1 && rowsThatOffer() == [h.id("chalk")])
        h.model.openFixAll()
        #expect(h.model.fixAll?.steps.map(\.id) == [h.id("chalk")])
        #expect(h.model.fixAll?.skipped.first { $0.id == h.id("lodash") }?.reason == "Needs your administrator password")
    }

    /// The review says what it leaves alone in each row's own words: Apple's Ruby and Python, Homebrew without the
    /// fix, a dependent that pins the package, a command the app does not run. A lower-severity row with nothing to
    /// say is not listed.
    @Test func theReviewSaysWhatItLeavesAloneAndWhy() {
        let review = PreviewData.fixAllReview
        let reasons = Dictionary(uniqueKeysWithValues: review.skipped.map { ($0.id, $0.reason) })
        typealias F = PreviewData.FixID
        #expect(reasons[F.starlette] == "fastapi 0.120.0 needs starlette < 0.49.0 — update fastapi first.")
        #expect(reasons[F.nokogiri] == "Part of macOS: only a macOS update changes Apple's Ruby and its gems.")
        #expect(reasons[F.setuptools]?.hasPrefix("Part of Apple's developer tools") == true)
        #expect(reasons[F.cpython] == "Homebrew still ships 3.12.17; the fix is 3.14.11 upstream.")
        #expect(reasons["pkg|PyPI|urllib3|1.26.5"] == "Nothing the app can run here: see its row")
        #expect(reasons[F.hacl]?.hasPrefix("Not run for you: it changes the project's dependencies") == true)   // lower, but it says why
        #expect(reasons["pkg|crates.io|time|0.1.43"] == nil && reasons["pkg|PyPI|pygments|2.14.0|py3.15.2"] == nil)   // lower, nothing to say
        // everything that needs action is either a step or listed
        let planned = Set(review.steps.flatMap(\.findings).map(\.id))
        for f in PreviewData.fixFindings where f.group.needsAction { #expect(planned.contains(f.id) || reasons[f.id] != nil, "\(f.id)") }
        // and nothing is both
        #expect(planned.isDisjoint(with: reasons.keys))
    }

    /// One command that fixes several findings (jupyterlab's formula brings tornado and jinja2) is one step that names
    /// both; in the app it runs once, and each finding is checked again and keeps its own outcome.
    @Test func oneCommandForSeveralFindingsIsOneStepRunOnce() async throws {
        let review = PreviewData.fixAllReview
        let jupyter = try #require(review.steps.first { $0.findings.contains { $0.id == PreviewData.FixAllID.tornado } })
        #expect(jupyter.findings.map(\.id) == [PreviewData.FixAllID.tornado, PreviewData.FixAllID.jinja2])
        #expect(jupyter.name == "jupyterlab" && jupyter.place == "Homebrew" && jupyter.plan.command == "brew upgrade jupyterlab")
        #expect(review.steps.count == 7 && review.findingCount == 8)
        #expect(Set(review.steps.map(\.plan.invocation)).count == review.steps.count)              // no command twice

        // in the app: two findings whose command is the same
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21")], twin: true)
        let (lodash, twin) = (h.findings[0].id, h.findings[1].id)
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 2)
        h.model.openFixAll()
        #expect(h.model.fixAll?.steps.count == 1 && h.model.fixAll?.steps[0].findings.map(\.id) == [lodash, twin])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.npmInstalls == ["lodash@4.17.21"])                                                // once
        #expect(h.model.fixes[lodash]?.outcome == .fixed(now: "4.17.21") && h.model.fixes[twin]?.outcome == .fixed(now: "4.17.21"))
        #expect(h.model.fixAll?.summary == "Fixed 2")
    }

    /// Worst first: malicious removals, exploited in the wild, critical, high, the rest; the panel's order within each.
    @Test func stepsGoWorstFirst() {
        let tools = ToolEnvironment(base: [:], isExecutable: { _ in true })
        func f(_ name: String, _ group: Finding.Group, _ severity: Severity?, exploited: Bool = false, malicious: Bool = false) -> Finding {
            let inputs = UpgradeCommand.Inputs(origin: .npmGlobal(npm: "/opt/homebrew/bin/npm"), name: name, ecosystem: .npm,
                                               target: malicious ? nil : "9.9.9", malicious: malicious)
            return Finding(id: "pkg|npm|\(name)|1.0.0", group: group, subject: .package(ecosystem: .npm, name: name), title: name, installedVersion: "1.0.0",
                           fixedVersion: malicious ? nil : "9.9.9", severity: severity, advisoryIDs: [], flawCount: 1, exploited: exploited,
                           malicious: malicious, note: nil, bigIssue: nil, origins: [inputs.origin], pageURL: SiteURL.packagePage(.npm, name, version: "1.0.0"),
                           upgradeCommand: UpgradeCommand.advice(inputs).command, verification: .none, grade: nil, commandInputs: inputs)
        }
        // in an order that is none of the right ones
        let findings = [f("low", .other, .low), f("high-a", .criticalHigh, .high), f("evil", .malicious, nil, malicious: true),
                        f("none", .other, nil), f("moderate", .other, .moderate), f("critical", .criticalHigh, .critical),
                        f("kev", .exploited, .moderate, exploited: true), f("high-b", .criticalHigh, .high)]
        var rows: [String: FixRowState] = [:]
        for x in findings {
            guard case let .success(plan) = FixPlan.make(for: x, tools: tools) else { Issue.record("no plan for \(x.title)"); return }
            rows[x.id] = FixRowState(availability: .offered(FixOffer(plan: plan)))
        }
        let review = FixAll.review(findings, fixes: rows)
        #expect(review.steps.map(\.name) == ["evil", "kev", "critical", "high-a", "high-b", "low", "none", "moderate"])
        #expect(review.steps[0].plan.action == .removal && FixAll.change(findings[2], review.steps[0].plan) == "1.0.0 → removed")
        #expect(FixAll.offered(findings, fixes: rows).map(\.0.title) == review.steps.map(\.name))
    }

    @Test func theSummaryCounts() {
        func step(_ outcomes: [FixOutcome], status: FixAllState.Step.Status = .done) -> FixAllState.Step {
            let fs = outcomes.indices.map { i in PreviewData.fixFindings[i] }
            return FixAllState.Step(findings: fs, offers: fs.map { _ in PreviewData.offer(PreviewData.FixID.nginx) }, status: status,
                                    outcomes: Dictionary(uniqueKeysWithValues: zip(fs.map(\.id), outcomes)))
        }
        var s = FixAllState(phase: .done, steps: [step([.fixed(now: "1"), .removed, .fixedCheck(now: "2", users: "x")]),
                                                  step([.fixed(now: "1"), .fixed(now: "1"), .fixed(now: "1")]),
                                                  step([.exitedWithError(1), .needsPassword, .blocked("why")])], skipped: [])
        #expect(s.summary == "Fixed 6 · 1 failed · 2 need you")
        #expect(s.tally == FixAllState.Tally(fixed: 6, failed: 1, needYou: 2))
        s.steps.append(step([.stopped("still 1.0")]))
        s.steps.append(step([.fixed(now: "1"), .fixed(now: "1")], status: .notRun))
        #expect(s.summary == "Fixed 6 · 1 failed · 2 need you · 3 not run")
        #expect(FixAllState(phase: .done, steps: [step([.needsPassword])], skipped: []).summary == "1 needs you")
        #expect(FixAllState(phase: .done, steps: [step([.broke("httpx 0.27.0"), .couldNotCheck("x")])], skipped: []).summary == "1 failed · 1 needs you")
    }

    // MARK: The run

    /// One step at a time, in the review's order: the next starts only once the last has ended and been checked again.
    @Test func stepsRunOneAtATimeInOrder() async throws {
        let h = try setUp(Self.four)
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 4)
        h.model.openFixAll()
        let order = ["minimist", "chalk", "lodash", "debug"]
        #expect(h.model.fixAll?.steps.map(\.name) == order)
        h.model.runFixAll()
        for (i, name) in order.enumerated() {
            try await waitUntil { launcher.runs.count == i + 1 }
            #expect(launcher.runs.count == i + 1, "step \(i + 1) did not start")
            guard launcher.runs.count == i + 1 else { return }
            #expect(launcher.runs[i].invocation.arguments == ["install", "-g", "\(name)@\(Self.four.first { $0.name == name }!.fixed)"])
            #expect(h.model.fixAll?.current == i && h.model.fixAll?.progressLine == "\(i + 1) of 4 · Updating \(name)…")
            #expect(h.model.fixAllPanel.run?.step == .running && h.model.fixes[h.id(name)]?.isBusy == true)
            #expect(h.model.fixes.values.filter(\.isBusy).count == 1)                              // nothing else runs
            try await Task.sleep(for: .milliseconds(150))
            #expect(launcher.runs.count == i + 1)                                                   // the next waits
            try h.installed(name, Self.four.first { $0.name == name }!.fixed)
            launcher.runs[i].end(.exited(0))
        }
        try await waitUntil { done(h) }
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 4")
        for name in order { #expect(h.model.fixes[h.id(name)]?.isResolved == true, "\(name)") }
        #expect(!h.model.initiallyExpanded.contains(h.id("lodash")))            // Fix all's own card shows the run, rows stay closed
    }

    /// An earlier step can change the picture: lodash's upgrade brings chalk 4.1.2 along. chalk's step checks it again
    /// first, finds it fixed, and does not run; its row says so.
    @Test func aStepAnEarlierOneAlreadyFixedIsNotRun() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21", severity: .critical),
                           Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2")])
        try Data("chalk@4.1.2".utf8).write(to: h.npm.deletingLastPathComponent().appendingPathComponent("also-lodash"))
        try await assessed(h)
        h.model.openFixAll()
        #expect(h.model.fixAll?.steps.map(\.name) == ["lodash", "chalk"])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.npmInstalls == ["lodash@4.17.21"])                                            // chalk's never ran
        #expect(h.model.fixAll?.steps[1].status == .skipped("Fixed by an earlier step"))
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .fixed(now: "4.1.2"))
        #expect(h.model.fixAll?.summary == "Fixed 2")
    }

    /// A step that breaks what depends on what it changed (pip also brought anyio 5, which httpx cannot take) ends Fix
    /// all there: nothing after it runs, and its Undo is offered, which puts the versions back.
    @Test func aStepThatBreaksSomethingStopsFixAllWithItsUndo() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21")], starlette: true)
        try await assessed(h)
        h.model.openFixAll()
        #expect(h.model.fixAll?.steps.map(\.name) == ["starlette", "lodash"])                  // exploited first
        h.model.runFixAll()
        try await waitUntil { done(h) }
        let starlette = h.id("starlette")
        #expect(h.model.fixes[starlette]?.outcome == .broke("httpx 0.27.0"))
        #expect(h.model.fixAll?.ending == .broke(step: 0, what: "httpx 0.27.0"))
        #expect(h.model.fixAll?.steps[1].status == .notRun && h.npmInstalls.isEmpty)           // lodash never ran
        #expect(h.model.fixAll?.summary == "1 failed · 1 not run")
        let undo = try #require(h.model.fixAllPanel.undo)
        #expect(undo.restores == ["anyio 4.0.0", "starlette 0.48.0"])
        h.model.undoFix(h.finding("starlette"))
        try await waitUntil { h.model.fixes[starlette]?.outcome == .undone("anyio 4.0.0, starlette 0.48.0") }
        #expect(h.model.fixes[starlette]?.outcome == .undone("anyio 4.0.0, starlette 0.48.0"))
    }

    /// A step that fails without breaking anything (a network error) is counted, and the next one runs.
    @Test func aFailedStepIsCountedAndTheNextRuns() async throws {
        let h = try setUp(Array(Self.four.prefix(2)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].print("npm ERR! code ECONNRESET\n")
        launcher.runs[0].end(.exited(1))                                                         // chalk, critical, first
        try await waitUntil { launcher.runs.count == 2 }
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .exitedWithError(1))
        try h.installed("lodash", "4.17.21")
        launcher.runs[1].end(.exited(0))
        try await waitUntil { done(h) }
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 1 · 1 failed")
        #expect(h.model.fixAllPanel.count == 1)                                     // chalk offers Retry, and counts again
    }

    /// Stop ends the step under way, as its own Stop does, and no other starts.
    @Test func stopEndsTheStepAndCancelsTheRest() async throws {
        let h = try setUp(Array(Self.four.prefix(3)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 && h.model.fixAllPanel.run?.step == .running }
        h.model.stopFixAll()
        #expect(launcher.runs[0].stopAsked)
        try await waitUntil { done(h) }
        #expect(launcher.runs.count == 1)
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .stopped("still 4.0.0"))
        #expect(h.model.fixAll?.ending == .stopped && h.model.fixAll?.steps.dropFirst().allSatisfy { $0.status == .notRun } == true)
        #expect(h.model.fixAll?.summary == "3 not run")
        #expect(h.model.fixes[h.id("lodash")]?.progress == nil)                    // untouched
    }

    /// One at a time: while a row's own fix runs, Fix all waits and says why; while Fix all runs, no row's fix, Retry,
    /// Undo or Terminal starts.
    @Test func fixAllAndASingleFixWaitForEachOther() async throws {
        let h = try setUp(Array(Self.four.prefix(3)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.beginFix(h.finding("debug"))
        try await waitUntil { h.model.fixes[h.id("debug")]?.preview != .loading }
        h.model.runFix(h.finding("debug"))
        try await waitUntil { launcher.runs.count == 1 }
        #expect(h.model.fixAllPanel.waitingFor == "debug" && h.model.fixAllPanel.why == "One fix at a time: debug is running.")
        h.model.openFixAll()
        #expect(h.model.fixAll == nil)
        try h.installed("debug", "2.6.9")
        launcher.runs[0].end(.exited(0))
        try await waitUntil { h.model.activeFix == nil }
        #expect(h.model.fixAllPanel.waitingFor == nil)

        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 2 }
        #expect(h.model.rowFixes[h.id("lodash")]?.waitingFor == "chalk")
        h.model.beginFix(h.finding("lodash"))
        try await waitUntil { h.model.fixes[h.id("lodash")]?.preview != .loading }
        h.model.runFix(h.finding("lodash"))                                                      // waits: nothing starts
        h.model.openFixAll()                                                                     // and the batch stays as it is
        #expect(launcher.runs.count == 2 && h.model.fixes[h.id("lodash")]?.progress == nil && h.model.fixAll?.phase == .running)
        launcher.runs[1].end(.exited(0))
        try await waitUntil { launcher.runs.count == 3 }
        launcher.runs[2].end(.exited(0))
        try await waitUntil { done(h) }
    }

    /// No Terminal inside Fix all: a step that needs a password is counted as needing you, Fix all goes on, and nothing
    /// opens Terminal, before or after.
    @Test func noTerminalInsideFixAll() async throws {
        let terminal = CountingTerminal()
        let h = try setUp(Array(Self.four.prefix(2)), terminal: terminal)
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].print("sudo: a terminal is required to read the password\n")
        launcher.runs[0].end(.needsPassword)
        try await waitUntil { launcher.runs.count == 2 }
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .needsPassword)
        h.model.runFixInTerminal(h.finding("chalk"))                                              // refused while Fix all runs
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .needsPassword)
        try h.installed("lodash", "4.17.21")
        launcher.runs[1].end(.exited(0))
        try await waitUntil { done(h) }
        #expect(h.model.fixAll?.summary == "Fixed 1 · 1 needs you")
        #expect(terminal.lock.withLock { terminal.opened } == 0)
        // Fix all's own views offer no Terminal anywhere
        let views = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/FixAllViews.swift"), encoding: .utf8)
        let code = views.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
        #expect(!code.contains("Terminal") && !code.contains("runInTerminal"))
    }

    /// The batch lives in the model: a panel opened again draws it from there, as it draws a row's run.
    @Test func thePanelDrawsFixAllFromTheModel() async throws {
        let h = try setUp(Array(Self.four.prefix(2)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].print("step one\n")
        try await waitUntil { h.model.fixAllPanel.run?.log.lines == ["step one"] }
        let panel = h.model.fixAllPanel                                                          // what a new panel gets
        #expect(panel.batch?.phase == .running && panel.batch?.progressLine == "1 of 2 · Updating chalk…" && panel.run?.log.lines == ["step one"])
        launcher.runs[0].end(.exited(0))
        try await waitUntil { launcher.runs.count == 2 }
        launcher.runs[1].end(.exited(0))
        try await waitUntil { done(h) }
        h.model.closeFixAll()
        #expect(h.model.fixAll == nil)
    }

    /// The row draws its button from the same decision Fix all counts (FixRowState.offeredFix), so the two cannot
    /// differ; and the header's button is the rows' own FixButton.
    @Test func theRowAndTheCountShareOneDecision() throws {
        let row = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/FindingRow.swift"), encoding: .utf8)
        #expect(row.contains("if let offer = fix.offeredFix {") && row.contains("canRetry: fix.offeredFix != nil"))
        #expect(!row.contains("case let .offered(offer)?:"))
        let panel = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/PopoverView.swift"), encoding: .utf8)
        #expect(panel.contains("FixButton(title: \"Fix all ("))
    }
}
