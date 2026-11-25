import Darwin
import Foundation
import Testing
@testable import OSVAKit

// Fix all's batches, partial fixes and upgrades together, as OSVAKit decides them: what a set of pip changes may do to
// the end state, the constraints a partial fix is asked within, pip's resolver's set and its gates, one command per tool,
// brew going on past a cask that asked for a password, and the casks whose upgrade would change nothing or needs root.

/// Answers each invocation from a closure and remembers every argv.
final class ScriptedRunner: CommandRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls: [[String]] = []
    let answer: @Sendable ([String]) -> CommandResult
    init(_ answer: @escaping @Sendable ([String]) -> CommandResult) { self.answer = answer }
    var calls: [[String]] { lock.withLock { _calls } }
    func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
        lock.withLock { _calls.append([executable] + arguments) }
        return answer([executable] + arguments)
    }
}

/// The site, as a fix asks it: an answer within constraints, and the answers at exact versions.
final class FakeFixServer: FixServer, @unchecked Sendable {
    private let lock = NSLock()
    private var _asked: [[String]] = []
    let answer: BatchResponse.Result?
    let known: [PackageVersion: BatchResponse.Result]
    /// `answer`: the site's answer within constraints. `known`: the flaws (ids) the site reports at each version, with no
    /// ranges; `results`: whole answers, which take their place.
    init(answer: BatchResponse.Result? = nil, known: [PackageVersion: Set<String>] = [:], results: [PackageVersion: BatchResponse.Result] = [:]) {
        self.answer = answer
        self.known = Dictionary(uniqueKeysWithValues: known.map { v, ids in
            (v, try! BatchCheckTests.result(v.name, v.version, flaws: ids.sorted().map { BatchCheckTests.flaw($0) }))
        }).merging(results) { _, whole in whole }
    }
    var asked: [[String]] { lock.withLock { _asked } }
    func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Result?, FixServerError> {
        lock.withLock { _asked.append(constraints) }
        return .success(answer)
    }
    func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: BatchResponse.Result], FixServerError> {
        .success(known.filter { versions.contains($0.key) })
    }
}

func ok(_ text: String) -> CommandResult { CommandResult(status: 0, stdout: Data(text.utf8), stderr: Data()) }

/// pip's `--report` for these distributions (name, version, requirements).
func pipReport(_ installs: [(String, String, [String])]) -> String {
    let items: [[String: Any]] = installs.map { n, v, r in ["requested": true, "metadata": ["name": n, "version": v, "requires_dist": r]] }
    let json = try! JSONSerialization.data(withJSONObject: ["version": "1", "pip_version": "24.0", "install": items, "environment": [:]])
    return String(decoding: json, as: UTF8.self)
}

@Suite struct ProposalTests {
    static let python = PythonEnvironment(executable: "/opt/test/bin/python3", version: "3.11.14", kind: .pythonOrg, externallyManaged: false,
                                          userSite: nil, formula: nil)
    static let markers = ["python_version": "3.11", "sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix"]

    /// A pip finding in the test Python: `name` at `installed`, its fix `fixed`.
    static func finding(_ name: String, _ installed: String, _ fixed: String, flaws: Int = 1, exploited: Bool = false) -> Finding {
        let upgrade = Fixture.fix(fixed, above: installed)
        let inputs = UpgradeCommand.Inputs(origin: .pip(python: python, user: false, formula: nil), name: name, ecosystem: .pypi, target: upgrade, malicious: false)
        return Finding(id: "pkg|PyPI|\(name)|\(installed)", group: exploited ? .exploited : .criticalHigh, subject: .package(ecosystem: .pypi, name: name),
                       title: name, installedVersion: installed, upgrade: upgrade, severity: .high, advisoryIDs: [], flawCount: flaws,
                       exploited: exploited, malicious: false, note: nil, bigIssue: nil, origins: [inputs.origin],
                       pageURL: SiteURL.packagePage(.pypi, name, version: installed), upgradeCommand: UpgradeCommand.advice(inputs).command,
                       verification: .none, grade: nil, commandInputs: inputs)
    }

    /// A Python whose sys.path is `folders`, whose pip is 24.0, and whose dry run answers `report` for the requirements.
    static func tools(_ folders: [String], report: @escaping @Sendable ([String]) -> CommandResult = { _ in ok(pipReport([])) }) -> (ToolEnvironment, ScriptedRunner) {
        let runner = ScriptedRunner { argv in
            let args = Array(argv.dropFirst())
            if args.first == "-c" {
                let json = try! JSONSerialization.data(withJSONObject: ["path": folders, "markers": markers])
                return ok(String(decoding: json, as: UTF8.self))
            }
            if args == ["-m", "pip", "--version"] { return ok("pip 24.0 from /opt/test/lib/pip (python 3.11)") }
            if args.starts(with: ["-m", "pip", "install", "--dry-run", "--report", "-"]) {
                return report(Array(args.drop { !$0.hasPrefix("--no-input") }.dropFirst()))
            }
            return CommandResult(status: 2, stdout: Data(), stderr: Data("unexpected: \(args)".utf8))
        }
        return (ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: runner, isExecutable: { _ in true }), runner)
    }

    /// A site folder with these distributions (name, version, requirements, editable).
    static func site(_ dists: [(String, String, [String], Bool)], copying: String? = nil) -> String {
        let dir = temporaryDirectory()
        if let copying {
            for entry in try! FileManager.default.contentsOfDirectory(atPath: copying) {
                try! FileManager.default.copyItem(atPath: copying + "/" + entry, toPath: dir.appendingPathComponent(entry).path)
            }
        }
        for (name, version, requires, editable) in dists {
            let d = dir.appendingPathComponent("\(name.replacingOccurrences(of: "-", with: "_"))-\(version).dist-info")
            write("Metadata-Version: 2.1\nName: \(name)\nVersion: \(version)\n" + requires.map { "Requires-Dist: \($0)\n" }.joined(), to: d.appendingPathComponent("METADATA"))
            if editable { write(#"{"url": "file:///Users/ana/code/\#(name)", "dir_info": {"editable": true}}"#, to: d.appendingPathComponent("direct_url.json")) }
        }
        return dir.path
    }

    static let starletteSite = Fixture.url("python-site/before").path
    /// The same site without legacy-pkg, which uses starlette and would not move with it past 1.0 (a runtime boundary).
    static let starletteClean: String = {
        let dir = temporaryDirectory("starletteClean")
        for entry in try! FileManager.default.contentsOfDirectory(atPath: starletteSite) where !entry.hasPrefix("legacy_pkg") {
            try! FileManager.default.copyItem(atPath: starletteSite + "/" + entry, toPath: dir.appendingPathComponent(entry).path)
        }
        return dir.path
    }()

    // MARK: Constraints

    @Test func theConstraintsTheSiteTakesAreVersionsAndOperatorsOnly() {
        for good in ["<2.9", "~=2.8.0", "<0.49.0,>=0.40.0", "==2.8.*", "!=1.8,<3", ">=1.0rc1", "<2.0.post1", ">=1.0.dev3"] {
            #expect(PythonConstraints.isSendable(good), "\(good)")
        }
        for bad in ["", "< 2.9", "torch<2.9", "<2.9; python_version<'3.12'", "===2.8", "<2.9+local", "<1!2.0", "<2.*", "~=2", "<2.9,",
                    "<2.9,<3,<4,<5,<6", String(repeating: "<1", count: 40), "<2.9\n", "<٢.٩", "<2.9RC1", "*"] {
            #expect(!PythonConstraints.isSendable(bad), "\(bad)")
        }
        #expect(PythonConstraints.sendable([PythonSpecifier("< 0.49.0")!, PythonSpecifier(">= 0.40.0")!]) == "<0.49.0,>=0.40.0")
        #expect(PythonConstraints.words("<2.9") == "below 2.9" && PythonConstraints.words("<0.49.0,>=0.40.0") == "below 0.49.0")
        #expect(PythonConstraints.words("~=2.8.0") == "2.8" && PythonConstraints.words("==2.8.*") == "2.8")
    }

    /// The owner's torch: torchaudio pins it (it moves with it), and whisperx uses it past the torchaudio 2.9 boundary:
    /// the one constraint is "<2.9", from whisperx. starlette: fastapi's and the instrumentator's own specifiers.
    @Test func whatHoldsAnUpgradeBackBecomesTheConstraints() {
        let torch = PythonSite(distributions: [
            PythonDistribution(name: "torch", version: "2.7.0", requires: []),
            PythonDistribution(name: "torchaudio", version: "2.7.0", requires: ["torch==2.7.0"]),
            PythonDistribution(name: "whisperx", version: "3.3.4", requires: ["torch>=2", "torchaudio>=2", "pyannote.audio==3.3.2"]),
            PythonDistribution(name: "pyannote.audio", version: "3.3.2", requires: ["torchaudio>=2.2"]),
        ], markers: Self.markers)
        #expect(PythonConstraints.blocking("torch", from: "2.7.0", to: "2.13.0", in: torch) == [FixConstraint(specifier: "<2.9", from: "whisperx", boundary: true)])
        let starlette = PythonSite(folders: [Self.starletteSite], markers: Self.markers)
        #expect(PythonConstraints.blocking("starlette", from: "0.48.0", to: "1.3.1", in: starlette)
                == [FixConstraint(specifier: "<0.49.0,>=0.40.0", from: "fastapi", boundary: false),
                    FixConstraint(specifier: ">=0.30.0,<1.0.0", from: "prometheus-fastapi-instrumentator", boundary: false),
                    FixConstraint(specifier: "<1.0", from: "fastapi", boundary: true)])
        #expect(PythonConstraints.blocking("anyio", from: "4.11.0", to: "4.12.0", in: starlette) == nil)        // nothing holds it back
    }

    /// torch 2.7.0 with whisperx past the torchaudio 2.9 boundary: the full fix (2.13.0) is blocked, and the site is asked
    /// within "<2.9".
    static func torchSite() -> (ToolEnvironment, Finding) {
        let folder = Self.site([("torch", "2.7.0", [], false), ("torchaudio", "2.7.0", ["torch==2.7.0"], false),
                                ("whisperx", "3.3.4", ["torch>=2", "torchaudio>=2"], false)])
        return (Self.tools([folder]).0, Self.finding("torch", "2.7.0", "2.13.0", flaws: 14))
    }

    /// The site's answer for torch 2.7.0 within "<2.9": `flaws` (raw, BatchCheckTests.flaw), its plan's `target`, and g
    /// remaining, blocked by the constraint.
    static func torchAnswer(_ flaws: [String], target: String?) -> BatchResponse.Result {
        try! BatchCheckTests.result("torch", "2.7.0", flaws: flaws, plan: BatchCheckTests.plan(target, remaining:
            #"[{"id":"g","reason":"blocked-by-constraint","constraint":"<2.9","fixed_in":"2.9.0"}]"#))
    }

    /// Six flaws 2.8.0 leaves, and g, which only 2.9.0 does.
    static let sixAndG = ["a", "b", "c", "d", "e", "f"].map { BatchCheckTests.flaw($0, ranges: #"[{"fixed":"2.8.0"}]"#) }
        + [BatchCheckTests.flaw("g", ranges: #"[{"fixed":"2.9.0"}]"#)]

    /// The full fix is blocked by the boundary: the site is asked within "<2.9" and its 2.8.0 is offered as a proposal,
    /// with torchaudio moving along, saying how much it fixes and who holds the rest back. A target the local gate
    /// refuses is not offered.
    @Test func aPartialFixIsProposedWithinWhatBlocksTheFullOne() async throws {
        let (tools, torch) = Self.torchSite()
        let server = FakeFixServer(answer: Self.torchAnswer(Self.sixAndG, target: "2.8.0"))
        let a = await FixAdvisor(tools: tools, home: "/Users/ana", server: server).assess(torch)
        guard case let .propose(why, offer) = a, case .partial? = offer.proposal else { Issue.record("\(a)"); return }
        #expect(why.hasPrefix("torch 2.9 goes with torchaudio 2.9"))
        #expect(server.asked == [["<2.9"]])
        #expect(offer.plan.target == "2.8.0" && offer.plan.pip?.requirement == "torch==2.8.0" && offer.companions == ["torchaudio"])
        #expect(offer.plan.command == "/opt/test/bin/python3 -m pip install --upgrade torch==2.8.0")
        #expect(offer.proposal?.line(offer.plan) == "Partly fixes: 6 of 14 flaws. whisperx needs torch below 2.9.")
        #expect(offer.proposal?.reviewLine(offer.plan) == "torch to 2.8.0 (6 of 14; whisperx needs below 2.9)")
        #expect(offer.partialTarget?.version == "2.8.0")
        #expect(FixPlan.make(for: torch, tools: tools, home: "/Users/ana", target: offer.partialTarget) == .success(offer.plan))   // made again the same

        // a target past the boundary, or no target: nothing proposed
        let past = FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: Self.torchAnswer(Self.sixAndG, target: "2.9.1")))
        guard case .refused = await past.assess(torch) else { Issue.record("a target past the boundary was proposed"); return }
        let none = FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: Self.torchAnswer(Self.sixAndG, target: nil)))
        guard case .refused = await none.assess(torch) else { Issue.record("no target, yet a proposal"); return }
    }

    /// The site's partial target is proposed only when the core confirms it: 2.8.0 inside the only flaw's published range
    /// (fixed in 3.0) is refused, whatever the plan says it fixes.
    @Test func aPartialTargetTheCoreRejectsIsNotProposed() async {
        let (tools, torch) = Self.torchSite()
        let answer = Self.torchAnswer([BatchCheckTests.flaw("a", ranges: #"[{"fixed":"3.0"}]"#)], target: "2.8.0")
        let a = await FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: answer)).assess(torch)
        guard case .refused = a else { Issue.record("a target the core rejects was proposed: \(a)"); return }
    }

    /// A target the core confirms is proposed, and "fixes" is the core's count, not the plan's list (which names two).
    @Test func aPartialTargetTheCoreConfirmsIsProposed() async {
        let (tools, torch) = Self.torchSite()
        var answer = Self.torchAnswer([BatchCheckTests.flaw("a", ranges: #"[{"fixed":"2.8.0"}]"#), BatchCheckTests.flaw("g", ranges: #"[{"fixed":"2.9.0"}]"#)],
                                      target: "2.8.0")
        answer.plan?.fixes = ["a", "g"]
        let a = await FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: answer)).assess(torch)
        guard case let .propose(_, offer) = a, case let .partial(p)? = offer.proposal else { Issue.record("\(a)"); return }
        #expect(p.fixes == 1 && p.of == 14 && p.target.version == "2.8.0" && offer.plan.target == "2.8.0")
    }

    /// The partial target counts only the flaws the finding is shown for, those that can affect this Mac: one that leaves
    /// only a Windows flaw is not proposed, and a Windows flaw it leaves is not counted.
    @Test func aPartialFixCountsOnlyWhatAffectsThisMac() async {
        let (tools, torch) = Self.torchSite()
        let windows = BatchCheckTests.flaw("w", ranges: #"[{"fixed":"2.8.0"}]"#, platform: "windows")
        let g = BatchCheckTests.flaw("g", ranges: #"[{"fixed":"2.9.0"}]"#)
        let only = await FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: Self.torchAnswer([windows, g], target: "2.8.0"))).assess(torch)
        guard case .refused = only else { Issue.record("a target that leaves only a Windows flaw was proposed: \(only)"); return }
        let mac = BatchCheckTests.flaw("a", ranges: #"[{"fixed":"2.8.0"}]"#)
        let both = await FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer(answer: Self.torchAnswer([mac, windows, g], target: "2.8.0"))).assess(torch)
        guard case let .propose(_, offer) = both, case let .partial(p)? = offer.proposal else { Issue.record("\(both)"); return }
        #expect(p.fixes == 1)
    }

    /// A fix's questions get the site's whole answers, their flaws with the ranges it publishes, so the core decides
    /// them as a scan's: the answer within constraints, and the answers at exact versions, with none for a version the
    /// site says nothing about, or a package the public index does not list.
    @Test func aFixAsksTheSiteForWholeAnswers() async throws {
        let body = #"{"checked":1,"packages":[{"ecosystem":"PyPI","name":"torch","version":"2.7.0","distinct_flaws":1,"worst_severity":"HIGH","#
            + #""advisories":["A"],"flaws":[{"id":"A","severity":"HIGH","fixed_in":["2.8.0"],"ranges":[{"fixed":"2.8.0"}]}],"#
            + #""plan":{"target":"2.8.0","fixes":["A"],"remaining":[]}}]}"#
        let transport = RecordedTransport { request, _ in
            switch request.url!.path {
            case "/data/app-index.tsv": return .init(status: 200, headers: ["ETag": "\"v1\""], body: Fixture.data("api/app-index.tsv"))
            case "/api/v1/check/batch": return .init(status: 200, body: Data(body.utf8))
            default: return .init(status: 404, body: Data())
            }
        }
        let dir = temporaryDirectory()
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: dir), tools: .fixture(home: dir), folders: [], applicationRoots: []),
                              transport: transport, pause: { _ in })
        let at = { (v: String) in PackageVersion(name: "torch", version: v) }
        let known = try await scanner.flaws([at("2.7.0"), at("2.8.0"), PackageVersion(name: "not-in-the-index", version: "1.0")], python: Self.python).get()
        #expect(Array(known.keys) == [at("2.7.0")])
        #expect(known[at("2.7.0")]?.flaws.map(\.ranges) == [[AffectedRange(fixed: "2.8.0")]])
        let answer = try await scanner.plan(Self.finding("torch", "2.7.0", "2.13.0"), within: ["<2.9"]).get()
        #expect(answer?.flaws.map(\.ranges) == [[AffectedRange(fixed: "2.8.0")]] && answer?.plan?.target == "2.8.0")
    }

    // MARK: Upgrade together

    /// starlette's fix is blocked by fastapi's and the instrumentator's specifiers, and no partial fix exists under them:
    /// the proposal names both. pip's resolver (a fake report, on the real metadata) moves them to versions that take
    /// starlette 1.3.1; the end state holds, and nothing moved brings a new flaw: every version is pinned.
    @Test func anUpgradeTogetherIsAcceptedWhenTheSetHolds() async throws {
        let report = pipReport([("starlette", "1.3.1", ["anyio<5,>=3.6.2", "typing-extensions>=4.10.0; python_version < \"3.13\""]),
                                ("fastapi", "0.135.2", ["starlette<2.0.0,>=0.46.0", "pydantic!=1.8,!=1.8.1,!=2.0.0,!=2.0.1,!=2.1.0,<3.0.0,>=1.7.4",
                                                        "typing-extensions>=4.8.0", "annotated-doc>=0.0.2"]),
                                ("prometheus-fastapi-instrumentator", "7.2.0", ["prometheus-client<1.0.0,>=0.8.0", "starlette<2.0.0,>=0.30.0"])])
        let (tools, runner) = Self.tools([Self.starletteClean]) { _ in ok(report) }
        // the site's flaws at 0.48.0, with their ranges: the core confirms pip's 1.3.1 fixes what 1.3.1 fixes
        let flaws = [BatchCheckTests.flaw("GHSA-starlette", ranges: #"[{"fixed":"1.3.1"}]"#),
                     BatchCheckTests.flaw("CVE-2026-1", ranges: #"[{"introduced":"0.40.0","fixed":"0.49.1"}]"#)]
        let server = FakeFixServer(answer: try BatchCheckTests.result("starlette", "0.48.0", flaws: flaws, plan: BatchCheckTests.plan(nil)),
                                   results: [PackageVersion(name: "starlette", version: "0.48.0"): try BatchCheckTests.result("starlette", "0.48.0", flaws: flaws)])
        let advisor = FixAdvisor(tools: tools, home: "/Users/ana", server: server)
        let starlette = Self.finding("starlette", "0.48.0", "1.3.1", flaws: 6, exploited: true)
        guard case let .propose(why, offer) = await advisor.assess(starlette), case let .together(t)? = offer.proposal else { Issue.record("no proposal"); return }
        #expect(why == "fastapi 0.120.0 needs starlette < 0.49.0, and 1 more — update them first.")
        #expect(t.blockers == ["fastapi", "prometheus-fastapi-instrumentator"] && t.requirements == ["starlette>=1.3.1", "fastapi", "prometheus-fastapi-instrumentator"])
        #expect(offer.proposal?.line(offer.plan) == "Update starlette with fastapi and the instrumentator (fixes the exploited flaw)")
        #expect(offer.proposal?.asks == "pip asks PyPI about starlette, fastapi, prometheus-fastapi-instrumentator")
        let p = await advisor.preview(offer)
        #expect(p.blocked == nil, "\(p.blocked ?? "")")
        #expect(p.pins == ["starlette==1.3.1", "fastapi==0.135.2", "prometheus-fastapi-instrumentator==7.2.0"])
        #expect(runner.calls.contains(["/opt/test/bin/python3", "-m", "pip", "install", "--dry-run", "--report", "-", "--quiet", "--only-binary=:all:",
                                       "--disable-pip-version-check", "--no-input", "starlette>=1.3.1", "fastapi", "prometheus-fastapi-instrumentator"]))
        // with legacy-pkg installed, which uses starlette and does not move, the same set crosses starlette 1.0: refused
        let (withLegacy, _) = Self.tools([Self.starletteSite]) { _ in ok(report) }
        let refused = await FixAdvisor(tools: withLegacy, home: "/Users/ana", server: server).preview(offer)
        #expect(refused.blocked == "starlette 1.0 removed APIs of the 0.x series — legacy-pkg 1.0 may rely on it")
        #expect(PipSetPreviewer.invocation(python: Self.python.executable, user: false, pins: p.pins).arguments
                == ["-m", "pip", "install", "--disable-pip-version-check", "--no-input", "starlette==1.3.1", "fastapi==0.135.2", "prometheus-fastapi-instrumentator==7.2.0"])
    }

    /// The same set, where the site knows a flaw in fastapi 0.135.2 that 0.120.0 does not have: refused, and said so.
    @Test func anUpgradeTogetherThatBringsANewFlawIsRefused() async throws {
        let report = pipReport([("starlette", "1.3.1", ["anyio<5,>=3.6.2"]), ("fastapi", "0.135.2", ["starlette<2.0.0,>=0.46.0"]),
                                ("prometheus-fastapi-instrumentator", "7.2.0", ["starlette<2.0.0,>=0.30.0"])])
        let (tools, _) = Self.tools([Self.starletteClean]) { _ in ok(report) }
        let server = FakeFixServer(known: [PackageVersion(name: "fastapi", version: "0.135.2"): ["GHSA-new1"]])
        let offer = FixOffer(plan: try FixPlan.make(for: Self.finding("starlette", "0.48.0", "1.3.1"), tools: tools, home: "/Users/ana").get(),
                             proposal: .together(.init(package: "starlette", fix: "1.3.1", blockers: ["fastapi", "prometheus-fastapi-instrumentator"],
                                                       python: Self.python)))
        let p = await FixAdvisor(tools: tools, home: "/Users/ana", server: server).preview(offer)
        #expect(p.blocked == "fastapi 0.135.2 has GHSA-new1, which 0.120.0 does not")
        #expect(p.pins.isEmpty)
    }

    /// A project installed for development holds fastapi below 0.121: pip is asked within its range, finds no set, and
    /// the line says where to change it. When the project itself is what blocks starlette, nothing is proposed.
    @Test func aProjectOfThePersonsHoldsItBack() async throws {
        let folder = Self.site([("blooper-backend", "0.1.0", ["fastapi<0.121", "uvicorn>=0.30"], true)], copying: Self.starletteSite)
        let (tools, runner) = Self.tools([folder]) { _ in
            CommandResult(status: 1, stdout: Data(), stderr: Data("ERROR: ResolutionImpossible: for help visit https://pip.pypa.io".utf8))
        }
        let advisor = FixAdvisor(tools: tools, home: "/Users/ana", server: FakeFixServer())
        let starlette = Self.finding("starlette", "0.48.0", "1.3.1", exploited: true)
        guard case let .propose(_, offer) = await advisor.assess(starlette), case let .together(t)? = offer.proposal else { Issue.record("no proposal"); return }
        #expect(t.requirements == ["starlette>=1.3.1", "fastapi<0.121", "prometheus-fastapi-instrumentator"])     // never "blooper-backend"
        let p = await advisor.preview(offer)
        #expect(p.blocked == "Your project blooper-backend requires fastapi <0.121. Update it there")
        #expect(!runner.calls.joined().contains("blooper-backend"))

        let mine = Self.site([("starlette", "0.48.0", [], false), ("blooper-backend", "0.1.0", ["starlette<0.49"], true)])
        let (tools2, _) = Self.tools([mine])
        let a = await FixAdvisor(tools: tools2, home: "/Users/ana", server: FakeFixServer()).assess(starlette)
        #expect(a == .refused("blooper-backend 0.1.0 needs starlette < 0.49 — it is a project installed for development: raise its starlette range there."))
    }

    /// pip's resolver picks demo 2.3 for `demo>=2.0`, inside a range ([2.2, 2.4)) of the flaw that 2.0 leaves. It is not
    /// a new flaw (1.0 has it too), but the set would not fix it: refused. pip's 2.4 leaves it: accepted.
    @Test func pipsResolvedVersionMustFixWhatTheFixFixes() async throws {
        let folder = Self.site([("demo", "1.0", [], false), ("dep", "1.0", ["demo<2"], false)])
        let flaw = BatchCheckTests.flaw("A", ranges: #"[{"fixed":"2.0"},{"introduced":"2.2","fixed":"2.4"}]"#)
        func preview(pipPicks own: String) async throws -> FixPreview {
            let (tools, _) = Self.tools([folder]) { _ in ok(pipReport([("demo", own, []), ("dep", "1.1", ["demo>=2"])])) }
            let at = { (v: String) in PackageVersion(name: "demo", version: v) }
            let server = FakeFixServer(results: [at("1.0"): try! BatchCheckTests.result("demo", "1.0", flaws: [flaw]),
                                                 at(own): try! BatchCheckTests.result("demo", own, flaws: own == "2.3" ? [flaw] : [])])
            let offer = FixOffer(plan: try FixPlan.make(for: Self.finding("demo", "1.0", "2.0"), tools: tools, home: "/Users/ana").get(),
                                 proposal: .together(.init(package: "demo", fix: "2.0", blockers: ["dep"], python: Self.python)))
            return await FixAdvisor(tools: tools, home: "/Users/ana", server: server).preview(offer)
        }
        let refused = try await preview(pipPicks: "2.3")
        #expect(refused.blocked == "pip's set would install demo 2.3, which the core does not confirm fixes what 2.0 fixes")
        #expect(refused.pins.isEmpty)
        let accepted = try await preview(pipPicks: "2.4")
        #expect(accepted.blocked == nil && accepted.pins == ["demo==2.4", "dep==1.1"])
    }

    // MARK: The end state

    /// A pair fine alone and broken together: alpha 1.1 needs beta below 2.1, and beta goes to 2.1. Each alone passes;
    /// together the end state does not.
    @Test func theEndStateIsCheckedAsAWhole() {
        let site = PythonSite(distributions: [PythonDistribution(name: "alpha", version: "1.0", requires: []),
                                              PythonDistribution(name: "beta", version: "2.0", requires: [])], markers: Self.markers)
        let alpha = PythonDistribution(name: "alpha", version: "1.1", requires: ["beta<2.1"])
        let beta = PythonDistribution(name: "beta", version: "2.1", requires: [])
        #expect(PipSetGuard.refusal(site, installs: [alpha]) == nil)
        #expect(PipSetGuard.refusal(site, installs: [beta]) == nil)
        #expect(PipSetGuard.refusal(site, installs: [alpha, beta]) == "alpha 1.1 needs beta < 2.1")
        // a requirement already unmet before is not the set's doing
        let broken = PythonSite(distributions: [PythonDistribution(name: "gamma", version: "1.0", requires: ["missing>=1"]),
                                                PythonDistribution(name: "beta", version: "2.0", requires: [])], markers: Self.markers)
        #expect(PipSetGuard.refusal(broken, installs: [PythonDistribution(name: "gamma", version: "1.1", requires: ["missing>=1"]), beta]) == nil)
        // a runtime boundary in the set
        let torch = PythonSite(distributions: [PythonDistribution(name: "torch", version: "2.7.0", requires: []),
                                               PythonDistribution(name: "whisperx", version: "3.3.4", requires: ["torch>=2"])], markers: Self.markers)
        #expect(PipSetGuard.refusal(torch, installs: [PythonDistribution(name: "torch", version: "2.9.0", requires: [])])?.hasPrefix("torch 2.9 goes with") == true)
    }

    /// A project installed for development is never replaced by a release, and nothing it uses moves past a major
    /// version.
    @Test func aProjectOfThePersonsIsNeverMoved() {
        let site = PythonSite(distributions: [PythonDistribution(name: "starlette", version: "0.48.0", requires: []),
                                              PythonDistribution(name: "blooper-backend", version: "0.1.0", requires: ["starlette>=0.40"], editable: true)],
                              markers: Self.markers)
        #expect(PipSetGuard.refusal(site, installs: [PythonDistribution(name: "blooper-backend", version: "0.2.0", requires: [])])
                == "It would replace blooper-backend, your project installed for development")
        #expect(PipSetGuard.refusal(site, installs: [PythonDistribution(name: "starlette", version: "1.3.1", requires: [])])
                == "Your project blooper-backend uses starlette 0.x; this moves it to 1.3.1. Update it there")
        #expect(PipSetGuard.refusal(site, installs: [PythonDistribution(name: "starlette", version: "0.48.2", requires: [])]) == nil)
    }

    @Test func readsPipsReport() throws {
        let installs = try #require(PipReport.parse(Data(pipReport([("starlette", "1.3.1", ["anyio<5"]), ("fastapi", "0.135.2", [])]).utf8)))
        #expect(installs.map(\.name) == ["starlette", "fastapi"] && installs[0].requires == ["anyio<5"] && installs[1].version == "0.135.2")
        #expect(PipReport.parse(Data("Would install x-1".utf8)) == nil)
        #expect(PipReport.line(installs) == "Would install starlette 1.3.1, fastapi 0.135.2")
    }

    // MARK: One command per tool

    @Test func plansJoinTheirToolsCommand() {
        let tools = ToolEnvironment(base: [:], isExecutable: { _ in true })
        func plan(_ origin: Origin, _ name: String, _ eco: Ecosystem?, malicious: Bool = false) -> FixPlan {
            let upgrade = malicious ? nil : Fixture.fix("9.9.9", above: "1.0.0")
            let inputs = UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: eco, target: upgrade, malicious: malicious)
            let f = Finding(id: name, group: .criticalHigh, subject: eco.map { .package(ecosystem: $0, name: name) } ?? .project(slug: name, name: name, installedAs: name),
                            title: name, installedVersion: "1.0.0", upgrade: upgrade, severity: .high, advisoryIDs: [], flawCount: 1,
                            exploited: false, malicious: malicious, note: nil, bigIssue: nil, origins: [origin], pageURL: SiteURL.projectPage(slug: name),
                            upgradeCommand: UpgradeCommand.advice(inputs).command, verification: .none, grade: nil, commandInputs: inputs)
            return try! FixPlan.make(for: f, tools: tools).get()
        }
        let brew = "/opt/homebrew/bin/brew"
        let nginx = plan(.homebrewFormula(name: "nginx"), "nginx", nil), slack = plan(.homebrewCask(token: "slack"), "slack", nil)
        let lodash = plan(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "lodash", .npm)
        let evil = plan(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "evil", .npm, malicious: true)
        let urllib3 = plan(.pip(python: Self.python, user: false, formula: nil), "urllib3", .pypi)
        #expect(FixBatchKind.of(nginx) == .formulae(brew: brew) && FixBatchKind.of(slack) == .casks(brew: brew))
        #expect(FixBatchKind.of(lodash) == .npm(npm: "/opt/homebrew/bin/npm") && FixBatchKind.of(urllib3) == .pip(python: Self.python.executable, user: false))
        #expect(FixBatchKind.of(evil) == .single(evil.invocation))                                  // a removal is its own
        #expect(FixBatchKind.formulae(brew: brew).invocation(["nginx", "openssh", "nginx"]).argv == [brew, "upgrade", "nginx", "openssh"])
        #expect(FixBatchKind.casks(brew: brew).invocation(["slack", "zoom"]).argv == [brew, "upgrade", "--cask", "slack", "zoom"])
        #expect(FixBatchKind.casks(brew: brew).dryRun(["slack"])?.argv == [brew, "upgrade", "--cask", "--dry-run", "slack"])
        #expect(FixBatchKind.npm(npm: "/n").invocation([FixBatchKind.argument(lodash)!, "chalk@4.1.2"]).argv == ["/n", "install", "-g", "lodash@9.9.9", "chalk@4.1.2"])
        let order: [Int] = [FixBatchKind.of(lodash).order(removal: false), FixBatchKind.of(urllib3).order(removal: false),
                            FixBatchKind.of(slack).order(removal: false), FixBatchKind.of(nginx).order(removal: false), FixBatchKind.of(evil).order(removal: true)]
        #expect(order == [4, 3, 2, 1, 0])
    }

    /// Which item of a batch asked for a password, from brew's headings; a prompt before any item is named cannot be
    /// told.
    @Test func thePasswordPromptBelongsToTheItemTheLogWasOn() {
        let log = FixLog(["==> Upgrading 3 outdated packages:", "==> Upgrading slack", "==> Upgrading zoom",
                          "==> Running installer for zoom with sudo; the password may be necessary.",
                          "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper",
                          "==> Upgrading signal", "🍺  signal was successfully upgraded!"])
        #expect(FixBatchLog.askedForPassword(log, items: ["slack", "zoom", "signal"]) == ["zoom"])
        #expect(FixBatchLog.askedForPassword(FixLog(["sudo: a password is required"]), items: ["zoom"]) == nil)
        #expect(FixBatchLog.askedForPassword(FixLog(["==> Upgrading slack", "done"]), items: ["slack"]) == [])
    }

    /// A real process standing in for brew: the second cask's installer asks for a password (sudo fails at once without
    /// a terminal), then brew goes on to the third. A batch lets it; a single fix stops at the prompt.
    @Test func brewGoesOnPastACaskThatAskedForAPassword() async throws {
        let dir = temporaryDirectory()
        let brew = dir.appendingPathComponent("brew")
        write("""
        #!/bin/sh
        here="$(dirname "$0")"
        shift 2
        status=0
        for c in "$@"; do
          echo "==> Upgrading $c"
          if [ "$c" = "zoom" ]; then
            echo "==> Running installer for zoom with sudo; the password may be necessary."
            echo "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper" >&2
            sleep 4; status=1; continue
          fi
          touch "$here/upgraded-$c"
        done
        exit $status

        """, to: brew)
        chmod(brew.path, 0o755)
        func run(_ limits: FixLimits) async -> (FixEnding, FixLog) {
            let p = FixProcessLauncher().launch(FixInvocation(executable: brew.path, arguments: ["upgrade", "--cask", "slack", "zoom", "signal"]),
                                                environment: ["PATH": "/usr/bin:/bin"], limits: limits) { _ in }
            return await p.ending()
        }
        let (ending, log) = await run(FixLimits(grace: 1, stopsAtPassword: false))
        #expect(ending == .needsPassword)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("upgraded-slack").path))
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("upgraded-signal").path))   // went on past zoom
        #expect(FixBatchLog.askedForPassword(log, items: ["slack", "zoom", "signal"]) == ["zoom"])
        try FileManager.default.removeItem(at: dir.appendingPathComponent("upgraded-signal"))
        let (single, _) = await run(FixLimits(grace: 1))
        #expect(single == .needsPassword && !FileManager.default.fileExists(atPath: dir.appendingPathComponent("upgraded-signal").path))
    }

    // MARK: Casks

    /// brew info's answer for a cask, with its artifacts.
    static func caskInfo(_ token: String, version: String, installed: String?, artifacts: String = #"[{"app":["App.app"]}]"#) -> String {
        #"{"formulae":[],"casks":[{"token":"\#(token)","version":"\#(version)","installed":\#(installed.map { "\"\($0)\"" } ?? "null"),"outdated":false,"disabled":false,"artifacts":\#(artifacts)}]}"#
    }

    /// An Electron app at `bundle`, its own version written in its Info.plist; the finding about the Electron in it.
    static func electronApp(_ name: String, token: String, version: String, electron: String, in dir: URL) -> Finding {
        let bundle = dir.appendingPathComponent("\(name).app")
        write("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>\(version)</string></dict></plist>
        """, to: bundle.appendingPathComponent("Contents/Info.plist"))
        let origin = Origin.electronApp(name: name, bundlePath: bundle.path, caskToken: token)
        let inputs = UpgradeCommand.Inputs(origin: origin, name: "electron", ecosystem: .npm, target: Fixture.fix("42.11.16", above: electron), malicious: false)
        return Finding(id: "app|\(bundle.path)|\(electron)", group: .exploited, subject: .package(ecosystem: .npm, name: "electron"), title: name,
                       component: "Electron", installedVersion: electron, upgrade: inputs.target.map { _ in Fixture.fix("42.11.16", above: electron) }, severity: .high, advisoryIDs: [], flawCount: 50,
                       exploited: true, malicious: false, note: nil, bigIssue: nil, origins: [origin],
                       pageURL: SiteURL.packagePage(.npm, "electron", version: electron), upgradeCommand: UpgradeCommand.advice(inputs).command,
                       verification: .none, grade: nil, commandInputs: inputs)
    }

    static func assess(_ finding: Finding, info: String, systemRoot: String = "") async -> FixAssessment {
        let runner = ScriptedRunner { _ in ok(info) }
        var tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: runner, isExecutable: { _ in true })
        tools.systemRoot = systemRoot
        return await FixAdvisor(tools: tools, home: "/Users/ana").assess(finding)
    }

    /// The owner's two no-ops: OpenMTP at Homebrew's newest (the record says so too), and Dropbox, which updates itself
    /// past a record that is far behind. Neither gets a button, so Fix all does not count them; the row says why.
    @Test func aCaskUpgradeThatCannotChangeTheAppIsNotOffered() async {
        let dir = temporaryDirectory()
        let openmtp = Self.electronApp("OpenMTP", token: "openmtp", version: "3.3.0", electron: "18.3.15", in: dir)
        #expect(await Self.assess(openmtp, info: Self.caskInfo("openmtp", version: "3.3.0", installed: "3.3.0"))
                == .withheld("Newest version installed; no fixed release yet. It still ships Electron 18.3.15."))
        let dropbox = Self.electronApp("Dropbox", token: "dropbox", version: "280.4.5053", electron: "37.10.3", in: dir)
        #expect(await Self.assess(dropbox, info: Self.caskInfo("dropbox", version: "280.4.5053,1234", installed: "236.4.5918"))
                == .withheld("Newest version installed; no fixed release yet. It still ships Electron 37.10.3."))
        // a newer one is offered, and the line names the app's own version, not the record's
        guard case let .offer(o) = await Self.assess(dropbox, info: Self.caskInfo("dropbox", version: "281.1.0", installed: "236.4.5918")) else {
            Issue.record("a newer Dropbox was not offered"); return
        }
        #expect(o.homebrew == "Has Dropbox 281.1.0; 280.4.5053 is installed. Whether that brings the fix shows when the app checks again.")
        // brew info did not answer: never offered blind
        guard case .withheld = await Self.assess(dropbox, info: "not json") else { Issue.record("offered without Homebrew's answer"); return }
    }

    /// A cask whose update runs as root is Terminal only: its record's pkg or installer, an uninstall step that needs root
    /// (a kernel extension, receipts, a system service, files outside the home folder, a script with sudo), or an app
    /// bundle this user cannot replace.
    @Test func aCaskThatNeedsAPasswordIsTerminalOnly() async throws {
        let dir = temporaryDirectory()
        let app = Self.electronApp("Zoom", token: "zoom", version: "6.2.5", electron: "30.0.0", in: dir)
        let root = temporaryDirectory()
        write("<plist/>", to: root.appendingPathComponent("Library/LaunchDaemons/us.zoom.daemon.plist"))
        let cases: [(String, String)] = [
            (#"[{"pkg":["Zoom.pkg"]}]"#, "its update runs an installer package"),
            (#"[{"installer":[{"script":{"executable":"install.sh"}}]}]"#, "its update runs an installer"),
            (#"[{"app":["Zoom.app"]},{"uninstall":[{"kext":"com.zoom.kext","quit":"us.zoom.xos"}]}]"#, "its update runs a kernel extension"),
            (#"[{"uninstall":[{"pkgutil":"us.zoom.pkg"}]}]"#, "its update runs installer receipts"),
            (#"[{"uninstall":[{"delete":["/Library/Internet Plug-Ins/ZoomUsPlugIn.plugin"]}]}]"#, "its update runs files outside your home folder"),
            (#"[{"zap":[{"script":{"executable":"rm.sh","sudo":true}}]}]"#, "its update runs a script run as root"),
            (#"[{"uninstall":[{"launchctl":"us.zoom.daemon"}]}]"#, "its update stops a system service"),
        ]
        for (artifacts, why) in cases {
            let a = await Self.assess(app, info: Self.caskInfo("zoom", version: "6.3.11", installed: "6.2.5", artifacts: artifacts), systemRoot: root.path)
            guard case let .terminal(offer, line) = a else { Issue.record("\(artifacts): \(a)"); continue }
            #expect(line == "Needs your administrator password: \(why).")
            #expect(offer.plan.command == "brew upgrade --cask zoom")
        }
        // a user agent's launchctl and files in the home folder need no root
        guard case .offer = await Self.assess(app, info: Self.caskInfo("zoom", version: "6.3.11", installed: "6.2.5",
                                                                     artifacts: #"[{"uninstall":[{"launchctl":"us.zoom.agent","delete":["~/Library/Zoom"]}]}]"#),
                                              systemRoot: root.path) else { Issue.record("a user-level uninstall was refused"); return }
        // an app bundle this user cannot replace
        let bundle = dir.appendingPathComponent("Zoom.app").path
        chmod(bundle, 0o555)
        defer { chmod(bundle, 0o755) }
        guard case let .terminal(_, line) = await Self.assess(app, info: Self.caskInfo("zoom", version: "6.3.11", installed: "6.2.5")) else {
            Issue.record("an unwritable app was offered"); return
        }
        #expect(line == "Needs your administrator password: this user cannot replace the app.")
    }

    @Test func readsACasksArtifacts() throws {
        let json = #"{"formulae":[],"casks":[{"token":"dropbox","version":"280.4.5053","installed":"236.4.5918","artifacts":[{"app":["Dropbox.app"]},{"uninstall":[{"launchctl":"com.dropbox.DropboxMacUpdate.agent","kext":"com.getdropbox.dropbox.kext","delete":["/Library/DropboxHelperTools"]}]},{"zap":[{"trash":["~/.dropbox"]}]}]}]}"#
        let info = try #require(HomebrewInfo.parse(Data(json.utf8), name: "dropbox", cask: true))
        #expect(info.artifacts == CaskArtifacts(apps: ["Dropbox.app"], privileged: ["a kernel extension", "files outside your home folder"],
                                                services: ["com.dropbox.DropboxMacUpdate.agent"]))
    }
}
