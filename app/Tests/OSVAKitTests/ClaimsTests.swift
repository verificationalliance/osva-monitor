import Foundation
import Testing
@testable import OSVAKit

/// The claims about the app, checked on its own findings, and the routing that makes them true, checked in its source:
///   - a version is flagged as affected only if it lies inside a range the site publishes for that flaw;
///   - every version the app suggests upgrading to is newer than the installed one, and lies outside the published
///     ranges of every flaw it says that version fixes;
///   - only Core.swift makes a `CheckedUpgrade`, and nothing writes a version to upgrade to, or a command's version,
///     from anything else.
/// And what the README and the proof report (.verificationalliance.json) say: the same sentences, and theorems that exist.
/// scripts/claims-mutants.sh breaks each in turn and expects this suite to fail.
@Suite struct ClaimsTests {
    let core = Core.shared

    static let claims = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-claims.json")).packages

    static func package(_ name: String) -> Finding {
        BatchCheckTests.findings(claims.filter { $0.name == name }).first!
    }

    static func report(_ findings: [Finding]) -> ScanReport {
        ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(), findings: findings, sent: SentRecord(), indexGeneratedAt: nil, problems: [])
    }

    // MARK: Behaviour (the mutants likely-as-flagged, unchecked-target, lenient-decoding)

    /// A flaw the site publishes no ranges for is likely affected at most, never affected, and never counted.
    @Test func likelyIsNeverAffected() {
        let f = Self.package("likely-pkg")
        #expect(f.group == .likely)
        #expect(Self.report([f]).actionCount == 0)
    }

    /// The server's target 1.5.0 lies inside the flaw's only published range: the core's judgement names no upgrade, at
    /// its door and in the package's check (a finding also takes a target only for a flaw it leaves, a second layer that
    /// would hide a wrong judgement here), and the finding shows no version and no command.
    @Test func aServerTargetTheCoreRejectsIsNeverShown() throws {
        let inside = [CoreAdvisory(ranges: [AffectedRange(fixed: "2.0.0")], fixed: [])]
        let judged = try #require(core.judge("1.5.0", from: "1.0.0", advisories: inside, flagged: [true]))
        #expect(judged.leaves == [false] && judged.upgrade == nil)
        let answer = try #require(Self.claims.first { $0.name == "inside-target" })
        let check = BatchCheck.read(answer, installed: "1.0.0")
        #expect(check.upgrade == nil && check.target == .unconfirmed && check.fixed.isEmpty)
        let f = Self.package("inside-target")
        #expect(f.group == .criticalHigh)
        #expect(f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
    }

    /// A range with a key nobody publishes ("fixd") does not read: the flaw is reported, never inside a wider range. The
    /// same range in a project's record gives no affected finding at 3.0.
    @Test func anUnknownRangeKeyIsNeverAWiderRange() throws {
        #expect(Self.package("typo-range").group == .reported)
        let record = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"nginx","name":"nginx","recent":[{"id":"CVE-TYPO","sev":"HIGH","ranges":[{"introduced":"1.0","fixd":"2.0"}]}]}
            """#.utf8))
        let brew = FindingBuilder.BrewMatch(item: HomebrewItem(kind: .formula, name: "nginx", version: "3.0", urls: []),
                                            project: Fixture.index.project(slug: "nginx")!)
        let found = FindingBuilder(index: Fixture.index).findings(approved: [:], verdicts: [:], brew: [brew], projects: ["nginx": record], bigIssues: [])
        #expect(!found.contains { $0.group.needsAction || $0.group == .other })
    }

    // MARK: The claims, over the recorded answers

    /// One finding, with what the claims are read against: the ranges published for the advisories it can name (by id
    /// and alias) and each id's aliases. `kind` says how the app made it.
    struct Checked {
        var kind: String; var finding: Finding; var ranges: [String: [AffectedRange]]; var same: [String: Set<String>]
        /// The ids of flaws of another platform than this Mac's (an exact-version answer's `platform`): their ranges
        /// never block a version suggested for software on this Mac.
        var elsewhere: Set<String> = []
    }

    /// The ids of these flaws that are another platform's.
    static func elsewhere(_ flaws: [BatchResponse.Flaw]) -> Set<String> { Set(flaws.filter { !$0.affectsThisMac }.flatMap { [$0.id] + $0.aliases }) }

    static func reading(_ flaws: [BatchResponse.Flaw]) -> (ranges: [String: [AffectedRange]], same: [String: Set<String>]) {
        var ranges: [String: [AffectedRange]] = [:], same: [String: Set<String>] = [:]
        for flaw in flaws {
            let ids = [flaw.id] + flaw.aliases
            for id in ids { ranges[id] = flaw.ranges; same[id, default: []].formUnion(ids) }
        }
        return (ranges, same)
    }

    static func reading(_ recent: [ProjectResponse.Advisory]) -> (ranges: [String: [AffectedRange]], same: [String: Set<String>]) {
        var ranges: [String: [AffectedRange]] = [:], same: [String: Set<String>] = [:]
        for a in recent {
            let ids = [a.id] + (a.cve.map { [$0] } ?? [])
            for id in ids { ranges[id] = a.rangesUnreadable ? nil : a.ranges; same[id, default: []].formUnion(ids) }
        }
        return (ranges, same)
    }

    static func record(_ slug: String, _ advisories: String) -> ProjectResponse {
        try! JSONDecoder().decode(ProjectResponse.self, from: Data(#"{"slug":"\#(slug)","name":"\#(slug)","recent":[\#(advisories)]}"#.utf8))
    }

    static func item(_ slug: String, ids: [String], fixedIn: [String]) -> StateResponse.BigIssue {
        try! JSONDecoder().decode(StateResponse.BigIssue.self, from: Data((#"{"name":"\#(slug)","slug":"\#(slug)","severity":"HIGH","exploited":true,"#
            + #""date":"2026-11-20","ids":[\#(ids.map { "\"\($0)\"" }.joined(separator: ","))],"#
            + #""fixed_in":[\#(fixedIn.map { "\"\($0)\"" }.joined(separator: ","))],"title":"Item"}"#).utf8))
    }

    /// The findings the claims are checked on, each kind the app makes but Java's (its shown versions are not the
    /// compared ones), and the findings whose answer the check could not find (`missed`, which must stay empty: a finding
    /// skipped is a claim unchecked).
    static let sample: (checked: [Checked], missed: [String]) = {
        var out: [Checked] = [], missed: [String] = []
        // packages checked by exact version: the batch answers with published ranges, and the claims fixture
        for file in ["check-batch-plan.json", "check-batch-live-2026-11-25.json", "check-batch-programs-live-2026-11-25.json", "check-batch-claims.json"] {
            let results = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/" + file)).packages
            for f in BatchCheckTests.findings(results) {
                guard case let .package(eco, name) = f.subject,
                      let r = results.first(where: { $0.ecosystem == eco.rawValue && $0.name == name && $0.version == f.installedVersion })
                else { missed.append(f.id); continue }
                let (ranges, same) = reading(r.flaws)
                out.append(Checked(kind: "package", finding: f, ranges: ranges, same: same, elsewhere: elsewhere(r.flaws)))
            }
        }
        // programs and tools: a row shows its worst part, its version as people write it ("0.23.0" for "v0.23.0")
        let programs = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-programs-live-2026-11-25.json")).packages
        let fd = BuiltProgram(language: .rust, path: "/Users/ana/.cargo/bin/fd", name: "fd", version: "10.5.2", place: .cargoInstall, formula: nil,
                              package: "fd-find", module: "fd-find", toolchain: nil)
        let installed = [("golang.org/x/net", "v0.23.0"), ("golang.org/x/text", "v0.3.7"), ("stdlib", "1.22.3"), ("golang.org/x/sys", "v0.35.0")].map {
            InstalledPackage(ecosystem: .go, name: $0.0, version: $0.1, origin: .program(ProgramFindingTests.gh))
        } + [("black", "24.1.0"), ("requests", "2.25.0")].map { InstalledPackage(ecosystem: .pypi, name: $0.0, version: $0.1, origin: .pythonTool(ProgramFindingTests.black)) }
          + [InstalledPackage(ecosystem: .crates, name: "time", version: "0.1.43", origin: .program(fd))]
        let selection = PrivacyFilter(index: ProgramFindingTests.index).approve(installed)
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in
            programs.first { $0.ecosystem == a.ecosystem.rawValue && $0.name == a.name && $0.version == a.version }.map { (a, $0) }
        })
        for f in FindingBuilder(index: ProgramFindingTests.index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: []) {
            guard case let .package(eco, name) = f.subject, let r = programs.first(where: {
                $0.ecosystem == eco.rawValue && $0.name == name && FindingBuilder.Component.shown($0.version) == f.installedVersion
            }) else { missed.append(f.id); continue }
            let (ranges, same) = reading(r.flaws)
            out.append(Checked(kind: "program", finding: f, ranges: ranges, same: same, elsewhere: elsewhere(r.flaws)))
        }
        // Homebrew formulae decided by their projects' records
        let postgres = try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-postgres.json"))
        let cpython = try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-cpython-ranges.json"))
        let brew: [(String, String, ProjectResponse)] = [
            ("postgresql@14", "14.10", postgres), ("postgresql@15", "15.19", postgres), ("postgresql@16", "16.14", postgres),
            ("postgresql@16", "16.16", postgres), ("postgresql@17", "17.0", postgres), ("postgresql@18", "18.6", postgres),
            ("python@3.11", "3.11.18", cpython), ("python@3.12", "3.12.16", cpython), ("python@3.13", "3.13.18", cpython),
            ("python@3.14", "3.14.10", cpython), ("python@3.14", "3.14.11", cpython),
        ]
        func brewMatch(_ formula: String, _ version: String, _ slug: String) -> FindingBuilder.BrewMatch {
            .init(item: HomebrewItem(kind: .formula, name: formula, version: version, urls: []), project: Fixture.index.project(slug: slug)!)
        }
        for (formula, version, project) in brew {
            let (ranges, same) = reading(project.recent)
            for f in FindingBuilder(index: Fixture.index).findings(approved: [:], verdicts: [:], brew: [brewMatch(formula, version, project.slug)],
                                                                   projects: [project.slug: project], bigIssues: []) {
                out.append(Checked(kind: "project", finding: f, ranges: ranges, same: same))
            }
        }
        // apps and the libraries they bundle, by their product records, here with ranges where a record names one fix
        var products: [String: ProductResponse] = [:]
        for (key, product) in BundleFindingTests.products {
            var p = product
            p.recent = p.recent.map { a in var a = a; if a.fixedHint.count == 1 { a.ranges = [AffectedRange(fixed: a.fixedHint[0])] }; return a }
            products[key] = p
        }
        let (_, apps) = BundleFindingTests.applications()
        for f in BundleCheck.match(apps, index: Make.index).findings(products: products, projects: ["cpython": cpython]) {
            let recent: [ProjectResponse.Advisory]
            switch f.subject {
            case let .product(key, _): recent = products[key]?.recent ?? []
            case let .project(slug, _, _) where slug == "cpython": recent = cpython.recent
            default: if !f.malicious { missed.append(f.id) }; continue
            }
            let (ranges, same) = reading(recent)
            out.append(Checked(kind: "product", finding: f, ranges: ranges, same: same))
        }
        // MacPorts, Nix and conda packages matched to graded projects
        let nginx = record("nginx", #"{"id":"CVE-M1","sev":"HIGH","ranges":[{"introduced":"1.30.0","fixed":"1.30.7"},{"introduced":"1.31.0","fixed":"1.31.9"}]},"#
                                    + #"{"id":"CVE-M2","sev":"CRITICAL","ranges":[{"fixed":"1.30.5"}]}"#)
        let openssl = record("openssl", #"{"id":"CVE-O1","sev":"HIGH","ranges":[{"introduced":"3.0.0","fixed":"3.0.15"}]}"#)
        let profile = NixProfile(path: "/Users/ana/.nix-profile", style: .profile, shared: false)
        let env = CondaEnvironment(prefix: "/Users/ana/miniforge3", name: "base", named: true, tool: .conda, python: "3.11.5")
        let managed = [ManagedPackage(manager: .macports, name: "nginx", version: "1.30.2", origin: .macports(port: "nginx")),
                       ManagedPackage(manager: .nix, name: "nginx", version: "1.31.8", origin: .nix(profile: profile, element: "nginx")),
                       ManagedPackage(manager: .conda, name: "openssl", version: "3.0.12", origin: .conda(env: env))]
        let matches = managed.map { FindingBuilder.ManagedMatch(package: $0, project: ProgramFindingTests.index.project(manager: $0.manager.rawValue, package: $0.name)!) }
        for f in FindingBuilder(index: ProgramFindingTests.index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": nginx, "openssl": openssl],
                                                                           bigIssues: [], managed: matches) {
            let (ranges, same) = reading(f.title == "openssl" || f.title == "OpenSSL" ? openssl.recent : nginx.recent)
            out.append(Checked(kind: "managed", finding: f, ranges: ranges, same: same))
        }
        // findings an item of the "patch these first" list promotes or makes: a formula's, an app's Electron, each way
        let promotedRecord = record("nginx", #"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null},"#
                                             + #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.12"}]}"#)
        let madeRecord = record("cpython", #"{"id":"CVE-R","sev":"MODERATE","ranges":[{"introduced":"3.11.0","fixed":"3.11.20"}]}"#)
        let itemFindings = FindingBuilder(index: Fixture.index).findings(
            approved: [:], verdicts: [:], brew: [brewMatch("nginx", "1.31.5", "nginx"), brewMatch("python@3.11", "3.11.18", "cpython")],
            projects: ["nginx": promotedRecord, "cpython": madeRecord],
            bigIssues: [item("nginx", ids: ["CVE-K"], fixedIn: []), item("cpython", ids: ["CVE-R"], fixedIn: [])])
        for f in itemFindings {
            let (ranges, same) = reading((f.title == "nginx" ? promotedRecord : madeRecord).recent)
            out.append(Checked(kind: "item", finding: f, ranges: ranges, same: same))
        }
        let electron = try! BatchCheckTests.electronItem()
        let reported = try! BatchCheckTests.result("npm", "electron", "28.1.0", flaws: [BatchCheckTests.flaw("CVE-EL", severity: "HIGH")],
                                                   plan: BatchCheckTests.plan("28.3.2"))
        let (electronRanges, electronSame) = reading(BatchCheckTests.electronRecord.recent)
        for f in BatchCheckTests.findings([reported], index: Fixture.index, bigIssues: [electron], projects: ["electron": BatchCheckTests.electronRecord]) { _ in
            BatchCheckTests.slack
        } {
            out.append(Checked(kind: "item", finding: f, ranges: electronRanges, same: electronSame))
        }
        let approved = PrivacyFilter(index: Fixture.index).approve([InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0",
                                                                                      origin: BatchCheckTests.slack)]).approved
        for f in FindingBuilder(index: Fixture.index).findings(approved: approved, verdicts: [:], brew: [], projects: ["electron": BatchCheckTests.electronRecord],
                                                               bigIssues: [electron]) {
            out.append(Checked(kind: "item", finding: f, ranges: electronRanges, same: electronSame))
        }
        return (out, missed)
    }()

    static var checked: [Checked] { sample.checked }

    /// A finding listed with nothing to do on this Mac: every flaw outside its published ranges, or of another platform.
    static func listedOnly(_ f: Finding) -> Bool { f.outsideItsRanges == true || f.onlyElsewhere == true }

    /// The findings in today's groups that say the version is affected: malicious ones aside, and those listed with
    /// nothing to do on this Mac, which say it is not (`everyListedFindingWithNothingToDoIsNotAffected`).
    static var affected: [Checked] {
        checked.filter { !$0.finding.malicious && [.exploited, .criticalHigh, .other].contains($0.finding.group) && !listedOnly($0.finding) }
    }

    /// The sample reaches every kind of finding these claims are about, each with findings in today's groups and with
    /// versions named, and every finding is read against its own answer: none is skipped.
    @Test func theClaimsAreCheckedOnEveryKindOfFinding() {
        #expect(Self.sample.missed == [], "findings whose answer the check could not find")
        let affected = Set(Self.affected.map(\.kind))
        let named = Set(Self.checked.filter { $0.finding.fixedVersion != nil && !$0.finding.malicious }.map(\.kind))
        let kinds: Set = ["package", "program", "project", "product", "managed", "item"]
        #expect(affected == kinds, "kinds with affected findings: \(affected.sorted())")
        #expect(named == kinds, "kinds with versions named: \(named.sorted())")
    }

    /// "A version is flagged as affected only if it lies inside an affected range the site publishes for that flaw":
    /// every finding in today's groups, malicious ones aside, has an advisory whose published ranges hold its version,
    /// by the test's own comparisons (RangesTests.holds).
    @Test func everyAffectedFindingLiesInsideAPublishedRange() {
        let affected = Self.affected
        #expect(affected.count >= 20, "the sample has affected findings to check")
        for c in affected {
            let f = c.finding
            let holding = f.advisoryIDs.filter { id in (c.ranges[id] ?? []).contains { RangesTests.holds($0, f.installedVersion) } }
            #expect(!holding.isEmpty, "\(c.kind) \(f.id) is in \(f.group) with no published range holding \(f.installedVersion)")
        }
    }

    /// What is listed with nothing to do on this Mac is in Other, never counted and never "not checked", and does not
    /// look affected: a finding outside its published ranges has none that holds its version and no severity; one whose
    /// flaws are all of another platform has a severity only when a published range holds its version there. Neither
    /// names a version. The claims fixture has both kinds, so this is never checked on nothing.
    @Test func everyListedFindingWithNothingToDoIsNotAffected() {
        let listed = Self.checked.filter { !$0.finding.malicious && Self.listedOnly($0.finding) }
        #expect(listed.contains { $0.finding.outsideItsRanges == true } && listed.contains { $0.finding.onlyElsewhere == true },
                "the sample has findings outside their ranges and findings of another platform")
        for c in listed {
            let f = c.finding
            let holding = f.advisoryIDs.filter { id in (c.ranges[id] ?? []).contains { RangesTests.holds($0, f.installedVersion) } }
            #expect(f.group == .other && !f.exploited && f.notChecked == nil && f.fixedVersion == nil && f.upgradeCommand == nil,
                    "\(c.kind) \(f.id) is listed with nothing to do, yet looks like something to do")
            if f.outsideItsRanges == true {
                #expect(holding.isEmpty && f.severity == nil, "\(c.kind) \(f.id) is outside its ranges, with \(holding) holding it, severity \(String(describing: f.severity))")
            }
            if f.severity != nil {
                #expect(!holding.isEmpty, "\(c.kind) \(f.id) has another platform's severity with no published range holding \(f.installedVersion)")
            }
        }
    }

    /// "Every version it suggests upgrading to is newer than yours and lies outside the published ranges of every
    /// advisory it says that version fixes": the advisories whose ranges hold the installed version, less those the
    /// finding lists as not fixed. And for a package checked by exact version (ruling 8, as corrected), it lands inside
    /// none of the published ranges the installed version is outside of that apply to this Mac: the core's own upgrades
    /// never do (`upgradeFor_leaves`). A Windows-only flaw's range does not block it (`windows-range-target`).
    @Test func everyNamedVersionLeavesTheAdvisoriesItFixes() {
        let named = Self.checked.filter { $0.finding.fixedVersion != nil && !$0.finding.malicious }
        #expect(named.count >= 20, "the sample names versions to check")
        for c in named {
            let f = c.finding, fixed = f.fixedVersion!, installed = f.installedVersion
            #expect(core.compareVersions(fixed, installed) > 0, "\(c.kind) \(f.id): \(fixed) is not above \(installed)")
            let notFixed = Set(f.unresolved.flatMap { c.same[$0.id] ?? [$0.id] })
            for id in f.advisoryIDs where !notFixed.contains(id) {
                let rs = c.ranges[id] ?? []
                guard rs.contains(where: { RangesTests.holds($0, installed) }) else { continue }
                #expect(!rs.contains { RangesTests.holds($0, fixed) }, "\(c.kind) \(f.id): \(fixed) lies inside \(id)'s published ranges")
            }
            guard c.kind == "package" || c.kind == "program" else { continue }
            for (id, rs) in c.ranges.sorted(by: { $0.key < $1.key })
            where !notFixed.contains(id) && !c.elsewhere.contains(id) && !rs.isEmpty && !rs.contains(where: { RangesTests.holds($0, installed) }) {
                #expect(!rs.contains { RangesTests.holds($0, fixed) }, "\(c.kind) \(f.id): \(fixed) lands inside \(id)'s published ranges, which \(installed) is outside of")
            }
        }
        #expect(Self.package("lands-inside").fixedVersion == nil, "the claims fixture's lands-inside names a version inside GHSA-land-b")
        #expect(Self.package("windows-range-target").fixedVersion == "2.0.0",
                "the claims fixture's windows-range-target is refused for a Windows-only flaw's range, on a Mac")
    }

    /// A flaw's "Fixed in X, not by this upgrade" is held to what a named version is: above the installed version, and
    /// outside that flaw's published ranges when they hold the installed version. A malicious package names none: the
    /// core checked none, and the advice is to remove it.
    @Test func everyFlawsFixedInLeavesThatFlaw() {
        var named = 0
        for c in Self.checked {
            let f = c.finding
            for u in f.unresolved {
                guard let fixedIn = u.fixedIn else { continue }
                named += 1
                #expect(!f.malicious, "\(c.kind) \(f.id), malicious, names \(fixedIn) as \(u.id)'s fix")
                let rs = (c.same[u.id] ?? [u.id]).flatMap { c.ranges[$0] ?? [] }
                guard c.kind != "program" || !rs.isEmpty else { continue }       // a program's row shows its worst part's version only
                #expect(core.compareVersions(fixedIn, f.installedVersion) > 0, "\(c.kind) \(f.id): \(u.id)'s \(fixedIn) is not above \(f.installedVersion)")
                guard rs.contains(where: { RangesTests.holds($0, f.installedVersion) }) else { continue }
                #expect(!rs.contains { RangesTests.holds($0, fixedIn) }, "\(c.kind) \(f.id): \(u.id)'s \(fixedIn) lies inside its published ranges")
            }
        }
        #expect(named >= 2, "the sample names fixed-in versions to check")
        #expect(Self.package("unfixed-fixed-in").unresolved.map(\.id) == ["GHSA-uf-b"], "the claims fixture's unfixed-fixed-in lists its flaw")
        // a flaw with a range per release branch: its "Fixed in" is the fix on the installed version's branch, never the
        // first one it names (1.4.2, below 2.5.0)
        let branches = Self.package("multi-branch")
        #expect(branches.fixedVersion == "2.5.5" && branches.unresolved.map(\.id) == ["GHSA-mb"] && branches.unresolved.map(\.fixedIn) == ["2.6.1"],
                "the claims fixture's multi-branch: \(branches.unresolved.map { "\($0.id) \($0.fixedIn ?? "-")" })")
        #expect(Self.package("malicious-remaining").unresolved.map(\.id) == ["GHSA-mr"], "the claims fixture's malicious-remaining lists its flaw")
    }

    /// A note that names a version as fixed ("the issuer names X as fixed", "lists V as affected and X as fixed") names
    /// the version the finding shows, which the core checked: never the issuer's own word, unchecked.
    @Test func aNoteNamesOnlyTheCheckedVersion() {
        var said = 0
        for c in Self.checked {
            let f = c.finding
            for m in (f.note ?? "").matches(of: /(?:names|and) ([^\s,]+) as fixed/) {
                said += 1
                #expect(String(m.output.1) == f.fixedVersion, "\(c.kind) \(f.id) says \(m.output.0) but shows \(f.fixedVersion ?? "no version")")
            }
        }
        #expect(said >= 10, "the sample has notes that name a fixed version")
        #expect(Self.package("likely-unconfirmed").note == "Likely affected: the site publishes no affected ranges. No checked fixed version yet; see the site.")
    }

    // MARK: The routing, in the source

    /// app/Sources, each Swift file's path (from app/Sources) and its lines without comments. The patterns below mark a
    /// name's start with `(?:^|[^A-Za-z0-9_])`, not `\b`: Swift's `\b` is Unicode's word boundary, and there is none
    /// inside "self.fixedVersion" or "Core.shared.newestVersion(".
    static let sources: [(path: String, lines: [String])] = {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources")
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!.compactMap { $0 as? URL }
            .filter { $0.pathExtension == "swift" }.sorted { $0.path < $1.path }
        return files.map { url in
            let path = String(url.path.dropFirst(root.path.count + 1))
            let lines = try! String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n").map { line -> String in
                if line.trimmingCharacters(in: .whitespaces).hasPrefix("//") { return "" }
                return line.range(of: " // ").map { String(line[..<$0.lowerBound]) } ?? line
            }
            return (path, lines)
        }
    }()

    /// A file's code, comments aside, as one text.
    static func code(_ path: String) -> String? { sources.first { $0.path == path }?.lines.joined(separator: "\n") }

    /// The lines of code (comments aside) that match `pattern`, as "path: line", but those `allowed` says may.
    static func lines(matching pattern: _StringProcessing.Regex<Substring>, except allowed: (String, String) -> Bool = { _, _ in false }) -> [String] {
        sources.flatMap { file in
            file.lines.filter { line in line.contains(pattern) && !allowed(file.path, line) }.map { "\(file.path): \($0.trimmingCharacters(in: .whitespaces))" }
        }
    }

    /// Every match of `pattern` across each file's whole code (so across lines), as "path: match".
    static func matches(of pattern: _StringProcessing.Regex<Substring>, except allowed: (String) -> Bool = { _ in false }) -> [String] {
        sources.filter { !allowed($0.path) }.flatMap { file in
            file.lines.joined(separator: "\n").matches(of: pattern).map { "\(file.path): \($0.output)" }
        }
    }

    /// A line allowed by a fragment of it, in its file: `(path, fragment)`.
    static func allowed(_ list: [(String, String)]) -> (String, String) -> Bool {
        { path, line in list.contains { $0.0 == path && line.contains($0.1) } }
    }

    /// Only Core.swift makes a `CheckedUpgrade` or a `Judgement`, and only it extends them, but for the one extension that
    /// writes a checked version in its style (OSVAKit's `display`, in Verified.swift); a version is shown only as a
    /// `CheckedUpgrade.Display` style writes it (`.displayed(.java)`, `.displayed(.program)`); the old doors are gone; a
    /// newest or oldest version is picked only on the lines that read installed versions or hand it to the core's judge;
    /// the server's planned target (`unjudgedTarget`) is read only where the core judges it.
    @Test func onlyCoreSwiftBuildsACheckedUpgrade() throws {
        try #require(Self.code("OSVAVerified/Core.swift") != nil, "the scan reads app/Sources")
        let core = "OSVAVerified/Core.swift", shown = "OSVAKit/Verified.swift"
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:CheckedUpgrade|Judgement)\s*\(/, except: { path, _ in path == core }) == [])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])extension\s+(?:(?:OSVAKit|OSVAVerified)\s*\.\s*)?(?:CheckedUpgrade|Judgement)(?![A-Za-z0-9_])/,
                           except: { path, line in path == core || (path == shown && line == "extension CheckedUpgrade {") }) == [])
        // a version is shown only as CheckedUpgrade.Display writes it: a closed set of styles that carry no text
        let display = try #require(Self.code(core))
        let styles = try #require(display.firstMatch(of: /public enum Display: Sendable, Hashable \{([^}]*)\}/)?.1)
        let cases = styles.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("case ") }
        #expect(cases == ["case asChecked", "case java", "case program"], "CheckedUpgrade.Display: \(cases)")
        #expect(display.contains("public func displayed(_ style: Display) -> CheckedUpgrade { CheckedUpgrade(self, style: style) }"))
        // and the one extension writes the checked version in its style, and nothing else
        let written = try #require(Self.code(shown).flatMap { Self.declarations($0).first { $0.keyword == "extension" && $0.name == "CheckedUpgrade" } })
        #expect(written.body.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } == [
            "public var display: String {", "switch style {", "case .asChecked: return version", "case .java: return JavaVersion.shown(version)",
            "case .program: return FindingBuilder.Component.shown(version)", "}", "}",
        ], "OSVAKit's display")
        #expect(Self.lines(matching: /\.displayed\((?!\.java\)|\.asChecked\)|\.program\)|Self\.display\(slug: slug\)\))/) == [])
        // the old doors are gone
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:nearestVersion|affectedness)(?![A-Za-z0-9_])|osva_affected|osva_upgrade_ranges/) == [])
        // a newest or oldest version is picked only where an installed version is read, or the pick goes to the judge:
        // any mention of the function, called or not, on these lines alone
        let picks = Self.allowed([
            (core, "public func newestVersion("), (core, "public func sortedVersions("), (core, "versions.sorted { compareVersions($0, $1) < 0 }"),
            ("OSVAKit/Inventory/HomebrewSource.swift", "?? Core.shared.newestVersion(installed) ?? installed[0]"),
            ("OSVAKit/Inventory/ExtensionSource.swift", "guard let newest = Core.shared.newestVersion(versions.map(Self.chromiumFolderVersion))"),
            ("OSVAKit/Scan/Scanner.swift", "let newest = Core.shared.newestVersion(versions) ?? versions[0]"),
            ("OSVAKit/Fix/HomebrewAvailability.swift", "let inUse = linked ?? Core.shared.newestVersion(installed)"),
            ("OSVAKit/Scan/JavaCheck.swift", "return (kept, core.newestVersion(fixes), said)"),
            ("OSVAKit/Scan/JavaCheck.swift", "guard let first = core.sortedVersions(builds.map(\\.build)).first"),
            ("OSVAKit/Scan/ProgramFindings.swift", "guard let target = core.newestVersion(decided.compactMap { $0.upgrade?.version })"),
            ("OSVAKit/Scan/ProgramFindings.swift", "let installed = core.newestVersion(decided.map(\\.package.version))"),
            ("OSVAKit/Scan/ProgramFindings.swift", "let versions = Core.shared.sortedVersions(Array(Set(same.map(\\.package.version)))).map(Component.shown)"),
            // the newest last affected version, which is said, never offered
            ("OSVAKit/Scan/AdvisoryCheck.swift", "return core.newestVersion(holding.compactMap(\\.lastAffected))"),
        ])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:newestVersion|sortedVersions)(?![A-Za-z0-9_])/, except: picks) == [])
        // what the core weighs is made only from what the site publishes (the answers' readers), by the project path's
        // reading of a record, and by the previews: no advisory or range of the app's own
        let readers: Set = ["OSVAKit/API/Responses.swift", "OSVAKit/Scan/AdvisoryCheck.swift"]
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:CoreAdvisory|AffectedRange)\s*(?:\.\s*init\s*)?\(|(?:CoreAdvisory|AffectedRange)\??\s*=\s*\.init\s*\(/,
                           except: { path, _ in readers.contains(path) || path.hasPrefix("OSVAMonitorUI/PreviewData") }) == [])
        // the server's planned target is read only where the core judges it (and where it is decoded)
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])unjudgedTarget(?![A-Za-z0-9_])/, except: { path, _ in
            path == "OSVAKit/Scan/BatchCheck.swift" || path == "OSVAKit/API/Responses.swift"
        }) == [])
    }

    /// A published range's bounds, and an advisory's ranges and first fixed versions, are constants: no code can take a
    /// range the site published, move its `fixed`, and ask the core to approve the result. Neither type has a `var` bound
    /// or a mutating method, and nothing extends either outside Core.swift (an extension could rebuild one; making one
    /// is held to the answers' readers by `onlyCoreSwiftBuildsACheckedUpgrade`).
    @Test func publishedRangesAreConstants() throws {
        let core = try #require(Self.code("OSVAVerified/Core.swift"))
        let types = Self.declarations(core).filter { $0.keyword == "struct" && ($0.name == "AffectedRange" || $0.name == "CoreAdvisory") }
        #expect(types.map(\.name).sorted() == ["AffectedRange", "CoreAdvisory"])
        for t in types {
            #expect(!t.body.contains(/(?:^|[^A-Za-z0-9_])var\s+`?(?:introduced|fixed|lastAffected|ranges)`?(?![A-Za-z0-9_])/), "\(t.name) has a settable field")
            #expect(!t.body.contains(/(?:^|[^A-Za-z0-9_])mutating(?![A-Za-z0-9_])/), "\(t.name) has a mutating method")
        }
        for line in ["public let introduced: String?", "public let fixed: String?", "public let lastAffected: String?",
                     "public let ranges: [AffectedRange]?", "public let fixed: [String]"] {
            #expect(core.contains(line), "Core.swift: \(line)")
        }
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])extension\s+(?:(?:OSVAKit|OSVAVerified)\s*\.\s*)?(?:AffectedRange|CoreAdvisory)(?![A-Za-z0-9_])/) == [])
    }

    /// Core.swift is the whole of its module, OSVAVerified, which depends on the C module (OSVACore) alone; OSVAKit
    /// reaches the core only through it. So no other Swift code of the app is in scope where Core.swift calls the core:
    /// were Core.swift in OSVAKit, a function of OSVAKit's own named like a core function (osva_pct_encode, with the same
    /// signature) would be called in its place. And nothing else declares a core function's name or a type named like
    /// either module, or imports the C module.
    @Test func theBridgeIsAloneInItsModule() throws {
        let folder = Self.repository.appendingPathComponent("app/Sources/OSVAVerified")
        let files = try #require(FileManager.default.enumerator(atPath: folder.path)).compactMap { $0 as? String }.sorted()
        #expect(files == ["Core.swift"], "app/Sources/OSVAVerified holds \(files)")
        let manifest = try Self.text("app/Package.swift").split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        #expect(manifest.filter { $0.contains("\"OSVAVerified\"") } == [
            ".target(name: \"OSVAVerified\", dependencies: [\"OSVACore\"]),",
            ".target(name: \"OSVAKit\", dependencies: [\"OSVAVerified\"]),",
            ".testTarget(name: \"OSVAKitTests\", dependencies: [\"OSVAKit\", \"OSVAVerified\", \"OSVACore\"], resources: [.copy(\"Fixtures\")]),",
        ], "the targets that name OSVAVerified")
        #expect(manifest.filter { $0.contains("\"OSVACore\"") } == [
            "name: \"OSVACore\",",
            ".target(name: \"OSVAVerified\", dependencies: [\"OSVACore\"]),",
            ".testTarget(name: \"OSVAKitTests\", dependencies: [\"OSVAKit\", \"OSVAVerified\", \"OSVACore\"], resources: [.copy(\"Fixtures\")]),",
        ], "the C module, and what depends on it")
        let bridge = "OSVAVerified/Core.swift"
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:func|var|let|case|struct|enum|class|actor|protocol|typealias|macro)\s+`?osva_/,
                           except: { path, _ in path == bridge }) == [])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:struct|enum|class|actor|protocol|typealias)\s+`?(?:OSVACore|OSVAVerified)`?(?![A-Za-z0-9_])/) == [])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])import\s+(?:[a-z]+\s+)?OSVACore(?![A-Za-z0-9_])/, except: { path, _ in path == bridge }) == [])
    }

    /// Nothing writes a finding's version to upgrade to, its command, or a command's version, but from a `CheckedUpgrade`
    /// or an `UpgradeCommand.Advice`: they are `private(set)`; every line of Finding.swift that names `fixedVersion` or
    /// `upgradeCommand` is one of the known ones (so no assignment split over lines, tuple or inout gets through); and
    /// UpgradeCommand.swift writes `Inputs.target` only as `self.target = target?.version`.
    @Test func versionsAreWrittenOnlyFromACheckedUpgrade() throws {
        let finding = try #require(Self.code("OSVAKit/Model/Finding.swift")), command = try #require(Self.code("OSVAKit/Scan/UpgradeCommand.swift"))
        let known: Set = [
            "public private(set) var fixedVersion: String?",
            "self.fixedVersion = upgrade?.display; self.severity = severity; self.advisoryIDs = advisoryIDs; self.flawCount = flawCount",
            "public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }",
            "return fixedVersion.map { \"\\(installedLabel) → \\($0)\" } ?? installedLabel",
            "public private(set) var upgradeCommand: String?",
            "self.origins = origins; self.pageURL = pageURL; self.upgradeCommand = advice?.command",
            "public mutating func setAdvice(_ advice: UpgradeCommand.Advice?) { upgradeCommand = advice?.command }",
        ]
        let named = finding.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.contains(/(?:^|[^A-Za-z0-9_])(?:fixedVersion|upgradeCommand)(?![A-Za-z0-9_])/) }
        #expect(named.filter { !known.contains($0) } == [], "lines of Finding.swift that name fixedVersion or upgradeCommand")
        #expect(Set(named) == known, "the known lines are all there")
        #expect(finding.contains("public private(set) var note: String?"))
        #expect(command.contains("public private(set) var target: String?"))
        #expect(command.contains("public fileprivate(set) var command: String?") && command.contains("public fileprivate(set) var note: String?"))
        // Inputs.target: an assignment (however it is spread over lines), a tuple, an inout or a key path
        let writes = command.matches(of: /(?:^|[^A-Za-z0-9_.?!])((?:let|var)\s+)?((?:[A-Za-z0-9_?!]+\.)*)target\s*=(?!=)\s*([^;\n]*)/)
            .filter { $0.output.1 == nil }                                       // a local's declaration is no write
            .map { "\($0.output.2)target = \($0.output.3)" }
        #expect(writes == ["self.target = target?.version"], "writes of a target in UpgradeCommand.swift: \(writes)")
        #expect(command.matches(of: /&\s*(?:[A-Za-z0-9_?!]+\.)*target(?![A-Za-z0-9_])|\\(?:[A-Za-z0-9_.]*)\.target(?![A-Za-z0-9_])/).isEmpty)
        #expect(command.matches(of: /\([^()]*[^A-Za-z0-9_]target(?![A-Za-z0-9_])[^()]*\)\s*=(?!=)/).isEmpty)
        #expect(Self.lines(matching: /(?:commandInputs\??|[iI]nputs)\.target\s*=(?!=)/) == [])
    }

    /// A version or a command could also come back from text: a finding, its inputs or a report decoded from JSON. Only
    /// the saved report (Storage.swift) and osva-render's report are read back so.
    @Test func onlyTheSavedReportIsDecoded() {
        let readers: Set = ["OSVAKit/Scan/Storage.swift", "osva-render/main.swift"]
        #expect(Self.matches(of: /(?:^|[^A-Za-z0-9_])(?:Finding|ScanReport|Inputs)\s*[\]>)]*\s*\.self(?![A-Za-z0-9_])/, except: readers.contains) == [])
        #expect(Self.matches(of: /(?:^|[^A-Za-z0-9_])(?:Finding|ScanReport|Inputs)\s*(?:\.init)?\s*\(\s*from\s*:/) == [])
        #expect(Self.matches(of: /typealias\s+[A-Za-z0-9_]+\s*=\s*(?:[A-Za-z0-9_]+\.)*(?:Finding|ScanReport|Inputs)(?![A-Za-z0-9_.])/) == [])
        #expect(Self.matches(of: /decode\s*\(\s*type\s*\(\s*of\s*:/) == [])
    }

    /// A generic re-decode would forge any of them (B5): a value encoded, its JSON or property list edited, and decoded
    /// again, its type never named. So a value is decoded, and a decoder made, only on known lines; nothing builds JSON or
    /// a property list from a dictionary; the app has no decoder of its own, and makes no value from one but in a type's
    /// own `init(from:)`; and the keys that carry a version, a command or its inputs are written only where they live.
    @Test func decodingHappensOnlyOnKnownLines() {
        let decodes = Self.allowed([
            ("OSVAKit/API/APIClient.swift", "do { return try JSONDecoder().decode(type, from: data) }"),
            ("OSVAKit/Index/IndexStore.swift", "var meta = (try? Data(contentsOf: metaURL)).flatMap { try? JSONDecoder().decode(Meta.self, from: $0) }"),
            ("OSVAKit/Index/IndexStore.swift", "let index = try PublicIndex.decode(data)"),
            ("OSVAKit/Index/IndexStore.swift", "let index = try PublicIndex.decode(Data(contentsOf: dataURL))"),
            ("OSVAKit/Scan/Storage.swift", "let decoder = JSONDecoder()"),
            ("OSVAKit/Scan/Storage.swift", "return try? decoder.decode(type, from: data)"),
            ("OSVAKit/Scan/DiskCache.swift", "read(namespace, key, maxAge: maxAge).flatMap { try? JSONDecoder().decode(type, from: $0) }"),
            ("OSVAKit/Fix/FixScript.swift", "let wire = try? JSONDecoder().decode(Wire.self, from: Data(buffer.prefix(n))),"),
            ("OSVAMonitorUI/PreviewData+Java.swift", "return try! JSONDecoder().decode(ProjectResponse.self, from: Data(json.utf8))"),
            ("osva-render/main.swift", "let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601"),
            ("osva-render/main.swift", "let real = try decoder.decode(ScanReport.self, from: Data(contentsOf: URL(fileURLWithPath: reportPath)))"),
        ])
        // a container's own decode inside a type's init(from:) (`forKey:`, or a single value's) makes no new value
        #expect(Self.lines(matching: /\.decode\s*\((?![^)]*forKey\s*:)|(?:^|[^A-Za-z0-9_])(?:JSONDecoder|PropertyListDecoder)(?![A-Za-z0-9_])/,
                           except: { path, line in decodes(path, line) || line.contains("singleValueContainer().decode(") }) == [])
        #expect(Self.lines(matching: /(?:JSONSerialization|PropertyListSerialization)\s*\.\s*data\s*\(/) == [])
        #expect(Self.lines(matching: /(?:struct|class|enum|actor|extension|protocol)\s+[A-Za-z0-9_.]+\s*:[^{]*(?:^|[^A-Za-z0-9_])(?:TopLevelDecoder|Decoder)(?![A-Za-z0-9_])/) == [])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_.])(?:[A-Z][A-Za-z0-9_]*)\s*(?:\.init)?\s*\(\s*from\s*:/) == [])
        let homes: Set = ["OSVAKit/Model/Finding.swift", "OSVAKit/Scan/UpgradeCommand.swift", "OSVAKit/Scan/Storage.swift"]
        #expect(Self.lines(matching: /"(?:fixedVersion|upgradeCommand|commandInputs)"/, except: { path, _ in homes.contains(path) }) == [])
        // "target" is read from Homebrew's cask records; written as a key, it is a command's version
        #expect(Self.lines(matching: /\[\s*"target"\s*\]\s*=(?!=)|"target"\s*:/, except: { path, _ in homes.contains(path) }) == [])
    }

    /// Each type declared or extended in `code`: its keyword, its name, what follows the colon after it, and its body,
    /// braces matched (a brace inside a string counts too).
    static func declarations(_ code: String) -> [(keyword: Substring, name: String, inherits: Substring, body: Substring)] {
        code.matches(of: /(?:^|[^A-Za-z0-9_])(struct|class|enum|actor|extension)\s+([A-Za-z0-9_.]+)(?:<[^>{]*>)?\s*(?::([^{]*))?\{/).map { m in
            var depth = 0, i = code.index(before: m.range.upperBound)
            while i < code.endIndex {
                if code[i] == "{" { depth += 1 } else if code[i] == "}" { depth -= 1; if depth == 0 { break } }
                i = code.index(after: i)
            }
            return (m.output.1, String(m.output.2.split(separator: ".").last ?? m.output.2), m.output.3 ?? "", code[m.range.upperBound..<i])
        }
    }

    /// A version, a command and what a command is made from live in a `Finding`, and are saved only in a report's
    /// findings: no other property or enum case is named `fixedVersion`, `upgradeCommand` or `commandInputs`, and no
    /// `Codable` type but `Finding` and `ScanReport` names a `Finding`, an `UpgradeCommand.Inputs` or a `ScanReport` in its
    /// body (one would bring them back from text past `onlyTheSavedReportIsDecoded`), wherever it is made `Codable`.
    @Test func versionsAndCommandsLiveOnlyInAFinding() throws {
        let finding = "OSVAKit/Model/Finding.swift"
        #expect(Self.lines(matching: /(?:^|[{;])\h*(?:@[A-Za-z0-9_]+(?:\([^)]*\))?\s+)*(?:(?:public|private|fileprivate|internal|package|open|static|class|final|lazy|weak|unowned|nonisolated|override|dynamic|required|convenience|mutating)(?:\([a-z]+\))?\h+)*(?:(?:var|let)\h+|(?:indirect\h+)?case\h+(?:`?[A-Za-z0-9_]+`?(?:\([^)]*\))?(?:\h*=\h*[^,]+)?\h*,\h*)*)`?(?:fixedVersion|upgradeCommand|commandInputs)`?(?![A-Za-z0-9_])/,
                           except: { path, _ in path == finding }) == [])
        let types = Self.sources.map { (path: $0.path, declared: Self.declarations($0.lines.joined(separator: "\n"))) }
        let codable = Set(types.flatMap { $0.declared.filter { $0.inherits.contains(/(?:^|[^A-Za-z0-9_])(?:Codable|Decodable)(?![A-Za-z0-9_])/) }.map { $0.name } })
        try #require(codable.isSuperset(of: ["Finding", "ScanReport", "Inputs", "Coverage"]), "the scan finds the Codable types")
        let carriers = types.flatMap { file in
            file.declared.filter { $0.keyword != "extension" && codable.contains($0.name) && $0.body.contains(/(?:^|[^A-Za-z0-9_])(?:Finding|Inputs|ScanReport)(?![A-Za-z0-9_.])/) }
                .map { "\(file.path): \($0.name)" }
        }
        #expect(carriers.sorted() == ["OSVAKit/Model/Finding.swift: Finding", "OSVAKit/Model/ScanReport.swift: ScanReport"])
    }

    /// Only the command builders write a command: UpgradeCommand, its extensions for programs and tools and for Java
    /// runtimes, and BundleAdvice. Elsewhere an advice is withheld (`command: nil`) or passed on whole.
    @Test func onlyTheBuildersWriteACommand() {
        let builders: Set = ["OSVAKit/Scan/UpgradeCommand.swift", "OSVAKit/Scan/ProgramCommands.swift", "OSVAKit/Scan/BundleAdvice.swift"]
        let java = Self.allowed([("OSVAKit/Scan/JavaCheck.swift", "if let cask = r.cask { return Advice(command: \"brew upgrade --cask \\(quote(cask))\") }"),
                                 ("OSVAKit/Scan/JavaCheck.swift", "if let formula = r.formula { return Advice(command: \"brew upgrade \\(quote(formula))\") }")])
        #expect(Self.lines(matching: /(?:Advice|\.init)\s*\(\s*command\s*:(?!\s*nil(?![A-Za-z0-9_]))/, except: { path, line in
            builders.contains(path) || java(path, line)
        }) == [])
        #expect(Self.matches(of: /(?:Advice|\.init)\s*\(\s*command\s*:\s*\n/) == [], "a command on the next line is still a command")
    }

    /// No command builder writes `@latest`, which lets a registry pick the version; and nothing reinterprets memory,
    /// which could forge a `CheckedUpgrade`, but the lines that read bytes (a bundle's, the index's) and the screen
    /// capture's one C function pointer.
    @Test func noLatestAndNoBitCasts() {
        #expect(Self.lines(matching: /@latest/) == [])
        let readers = Self.allowed([
            ("OSVAMonitor/CaptureMode.swift", "return unsafeBitCast(symbol, to: CreateImage.self)"),
            ("OSVAKit/Inventory/BundleReaders.swift", "let ok = data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Bool in"),
            ("OSVAKit/Inventory/BundleReaders.swift", "let bytes = raw.bindMemory(to: UInt8.self)"),
            ("OSVAKit/Index/PublicIndex.swift", "data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in"),
            ("OSVAKit/Index/PublicIndex.swift", "let bytes = raw.bindMemory(to: UInt8.self)"),
        ])
        let memory = /(?:^|[^A-Za-z0-9_])(?:unsafeBitCast|unsafeDowncast|Unsafe(?:Mutable)?Raw(?:Buffer)?Pointer|withMemoryRebound|assumingMemoryBound|bindMemory|loadUnaligned|storeBytes)(?![A-Za-z0-9_])|\.load\s*\(\s*(?:fromByteOffset\s*:[^)]*,\s*)?as\s*:/
        #expect(Self.lines(matching: memory, except: readers) == [])
    }

    // MARK: What the proof report and the README say

    /// The proof report's claims, about the core, each with the theorem that states it.
    static let proofClaims: [(says: String, theorem: String)] = [
        ("The core's advisory check flags a version as in range only if it lies inside one of the advisory's published ranges, in the core's version order.",
         "OSVA.verdict_inRange_sound"),
        ("Every upgrade the core suggests lies outside the published ranges of every advisory it was given that publishes them, in the core's version order.",
         "OSVA.upgradeFor_leaves"),
        ("The core says an upgrade fixes an advisory with published ranges only if the upgrade lies outside them, in the core's version order.",
         "OSVA.judge_spec"),
        ("The core's URL encoding never outputs /, ?, #, @ or :.", "OSVA.encode_no_delimiters"),
    ]

    /// What the README says of the app: the claims this suite checks, and how the routing is held.
    static let readmeSentences = [
        "A version is flagged as affected only if it lies inside an affected range the site publishes for that vulnerability.",
        "Every version it suggests upgrading to is newer than yours and lies outside the published ranges of every advisory it says that version fixes.",
        "Names in request URLs never contain /, ?, #, @ or :.",
        "Malicious packages are flagged from the malware record itself.",
        "In the app's code, only the verified core can make a version to upgrade to, and the commands are built only from such versions: "
            + "the types allow nothing else, and a guard test scans the source for ways around them.",
        "A report saved on disk is shown as it was saved until the app scans again.",
        "Rebuilds, the exception above, may use the installed version.",
        "On the project and product paths, an advisory that states no versions shows only if it is exploited, or beside another finding.",
    ]

    static let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()

    static func text(_ path: String) throws -> String { try String(contentsOf: repository.appendingPathComponent(path), encoding: .utf8) }

    /// The manifest claims exactly these sentences, each with its theorem, about the code; each theorem is proved in
    /// core/OSVACore and audited in core/Audit.lean. The README says its sentences and the section's title, and every
    /// count of theorems in it and in its figure is the one scripts/check-core.sh requires, which is Audit.lean's.
    @Test func theManifestClaimsTheProvedTheorems() throws {
        struct Manifest: Decodable { struct Claim: Decodable { var says, theorem, about: String }; var claims: [Claim] }
        let manifest = try JSONDecoder().decode(Manifest.self, from: Data(try Self.text(".verificationalliance.json").utf8))
        #expect(manifest.claims.map(\.says) == Self.proofClaims.map { $0.says })
        #expect(manifest.claims.map(\.theorem) == Self.proofClaims.map { $0.theorem })
        #expect(manifest.claims.allSatisfy { $0.about == "code" })

        let folder = Self.repository.appendingPathComponent("core/OSVACore")
        let lean = try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { $0.hasSuffix(".lean") }
            .flatMap { try Self.text("core/OSVACore/" + $0).split(separator: "\n") }
        let audit = try Self.text("core/Audit.lean").split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        for claim in Self.proofClaims {
            let name = claim.theorem.dropFirst("OSVA.".count)
            #expect(lean.contains { $0.hasPrefix("theorem \(name) ") }, "\(name) is a theorem in core/OSVACore")
            #expect(audit.contains("#print axioms \(name)"), "\(name) is in core/Audit.lean")
        }

        let readme = try Self.text("README.md"), prose = readme.replacing(/\s+/, with: " ")
        #expect((Self.readmeSentences + [Finding.Group.likely.title]).filter { !prose.contains($0) } == [], "what README.md does not say")
        let required = try #require(try Self.text("scripts/check-core.sh").firstMatch(of: /\[ "\$n" -lt (\d+) \]/).flatMap { Int($0.output.1) })
        #expect(audit.filter { $0.hasPrefix("#print axioms ") }.count == required)
        let counts = try (readme + Self.text("docs/how-it-is-proved.svg")).matches(of: /(\d+) (?:theorems|proofs)/).map { Int($0.output.1)! }
        #expect(counts.count >= 3 && counts.allSatisfy { $0 == required }, "theorem counts \(counts), check-core.sh's \(required)")
    }
}
