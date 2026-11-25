import Foundation
import Testing
@testable import OSVAKit

/// The claims about the app, checked on its own findings, and the routing that makes them true, checked in its source:
///   - a version is flagged as affected only if it lies inside a range the site publishes for that flaw;
///   - every version the app suggests upgrading to is newer than the installed one, and lies outside the published
///     ranges of every flaw it says that version fixes;
///   - only Core.swift makes a `CheckedUpgrade`, and nothing writes a version to upgrade to, or a command's version,
///     from anything else.
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
    struct Checked { var kind: String; var finding: Finding; var ranges: [String: [AffectedRange]]; var same: [String: Set<String>] }

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
                out.append(Checked(kind: "package", finding: f, ranges: ranges, same: same))
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
            out.append(Checked(kind: "program", finding: f, ranges: ranges, same: same))
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

    /// The sample reaches every kind of finding these claims are about, each with findings in today's groups and with
    /// versions named, and every finding is read against its own answer: none is skipped.
    @Test func theClaimsAreCheckedOnEveryKindOfFinding() {
        #expect(Self.sample.missed == [], "findings whose answer the check could not find")
        let affected = Set(Self.checked.filter { !$0.finding.malicious && [.exploited, .criticalHigh, .other].contains($0.finding.group) }.map(\.kind))
        let named = Set(Self.checked.filter { $0.finding.fixedVersion != nil && !$0.finding.malicious }.map(\.kind))
        let kinds: Set = ["package", "program", "project", "product", "managed", "item"]
        #expect(affected == kinds, "kinds with affected findings: \(affected.sorted())")
        #expect(named == kinds, "kinds with versions named: \(named.sorted())")
    }

    /// "A version is flagged as affected only if it lies inside an affected range the site publishes for that flaw":
    /// every finding in today's groups, malicious ones aside, has an advisory whose published ranges hold its version,
    /// by the test's own comparisons (RangesTests.holds).
    @Test func everyAffectedFindingLiesInsideAPublishedRange() {
        let affected = Self.checked.filter { !$0.finding.malicious && [.exploited, .criticalHigh, .other].contains($0.finding.group) }
        #expect(affected.count >= 20, "the sample has affected findings to check")
        for c in affected {
            let f = c.finding
            let holding = f.advisoryIDs.filter { id in (c.ranges[id] ?? []).contains { RangesTests.holds($0, f.installedVersion) } }
            #expect(!holding.isEmpty, "\(c.kind) \(f.id) is in \(f.group) with no published range holding \(f.installedVersion)")
        }
    }

    /// "Every version it suggests upgrading to is newer than yours and lies outside the published ranges of every
    /// advisory it says that version fixes": the advisories whose ranges hold the installed version, less those the
    /// finding lists as not fixed.
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
        }
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

    /// Only Core.swift makes a `CheckedUpgrade` or a `Judgement`, and only it extends them; a version is shown only as a
    /// `CheckedUpgrade.Display` style writes it (`.displayed(.java)`, `.displayed(.program)`); the old doors are gone; a
    /// newest or oldest version is picked only on the lines that read installed versions or hand it to the core's judge;
    /// the server's planned target (`unjudgedTarget`) is read only where the core judges it.
    @Test func onlyCoreSwiftBuildsACheckedUpgrade() throws {
        try #require(Self.code("OSVAKit/Core.swift") != nil, "the scan reads app/Sources")
        let core = "OSVAKit/Core.swift"
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])(?:CheckedUpgrade|Judgement)\s*\(/, except: { path, _ in path == core }) == [])
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])extension\s+(?:OSVAKit\s*\.\s*)?(?:CheckedUpgrade|Judgement)(?![A-Za-z0-9_])/,
                           except: { path, _ in path == core }) == [])
        // a version is shown only as CheckedUpgrade.Display writes it: a closed set of styles that carry no text
        let display = try #require(Self.code(core))
        let styles = try #require(display.firstMatch(of: /public enum Display: Sendable, Hashable \{([^}]*)\}/)?.1)
        let cases = styles.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("case ") }
        #expect(cases == ["case asChecked", "case java", "case program"], "CheckedUpgrade.Display: \(cases)")
        #expect(display.contains("public func displayed(_ style: Display) -> CheckedUpgrade { CheckedUpgrade(self, style: style) }"))
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
        // the server's planned target is read only where the core judges it (and where it is decoded)
        #expect(Self.lines(matching: /(?:^|[^A-Za-z0-9_])unjudgedTarget(?![A-Za-z0-9_])/, except: { path, _ in
            path == "OSVAKit/Scan/BatchCheck.swift" || path == "OSVAKit/API/Responses.swift"
        }) == [])
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
}
