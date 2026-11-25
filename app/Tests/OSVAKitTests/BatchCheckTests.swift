import Foundation
import Testing
@testable import OSVAKit

/// Packages checked by exact version (api/v1/check/batch): a flaw is affected only when the core finds the version in a
/// range the site publishes for it, likely affected when it publishes none and the first fixed versions say so, and
/// otherwise reported, not checked. The server's target is shown only when the core confirms it.
@Suite struct BatchCheckTests {
    /// One flaw, as the API writes it. `ranges` and `fixedIn` are raw JSON, so a test can send what a server might.
    static func flaw(_ id: String, ranges: String = "null", fixedIn: String = "[]", severity: String = "HIGH", exploited: Bool = false,
                     platform: String? = nil, malicious: Bool = false) -> String {
        #"{"id":"\#(id)","severity":"\#(severity)","summary":"Summary of \#(id)","fixed_in":\#(fixedIn),"ranges":\#(ranges),"#
            + #""platform":\#(platform.map { "\"\($0)\"" } ?? "null"),"exploited_since":\#(exploited ? "\"2026-11-01\"" : "null"),"#
            + #""malicious":\#(malicious)}"#
    }

    /// One PyPI package's answer.
    static func result(_ name: String, _ version: String, distinct: Int? = nil, flaws: [String], plan: String = "null") throws -> BatchResponse.Result {
        try result("PyPI", name, version, distinct: distinct, flaws: flaws, plan: plan)
    }

    /// One package's answer. `distinct` defaults to the number of flaws listed; `worst` and `exploited` are what the
    /// answer says of all its flaws, listed or not.
    static func result(_ ecosystem: String, _ name: String, _ version: String, distinct: Int? = nil, flaws: [String],
                       plan: String = "null", worst: String = "HIGH", exploited: [String] = []) throws -> BatchResponse.Result {
        let json = #"{"ecosystem":"\#(ecosystem)","name":"\#(name)","version":"\#(version)","distinct_flaws":\#(distinct ?? flaws.count),"#
            + #""worst_severity":"\#(worst)","exploited":[\#(exploited.map { "\"\($0)\"" }.joined(separator: ","))],"advisories":[],"#
            + #""flaws":[\#(flaws.joined(separator: ","))],"plan":\#(plan)}"#
        return try JSONDecoder().decode(BatchResponse.Result.self, from: Data(json.utf8))
    }

    static func plan(_ target: String?, remaining: String = "[]") -> String {
        #"{"target":\#(target.map { "\"\($0)\"" } ?? "null"),"fixes":[],"remaining":\#(remaining)}"#
    }

    /// The findings FindingBuilder makes of these answers, each package installed once: with npm (global) or pip, or
    /// where `origin` says.
    static func findings(_ results: [BatchResponse.Result], index: PublicIndex? = nil, bigIssues: [StateResponse.BigIssue] = [],
                         projects: [String: ProjectResponse] = [:], origin: ((BatchResponse.Result) -> Origin)? = nil) -> [Finding] {
        let index = index ?? PublicIndex(generatedAt: "T", packages: results.map { (Ecosystem($0.ecosystem), $0.name) }, projects: [])
        let installed = results.map { r in
            InstalledPackage(ecosystem: Ecosystem(r.ecosystem), name: r.name, version: r.version,
                             origin: origin?(r) ?? (r.ecosystem == "PyPI" ? .pip(python: Fixture.applePython, user: false, formula: nil)
                                                                          : .npmGlobal(npm: "/opt/homebrew/bin/npm")))
        }
        let selection = PrivacyFilter(index: index).approve(installed)
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in
            results.first { $0.name == a.name && $0.version == a.version }.map { (a, $0) }
        })
        return FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: projects, bigIssues: bigIssues)
    }

    static let oauthlib = flaw("CVE-2026-49264", ranges: #"[{"introduced":"0.6.1","fixed":"4.0.0"}]"#, fixedIn: #"["4.0.0"]"#)

    @Test func aFlawInsideItsRangesIsAffected() throws {
        let c = BatchCheck.read(try Self.result("oauthlib", "3.2.2", flaws: [Self.oauthlib]), installed: "3.2.2")
        #expect(c.check == .affected && c.affected.map(\.id) == ["CVE-2026-49264"])
        #expect(c.likely.isEmpty && c.reported.isEmpty && c.unlisted == 0)
        // just past its range, the same flaw is reported, not checked
        let past = BatchCheck.read(try Self.result("oauthlib", "4.0.0", flaws: [Self.oauthlib]), installed: "4.0.0")
        #expect(past.check == .reported && past.reported.map(\.reason) == [.outsideRanges])
    }

    @Test func aFlawWithoutRangesIsLikelyOrReported() throws {
        let nginx = Self.flaw("CVE-N", fixedIn: #"["1.30.7","1.31.9"]"#)
        let likely = BatchCheck.read(try Self.result("npm", "n", "1.31.5", flaws: [nginx]), installed: "1.31.5")
        #expect(likely.check == .likely && likely.likely.map(\.id) == ["CVE-N"] && likely.affected.isEmpty)
        let r = try Self.result("npm", "n", "1.32.0", flaws: [nginx])
        let above = BatchCheck.read(r, installed: "1.32.0")
        #expect(above.check == .reported && above.reported == [.init(flaw: r.flaws[0], reason: .noRanges)])
        // [] reads as no ranges; a flaw with neither ranges nor fixed versions states nothing, and is reported
        let empty = BatchCheck.read(try Self.result("npm", "n", "1.0", flaws: [Self.flaw("E", ranges: "[]", fixedIn: #"["2.0"]"#)]), installed: "1.0")
        #expect(empty.check == .likely)
        let silent = BatchCheck.read(try Self.result("npm", "n", "1.0", flaws: [Self.flaw("S")]), installed: "1.0")
        #expect(silent.check == .reported && silent.reported.map(\.reason) == [.noRanges])
    }

    @Test func aBoundaryTheCoreOrdersDifferentlyIsReportedNotDropped() throws {
        // Where the core's order is not the ecosystem's (Version.lean): semver puts a numeric pre-release "2.0.0-1" below
        // 2.0.0, the core reads the number as continuing the version. The flaw is reported, never dropped.
        let npm = try Self.result("npm", "numeric", "2.0.0-1", flaws: [Self.flaw("CVE-Z", ranges: #"[{"fixed":"2.0.0"}]"#, fixedIn: #"["2.0.0"]"#)])
        let c = BatchCheck.read(npm, installed: npm.version)
        #expect(c.check == .reported && c.reported.map(\.reason) == [.outsideRanges])
        let f = Self.findings([npm])
        #expect(f.count == 1 && f.allSatisfy { $0.group == .reported && $0.flawCount == 1 })
        #expect(f.first?.note == "Reported by the site, not checked: the affected ranges it publishes for CVE-Z do not include 2.0.0-1.")
        // The plan's first examples are ordered as their ecosystems order them since #12: PyPI's 1.0 is 1.0.0, and npm's
        // canary is below its release. Since #17 so are semver's "-0" and Go's pseudo-versions on a "-0." base, below
        // their release. All are affected.
        let pypi = try Self.result("PyPI", "one", "1.0", flaws: [Self.flaw("CVE-O", ranges: #"[{"introduced":"1.0.0","fixed":"2.0"}]"#)])
        let canary = try Self.result("npm", "next", "15.0.0-canary.12", flaws: [Self.flaw("CVE-C", ranges: #"[{"fixed":"15.0.0"}]"#)])
        let zero = try Self.result("npm", "zero", "2.0.0-0", flaws: [Self.flaw("CVE-0", ranges: #"[{"fixed":"2.0.0"}]"#, fixedIn: #"["2.0.0"]"#)])
        let go = try Self.result("Go", "example.com/pseudo", "v1.2.4-0.20191109021931-abcdefabcdef",
                                 flaws: [Self.flaw("GO-P", ranges: #"[{"fixed":"1.2.4"}]"#, fixedIn: #"["v1.2.4"]"#)])
        for r in [pypi, canary, zero, go] { #expect(BatchCheck.read(r, installed: r.version).check == .affected, "\(r.version)") }
    }

    @Test func unreadableRangesAreReported() throws {
        let r = try Self.result("u", "3.0", flaws: [Self.flaw("CVE-U", ranges: #"[{"introduced":"1.0","limit":"2.0"}]"#, fixedIn: #"["2.0"]"#),
                                                    Self.flaw("CVE-F", ranges: #"[{"fixed":"4.0"}]"#, fixedIn: #""4.0""#)])
        let c = BatchCheck.read(r, installed: "3.0")
        #expect(c.check == .reported && c.reported.map(\.reason) == [.unreadable, .unreadable] && c.affected.isEmpty)
        let f = try #require(Self.findings([r]).first)
        #expect(f.group == .reported && f.note == "Reported by the site, not checked: the app could not read its affected ranges for CVE-U (and 1 more).")
    }

    @Test func flawsPastTheListAreReported() throws {
        let listed = (0..<40).map { Self.flaw("CVE-\($0)", ranges: #"[{"fixed":"9"}]"#, severity: "MODERATE") }
        let r = try Self.result("npm", "big", "1", distinct: 45, flaws: listed)
        let c = BatchCheck.read(r, installed: "1")
        #expect(c.check == .affected && c.affected.count == 40 && c.unlisted == 5 && c.reported.isEmpty)
        let f = try #require(Self.findings([r]).first)
        #expect(f.flawCount == 40 && f.note?.hasSuffix("5 more flaws are reported, not checked.") == true)
        // listed none: every flaw is past the list
        let none = try Self.result("npm", "big", "1", distinct: 3, flaws: [])
        let g = try #require(Self.findings([none]).first)
        #expect(g.group == .reported && g.flawCount == 3 && g.note == "Reported by the site, not checked: 3 flaws are not listed.")
    }

    @Test func aServerTargetIsShownOnlyWhenTheCoreConfirmsIt() throws {
        func check(_ target: String?) throws -> BatchCheck {
            BatchCheck.read(try Self.result("oauthlib", "3.2.2", flaws: [Self.oauthlib], plan: Self.plan(target)), installed: "3.2.2")
        }
        let good = try check("4.0.0")
        #expect(good.upgrade?.version == "4.0.0" && good.target == .confirmed && good.fixed == ["CVE-2026-49264"] && good.notFixed.isEmpty)
        let inside = try check("3.9"), same = try check("3.2.2"), odd = try check("4.0.0; touch /tmp/x"), none = try check(nil)
        #expect(inside.upgrade == nil && inside.target == .unconfirmed && inside.fixed.isEmpty)   // inside the range
        #expect(same.upgrade == nil && same.target == .unconfirmed)                                // not above
        #expect(odd.upgrade == nil && odd.target == .notAVersion)                                  // not a version
        #expect(none.upgrade == nil && none.target == .none && none.notFixed.map(\.flaw.id) == ["CVE-2026-49264"])
        // the finding: no version, no command, and why
        let f = try #require(Self.findings([try Self.result("oauthlib", "3.2.2", flaws: [Self.oauthlib], plan: Self.plan("3.9"))]).first)
        #expect(f.group == .criticalHigh && f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "No checked fixed version yet; see the site.")
        // nor one without a version: npm's would install @latest
        let npm = try #require(Self.findings([try Self.result("npm", "oauthlib", "3.2.2", flaws: [Self.oauthlib], plan: Self.plan("3.9"))]).first)
        #expect(npm.fixedVersion == nil && npm.upgradeCommand == nil && npm.commandInputs == nil)
        let ok = try #require(Self.findings([try Self.result("oauthlib", "3.2.2", flaws: [Self.oauthlib], plan: Self.plan("4.0.0"))]).first)
        #expect(ok.fixedVersion == "4.0.0" && ok.fixesCount == 1 && ok.upgradeCommand == "/usr/bin/python3 -m pip install --user --upgrade oauthlib==4.0.0")
    }

    @Test func torchKeepsItsPartialUpgrade() throws {
        let r = try Self.result("torch", "2.2.0", flaws: [Self.flaw("A", ranges: #"[{"fixed":"2.7.1-rc1"}]"#), Self.flaw("B", ranges: "[{}]")],
                                plan: Self.plan("2.13.0", remaining: #"[{"id":"B","fixed_in":null,"reason":"no-fix","detail":null}]"#))
        let c = BatchCheck.read(r, installed: "2.2.0")
        #expect(c.upgrade?.version == "2.13.0" && c.fixed == ["A"])
        #expect(c.notFixed.map(\.flaw.id) == ["B"] && c.notFixed.first?.reason == .noFix && c.notFixed.first?.fixedIn == nil)
        let f = try #require(Self.findings([r]).first)
        #expect(f.fixedVersion == "2.13.0" && f.fixesCount == 1 && f.unresolved.map(\.explanation) == ["No fixed release yet"])
    }

    @Test func anUnfixedFlawsFixedInIsShownOnlyIfTheCoreConfirmsIt() throws {
        func check(_ ranges: String) throws -> BatchCheck {
            let r = try Self.result("setuptools", "58.0.4",
                                    flaws: [Self.flaw("A", ranges: #"[{"fixed":"78.1.1"}]"#), Self.flaw("B", ranges: ranges, severity: "MODERATE")],
                                    plan: Self.plan("78.1.1", remaining: #"[{"id":"B","fixed_in":"83.0.0","reason":"needs-python","detail":"Python >=3.10"}]"#))
            return BatchCheck.read(r, installed: "58.0.4")
        }
        let confirmed = try check(#"[{"fixed":"83.0.0"}]"#)
        #expect(confirmed.notFixed.map(\.flaw.id) == ["B"] && confirmed.notFixed.first?.fixedIn?.version == "83.0.0")
        let not = try check(#"[{"fixed":"84.0"}]"#)
        #expect(not.notFixed.map(\.flaw.id) == ["B"] && not.notFixed.first?.fixedIn == nil && not.notFixed.first?.reason == .needsPython)
    }

    @Test func aPackageWithOnlyReportedFlawsIsNotCounted() throws {
        let r = try Self.result("npm", "lodash", "4.17.20", flaws: [Self.flaw("CVE-X", severity: "CRITICAL", exploited: true)], plan: Self.plan("4.17.21"))
        let f = try #require(Self.findings([r], index: Fixture.index).first)
        #expect(f.group == .reported && !f.group.needsAction)
        let report = ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(), findings: [f], sent: SentRecord(),
                                indexGeneratedAt: nil, problems: [])
        #expect(report.actionCount == 0)
        #expect(f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil && f.unresolved.isEmpty)
        #expect(f.note == "Reported by the site, not checked: it publishes no affected ranges for CVE-X.")
        // how serious it would be stays visible
        #expect(f.severity == .critical && f.exploited && f.flawCount == 1)
    }

    @Test func groupsKeepTheirSavedNumbers() throws {
        #expect((0...5).map { Finding.Group(rawValue: $0) } == [.malicious, .exploited, .criticalHigh, .other, .likely, .reported])
        #expect(Finding.Group.allCases.filter(\.needsAction) == [.malicious, .exploited, .criticalHigh])
        #expect(Finding.Group.allCases.filter(\.isNotChecked) == [.likely, .reported])
        // a report saved by 0.5.1 reads with the same group
        let saved = Finding(id: "x", group: .criticalHigh, subject: .package(ecosystem: .npm, name: "x"), title: "x", installedVersion: "1",
                            upgrade: Fixture.fix("2", above: "1"), severity: .high, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil,
                            bigIssue: nil, origins: [.npmGlobal(npm: "npm")], pageURL: SiteURL.home, upgradeCommand: nil, verification: .none, grade: nil)
        let json = String(decoding: try JSONEncoder().encode(saved), as: UTF8.self)
        #expect(json.contains(#""group":2"#))
        #expect(try JSONDecoder().decode(Finding.self, from: Data(json.utf8)).group == .criticalHigh)
    }

    @Test func foldingAReportedProgramKeepsTheProjectsGroup() throws {
        // postgresql@16 16.14 is affected by PostgreSQL's ranges; a Go program the formula ships has only a reported flaw
        let index = ProgramFindingTests.index
        let postgres = try JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-postgres.json"))
        let brew = FindingBuilder.BrewMatch(item: HomebrewItem(kind: .formula, name: "postgresql@16", version: "16.14", urls: []),
                                            project: index.project(slug: "postgres")!)
        let exporter = BuiltProgram(language: .go, path: "/opt/homebrew/bin/pg-exporter", name: "pg-exporter", version: "16.14", place: .homebrew,
                                    formula: "postgresql@16", package: nil, toolchain: "1.22.3")
        let stdlib = try Self.result("Go", "stdlib", "1.22.3", flaws: [Self.flaw("GO-R", severity: "CRITICAL", exploited: true)])
        let selection = PrivacyFilter(index: index).approve([InstalledPackage(ecosystem: .go, name: "stdlib", version: "1.22.3", origin: .program(exporter))])
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.map { ($0, stdlib) })
        let alone = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [brew], projects: ["postgres": postgres],
                                                                       bigIssues: []).first)
        let folded = FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: [brew], projects: ["postgres": postgres],
                                                           bigIssues: [])
        try #require(folded.count == 1)
        #expect(alone.group == .criticalHigh && folded[0].group == .criticalHigh)
        #expect(folded[0].flawCount == alone.flawCount && folded[0].exploited == alone.exploited && folded[0].severity == alone.severity)
        // not counted, never hidden: said, and its exploited flaw marks the finding and notifies
        #expect(folded[0].note == (alone.note ?? "") + " pg-exporter 16.14 was built with Go 1.22.3, whose stdlib has 1 known flaw"
                + " — reported, not checked (GO-R, critical, exploited in the wild).")
        #expect(alone.notChecked == nil && folded[0].notChecked == Finding.NotChecked(id: "GO-R", exploited: true, critical: true))
        #expect(folded[0].deservesNotification)

        // the same for a program folded into its app's own finding
        let docker = BuiltProgram(language: .go, path: "/usr/local/bin/docker", name: "docker", version: nil, place: .app, formula: nil, package: nil,
                                  toolchain: nil, app: "Docker", cask: nil)
        let shipped = PrivacyFilter(index: index).approve([InstalledPackage(ecosystem: .go, name: "stdlib", version: "1.22.3", origin: .program(docker))])
        let program = try #require(FindingBuilder(index: index).findings(approved: shipped.approved,
                                                                         verdicts: Dictionary(uniqueKeysWithValues: shipped.approved.keys.map { ($0, stdlib) }),
                                                                         brew: [], projects: [:], bigIssues: []).first)
        #expect(program.group == .reported && program.flawCount == 1 && program.upgradeCommand == nil)
        let app = Finding(id: "product|docker|4.41.2", group: .criticalHigh, subject: .product(key: "docker", name: "Docker"), title: "Docker",
                          installedVersion: "4.41.2", upgrade: Fixture.fix("4.86.0", above: "4.41.2"), severity: .high, advisoryIDs: ["CVE-1"], flawCount: 6, exploited: false,
                          malicious: false, note: "The issuer lists 4.41.2 as affected and 4.86.0 as fixed.", bigIssue: nil,
                          origins: [.application(name: "Docker", bundlePath: "/Applications/Docker.app", caskToken: nil)], pageURL: SiteURL.home,
                          upgradeCommand: nil, verification: .none, grade: nil)
        let d = try #require(FindingBuilder.foldingProgramsIntoApps([program, app]).first)
        #expect(d.id == app.id && d.group == .criticalHigh && d.flawCount == 6 && !d.exploited && d.severity == .high)
        #expect(d.notChecked == Finding.NotChecked(id: "GO-R", exploited: true, critical: true))
        #expect(d.note == "The issuer lists 4.41.2 as affected and 4.86.0 as fixed. docker was built with Go 1.22.3, whose stdlib has 1 known flaw"
                + " — reported, not checked (GO-R, critical, exploited in the wild).")
    }

    @Test func mavenAndPackagistVersionsTheCoreMayMisorderAreReported() throws {
        // guava 31.1-jre: Maven may order "-jre" otherwise than the core, so neither likely nor clear, but reported
        let guava = try Self.result("Maven", "com.google.guava:guava", "31.1-jre", flaws: [Self.flaw("CVE-G", fixedIn: #"["33.7.2"]"#)])
        let g = BatchCheck.read(guava, installed: "31.1-jre")
        #expect(g.check == .reported && g.reported.map(\.reason) == [.uncertainOrder] && g.likely.isEmpty)
        let f = try #require(Self.findings([guava]).first)
        #expect(f.note == "Reported by the site, not checked: Maven may order 31.1-jre and the versions it names for CVE-G otherwise than the app does.")
        // a certain version with an uncertain bound is reported too; Composer's -p3 is a patch, decided
        let bound = try Self.result("Maven", "x:y", "33.0.0", flaws: [Self.flaw("CVE-B", ranges: #"[{"introduced":"1.0","fixed":"32.0.0-jre"}]"#)])
        #expect(BatchCheck.read(bound, installed: "33.0.0").reported.map(\.reason) == [.uncertainOrder])
        let composer = try Self.result("Packagist", "acme/lib", "2.4.6-p3", flaws: [Self.flaw("CVE-P", ranges: #"[{"fixed":"2.4.7"}]"#)])
        #expect(BatchCheck.read(composer, installed: "2.4.6-p3").check == .affected)
        // each place a version can carry an uncertain word: the first fixed versions, an introduced bound, a last affected
        // one; and Packagist as much as Maven
        let firstFixed = try Self.result("Maven", "x:y", "33.0", flaws: [Self.flaw("CVE-FF", fixedIn: #"["34.0-jre"]"#)])
        let introduced = try Self.result("Maven", "x:y", "33.0", flaws: [Self.flaw("CVE-I", ranges: #"[{"introduced":"30.0-jre","fixed":"34.0"}]"#)])
        let last = try Self.result("Maven", "x:y", "33.0", flaws: [Self.flaw("CVE-L", ranges: #"[{"introduced":"30.0","last_affected":"33.1-jre"}]"#)])
        let packagist = try Self.result("Packagist", "acme/lib", "3.0.0-RC1", flaws: [Self.flaw("CVE-RC", ranges: #"[{"fixed":"3.0.1"}]"#)])
        for r in [firstFixed, introduced, last, packagist] {
            #expect(BatchCheck.read(r, installed: r.version).reported.map(\.reason) == [.uncertainOrder], "\(r.flaws[0].id)")
        }
        // npm reads "-rc.1" as semver does: decided
        let npm = try Self.result("npm", "n", "1.0.0-rc.1", flaws: [Self.flaw("CVE-N", ranges: #"[{"fixed":"1.0.0"}]"#)])
        #expect(BatchCheck.read(npm, installed: "1.0.0-rc.1").check == .affected)
    }

    @Test func anUnreadableFlawAmongJudgedOnesKeepsThemAligned() throws {
        // Server data in any shape: flaws the core cannot weigh sit between the judged ones, and every per-flaw answer
        // stays with its own flaw. Nothing here may crash the app.
        let flaws = [
            Self.flaw("A", ranges: #"[{"fixed":"2.0"}]"#),                                   // affected, left by 3.0
            Self.flaw("U", ranges: #"[{"introduced":null,"fixed":"9.0"}]"#),                 // unreadable: a null bound
            Self.flaw("S"),                                                                  // states nothing
            Self.flaw("L", fixedIn: #"["2.5","5.0"]"#),                                      // likely, left by 5.0 only
            Self.flaw("F", ranges: #"[{"fixed":"4.0"}]"#, fixedIn: #"[4]"#),                 // unreadable fixed_in
            Self.flaw("B", ranges: #"[{"introduced":"0","fixed":"5.0"}]"#),                  // affected, not left by 3.0
            Self.flaw("M", ranges: "[{}]", platform: "windows"),                             // affected, another platform
            Self.flaw("W", ranges: #"[{"fixed":"2.0"}]"#, platform: "windows"),             // another platform, left by 3.0
            Self.flaw("A", ranges: #"[{"fixed":"2.0"}]"#),                                   // the same id twice
        ]
        let r = try Self.result("npm", "mixed", "1.0", flaws: flaws,
                                plan: Self.plan("3.0", remaining: #"[{"id":"B","fixed_in":"5.0","reason":"unknown"},{"id":"nope","reason":"no-fix"}]"#))
        let c = BatchCheck.read(r, installed: "1.0")
        #expect(c.affected.map(\.id) == ["A", "B", "M", "W", "A"] && c.likely.map(\.id) == ["L"])
        #expect(c.reported.map(\.flaw.id) == ["U", "S", "F"] && c.reported.map(\.reason) == [.unreadable, .noRanges, .unreadable])
        #expect(c.flagged.map(\.id) == ["A", "L", "B", "M", "W", "A"])
        #expect(c.upgrade?.version == "3.0" && c.fixed == ["A", "W", "A"])
        #expect(c.notFixed.map(\.flaw.id) == ["L", "B", "M"] && c.notFixed.map { $0.fixedIn?.version } == [nil, "5.0", nil])
        let five = try #require(c.judge("5.0"))
        #expect(five.leaves == [true, true, true, false, true, true] && five.upgrade?.fixCount == 5)
        #expect(c.judge("1.0") == nil && c.judge("not a version!") == nil)
        let f = try #require(Self.findings([r]).first)
        #expect(f.group == .criticalHigh && f.fixedVersion == "3.0" && f.flawCount == 3)
        #expect(f.fixesCount == 2)                                  // "fixes 2 here": W is fixed too, but not a flaw of this Mac
        #expect(f.unresolved.map(\.id) == ["L", "B", "M"] && f.unresolved.map(\.explanation)
                == ["Not fixed by this upgrade", "Fixed in 5.0, not by this upgrade", "Windows only, does not affect this Mac"])
        #expect(f.note?.hasSuffix("1 more flaw without published ranges likely affects it too. 3 more flaws are reported, not checked.") == true)
        // and nothing at all to weigh
        #expect(BatchCheck.read(try Self.result("npm", "mixed", "", flaws: []), installed: "").check == .reported)
    }

    @Test func theLiveAnswersAreCheckedAgainstTheirRanges() throws {
        // Every flaw the site sent on 2026-11-25 for these packages lies inside its published ranges, PyPI's included: none
        // is reported for a 1.0/1.0.0 boundary. time's record states no exact ranges, so its first fixed versions decide.
        // Every target the server planned is one the core confirms. It leaves every flaw but setuptools' two (another
        // platform; a newer Python) and three of Go's: the site publishes those as affected from 1.24.0-0 on, with no end,
        // because Go's records close that line at 1.24.0-rc.2, which the core's order puts below 1.24.0-0.
        let notLeft = ["setuptools": ["CVE-2026-59890", "GHSA-xmj3-9gf7-h52w"], "stdlib": ["CVE-2024-45341", "CVE-2024-45336", "CVE-2025-22866"]]
        var packages = 0
        for file in ["api/check-batch-live-2026-11-25.json", "api/check-batch-programs-live-2026-11-25.json"] {
            for r in try JSONDecoder().decode(BatchResponse.self, from: Fixture.data(file)).packages where !r.malicious {
                let c = BatchCheck.read(r, installed: r.version)
                #expect(c.reported.isEmpty && c.unlisted == 0, "\(r.name)")
                #expect(c.check == (r.name == "time" ? .likely : .affected), "\(r.name)")
                #expect(c.upgrade?.version == r.plan?.target, "\(r.name)")
                #expect(c.notFixed.map(\.flaw.id) == notLeft[r.name, default: []], "\(r.name)")
                packages += 1
            }
        }
        #expect(packages == 11)
    }

    @Test func theNoteSaysWhyAFindingIsNotChecked() throws {
        let nginx = Self.flaw("CVE-N", fixedIn: #"["1.30.7","1.31.9"]"#)
        let up = try #require(Self.findings([try Self.result("npm", "n", "1.31.5", flaws: [nginx], plan: Self.plan("1.31.9"))]).first)
        #expect(up.group == .likely && up.fixedVersion == "1.31.9" && up.upgradeCommand == "npm install -g n@1.31.9")
        #expect(up.note == "Likely affected: the site publishes no affected ranges, and the issuer names 1.31.9 as fixed.")
        let none = try #require(Self.findings([try Self.result("npm", "n", "1.31.5", flaws: [nginx], plan: Self.plan(nil))]).first)
        #expect(none.note == "Likely affected: the site publishes no affected ranges; no fixed version clears it.")
        // several reported: the worst is named (exploited first, then the most severe), and the rest counted
        let many = try Self.result("npm", "n", "3.0", distinct: 4, flaws: [Self.flaw("LOW", ranges: #"[{"fixed":"2.0"}]"#, severity: "LOW"),
                                                                            Self.flaw("CRIT", ranges: #"[{"fixed":"2.0"}]"#, severity: "CRITICAL"),
                                                                            Self.flaw("EXPL", ranges: #"[{"fixed":"1.0"}]"#, severity: "MODERATE", exploited: true)])
        let m = try #require(Self.findings([many]).first)
        #expect(m.note == "Reported by the site, not checked: the affected ranges it publishes for EXPL do not include 3.0 (and 3 more).")
        #expect(m.flawCount == 4 && m.severity == .critical && m.exploited)
    }
}

/// The review of #16: what a finding is shown for never hides an exploited or critical flaw it is not shown for, no
/// command installs a version the core did not check, and no unchecked version reaches a finding by another path.
extension BatchCheckTests {
    typealias Alert = Finding.NotChecked

    @Test func anAffectedFlawNeverHidesAnExploitedReportedOne() throws {
        // an affected low flaw, and a reported flaw that is critical and exploited
        let r = try Self.result("npm", "both", "1.0", flaws: [Self.flaw("LOW-A", ranges: #"[{"fixed":"2.0"}]"#, severity: "LOW"),
                                                             Self.flaw("RX", severity: "CRITICAL", exploited: true)], plan: Self.plan("2.0"))
        let f = try #require(Self.findings([r]).first)
        #expect(f.group == .other && f.severity == .low && !f.exploited && f.flawCount == 1)       // decided by the affected flaw
        #expect(f.notChecked == Alert(id: "RX", exploited: true, critical: true))                  // and never silent about the other
        #expect(f.deservesNotification && Finding.toNotify([f], after: nil).map(\.id) == [f.id])
        #expect(f.note == "1 more flaw is reported, not checked: RX, critical, exploited in the wild.")
        // a likely one is named the same way
        let l = try Self.result("npm", "both", "1.0", flaws: [Self.flaw("LOW-A", ranges: #"[{"fixed":"2.0"}]"#, severity: "LOW"),
                                                             Self.flaw("LC", fixedIn: #"["2.0"]"#, severity: "CRITICAL")], plan: Self.plan("2.0"))
        let g = try #require(Self.findings([l]).first)
        #expect(g.notChecked == Alert(id: "LC", exploited: false, critical: true) && !g.deservesNotification)
        #expect(g.note == "1 more flaw without published ranges likely affects it too: LC, critical.")
        #expect(g.fixesCount == 1)                          // 2.0 fixes both, but "fixes N here" counts the affected one only
    }

    @Test func flawsOnThisMacDecideBeforeAffectedOnesElsewhere() throws {
        // a Windows-only affected flaw, and a likely flaw on macOS that is critical and exploited: likely, and it notifies
        let win = Self.flaw("WIN", ranges: #"[{"fixed":"2.0"}]"#, platform: "windows")
        let likely = try Self.result("npm", "p", "1.0", flaws: [win, Self.flaw("LX", fixedIn: #"["2.0"]"#, severity: "CRITICAL", exploited: true)])
        let f = try #require(Self.findings([likely]).first)
        #expect(f.group == .likely && f.exploited && f.severity == .critical && f.flawCount == 1 && f.deservesNotification)
        #expect(f.notChecked == Alert(id: "LX", exploited: true, critical: true))
        // with a reported flaw on macOS instead: reported, not "nothing to do on this Mac"
        let reported = try Self.result("npm", "p", "1.0", flaws: [win, Self.flaw("RP", severity: "HIGH")])
        #expect(Self.findings([reported]).first?.group == .reported)
        // a likely flaw only on Windows is listed as another platform's, with nothing to do
        let elsewhere = try Self.result("npm", "p", "1.0", flaws: [Self.flaw("LW", fixedIn: #"["2.0"]"#, platform: "windows")], plan: Self.plan("2.0"))
        let e = try #require(Self.findings([elsewhere]).first)
        #expect(e.group == .other && e.upgradeCommand == nil && e.note == nil && e.notChecked == nil && e.flawCount == 1)
        // in a project folder, which may be deployed anywhere, the same flaw is likely
        let folder = Self.findings([elsewhere]) { _ in .folder(root: "/w", lockfile: "/w/package-lock.json", direct: true) }
        #expect(folder.first?.group == .likely)
    }

    @Test func anExploitedOrCriticalFlawPastTheListLeavesAMark() throws {
        let listed = Self.flaw("A", ranges: #"[{"fixed":"2.0"}]"#)
        // the answer names an exploited CVE that no listed flaw carries
        let exploited = try Self.result("npm", "big", "1.0", distinct: 3, flaws: [listed], plan: Self.plan("2.0"), exploited: ["CVE-UNL"])
        let f = try #require(Self.findings([exploited]).first)
        #expect(f.group == .criticalHigh && f.notChecked == Alert(id: "CVE-UNL", exploited: true, critical: false) && f.deservesNotification)
        #expect(f.note?.hasSuffix("2 more flaws are reported, not checked, among them CVE-UNL, exploited in the wild.") == true)
        // the answer's worst is critical, and no listed flaw is
        let critical = try Self.result("npm", "big", "1.0", distinct: 2, flaws: [listed], plan: Self.plan("2.0"), worst: "CRITICAL")
        let g = try #require(Self.findings([critical]).first)
        #expect(g.notChecked == Alert(id: nil, exploited: false, critical: true) && !g.deservesNotification)
        #expect(g.note?.hasSuffix("1 more flaw is reported, not checked: a critical one.") == true)
        // a listed flaw carrying the CVE as an alias, or the worst severity, says nothing more
        let carried = try Self.result("npm", "big", "1.0", distinct: 2, flaws: [listed], plan: Self.plan("2.0"), worst: "HIGH", exploited: ["A"])
        #expect(Self.findings([carried]).first?.notChecked == nil)
        // nothing listed at all: the answer's own severity and exploited CVEs
        let none = try Self.result("npm", "big", "1.0", distinct: 4, flaws: [], worst: "CRITICAL", exploited: ["CVE-K"])
        let h = try #require(Self.findings([none]).first)
        #expect(h.group == .reported && h.severity == .critical && h.exploited && h.notChecked == Alert(id: "CVE-K", exploited: true, critical: false))
    }

    @Test func aLikelyFindingSaysItsReportedFlawsToo() throws {
        let r = try Self.result("npm", "n", "1.31.5", flaws: [Self.flaw("CVE-N", fixedIn: #"["1.30.7","1.31.9"]"#), Self.flaw("CVE-R")],
                                plan: Self.plan("1.31.9"))
        let f = try #require(Self.findings([r]).first)
        #expect(f.note == "Likely affected: the site publishes no affected ranges, and the issuer names 1.31.9 as fixed. 1 more flaw is reported, not checked.")
    }

    @Test func theReportedNoteNamesTheMostUrgentFlaw() throws {
        func named(_ flaws: [String]) throws -> String? {
            try Self.findings([try Self.result("npm", "n", "3.0", flaws: flaws)]).first?.note
        }
        let outside = #"[{"fixed":"2.0"}]"#
        // exploited before severity, severity before order, the first listed on a tie
        #expect(try named([Self.flaw("CRIT", ranges: outside, severity: "CRITICAL"), Self.flaw("EXPL", ranges: outside, severity: "MODERATE", exploited: true)])?
                    .contains("for EXPL do not include") == true)
        #expect(try named([Self.flaw("HIGH", ranges: outside, severity: "HIGH"), Self.flaw("CRIT", ranges: outside, severity: "CRITICAL")])?
                    .contains("for CRIT do not include") == true)
        #expect(try named([Self.flaw("FIRST", ranges: outside), Self.flaw("SECOND", ranges: outside)])?.contains("for FIRST do not include") == true)
    }

    @Test func noCommandWithoutACheckedVersionButHomebrews() throws {
        // affected, and the server's plan names no fix: only Homebrew, which picks its own versions, keeps a command
        let flaw = Self.flaw("A", ranges: "[{}]")
        func command(_ eco: String, _ name: String, _ origin: Origin, plan: String = BatchCheckTests.plan(nil)) throws -> String? {
            try Self.findings([try Self.result(eco, name, "1.0", flaws: [flaw], plan: plan)]) { _ in origin }.first?.upgradeCommand
        }
        let env = CondaEnvironment(prefix: "/m", name: "base", named: true, tool: .conda, python: "3.11.5")
        #expect(try command("npm", "n", .npmGlobal(npm: "/opt/homebrew/bin/npm")) == nil)                      // was npm install -g n@latest
        #expect(try command("crates.io", "c", .cargoInstall) == nil)                                           // was cargo install c
        #expect(try command("RubyGems", "g", .gem(gem: "/usr/bin/gem")) == nil)                                // was gem update --user-install g
        #expect(try command("npm", "n", .folder(root: "/w", lockfile: "/w/package-lock.json", direct: true)) == nil)    // npm install n
        #expect(try command("npm", "n", .folder(root: "/w", lockfile: "/w/package-lock.json", direct: false)) == nil)   // npm update n
        #expect(try command("PyPI", "p", .conda(env: env)) == nil)                                             // conda update -n base p
        #expect(try command("npm", "electron", .electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack"))
                == "brew upgrade --cask slack")
        #expect(try command("PyPI", "six", .pip(python: Fixture.homebrewPython, user: false, formula: "python-six")) == "brew upgrade python-six")
        // but a version the server names that the core rejects leaves no command, Homebrew's included
        #expect(try command("npm", "electron", .electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack"),
                            plan: BatchCheckTests.plan("2.0")) == nil)
        // and the note says why there is none
        let npm = try Self.result("npm", "n", "1.0", flaws: [flaw], plan: Self.plan(nil))
        #expect(Self.findings([npm]).first?.note == "No fixed release yet.")
        let noPlan = try Self.result("npm", "n", "1.0", flaws: [flaw])
        #expect(Self.findings([noPlan]).first?.note == "No checked fixed version yet; see the site.")
        // a likely one the same
        let likely = try Self.result("npm", "n", "1.0", flaws: [Self.flaw("L", fixedIn: #"["2.0"]"#)], plan: Self.plan(nil))
        let l = try #require(Self.findings([likely]).first)
        #expect(l.upgradeCommand == nil && l.commandInputs == nil && l.note == "Likely affected: the site publishes no affected ranges; no fixed version clears it.")
        // an extension's note does not depend on a command, and stays
        let ext = Origin.addOn(host: .vscode, id: "eamodio.gitlens", name: "GitLens", profile: nil, path: "/p")
        #expect(Self.findings([noPlan]) { _ in ext }.first?.note == "Update GitLens in VS Code: it ships its own n.")
    }

    @Test func aLikelyFindingNeverContradictsItsTarget() throws {
        let l = Self.flaw("L", fixedIn: #"["2.0"]"#)
        let inside = try #require(Self.findings([try Self.result("npm", "n", "1.0", flaws: [l], plan: Self.plan("1.5"))]).first)
        #expect(inside.note == "Likely affected: the site publishes no affected ranges. No checked fixed version yet; see the site.")
        #expect(inside.fixedVersion == nil && inside.upgradeCommand == nil)
        let odd = try #require(Self.findings([try Self.result("npm", "n", "1.0", flaws: [l], plan: Self.plan("2.0; rm -rf ~"))]).first)
        #expect(odd.note == "Likely affected: the site publishes no affected ranges. "
                + "The server named a fixed version the app does not accept as a version; see the site.")
    }

    @Test func noUpgradeNoNotByThisUpgradeLine() throws {
        // the core does not confirm the server's target: no version on the row, so no "not by this upgrade" lines
        let r = try Self.result("npm", "n", "1.0", flaws: [Self.flaw("A", ranges: #"[{"fixed":"3.0"}]"#), Self.flaw("B", ranges: #"[{"fixed":"3.0"}]"#),
                                                         Self.flaw("C", ranges: "[{}]")],
                                plan: Self.plan("2.0", remaining: #"[{"id":"B","fixed_in":"3.0","reason":"blocked-by-constraint"},{"id":"C","reason":"no-fix"}]"#))
        let f = try #require(Self.findings([r]).first)
        #expect(f.fixedVersion == nil && f.unresolved.map(\.explanation) == ["No fixed release yet"])
    }

    @Test func aPatchTheseFirstItemNeverPromotesOrVersionsAnUncheckedFinding() throws {
        let issue = try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"""
            {"name":"Electron","slug":"electron","severity":"CRITICAL","exploited":true,"date":"2026-11-01","ids":["CVE-EL"],
             "fixed_in":["28.3.2"],"title":"Electron's renderer escapes"}
            """#.utf8))
        let app = Origin.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: nil)
        // the batch answer reports a flaw it cannot check: the item marks the finding, and signals, never more
        let reported = try Self.result("npm", "electron", "28.1.0", flaws: [Self.flaw("CVE-EL", severity: "HIGH")], plan: Self.plan("28.3.2"))
        let f = try #require(Self.findings([reported], index: Fixture.index, bigIssues: [issue]) { _ in app }.first)
        #expect(f.group == .reported && f.fixedVersion == nil && f.upgradeCommand == nil && f.bigIssue != nil)
        #expect(f.notChecked == Alert(id: "CVE-EL", exploited: true, critical: true) && f.deservesNotification)
        // without a batch finding, the item's own version is the core's, from its first fixed versions
        let made = FindingBuilder(index: Fixture.index).findings(
            approved: PrivacyFilter(index: Fixture.index).approve([InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0", origin: app)]).approved,
            verdicts: [:], brew: [], projects: [:], bigIssues: [issue])
        #expect(made.map(\.fixedVersion) == ["28.3.2"] && made.map(\.group) == [.likely])
        #expect(made.first?.note == "Likely affected: the site publishes no affected ranges, and the issuer names 28.3.2 as fixed.")
    }

    @Test func notifiedAgainOnlyWhenMoreSerious() throws {
        func f(_ group: Finding.Group, exploited: Bool = false, notChecked: Alert? = nil, big: String? = nil) -> Finding {
            Finding(id: "x", group: group, subject: .package(ecosystem: .npm, name: "x"), title: "x", installedVersion: "1", upgrade: nil,
                    severity: .high, advisoryIDs: [], flawCount: 1, exploited: exploited, malicious: false, note: nil, bigIssue: big,
                    origins: [.npmGlobal(npm: "npm")], pageURL: SiteURL.home, upgradeCommand: nil, verification: .none, grade: nil, notChecked: notChecked)
        }
        let kev = Alert(id: "CVE-1", exploited: true, critical: false)
        // 0.5.1 said exploited; the server's ranges cannot check it now: no second notification
        #expect(Finding.toNotify([f(.reported, exploited: true)], after: [f(.exploited, exploited: true)]).isEmpty)
        #expect(Finding.toNotify([f(.other, notChecked: kev)], after: [f(.exploited, exploited: true)]).isEmpty)
        // more serious: a more urgent group, newly exploited, a new item on the list
        #expect(Finding.toNotify([f(.exploited, exploited: true)], after: [f(.reported, exploited: true)]).count == 1)
        #expect(Finding.toNotify([f(.other, notChecked: kev)], after: [f(.other, big: "list")]).count == 1)
        #expect(Finding.toNotify([f(.other, big: "list 2")], after: [f(.other, big: "list")]).count == 1)
        #expect(Finding.toNotify([f(.other, big: "list")], after: [f(.other, big: "list")]).isEmpty)
        #expect(Finding.toNotify([f(.other, notChecked: kev)], after: nil).count == 1 && Finding.toNotify([f(.other)], after: nil).isEmpty)
        // Other, likely and reported call for no action: moving among them, with the same flaw exploited, is not more serious
        #expect(Finding.toNotify([f(.other, notChecked: kev)], after: [f(.likely, exploited: true, notChecked: kev)]).isEmpty)
        #expect(Finding.toNotify([f(.likely, exploited: true, notChecked: kev)], after: [f(.reported, exploited: true, notChecked: kev)]).isEmpty)
        #expect(Finding.toNotify([f(.criticalHigh, notChecked: kev)], after: [f(.likely, exploited: true, notChecked: kev)]).count == 1)
    }
}

/// The re-review of #18, and Task 6's "patch these first" Electron item.
extension BatchCheckTests {
    @Test func aTargetIsShownOnlyWhenItFixesAFlawTheFindingIsShownFor() throws {
        // a Windows-only affected flaw, a macOS likely flaw first fixed in 3.0.0, and the server's target 2.0.0: the core
        // confirms 2.0.0 for the Windows flaw only, so the likely finding names no version and offers no command
        let flaws = [Self.flaw("WIN", ranges: #"[{"fixed":"2.0.0"}]"#, platform: "windows"), Self.flaw("L", fixedIn: #"["3.0.0"]"#)]
        let r = try Self.result("npm", "p", "1.0.0", flaws: flaws, plan: Self.plan("2.0.0"))
        #expect(BatchCheck.read(r, installed: "1.0.0").upgrade?.version == "2.0.0")
        let f = try #require(Self.findings([r]).first)
        #expect(f.group == .likely && f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "Likely affected: the site publishes no affected ranges. No checked fixed version yet; see the site.")
        // a program's part the same
        let fd = BuiltProgram(language: .rust, path: "/Users/ana/.cargo/bin/fd", name: "fd", version: "10.5.2", place: .cargoInstall, formula: nil,
                              package: "fd-find", module: "fd-find", toolchain: nil)
        let crate = try Self.result("crates.io", "p", "1.0.0", flaws: flaws, plan: Self.plan("2.0.0"))
        let program = try #require(Self.findings([crate]) { _ in .program(fd) }.first)
        #expect(program.group == .likely && program.fixedVersion == nil && program.upgradeCommand == nil)
        // in a project folder, which may be deployed anywhere, the Windows flaw counts: affected, and 2.0.0 fixes it
        let folder = try #require(Self.findings([r]) { _ in .folder(root: "/w", lockfile: "/w/package-lock.json", direct: true) }.first)
        #expect(folder.group == .criticalHigh && folder.fixedVersion == "2.0.0")
    }

    @Test func theReportedNoteCountsWhatTheFindingCounts() throws {
        // this Mac's reported flaw is named, not a Windows-only one, and "(and k more)" counts what the finding counts
        let outside = #"[{"fixed":"2.0"}]"#
        let r = try Self.result("npm", "n", "3.0", distinct: 4, flaws: [Self.flaw("WIN", ranges: outside, severity: "CRITICAL", exploited: true, platform: "windows"),
                                                                       Self.flaw("MAC", ranges: outside)])
        let f = try #require(Self.findings([r]).first)
        #expect(f.group == .reported && f.flawCount == 3)
        #expect(f.note == "Reported by the site, not checked: the affected ranges it publishes for MAC do not include 3.0 (and 2 more).")
        // in a project folder every flaw counts, and the most urgent is named
        let folder = try #require(Self.findings([r]) { _ in .folder(root: "/w", lockfile: "/w/package-lock.json", direct: true) }.first)
        #expect(folder.flawCount == 4 && folder.note == "Reported by the site, not checked: the affected ranges it publishes for WIN do not include 3.0 (and 3 more).")
        // only the flaws past the list on this Mac: they are what it says
        let unlisted = try Self.result("npm", "n", "3.0", distinct: 3, flaws: [Self.flaw("WIN", ranges: outside, platform: "windows")])
        #expect(Self.findings([unlisted]).first?.note == "Reported by the site, not checked: 2 flaws are not listed.")
    }

    @Test func thePatchTheseFirstElectronItemIsLikelyAndItsVersionChecked() throws {
        let app = Origin.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack")
        func made(_ fixedIn: [String]) throws -> Finding {
            let issue = try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data((#"{"name":"Electron","slug":"electron","severity":"CRITICAL","exploited":true,"#
                + #""date":"2026-11-01","ids":["CVE-EL"],"fixed_in":[\#(fixedIn.map { "\"\($0)\"" }.joined(separator: ","))],"title":"Electron's renderer escapes"}"#).utf8))
            let approved = PrivacyFilter(index: Fixture.index).approve([InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0", origin: app)]).approved
            return try #require(FindingBuilder(index: Fixture.index).findings(approved: approved, verdicts: [:], brew: [], projects: [:], bigIssues: [issue]).first)
        }
        // decided by its first fixed versions alone: likely, never in the exploited group; marked, and it notifies
        let f = try made(["28.3.2"])
        #expect(f.group == .likely && f.fixedVersion == "28.3.2" && f.upgradeCommand == "brew upgrade --cask slack")
        #expect(f.notChecked == Alert(id: "CVE-EL", exploited: true, critical: true) && f.deservesNotification)
        // a version the core picks that does not read as a version is never shown, and no command runs for it
        let odd = try made(["28.3.2;reboot"])
        #expect(odd.fixedVersion == nil && odd.upgradeCommand == nil && odd.commandInputs == nil)
        #expect(odd.note == "Likely affected: the site publishes no affected ranges. The server named a fixed version the app does not accept as a version; see the site.")
        // more work than the core may be asked for: no version, and no command, Homebrew's included
        let many = try made((0..<500).map { "29.\($0)" })
        #expect(many.fixedVersion == nil && many.upgradeCommand == nil && many.commandInputs == nil)
        #expect(many.note == "Likely affected: the site publishes no affected ranges. No checked fixed version yet; see the site.")
    }

    /// MK: an item the electron project's published ranges hold promotes the app's batch finding, with the item's version
    /// and sentence.
    @Test func anElectronItemTheRangesHoldPromotesTheAppsFinding() throws {
        let issue = try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"""
            {"name":"Electron","slug":"electron","severity":"CRITICAL","exploited":true,"date":"2026-11-01","ids":["CVE-EL"],
             "fixed_in":["28.3.2"],"title":"Electron's renderer escapes"}
            """#.utf8))
        let record = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"electron","name":"Electron","recent":[{"id":"CVE-EL","sev":"HIGH","ranges":[{"introduced":"28.0.0","fixed":"28.3.2"}]}]}
            """#.utf8))
        let app = Origin.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack")
        let reported = try Self.result("npm", "electron", "28.1.0", flaws: [Self.flaw("CVE-EL", severity: "HIGH")], plan: Self.plan("28.3.2"))
        let f = try #require(Self.findings([reported], index: Fixture.index, bigIssues: [issue], projects: ["electron": record]) { _ in app }.first)
        #expect(f.group == .exploited && f.exploited && f.severity == .critical && f.flawCount == 1 && f.bigIssue != nil)
        #expect(f.fixedVersion == "28.3.2" && f.upgradeCommand == "brew upgrade --cask slack")
        #expect(f.note?.hasPrefix("The issuer lists 28.1.0 as affected and 28.3.2 as fixed.") == true)
        // a likely finding's version (28.2.0) that the item's range still holds gives way to the item's
        let likely = try Self.result("npm", "electron", "28.1.0", flaws: [Self.flaw("CVE-L", fixedIn: #"["28.2.0"]"#)], plan: Self.plan("28.2.0"))
        let g = try #require(Self.findings([likely], index: Fixture.index, bigIssues: [issue], projects: ["electron": record]) { _ in app }.first)
        #expect(g.group == .exploited && g.fixedVersion == "28.3.2" && g.flawCount == 1 && g.upgradeCommand == "brew upgrade --cask slack")
        #expect(g.note == "The issuer lists 28.1.0 as affected and 28.3.2 as fixed. 1 more flaw without published ranges likely affects it too.")
        // without the project's record, the item decides by its first fixed versions: marked, never promoted
        let marked = try #require(Self.findings([reported], index: Fixture.index, bigIssues: [issue]) { _ in app }.first)
        #expect(marked.group == .reported && marked.fixedVersion == nil && marked.notChecked?.exploited == true)
    }

    /// The review of #20 and #21: a package's finding an item promotes is made again from its answer with the item in it,
    /// so the version, "fixes N" and what it does not fix are the core's.
    static func electronItem(exploited: Bool = true, severity: String = "CRITICAL") throws -> StateResponse.BigIssue {
        try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"""
            {"name":"Electron","slug":"electron","severity":"\#(severity)","exploited":\#(exploited),"date":"2026-11-01","ids":["CVE-EL"],
             "fixed_in":["28.3.2"],"title":"Electron's renderer escapes"}
            """#.utf8))
    }
    static let electronRecord = try! JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
        {"slug":"electron","name":"Electron","recent":[{"id":"CVE-EL","sev":"HIGH","ranges":[{"introduced":"28.0.0","fixed":"28.3.2"}]}]}
        """#.utf8))
    static let slack = Origin.electronApp(name: "Slack", bundlePath: "/Applications/Slack.app", caskToken: "slack")

    @Test func aPromotedPackageFindingIsJudgedAgainstAllItsFlaws() throws {
        // N1, scenario 1: A fixed in 28.2.0, BB in 28.3.0, target 28.2.0; the item's range moves the version to 28.3.2,
        // which leaves all three
        let a = Self.flaw("A", ranges: #"[{"fixed":"28.2.0"}]"#), bb = Self.flaw("BB", ranges: #"[{"fixed":"28.3.0"}]"#)
        let before = try #require(Self.findings([try Self.result("npm", "electron", "28.1.0", flaws: [a, bb], plan: Self.plan("28.2.0"))],
                                                index: Fixture.index) { _ in Self.slack }.first)
        #expect(before.fixedVersion == "28.2.0" && before.fixesCount == 1 && before.unresolved.map(\.id) == ["BB"])
        let one = try #require(Self.findings([try Self.result("npm", "electron", "28.1.0", flaws: [a, bb], plan: Self.plan("28.2.0"))], index: Fixture.index,
                                             bigIssues: [try Self.electronItem()], projects: ["electron": Self.electronRecord]) { _ in Self.slack }.first)
        #expect(one.group == .exploited && one.fixedVersion == "28.3.2" && one.flawCount == 3 && one.fixesCount == 3 && one.unresolved.isEmpty)
        #expect(one.note?.hasPrefix("The issuer lists 28.1.0 as affected and 28.3.2 as fixed.") == true && one.upgradeCommand == "brew upgrade --cask slack")
        // scenario 2: A has a second range, [28.3.0, 28.3.5): 28.3.2 does not leave it, and the row says so
        let a2 = Self.flaw("A", ranges: #"[{"fixed":"28.2.0"},{"introduced":"28.3.0","fixed":"28.3.5"}]"#)
        let two = try #require(Self.findings([try Self.result("npm", "electron", "28.1.0", flaws: [a2, bb], plan: Self.plan("28.2.0"))], index: Fixture.index,
                                             bigIssues: [try Self.electronItem()], projects: ["electron": Self.electronRecord]) { _ in Self.slack }.first)
        #expect(two.fixedVersion == "28.3.2" && two.fixesCount == 2 && two.unresolved.map(\.id) == ["A"])
        #expect(two.unresolved.first?.explanation == "Not fixed by this upgrade")
    }

    /// An Electron finding an item made, without a batch answer, is made again by a later item the core finds affected.
    @Test func anElectronFindingAnItemMadeIsMadeAgainByTheNext() throws {
        let first = try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"""
            {"name":"Electron","slug":"electron","severity":"HIGH","exploited":true,"ids":["CVE-OTHER"],"fixed_in":["28.2.0"],"title":"Another"}
            """#.utf8))
        let approved = PrivacyFilter(index: Fixture.index).approve([InstalledPackage(ecosystem: .npm, name: "electron", version: "28.1.0", origin: Self.slack)]).approved
        let f = try #require(FindingBuilder(index: Fixture.index).findings(approved: approved, verdicts: [:], brew: [], projects: ["electron": Self.electronRecord],
                                                                          bigIssues: [first, try Self.electronItem()]).first)
        #expect(f.group == .exploited && f.fixedVersion == "28.3.2" && f.upgradeCommand == "brew upgrade --cask slack")
        #expect(f.note == "The issuer lists 28.1.0 as affected and 28.3.2 as fixed. 1 more advisory without published ranges likely affects it too: CVE-OTHER, exploited in the wild.")
    }

    /// n1: a likely finding the item promotes keeps its other sentences, and names its most urgent likely flaw.
    @Test func aPromotedLikelyFindingKeepsWhatItSaid() throws {
        let likely = try Self.result("npm", "electron", "28.1.0", flaws: [Self.flaw("CVE-L", fixedIn: #"["28.2.0"]"#, severity: "CRITICAL"),
                                                                          Self.flaw("CVE-R", ranges: #"[{"fixed":"20.0.0"}]"#)], plan: Self.plan("28.2.0"))
        let f = try #require(Self.findings([likely], index: Fixture.index, bigIssues: [try Self.electronItem()],
                                           projects: ["electron": Self.electronRecord]) { _ in Self.slack }.first)
        #expect(f.group == .exploited && f.fixedVersion == "28.3.2" && f.flawCount == 1)
        #expect(f.note == "The issuer lists 28.1.0 as affected and 28.3.2 as fixed. 1 more flaw without published ranges likely affects it too: CVE-L, critical. "
                + "1 more flaw is reported, not checked.")
        #expect(f.notChecked == Alert(id: "CVE-L", exploited: false, critical: true))
    }

    /// MX5 (a package): an item that is not exploited, on a likely finding whose own flaw is: critical and high, not
    /// exploited, and the mark kept.
    @Test func anUnexploitedItemNeverMakesAPackageExploited() throws {
        let likely = try Self.result("npm", "electron", "28.1.0", flaws: [Self.flaw("CVE-X", fixedIn: #"["28.2.0"]"#, exploited: true)], plan: Self.plan("28.2.0"))
        let f = try #require(Self.findings([likely], index: Fixture.index, bigIssues: [try Self.electronItem(exploited: false, severity: "HIGH")],
                                           projects: ["electron": Self.electronRecord]) { _ in Self.slack }.first)
        #expect(f.group == .criticalHigh && !f.exploited && f.notChecked == Alert(id: "CVE-X", exploited: true, critical: false))
    }
}
