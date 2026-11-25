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

    /// One package's answer. `distinct` defaults to the number of flaws listed.
    static func result(_ ecosystem: String, _ name: String, _ version: String, distinct: Int? = nil, flaws: [String],
                       plan: String = "null") throws -> BatchResponse.Result {
        let json = #"{"ecosystem":"\#(ecosystem)","name":"\#(name)","version":"\#(version)","distinct_flaws":\#(distinct ?? flaws.count),"#
            + #""worst_severity":"HIGH","advisories":[],"flaws":[\#(flaws.joined(separator: ","))],"plan":\#(plan)}"#
        return try JSONDecoder().decode(BatchResponse.Result.self, from: Data(json.utf8))
    }

    static func plan(_ target: String?, remaining: String = "[]") -> String {
        #"{"target":\#(target.map { "\"\($0)\"" } ?? "null"),"fixes":[],"remaining":\#(remaining)}"#
    }

    /// The findings FindingBuilder makes of these answers, each package installed once with npm (global) or pip.
    static func findings(_ results: [BatchResponse.Result], index: PublicIndex? = nil) -> [Finding] {
        let index = index ?? PublicIndex(generatedAt: "T", packages: results.map { (Ecosystem($0.ecosystem), $0.name) }, projects: [])
        let installed = results.map { r in
            InstalledPackage(ecosystem: Ecosystem(r.ecosystem), name: r.name, version: r.version,
                             origin: r.ecosystem == "PyPI" ? .pip(python: Fixture.applePython, user: false, formula: nil) : .npmGlobal(npm: "/opt/homebrew/bin/npm"))
        }
        let selection = PrivacyFilter(index: index).approve(installed)
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in
            results.first { $0.name == a.name && $0.version == a.version }.map { (a, $0) }
        })
        return FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: [])
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
        // Where the core's order is not the ecosystem's (Version.lean): semver puts "2.0.0-0" below 2.0.0 and Go a
        // pseudo-version below its release, the core does not. The flaw is reported, never dropped.
        let npm = try Self.result("npm", "zero", "2.0.0-0", flaws: [Self.flaw("CVE-Z", ranges: #"[{"fixed":"2.0.0"}]"#, fixedIn: #"["2.0.0"]"#)])
        let go = try Self.result("Go", "example.com/pseudo", "v1.2.4-0.20191109021931-abcdefabcdef",
                                 flaws: [Self.flaw("GO-P", ranges: #"[{"fixed":"1.2.4"}]"#, fixedIn: #"["v1.2.4"]"#)])
        for r in [npm, go] {
            let c = BatchCheck.read(r, installed: r.version)
            #expect(c.check == .reported && c.reported.map(\.reason) == [.outsideRanges], "\(r.version)")
        }
        let f = Self.findings([npm, go])
        #expect(f.count == 2 && f.allSatisfy { $0.group == .reported && $0.flawCount == 1 })
        #expect(f.first { $0.title == "zero" }?.note
                == "Reported by the site, not checked: the affected ranges it publishes for CVE-Z do not include 2.0.0-0.")
        // The plan's first examples are ordered as their ecosystems order them since #12: PyPI's 1.0 is 1.0.0, and npm's
        // canary is below its release. Both are affected.
        let pypi = try Self.result("PyPI", "one", "1.0", flaws: [Self.flaw("CVE-O", ranges: #"[{"introduced":"1.0.0","fixed":"2.0"}]"#)])
        let canary = try Self.result("npm", "next", "15.0.0-canary.12", flaws: [Self.flaw("CVE-C", ranges: #"[{"fixed":"15.0.0"}]"#)])
        for r in [pypi, canary] { #expect(BatchCheck.read(r, installed: r.version).check == .affected, "\(r.version)") }
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
                            fixedVersion: "2", severity: .high, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil,
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
        #expect(folded[0].note == (alone.note ?? "") + " pg-exporter 16.14 was built with Go 1.22.3, whose stdlib has 1 known flaw — reported, not checked.")

        // the same for a program folded into its app's own finding
        let docker = BuiltProgram(language: .go, path: "/usr/local/bin/docker", name: "docker", version: nil, place: .app, formula: nil, package: nil,
                                  toolchain: nil, app: "Docker", cask: nil)
        let shipped = PrivacyFilter(index: index).approve([InstalledPackage(ecosystem: .go, name: "stdlib", version: "1.22.3", origin: .program(docker))])
        let program = try #require(FindingBuilder(index: index).findings(approved: shipped.approved,
                                                                         verdicts: Dictionary(uniqueKeysWithValues: shipped.approved.keys.map { ($0, stdlib) }),
                                                                         brew: [], projects: [:], bigIssues: []).first)
        #expect(program.group == .reported && program.flawCount == 1 && program.upgradeCommand == nil)
        let app = Finding(id: "product|docker|4.41.2", group: .criticalHigh, subject: .product(key: "docker", name: "Docker"), title: "Docker",
                          installedVersion: "4.41.2", fixedVersion: "4.86.0", severity: .high, advisoryIDs: ["CVE-1"], flawCount: 6, exploited: false,
                          malicious: false, note: "The issuer lists 4.41.2 as affected and 4.86.0 as fixed.", bigIssue: nil,
                          origins: [.application(name: "Docker", bundlePath: "/Applications/Docker.app", caskToken: nil)], pageURL: SiteURL.home,
                          upgradeCommand: nil, verification: .none, grade: nil)
        let d = try #require(FindingBuilder.foldingProgramsIntoApps([program, app]).first)
        #expect(d.id == app.id && d.group == .criticalHigh && d.flawCount == 6 && !d.exploited && d.severity == .high)
        #expect(d.note == "The issuer lists 4.41.2 as affected and 4.86.0 as fixed. docker was built with Go 1.22.3, whose stdlib has 1 known flaw — reported, not checked.")
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
