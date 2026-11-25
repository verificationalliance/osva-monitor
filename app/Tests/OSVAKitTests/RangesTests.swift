import Foundation
import Testing
@testable import OSVAKit

/// The issuer's affected ranges (the API's `ranges`; OSVACore/Ranges.lean) decide project and product findings, and first
/// fixed versions (`fixed_hint`) only for an advisory that has no ranges. The project fixtures are the server's answers
/// for PostgreSQL and CPython, built on 2026-11-19 from the CVE List: the records behind the false alarms on the owner's
/// Mac (python@3.11, 3.12 and 3.13 flagged by CVE-2026-119170, which affects only 3.14.10; postgresql@16 16.16 flagged by
/// the 18-only and per-branch PostgreSQL records).
@Suite struct RangesTests {
    let core = Core.shared
    let index = Fixture.index
    var postgres: ProjectResponse { try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-postgres.json")) }
    var cpython: ProjectResponse { try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-cpython-ranges.json")) }

    func brew(_ name: String, _ version: String, _ slug: String) -> FindingBuilder.BrewMatch {
        .init(item: HomebrewItem(kind: .formula, name: name, version: version, urls: []), project: index.project(slug: slug)!)
    }

    func findings(_ brew: [FindingBuilder.BrewMatch], _ projects: [String: ProjectResponse], big: [StateResponse.BigIssue] = []) -> [Finding] {
        FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: brew, projects: projects, bigIssues: big)
    }

    /// The same record as an app from before ranges would read it: fixed_hint only.
    func withoutRanges(_ p: ProjectResponse) -> ProjectResponse {
        var old = p
        old.recent = p.recent.map { var a = $0; a.ranges = nil; return a }
        return old
    }

    // MARK: The core, through its wrapper

    /// PostgreSQL's ranges for one advisory: one per release branch (CoreTests shares them).
    static let pg = [AffectedRange(fixed: "14.24"), AffectedRange(introduced: "15", fixed: "15.19"), AffectedRange(introduced: "16", fixed: "16.15"),
                     AffectedRange(introduced: "17", fixed: "17.11"), AffectedRange(introduced: "18", fixed: "18.6")]

    @Test func theCoreDecidesByRanges() {
        let pg = Self.pg
        #expect(core.affectedness(installed: "16.16", ranges: pg) == .notAffected)
        #expect(core.affectedness(installed: "16.14", ranges: pg) == .affected)
        #expect(core.upgrade(from: "16.14", ranges: pg) == "16.15")                // its own branch's fix, not 18.6
        #expect(core.affectedness(installed: "13.9", ranges: pg) == .affected)      // no introduced: from the first version
        #expect(core.affectedness(installed: "14.24", ranges: pg) == .notAffected)  // fixed is excluded
        #expect(core.affectedness(installed: "1.0", ranges: []) == .unknown && core.upgrade(from: "1.0", ranges: []) == nil)
        let open = [AffectedRange(introduced: "1.5")]
        #expect(core.affectedness(installed: "9.0", ranges: open) == .affected && core.upgrade(from: "9.0", ranges: open) == nil)
        let last = [AffectedRange(introduced: "2.11.0", lastAffected: "2.13.0")]
        #expect(core.affectedness(installed: "2.13.0", ranges: last) == .affected && core.affectedness(installed: "2.13.1", ranges: last) == .notAffected)
        // an upgrade that another range includes (a flaw that starts later) is skipped
        let later = [AffectedRange(introduced: "16", fixed: "16.15"), AffectedRange(introduced: "16.14", fixed: "16.20")]
        #expect(core.upgrade(from: "16.10", ranges: later) == "16.20")
        // a present but empty bound is a bound, never "absent"
        #expect(core.affectedness(installed: "dev", ranges: [AffectedRange(introduced: "", fixed: "1.0")]) == .notAffected)
    }

    /// A sample of range sets and versions, for checking the core's theorems with the wrapper's own comparisons as the
    /// reference (CoreTests shares them).
    static let sampleSets: [[AffectedRange]] = [
        [AffectedRange(fixed: "13.22"), AffectedRange(introduced: "14", fixed: "14.19"), AffectedRange(introduced: "16", fixed: "16.10")],
        [AffectedRange(introduced: "3.14.10", fixed: "3.14.11")],
        [AffectedRange(introduced: "2.11.0", lastAffected: "2.13.0"), AffectedRange(introduced: "3.0rc1")],
        [AffectedRange(fixed: "1.0"), AffectedRange(introduced: "0.9", fixed: "1.2"), AffectedRange(introduced: "1.1", lastAffected: "1.1.5")],
    ]
    static let sampleVersions = ["0.1", "0.9", "1.0", "1.1", "1.1.5", "1.2", "2.11.0", "2.12.1", "2.13.0", "2.14", "3.0rc1", "3.0", "3.14.10",
                                 "3.14.11", "13.9", "13.22", "14.18", "14.19", "16.9", "16.10", "16.16", "v16.9", "10.6p2", ""]

    /// Whether `r` holds `v`, by the wrapper's comparisons alone: the reference the core is checked against.
    static func holds(_ r: AffectedRange, _ v: String) -> Bool {
        let core = Core.shared
        return (r.introduced.map { core.compareVersions($0, v) <= 0 } ?? true) && (r.fixed.map { core.compareVersions(v, $0) < 0 } ?? true)
            && (r.lastAffected.map { core.compareVersions(v, $0) <= 0 } ?? true)
    }

    @Test func aWarningMeansTheVersionIsInARangeAndTheUpgradeIsInNone() {
        // Ranges.lean's theorems, on a sample, with the wrapper's own comparisons as the reference
        for rs in Self.sampleSets {
            for v in Self.sampleVersions {
                let inOne = rs.contains { Self.holds($0, v) }
                #expect((core.affectedness(installed: v, ranges: rs) == .affected) == inOne, "\(v) in \(rs)")
                if let u = core.upgrade(from: v, ranges: rs) {
                    #expect(core.compareVersions(v, u) < 0 && core.affectedness(installed: u, ranges: rs) == .notAffected, "\(v) → \(u)")
                }
            }
        }
    }

    // MARK: Reading the API

    @Test func advisoriesCarryRangesOrNone() throws {
        let json = #"""
        {"slug":"x","recent":[
         {"id":"A","sev":"HIGH","fixed_hint":["1.2"],"ranges":[{"introduced":"1.0","fixed":"1.2"},{"last_affected":"0.9"}],"ranges_note":null},
         {"id":"B","sev":"HIGH","fixed_hint":["3"],"ranges":null,"ranges_note":"wildcard '6.1.*' (lessThanOrEqual)"},
         {"id":"C","fixed_hint":[]},
         {"id":"D","ranges":[]},
         {"id":"E","ranges":"nonsense"},
         {"id":"F","fixed_hint":["2.0"],"ranges":[{"introduced":"1.0","limit":"2.0"}]},
         {"id":"G","ranges":[{"fixed":null}]},
         {"id":"H","ranges":[{"fixed":2}]},
         {"id":"I","ranges":[{}]},
         {"id":"J","ranges":[{"introduced":"1.0","fixed":"1.2"},"1.3"]},
         {"id":"K","fixed_hint":"1.2","ranges":[{"fixed":"1.2"}]},
         {"id":"L","fixed_hint":["1.2",3]},
         {"id":"M","fixed_hint":null,"ranges":[{"fixed":"1.2"}]}]}
        """#
        let p = try JSONDecoder().decode(ProjectResponse.self, from: Data(json.utf8))
        #expect(p.recent[0].ranges == [AffectedRange(introduced: "1.0", fixed: "1.2"), AffectedRange(lastAffected: "0.9")])
        #expect(p.recent[1].ranges == nil && p.recent[1].rangesNote == "wildcard '6.1.*' (lessThanOrEqual)")
        #expect(p.recent[2].ranges == nil)                          // an older server: no ranges at all
        #expect(p.recent[3].ranges == [])                           // the issuer says no version is affected
        #expect(p.recent[0...3].allSatisfy { !$0.rangesUnreadable })
        #expect(p.recent[4].ranges == nil && p.recent[4].rangesUnreadable)            // malformed: not checked, never wider
        // strict: an unknown key, a null or a number never reads as a wider range ("limit" dropped, null as absent)
        for i in 5...7 { #expect(p.recent[i].ranges == nil && p.recent[i].rangesUnreadable, "\(p.recent[i].id)") }
        #expect(p.recent[8].ranges == [AffectedRange()] && !p.recent[8].rangesUnreadable)   // {}: every version, as published
        #expect(p.recent[9].ranges == nil && p.recent[9].rangesUnreadable)            // one unreadable range spoils the list
        #expect(p.recent[5].coreAdvisory == nil && p.recent[8].coreAdvisory == CoreAdvisory(ranges: [AffectedRange()], fixed: []))
        #expect(p.recent[0].coreAdvisory == CoreAdvisory(ranges: p.recent[0].ranges, fixed: ["1.2"]))
        #expect(p.recent[1].coreAdvisory == CoreAdvisory(ranges: nil, fixed: ["3"]))
        // first fixed versions read as strictly: a list that does not read is unreadable, never []
        #expect(p.recent[0...9].allSatisfy { !$0.fixedHintUnreadable })
        #expect(p.recent[10].fixedHintUnreadable && p.recent[10].fixedHint == [] && p.recent[10].coreAdvisory == nil)
        #expect(p.recent[11].fixedHintUnreadable && p.recent[11].coreAdvisory == nil)
        #expect(!p.recent[12].fixedHintUnreadable && p.recent[12].coreAdvisory == CoreAdvisory(ranges: [AffectedRange(fixed: "1.2")], fixed: []))
        let again = try JSONDecoder().decode(ProjectResponse.self, from: JSONEncoder().encode(p))     // the cache's copy
        #expect(again.recent == p.recent)
        #expect(again.recent.map(\.rangesUnreadable) == [false, false, false, false, true, true, true, true, false, true, false, false, false])
        #expect(again.recent.map(\.fixedHintUnreadable) == [false, false, false, false, false, false, false, false, false, false, true, true, false])
    }

    @Test func aRangeReadsOnlyItsThreeBoundsAsStrings() throws {
        func range(_ json: String) -> AffectedRange? { try? JSONDecoder().decode(AffectedRange.self, from: Data(json.utf8)) }
        #expect(range(#"{"introduced":"1.0","fixed":"2.0","last_affected":"1.9"}"#) == AffectedRange(introduced: "1.0", fixed: "2.0", lastAffected: "1.9"))
        #expect(range(#"{"introduced":""}"#) == AffectedRange(introduced: ""))          // a present bound, even empty
        #expect(range("{}") == AffectedRange())
        for bad in [#"{"introduced":"1.0","limit":"2.0"}"#, #"{"fixed":null}"#, #"{"fixed":2}"#, #"{"fixed":true}"#, #"{"lastAffected":"1.0"}"#,
                    #"{"introduced":["1.0"]}"#, #""1.0""#, "null", "[]"] {
            #expect(range(bad) == nil, "\(bad)")
        }
        let r = AffectedRange(introduced: "1.0", lastAffected: "1.9")
        #expect(range(String(decoding: try JSONEncoder().encode(r), as: UTF8.self)) == r)
    }

    // MARK: Homebrew: CPython

    @Test func pythonOnOtherBranchesIsNotFlaggedByAFlawOnlyIn31410() throws {
        let py = cpython
        let flaw = try #require(py.recent.first { $0.id == "CVE-2026-119170" })
        #expect(flaw.ranges == [AffectedRange(introduced: "3.14.10", fixed: "3.14.11")] && flaw.fixedHint == ["3.14.11"])
        for (formula, version) in [("python@3.11", "3.11.18"), ("python@3.12", "3.12.16"), ("python@3.13", "3.13.18")] {
            #expect(!findings([brew(formula, version, "cpython")], ["cpython": py]).contains { $0.advisoryIDs.contains("CVE-2026-119170") },
                    "\(formula) \(version)")
        }
        #expect(findings([brew("python@3.12", "3.12.16", "cpython"), brew("python@3.13", "3.13.18", "cpython")], ["cpython": py]).isEmpty)
        // the one version it affects is flagged, with its own branch's fix
        let f = try #require(findings([brew("python@3.14", "3.14.10", "cpython")], ["cpython": py]).first)
        #expect(f.advisoryIDs == ["CVE-2026-119170"] && f.fixedVersion == "3.14.11" && f.upgradeCommand == "brew upgrade python@3.14")
        #expect(f.note == "The issuer lists 3.14.10 as affected and 3.14.11 as fixed.")
        // the same record read by first fixed versions alone: the false alarm the owner saw (now without the command,
        // since 3.14.11 is not a python@3.11 release)
        let old = findings([brew("python@3.11", "3.11.18", "cpython")], ["cpython": withoutRanges(py)])
        #expect(old.first?.advisoryIDs == ["CVE-2026-119170"])
        #expect(old.first?.note == "The issuer lists 3.11.18 as affected; its fix, 3.14.11, is not a python@3.11 release.")
    }

    @Test func aVersionedFormulaIsNeverToldToLeaveItsLine() throws {
        // PSF's CVE-2024-12254 lists everything below 3.12.9 as affected, and 3.12.16 is the first release in none of the
        // weighed ranges; python@3.11 cannot install either
        let py = cpython
        let f = try #require(findings([brew("python@3.11", "3.11.18", "cpython")], ["cpython": py]).first)
        #expect(f.advisoryIDs == ["CVE-2024-12254"])
        #expect(f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "The issuer lists 3.11.18 as affected; its fix, 3.12.16, is not a python@3.11 release.")
        let g = try #require(findings([brew("python@3.12", "3.12.8", "cpython")], ["cpython": py]).first { $0.advisoryIDs.contains("CVE-2024-12254") })
        #expect(g.fixedVersion.map { core.compareVersions($0, "3.12.9") >= 0 && $0.hasPrefix("3.12.") } == true && g.upgradeCommand == "brew upgrade python@3.12")
        #expect(FindingBuilder.formulaLine(HomebrewItem(kind: .formula, name: "openssl@3", version: "3.5.1", urls: [])) == [3])
        #expect(FindingBuilder.formulaLine(HomebrewItem(kind: .formula, name: "python@3.11", version: "3.11.18", urls: [])) == [3, 11])
        #expect(FindingBuilder.formulaLine(HomebrewItem(kind: .formula, name: "nginx", version: "1.31.0", urls: [])) == nil)
        #expect(FindingBuilder.formulaLine(HomebrewItem(kind: .cask, name: "x@2", version: "1", urls: [])) == nil)
        #expect(FindingBuilder.formulaLine(HomebrewItem(kind: .formula, name: "x@beta", version: "1", urls: [])) == nil)
        #expect(FindingBuilder.isOnLine("3.11.18", [3, 11]) && !FindingBuilder.isOnLine("3.12.9", [3, 11]) && FindingBuilder.isOnLine("16.16", [16])
                && !FindingBuilder.isOnLine("3", [3, 11]))
    }

    // MARK: Homebrew: PostgreSQL

    @Test func postgres1616IsInNoBranchsRange() throws {
        let pg = postgres
        #expect(pg.recent.count == 100 && pg.recent.allSatisfy { $0.ranges != nil })
        #expect(findings([brew("postgresql@16", "16.16", "postgres")], ["postgres": pg]).isEmpty)
        // an older 16.x is affected, and the upgrade is the newest 16.x fix, not a major version
        let f = try #require(findings([brew("postgresql@16", "16.14", "postgres")], ["postgres": pg]).first)
        #expect(f.fixedVersion == "16.16" && f.upgradeCommand == "brew upgrade postgresql@16")
        #expect(f.advisoryIDs.contains("CVE-2026-14662") && !f.advisoryIDs.contains("CVE-2026-116313"))     // 18 only
        #expect(f.note == "The issuer lists 16.14 as affected and 16.16 as fixed.")
        // 16.15 fixes the August batch but not November's, which starts at 16 and ends at 16.16: 16.15 is never proposed
        let g = try #require(findings([brew("postgresql@16", "16.9", "postgres")], ["postgres": pg]).first)
        #expect(g.fixedVersion == "16.16")
        // read by first fixed versions alone, 16.16 is flagged by the 18-only records: the false alarms the owner saw
        let old = findings([brew("postgresql@16", "16.16", "postgres")], ["postgres": withoutRanges(pg)])
        #expect(old.first?.advisoryIDs.contains("CVE-2026-116313") == true)
    }

    @Test func patchTheseFirstUsesTheProjectsRangesWhenItHasThem() throws {
        let issue = try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"""
            {"name":"PostgreSQL","slug":"postgres","severity":"HIGH","exploited":false,"date":"2026-11-12","ids":["CVE-2026-116313"],
             "fixed_in":["18.7"],"title":"vacuumdb lets a database owner execute code"}
            """#.utf8))
        // the list's first fixed version alone (18.7) flags 16.16; the record's ranges say 18 only
        #expect(findings([brew("postgresql@16", "16.16", "postgres")], ["postgres": postgres], big: [issue]).isEmpty)
        // without the project's record the list decides, as before
        #expect(findings([brew("postgresql@16", "16.16", "postgres")], [:], big: [issue]).count == 1)
        // an 18.x before the fix is flagged and marked
        let f = try #require(findings([brew("postgresql@18", "18.6", "postgres")], ["postgres": postgres], big: [issue]).first)
        #expect(f.bigIssue != nil && f.fixedVersion == "18.7")
    }

    @Test func eachAdvisorySaysHowItWasDecided() throws {
        #expect(AdvisoryCheck.decide("16.14", postgres.recent)?.hits.allSatisfy { $0.basis == .ranges } == true)
        let mixed = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"x","recent":[{"id":"A","sev":"HIGH","fixed_hint":["1.2"],"ranges":[{"fixed":"1.2"}]},
                                  {"id":"B","sev":"CRITICAL","fixed_hint":["1.4"],"ranges":null,"ranges_note":"only git ranges"},
                                  {"id":"C","sev":"LOW","fixed_hint":["9"],"ranges":[{}]}]}
            """#.utf8))
        let d = try #require(AdvisoryCheck.decide("1.0", mixed.recent))
        #expect(d.hits.map(\.advisory.id) == ["A", "B"] && d.hits.map(\.basis) == [.ranges, .firstFixed])     // C is low: not weighed
        #expect(d.target == "1.4" && d.note == "Likely affected: the issuer names 1.4 as fixed.")
        #expect(AdvisoryCheck.decide("1.0", [mixed.recent[0]])?.note == "The issuer lists 1.0 as affected and 1.2 as fixed.")
        let open = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"{"slug":"x","recent":[{"id":"A","sev":"HIGH","ranges":[{"introduced":"0.5"}]}]}"#.utf8))
        #expect(AdvisoryCheck.decide("1.0", open.recent)?.note == "The issuer lists 1.0 as affected. No fixed release yet.")
        #expect(AdvisoryCheck.decide("0.4", open.recent) == nil)
    }

    @Test func macPortsAndNixPackagesFollowTheRangesToo() throws {
        let project = try #require(index.project(slug: "postgres"))
        let current = ManagedPackage(manager: .macports, name: "postgresql16-server", version: "16.16", origin: .macports(port: "postgresql16-server"))
        let older = ManagedPackage(manager: .macports, name: "postgresql16-server", version: "16.14", origin: .macports(port: "postgresql16-server"))
        let f = FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["postgres": postgres], bigIssues: [],
                                                      managed: [current, older].map { .init(package: $0, project: project) })
        #expect(f.count == 1 && f.first?.installedVersion == "16.14" && f.first?.fixedVersion == "16.16")
        #expect(f.first?.note?.hasPrefix("The issuer lists 16.14 as affected and 16.16 as fixed.") == true)
    }

    // MARK: Apps and bundled libraries

    @Test func productsAreDecidedByRangesToo() throws {
        let zoom = try JSONDecoder().decode(ProductResponse.self, from: Data(#"""
            {"key":"zoom","name":"Zoom Workplace","recent":[
             {"id":"A","sev":"HIGH","fixed_hint":["6.6.12"],"ranges":[{"introduced":"6.6.0","fixed":"6.6.12"}]},
             {"id":"B","sev":"CRITICAL","kev":true,"fixed_hint":["6.5.9"],"ranges":[{"fixed":"6.5.9"}]}]}
            """#.utf8))
        let app = InstalledApp(name: "zoom.us", path: "/nonexistent/zoom.us.app", bundleID: "us.zoom.xos", shortVersion: "6.5.1", bundleVersion: nil, caskToken: nil)
        let check = BundleCheck.match(Inventory(apps: [app]), index: Make.index)
        let f = try #require(check.findings(products: ["zoom": zoom], projects: [:]).first)
        #expect(f.advisoryIDs == ["B"] && f.fixedVersion == "6.5.9" && f.exploited)
        #expect(f.note == "The issuer lists 6.5.1 as affected and 6.5.9 as fixed. Update zoom.us from its own menu or its website.")
        // by first fixed versions alone, A (6.6.0 up to 6.6.12) would flag 6.5.1 too
        var hintOnly = zoom
        hintOnly.recent = zoom.recent.map { var a = $0; a.ranges = nil; return a }
        #expect(Set(check.findings(products: ["zoom": hintOnly], projects: [:]).first?.advisoryIDs ?? []) == ["A", "B"])
    }
}
