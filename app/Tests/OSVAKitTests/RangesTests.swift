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
        // the same record read by first fixed versions alone: the false alarm the owner saw, now only likely and never
        // counted (and without the command, since 3.14.11 is not a python@3.11 release)
        let old = findings([brew("python@3.11", "3.11.18", "cpython")], ["cpython": withoutRanges(py)])
        #expect(old.first?.advisoryIDs.first == "CVE-2026-119170" && old.first?.group == .likely && old.first?.upgradeCommand == nil)
        #expect(old.first?.note == "Likely affected: the site publishes no affected ranges; the issuer's fix, 3.14.11, is not a python@3.11 release."
                + " 18 more advisories state no affected versions; not checked, among them CVE-2026-115557, critical.")
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
        // affected by A's ranges; B, without ranges, is likely, said and never counted; the core's upgrade leaves both
        #expect(d.check == .affected && d.target?.version == "1.4" && d.flawCount == 1 && d.group == .criticalHigh)
        #expect(d.note == "The issuer lists 1.0 as affected and 1.4 as fixed. 1 more advisory without published ranges likely affects it too: B, critical.")
        #expect(d.notChecked == Finding.NotChecked(id: "B", exploited: false, critical: true))
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
        #expect(f.advisoryIDs == ["B"] && f.fixedVersion == "6.5.9" && f.exploited && f.group == .exploited)
        #expect(f.note == "The issuer lists 6.5.1 as affected and 6.5.9 as fixed. Update zoom.us from its own menu or its website.")
        // by first fixed versions alone, A (6.6.0 up to 6.6.12) would flag 6.5.1 too: likely, never counted
        var hintOnly = zoom
        hintOnly.recent = zoom.recent.map { var a = $0; a.ranges = nil; return a }
        let likely = try #require(check.findings(products: ["zoom": hintOnly], projects: [:]).first)
        #expect(Set(likely.advisoryIDs) == ["A", "B"] && likely.group == .likely && !likely.group.needsAction)
    }
}

/// Task 6: a project's or product's advisory is affected only inside its published ranges; without them it is likely
/// affected, never counted; the upgrade is the core's; and a "patch these first" item never promotes or versions a
/// finding the core did not check.
extension RangesTests {
    /// A project record with these advisories, as the server writes them.
    func record(_ slug: String, _ advisories: [String]) throws -> ProjectResponse {
        try JSONDecoder().decode(ProjectResponse.self, from: Data(#"{"slug":"\#(slug)","name":"\#(slug)","recent":[\#(advisories.joined(separator: ","))]}"#.utf8))
    }

    func item(_ slug: String, ids: [String], fixedIn: [String], exploited: Bool = true, severity: String = "HIGH") throws -> StateResponse.BigIssue {
        let json = #"{"name":"\#(slug)","slug":"\#(slug)","severity":"\#(severity)","exploited":\#(exploited),"date":"2026-11-20","#
            + #""ids":[\#(ids.map { "\"\($0)\"" }.joined(separator: ","))],"fixed_in":[\#(fixedIn.map { "\"\($0)\"" }.joined(separator: ","))],"title":"Item"}"#
        return try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(json.utf8))
    }

    func report(_ findings: [Finding]) -> ScanReport {
        ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(), findings: findings, sent: SentRecord(), indexGeneratedAt: nil, problems: [])
    }

    @Test func anAdvisoryWithoutRangesIsLikelyNotAffected() throws {
        let nginx = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": nginx]).first)
        #expect(f.group == .likely && f.fixedVersion == "1.31.9" && f.upgradeCommand == "brew upgrade nginx")
        #expect(f.note == "Likely affected: the site publishes no affected ranges, and the issuer names 1.31.9 as fixed.")
        #expect(report([f]).actionCount == 0)
        // exploited in the wild: still likely, never counted, but marked, and it notifies
        let kev = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","kev":true,"fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#])
        let k = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": kev]).first)
        #expect(k.group == .likely && k.exploited && k.notChecked == Finding.NotChecked(id: "CVE-N", exploited: true, critical: false))
        #expect(k.deservesNotification && report([k]).actionCount == 0)
        // MacPorts and Nix the same
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        let m = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": kev], bigIssues: [],
                                                                   managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(m.group == .likely && m.fixedVersion == "1.31.9" && m.notChecked?.exploited == true)
        #expect(m.note?.hasPrefix("Likely affected: the site publishes no affected ranges, and the issuer names 1.31.9 as fixed.") == true)
    }

    @Test func anUnreadableAdvisoryIsReportedNeverAffected() throws {
        // its ranges do not read: decided by its first fixed versions alone, and then only reported
        let p = try record("nginx", [#"{"id":"CVE-U","sev":"CRITICAL","fixed_hint":["1.31.9"],"ranges":[{"introduced":"1.0","limit":"2.0"}]}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p]).first)
        #expect(f.group == .reported && f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "Reported by the site, not checked: the app could not read its affected ranges for CVE-U.")
        #expect(f.notChecked == Finding.NotChecked(id: "CVE-U", exploited: false, critical: true) && report([f]).actionCount == 0)
        // beside an affected one, it is said and marked, never counted
        let both = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#,
                                        #"{"id":"CVE-U","sev":"CRITICAL","fixed_hint":["1.31.9"],"ranges":[{"introduced":"1.0","limit":"2.0"}]}"#])
        let g = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": both]).first)
        #expect(g.group == .criticalHigh && g.flawCount == 1 && g.severity == .high && g.fixedVersion == "1.31.9")
        #expect(g.note == "The issuer lists 1.31.5 as affected and 1.31.9 as fixed. 1 more advisory is reported, not checked: CVE-U, critical.")
        #expect(g.notChecked == Finding.NotChecked(id: "CVE-U", exploited: false, critical: true))
    }

    @Test func theUpgradeLeavesRangedAndUnrangedAdvisoriesAlike() throws {
        let pg = try record("postgres", [#"{"id":"R","sev":"HIGH","fixed_hint":["16.15"],"ranges":[{"introduced":"16","fixed":"16.15"}]}"#,
                                         #"{"id":"F","sev":"HIGH","fixed_hint":["16.20"],"ranges":null}"#])
        let f = try #require(findings([brew("postgresql@16", "16.14", "postgres")], ["postgres": pg]).first)
        #expect(f.fixedVersion == "16.20" && f.group == .criticalHigh)
        let d = try #require(AdvisoryCheck.decide("16.14", pg.recent))
        #expect(d.target?.version == "16.20" && d.target?.fixCount == 2)
    }

    @Test func anUpgradeTheCoreWillNotWeighIsNeitherShownNorRun() throws {
        // more work than the core may be asked for: no version and no command, Homebrew's included
        let fixes = (0..<500).map { "\"2.\($0)\"" }.joined(separator: ",")
        let many = try record("nginx", [#"{"id":"CVE-M","sev":"HIGH","fixed_hint":[\#(fixes)],"ranges":null}"#])
        let f = try #require(findings([brew("nginx", "1.0", "nginx")], ["nginx": many]).first)
        #expect(f.group == .likely && f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "Likely affected: the site publishes no affected ranges. No checked fixed version yet; see the site.")
        // a fixed version the core picks that does not read as a version: the same
        let odd = try record("nginx", [#"{"id":"CVE-O","sev":"HIGH","fixed_hint":["1.31.9;reboot"],"ranges":[{"fixed":"1.31.9;reboot"}]}"#])
        let g = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": odd]).first)
        #expect(g.group == .criticalHigh && g.fixedVersion == nil && g.upgradeCommand == nil)
        #expect(g.note == "The issuer lists 1.31.5 as affected. The server named a fixed version the app does not accept as a version; see the site.")
    }

    @Test func aPatchTheseFirstItemNeverPromotesAnUncheckedFinding() throws {
        // a likely finding, and an exploited item on it whose advisory has no ranges: still likely, labelled, marked
        let nginx = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#])
        let unranged = try item("nginx", ids: ["CVE-N"], fixedIn: ["1.31.10"])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": nginx], big: [unranged]).first)
        #expect(f.group == .likely && f.bigIssue != nil && f.fixedVersion == "1.31.9" && !f.exploited)
        #expect(f.notChecked == Finding.NotChecked(id: "CVE-N", exploited: true, critical: false) && f.deservesNotification)
        // an item whose ranges hold the version makes it exploited
        let both = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#,
                                        #"{"id":"CVE-K","sev":"MODERATE","fixed_hint":["1.31.9"],"ranges":[{"introduced":"1.31.0","fixed":"1.31.9"}]}"#])
        let ranged = try item("nginx", ids: ["CVE-K"], fixedIn: ["1.31.9"])
        let g = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": both], big: [ranged]).first)
        #expect(g.group == .exploited && g.exploited && g.bigIssue != nil)
        // MacPorts the same, both ways
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        func managed(_ p: ProjectResponse, _ i: StateResponse.BigIssue) -> Finding? {
            FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": p], bigIssues: [i],
                                                  managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first
        }
        #expect(managed(nginx, unranged)?.group == .likely && managed(nginx, unranged)?.exploited == false && managed(nginx, unranged)?.bigIssue != nil)
        #expect(managed(both, ranged)?.group == .exploited)
        // without a finding of its own, an item decided by its first fixed versions makes a likely one, never an exploited one
        let made = try #require(findings([brew("nginx", "1.31.5", "nginx")], [:], big: [unranged]).first)
        #expect(made.group == .likely && made.fixedVersion == "1.31.10" && made.notChecked?.exploited == true && made.deservesNotification)
        #expect(made.note == "Likely affected: the site publishes no affected ranges, and the issuer names 1.31.10 as fixed.")
        let madeManaged = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: [:], bigIssues: [unranged],
                                                                             managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(madeManaged.group == .likely && madeManaged.fixedVersion == "1.31.10")
    }

    @Test func aPatchTheseFirstItemNeverFillsAnotherFindingsFix() throws {
        // affected, and no release leaves its range; an item the record does not know names 2.0 by its first fixed versions
        let open = try record("nginx", [#"{"id":"CVE-O","sev":"HIGH","ranges":[{"introduced":"1.0"}]}"#])
        let other = try item("nginx", ids: ["CVE-ELSE"], fixedIn: ["2.0"], exploited: false)
        let f = try #require(findings([brew("nginx", "1.5", "nginx")], ["nginx": open], big: [other]).first)
        #expect(f.group == .criticalHigh && f.bigIssue != nil && f.fixedVersion == nil && f.upgradeCommand == "brew upgrade nginx")
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.5", origin: .macports(port: "nginx"))
        let m = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": open], bigIssues: [other],
                                                                   managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(m.bigIssue != nil && m.fixedVersion == nil)
        // MacPorts picks its own version, which only Homebrew's is taken without a checked one: no command
        #expect(m.upgradeCommand == nil && m.note == "The issuer lists 1.5 as affected. No fixed release yet.")
        // a reported finding names no version, though the core has one for the item on it (1.31.9)
        let unread = try record("nginx", [#"{"id":"CVE-U","sev":"HIGH","fixed_hint":["1.31.9"],"ranges":[{"introduced":"1.0","limit":"2.0"}]}"#])
        let onIt = try item("nginx", ids: ["CVE-U"], fixedIn: ["1.31.9"])
        let r = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": unread], big: [onIt]).first)
        #expect(r.group == .reported && r.bigIssue != nil && r.fixedVersion == nil && r.upgradeCommand == nil)
        let reportedPort = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        let rm = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": unread], bigIssues: [onIt],
                                                                    managed: [.init(package: reportedPort, project: index.project(slug: "nginx")!)]).first)
        #expect(rm.group == .reported && rm.bigIssue != nil && rm.fixedVersion == nil)
    }
}

/// The review of #19: advisories that state nothing are never dropped when urgent, and an item that promotes a finding
/// brings its version and its sentence with it.
extension RangesTests {
    @Test func anExploitedAdvisoryThatStatesNothingMakesAReportedFinding() throws {
        // P1: an advisory exploited in the wild with no ranges and no fixed versions, alone: a reported finding for it
        let kev = try record("nginx", [#"{"id":"CVE-K","sev":"HIGH","kev":true,"fixed_hint":[],"ranges":null}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": kev]).first)
        #expect(f.group == .reported && f.flawCount == 1 && f.exploited && f.fixedVersion == nil && f.upgradeCommand == nil)
        #expect(f.advisoryIDs == ["CVE-K"] && f.notChecked == Finding.NotChecked(id: "CVE-K", exploited: true, critical: false))
        #expect(f.note == "Reported by the site, not checked: it publishes no affected versions for CVE-K." && report([f]).actionCount == 0)
        // the critical and the other advisories that state nothing beside it are counted, the critical one named
        let more = try record("nginx", [#"{"id":"CVE-K","sev":"HIGH","kev":true,"ranges":null}"#, #"{"id":"CVE-C","sev":"CRITICAL","ranges":null}"#,
                                        #"{"id":"CVE-H","sev":"HIGH","ranges":null}"#])
        let g = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": more]).first)
        #expect(g.group == .reported && g.flawCount == 1 && g.advisoryIDs == ["CVE-K", "CVE-C"])
        #expect(g.note == "Reported by the site, not checked: it publishes no affected versions for CVE-K. "
                + "2 more advisories state no affected versions; not checked, among them CVE-C, critical.")
        // ranges that cannot be read and no fixed versions: said as unreadable
        let unread = try record("nginx", [#"{"id":"CVE-U","sev":"HIGH","kev":true,"ranges":[{"introduced":"1.0","limit":"2.0"}]}"#])
        #expect(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": unread]).first?.note
                == "Reported by the site, not checked: the app could not read its affected ranges for CVE-U.")
        // a product's record the same
        let zoom = try JSONDecoder().decode(ProductResponse.self, from: Data(#"{"key":"zoom","name":"Zoom Workplace","recent":[{"id":"ZSB-K","sev":"HIGH","kev":true}]}"#.utf8))
        let app = InstalledApp(name: "zoom.us", path: "/nonexistent/zoom.us.app", bundleID: "us.zoom.xos", shortVersion: "6.6.10", bundleVersion: nil, caskToken: "zoom")
        let z = try #require(BundleCheck.match(Inventory(apps: [app]), index: Make.index).findings(products: ["zoom": zoom], projects: [:]).first)
        #expect(z.group == .reported && z.upgradeCommand == nil && z.notChecked?.exploited == true)
    }

    @Test func aCriticalAdvisoryThatStatesNothingMakesNoFindingAlone() throws {
        // evidence about no version in particular: on the site, never a finding of its own
        let critical = try record("nginx", [#"{"id":"CVE-C","sev":"CRITICAL","fixed_hint":[],"ranges":null}"#, #"{"id":"CVE-H","sev":"HIGH","ranges":null}"#])
        #expect(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": critical]).isEmpty)
        let zoom = try JSONDecoder().decode(ProductResponse.self, from: Data(#"{"key":"zoom","name":"Zoom Workplace","recent":[{"id":"ZSB-C","sev":"CRITICAL"}]}"#.utf8))
        let app = InstalledApp(name: "zoom.us", path: "/nonexistent/zoom.us.app", bundleID: "us.zoom.xos", shortVersion: "6.6.10", bundleVersion: nil, caskToken: "zoom")
        #expect(BundleCheck.match(Inventory(apps: [app]), index: Make.index).findings(products: ["zoom": zoom], projects: [:]).isEmpty)
    }

    @Test func aCriticalAdvisoryThatStatesNothingIsNamedBesideAFinding() throws {
        let mixed = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#, #"{"id":"CVE-C","sev":"CRITICAL","ranges":null}"#,
                                         #"{"id":"CVE-H","sev":"HIGH","ranges":null}"#])
        let g = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": mixed]).first)
        #expect(g.group == .criticalHigh && g.flawCount == 1 && g.fixedVersion == "1.31.9" && g.advisoryIDs == ["CVE-A", "CVE-C"])
        #expect(g.note == "The issuer lists 1.31.5 as affected and 1.31.9 as fixed. 2 more advisories state no affected versions; not checked, among them CVE-C, critical.")
        #expect(g.notChecked == Finding.NotChecked(id: "CVE-C", exploited: false, critical: true))
        // a high one that states nothing beside it is only counted
        let high = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#, #"{"id":"CVE-H","sev":"HIGH","ranges":null}"#])
        let h = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": high]).first)
        #expect(h.note == "The issuer lists 1.31.5 as affected and 1.31.9 as fixed. 1 more advisory states no affected versions; not checked." && h.notChecked == nil)
    }

    @Test func rangesThatReadDecideBesideFixedVersionsThatDoNot() throws {
        // P1b: the fixed versions do not read; the ranges do, and decide
        let p = try record("nginx", [#"{"id":"CVE-R","sev":"HIGH","fixed_hint":"1.31.9","ranges":[{"fixed":"1.31.9"}]}"#])
        #expect(p.recent[0].fixedHintUnreadable && p.recent[0].coreAdvisory == nil)
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p]).first)
        #expect(f.group == .criticalHigh && f.fixedVersion == "1.31.9" && f.note == "The issuer lists 1.31.5 as affected and 1.31.9 as fixed.")
        // without ranges, fixed versions that do not read state nothing
        let q = try record("nginx", [#"{"id":"CVE-F","sev":"HIGH","kev":true,"fixed_hint":"1.31.9","ranges":null}"#])
        #expect(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": q]).first?.note
                == "Reported by the site, not checked: the app could not read the fixed versions it names for CVE-F.")
    }

    /// I2: an item whose published ranges hold the version promotes the finding with its version and its sentence.
    @Test func anItemThatPromotesBringsItsVersionAndSentence() throws {
        // a likely finding (CVE-N, first fixed 1.31.9) and an exploited item on CVE-K, whose range holds 1.31.5
        func promoted(_ kRanges: String) throws -> Finding {
            let p = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#,
                                         #"{"id":"CVE-K","sev":"MODERATE","ranges":\#(kRanges)}"#])
            return try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [try item("nginx", ids: ["CVE-K"], fixedIn: [])]).first)
        }
        // P3: its own upgrade (1.31.9) lies inside the item's range: the item's, which leaves both
        let p3 = try promoted(#"[{"introduced":"1.31.0","fixed":"1.31.12"}]"#)
        #expect(p3.group == .exploited && p3.exploited && p3.fixedVersion == "1.31.12" && p3.flawCount == 1 && p3.bigIssue != nil)
        #expect(p3.note == "The issuer lists 1.31.5 as affected and 1.31.12 as fixed. 1 more advisory without published ranges likely affects it too.")
        #expect(p3.upgradeCommand == "brew upgrade nginx" && p3.advisoryIDs.contains("CVE-K"))
        // P4a: its own upgrade leaves the item's range: kept
        let p4a = try promoted(#"[{"introduced":"1.31.0","fixed":"1.31.9"}]"#)
        #expect(p4a.fixedVersion == "1.31.9" && p4a.note == "The issuer lists 1.31.5 as affected and 1.31.9 as fixed. 1 more advisory without published ranges likely affects it too.")
        // P4b: nothing leaves the item's range: no version
        let p4b = try promoted(#"[{"introduced":"1.31.0"}]"#)
        #expect(p4b.fixedVersion == nil && p4b.group == .exploited && p4b.upgradeCommand == "brew upgrade nginx")
        #expect(p4b.note == "The issuer lists 1.31.5 as affected. No fixed release yet. 1 more advisory without published ranges likely affects it too.")
        // on an affected finding the item is counted, unless its advisory is one already
        let affected = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#,
                                            #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.9"}]}"#])
        let counted = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": affected], big: [try item("nginx", ids: ["CVE-K"], fixedIn: [])]).first)
        #expect(counted.flawCount == 2 && counted.group == .exploited)
        let same = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": affected], big: [try item("nginx", ids: ["CVE-A"], fixedIn: [])]).first)
        #expect(same.flawCount == 1 && same.group == .exploited && same.exploited)
        // MacPorts the same
        let p = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.30.7","1.31.9"],"ranges":null}"#,
                                     #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.12"}]}"#])
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        let m = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": p],
                                                                   bigIssues: [try item("nginx", ids: ["CVE-K"], fixedIn: [])],
                                                                   managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(m.group == .exploited && m.fixedVersion == "1.31.12" && m.note?.hasPrefix("The issuer lists 1.31.5 as affected and 1.31.12 as fixed.") == true)
    }

    /// m3: an item that names no fixed version is still decided by the project's ranges.
    @Test func anItemWithoutFixedVersionsIsDecidedByTheRanges() throws {
        let p = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#,
                                     #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0"}]}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [try item("nginx", ids: ["CVE-K"], fixedIn: [])]).first)
        #expect(f.group == .exploited && f.bigIssue != nil && f.flawCount == 2)
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        let m = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": p],
                                                                   bigIssues: [try item("nginx", ids: ["CVE-K"], fixedIn: [])],
                                                                   managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(m.group == .exploited && m.bigIssue != nil)
        // without the project's record it decides nothing
        #expect(findings([brew("nginx", "1.31.5", "nginx")], [:], big: [try item("nginx", ids: ["CVE-K"], fixedIn: [])]).isEmpty)
    }

    /// MA: the upgrade of a finding an item makes leaves the project's weighed advisories too, even one that starts later.
    @Test func anItemsUpgradeLeavesTheProjectsAdvisoriesToo() throws {
        let later = try record("nginx", [#"{"id":"CVE-L","sev":"HIGH","ranges":[{"introduced":"1.31.9","fixed":"1.31.11"}]}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": later], big: [try item("nginx", ids: ["CVE-Z"], fixedIn: ["1.31.9"])]).first)
        #expect(f.group == .likely && f.fixedVersion == "1.31.11")
    }

    /// MD: an item that marks a finding keeps a more urgent mark it had.
    @Test func anItemNeverLowersAMark() throws {
        let p = try record("nginx", [#"{"id":"CVE-N","sev":"CRITICAL","kev":true,"fixed_hint":["1.31.9"],"ranges":null}"#])
        let critical = try item("nginx", ids: ["CVE-Z"], fixedIn: ["1.31.10"], exploited: false, severity: "CRITICAL")
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [critical]).first)
        #expect(f.bigIssue != nil && f.notChecked == Finding.NotChecked(id: "CVE-N", exploited: true, critical: true))
    }

    /// m1: a formula an item makes a finding for is never told to leave its line.
    @Test func anItemsFixOffTheFormulasLineIsNotOffered() throws {
        let f = try #require(findings([brew("python@3.11", "3.11.18", "cpython")], [:], big: [try item("cpython", ids: ["CVE-P"], fixedIn: ["3.12.5"])]).first)
        #expect(f.group == .likely && f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
        #expect(f.note == "Likely affected: the site publishes no affected ranges; the issuer's fix, 3.12.5, is not a python@3.11 release.")
    }

    /// MX4: the version must leave every advisory on the item that has published ranges, not just one.
    @Test func anItemsVersionLeavesEveryRangeOnIt() throws {
        // likely, its own version 1.31.7; the item's K1 holds 1.31.5 and 1.31.7 leaves it, but lands in K2
        let p = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","fixed_hint":["1.31.7"],"ranges":null}"#,
                                     #"{"id":"CVE-K1","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.7"}]}"#,
                                     #"{"id":"CVE-K2","sev":"MODERATE","ranges":[{"introduced":"1.31.6","fixed":"1.31.9"}]}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [try item("nginx", ids: ["CVE-K1", "CVE-K2"], fixedIn: [])]).first)
        #expect(f.group == .exploited && f.fixedVersion == "1.31.9")
    }

    /// MX5 (a project): an item that is not exploited, on a likely finding whose own advisory is: critical and high, not
    /// exploited, and the mark kept.
    @Test func anUnexploitedItemNeverMakesAProjectExploited() throws {
        let p = try record("nginx", [#"{"id":"CVE-N","sev":"HIGH","kev":true,"fixed_hint":["1.31.9"],"ranges":null}"#,
                                     #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.9"}]}"#])
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [try item("nginx", ids: ["CVE-K"], fixedIn: [], exploited: false)]).first)
        #expect(f.group == .criticalHigh && !f.exploited && f.notChecked == Finding.NotChecked(id: "CVE-N", exploited: true, critical: false))
    }

    /// MX10: an item that promotes keeps the marks earlier items left.
    @Test func aPromotionKeepsEarlierMarks() throws {
        let p = try record("nginx", [#"{"id":"CVE-A","sev":"HIGH","ranges":[{"fixed":"1.31.9"}]}"#,
                                     #"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.9"}]}"#])
        let likely = try item("nginx", ids: ["CVE-Z"], fixedIn: ["1.31.10"]), affected = try item("nginx", ids: ["CVE-K"], fixedIn: [], exploited: false)
        let f = try #require(findings([brew("nginx", "1.31.5", "nginx")], ["nginx": p], big: [likely, affected]).first)
        #expect(f.flawCount == 2 && f.notChecked == Finding.NotChecked(id: "CVE-Z", exploited: true, critical: false))
    }

    /// n2: a finding an item made is made again by a later item the core finds affected, never off its formula's line.
    @Test func aFindingAnItemMadeIsMadeAgainByTheNext() throws {
        let cpython = try record("cpython", [#"{"id":"CVE-R","sev":"MODERATE","ranges":[{"introduced":"3.11.0","fixed":"3.12.5"}]}"#])
        let first = try item("cpython", ids: ["CVE-P"], fixedIn: ["3.12.5"]), second = try item("cpython", ids: ["CVE-R"], fixedIn: [])
        let f = try #require(findings([brew("python@3.11", "3.11.18", "cpython")], ["cpython": cpython], big: [first, second]).first)
        #expect(f.group == .exploited && f.fixedVersion == nil && f.upgradeCommand == nil && f.flawCount == 1)
        #expect(f.note == "The issuer lists 3.11.18 as affected; its fix, 3.12.5, is not a python@3.11 release. "
                + "1 more advisory without published ranges likely affects it too: CVE-P, exploited in the wild.")
        // MacPorts the same
        let nginx = try record("nginx", [#"{"id":"CVE-K","sev":"MODERATE","ranges":[{"introduced":"1.31.0","fixed":"1.31.12"}]}"#])
        let port = ManagedPackage(manager: .macports, name: "nginx", version: "1.31.5", origin: .macports(port: "nginx"))
        let m = try #require(FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [], projects: ["nginx": nginx],
                                                                   bigIssues: [try item("nginx", ids: ["CVE-Z"], fixedIn: ["1.31.9"]),
                                                                               try item("nginx", ids: ["CVE-K"], fixedIn: [])],
                                                                   managed: [.init(package: port, project: index.project(slug: "nginx")!)]).first)
        #expect(m.group == .exploited && m.fixedVersion == "1.31.12" && m.note?.hasPrefix("The issuer lists 1.31.5 as affected and 1.31.12 as fixed.") == true)
    }
}
