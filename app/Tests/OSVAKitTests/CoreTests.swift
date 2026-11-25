import Foundation
import Testing
import OSVACore
@testable import OSVAKit

/// The wrapper's wiring to the verified core (the Lean-compiled core and its C shim), checked against the contracts
/// written in osva_core.h and the examples there.
@Suite struct CoreTests {
    let core = Core.shared

    @Test func headerIsACopyOfTheCoresHeader() throws {
        // Sources/OSVACore/include/osva_core.h must stay identical to ../core/include/osva_core.h.
        let here = URL(fileURLWithPath: #filePath)
        let app = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let copy = try String(contentsOf: app.appendingPathComponent("Sources/OSVACore/include/osva_core.h"), encoding: .utf8)
        let original = app.deletingLastPathComponent().appendingPathComponent("core/include/osva_core.h")
        try #require(FileManager.default.fileExists(atPath: original.path), "core/include/osva_core.h is next to app/")
        #expect(copy == (try String(contentsOf: original, encoding: .utf8)))
    }

    @Test func initIsSafeToCallAgain() {
        #expect(osva_core_init() == 0)
    }

    @Test("the header's examples, in order", arguments: [
        ["1.0rc1", "1.0", "1.0.post1", "1.0.1"],
        ["10.6", "10.6p2", "10.7"],
        ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0"],
        ["1.9", "1.10", "1.10.1", "2"],
        ["0.9.9", "v1.2.3", "1.2.4"],
    ])
    func order(_ ascending: [String]) {
        for (i, a) in ascending.enumerated() {
            for (j, b) in ascending.enumerated() {
                #expect(core.compareVersions(a, b) == (i < j ? -1 : i > j ? 1 : 0), "\(a) vs \(b)")
            }
        }
    }

    @Test func equalities() {
        #expect(core.compareVersions("v1.2.3", "1.2.3") == 0)            // leading v before a digit
        #expect(core.compareVersions("1.2.3+build.7", "1.2.3") == 0)     // build metadata
        #expect(core.compareVersions("1.02", "1.2") == 0)                // leading zeros
        #expect(core.compareVersions("1.0-alpha", "1.0a") == 0)          // a = alpha
        #expect(core.compareVersions("1.0RC1", "1.0rc1") == 0)           // words are case-insensitive
        #expect(core.compareVersions("1.0-pre", "1.0c") == 0)            // c = rc = pre = preview
        #expect(core.compareVersions("123456789012345678901234567890", "123456789012345678901234567891") == -1)  // any length
        #expect(core.compareVersions("", "") == 0)
        #expect(core.compareVersions("", "0") == -1)
    }

    @Test func helpersUseTheCoresOrder() {
        #expect(core.sortedVersions(["1.10", "1.9", "1.0rc1", "1.0"]) == ["1.0rc1", "1.0", "1.9", "1.10"])
        #expect(core.newestVersion(["3.5.10", "4.1.1", "4.0.4"]) == "4.1.1")
        #expect(core.newestVersion([]) == nil)
        #expect(core.nearestVersion(in: ["1.31.9", "1.30.7"], above: "1.30.2") == "1.30.7")
        #expect(core.nearestVersion(in: ["1.31.9", "1.30.7"], above: "1.31.9") == nil)
    }

    @Test("affectedness, per release branch", arguments: [
        // nginx names a fix per branch
        ("1.30.2", ["1.31.9", "1.30.7"], Core.Affectedness.affected),
        ("1.30.7", ["1.31.9", "1.30.7"], .notAffected),       // at its branch's fix
        ("1.30.9", ["1.31.9", "1.30.7"], .notAffected),       // past its branch's fix
        ("1.31.0", ["1.31.9", "1.30.7"], .affected),
        ("1.29.0", ["1.31.9", "1.30.7"], .affected),          // a branch with no fix, below a fix
        ("1.32.0", ["1.31.9", "1.30.7"], .notAffected),       // at or above every fix
        // OpenSSL: three branches
        ("3.5.9", ["4.1.1", "4.0.4", "3.5.10"], .affected),
        ("3.5.10", ["4.1.1", "4.0.4", "3.5.10"], .notAffected),
        ("4.0.4", ["4.1.1", "4.0.4", "3.5.10"], .notAffected),
        // OpenSSH's portable releases
        ("10.6p1", ["10.6p2"], .affected),
        ("10.6p2", ["10.6p2"], .notAffected),
        ("9.9", [], .unknown),
    ])
    func affected(_ installed: String, _ fixed: [String], _ expected: Core.Affectedness) {
        #expect(core.affectedness(installed: installed, fixedVersions: fixed) == expected)
    }

    @Test func anAffectedVersionAlwaysHasAFixAboveIt() {
        // Theorem 1 of Affected.lean, on a sample: whenever the core says affected, some fixed version is newer.
        let fixed = [["1.31.9", "1.30.7"], ["4.1.1", "4.0.4", "3.5.10"], ["2.0"], ["10.6p2", "9.9p3"]]
        let versions = ["0.1", "1.29.9", "1.30.6", "1.30.8", "1.31.10", "3.4.0", "3.5.11", "4.0.0", "9.9p1", "10.0", "10.6", "1.0rc1", "2.0", "5"]
        for f in fixed {
            for v in versions where core.affectedness(installed: v, fixedVersions: f) == .affected {
                #expect(f.contains { core.compareVersions($0, v) > 0 }, "\(v) with \(f)")
            }
        }
    }

    // MARK: Advisories: verdicts, upgrades, judgements (Decide.lean)

    /// PostgreSQL's advisory with its five published ranges, and one that names only a first fixed version.
    let pg = CoreAdvisory(ranges: RangesTests.pg, fixed: [])
    let ff1620 = CoreAdvisory(ranges: nil, fixed: ["16.20"])
    let nginx = CoreAdvisory(ranges: nil, fixed: ["1.30.7", "1.31.9"])

    @Test func verdictsReadRangesThenFirstFixedVersions() {
        #expect(core.verdicts(installed: "16.14", advisories: [pg, nginx]) == [.inRange, .clear])
        #expect(core.verdicts(installed: "1.31.5", advisories: [nginx]) == [.likely])
        #expect(core.verdicts(installed: "1.0", advisories: [CoreAdvisory(ranges: [], fixed: ["2.0"])]) == [.likely])   // [] reads as no ranges
        #expect(core.verdicts(installed: "16.16", advisories: [CoreAdvisory(ranges: RangesTests.pg, fixed: ["99"])]) == [.clear])  // ranges decide
        #expect(core.verdicts(installed: "1.0", advisories: []) == [])
    }

    @Test func theCoresUpgradeLeavesEveryAdvisory() {
        #expect(core.upgrade(from: "16.14", advisories: [pg, ff1620])?.version == "16.20")
        #expect(core.upgrade(from: "16.14", advisories: [pg, ff1620])?.display == "16.20")
        #expect(core.upgrade(from: "2.0", advisories: [CoreAdvisory(ranges: [AffectedRange(introduced: "1.5")], fixed: [])]) == nil)
        #expect(core.upgrade(from: "1.0", advisories: []) == nil)
    }

    @Test func judgeSaysWhichAdvisoriesAnUpgradeLeaves() throws {
        let both = try #require(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [0, 1]))
        #expect(both.leaves == [true, false] && both.upgrade?.version == "16.15")
        #expect(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [1])?.upgrade == nil)
        #expect(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [])?.upgrade == nil)
        #expect(core.judge("16.14", from: "16.14", advisories: [pg, ff1620], flagged: [0, 1]) == nil)     // not above
        #expect(core.judge("16.13", from: "16.14", advisories: [pg], flagged: [0]) == nil)
        let shown = try #require(both.upgrade?.displayed { "v" + $0 })
        #expect(shown.version == "16.15" && shown.display == "v16.15")
    }

    @Test func anAdvisoryThatStatesNothingIsNeverFixed() throws {
        // neither ranges nor first fixed versions: clear as a verdict, but no evidence that any version fixes it
        let silent = CoreAdvisory(ranges: nil, fixed: [])
        #expect(core.verdicts(installed: "1.0", advisories: [silent]) == [.clear])
        let j = try #require(core.judge("2.0", from: "1.0", advisories: [silent, nginx], flagged: [0]))
        #expect(j.leaves == [false, true] && j.upgrade == nil)
        #expect(core.upgrade(from: "1.31.5", advisories: [nginx, silent]) == nil)
        #expect(core.upgrade(from: "1.31.5", advisories: [nginx])?.version == "1.31.9")
    }

    @Test func theUpgradeIsAskedForAtMost200Advisories() {
        // osva_upgrade_for's cost is quadratic: more than one package's advisories are refused, not decided
        let one = CoreAdvisory(ranges: [AffectedRange(fixed: "2.0")], fixed: [])
        #expect(Core.upgradeAdvisoryLimit == 200)
        #expect(core.upgrade(from: "1.0", advisories: Array(repeating: one, count: 200))?.version == "2.0")
        #expect(core.upgrade(from: "1.0", advisories: Array(repeating: one, count: 201)) == nil)
    }

    @Test func verdictsAgreeWithTheReferenceOnASample() {
        // Decide.lean's theorems, on RangesTests' sample, with the wrapper's own comparisons as the reference
        for rs in RangesTests.sampleSets {
            let whole = [CoreAdvisory(ranges: rs, fixed: [])], split = rs.map { CoreAdvisory(ranges: [$0], fixed: []) }
            for v in RangesTests.sampleVersions {
                let holding = rs.map { RangesTests.holds($0, v) }
                #expect(core.verdicts(installed: v, advisories: whole) == [holding.contains(true) ? .inRange : .clear], "\(v) in \(rs)")
                #expect(core.verdicts(installed: v, advisories: split) == holding.map { $0 ? .inRange : .clear }, "\(v) in each of \(rs)")
                for advisories in [whole, split] {
                    guard let u = core.upgrade(from: v, advisories: advisories)?.version else { continue }
                    #expect(core.compareVersions(v, u) < 0 && !rs.contains { RangesTests.holds($0, u) }, "\(v) → \(u)")
                    #expect(core.judge(u, from: v, advisories: advisories, flagged: Set(advisories.indices))?.leaves.allSatisfy { $0 } == true)
                }
            }
        }
    }

    @Test func versionUncertainNamesVersionsTheCoreMayMisorder() {
        // a word after a '-' that is neither the release itself nor after it: Maven and Composer may order it otherwise
        for v in ["33.7.2-jre", "31.1-jre", "2.0.0-incubating", "1.0.0-rc.1"] { #expect(core.versionUncertain(v), "\(v)") }
        for v in ["33.7.2", "2.4.6-p3", "1.0-SP1", "5.3.0-RELEASE", "1.2.3", "10.6p2", "1.0rc1", "7.1.1-41", "1.0+build-jre", ""] {
            #expect(!core.versionUncertain(v), "\(v)")
        }
    }

    @Test func privacyFilterMatchesBytesExactly() {
        let index = KeyList(["npm\u{1F}lodash", "PyPI\u{1F}urllib3", "project\u{1F}openssl"])
        let mask = core.select(inventory: ["npm\u{1F}lodash", "npm\u{1F}Lodash", "PyPI\u{1F}urllib3 ", "project\u{1F}openssl", "npm\u{1F}left-pad", ""], index: index)
        #expect(mask == [true, false, false, true, false, false])
        #expect(core.select(inventory: [], index: index) == [])
        #expect(core.select(inventory: ["npm\u{1F}lodash"], index: KeyList([])) == [false])
    }

    @Test func percentEncodingKeepsOnlyUnreservedBytes() {
        #expect(core.percentEncode("lodash") == "lodash")
        #expect(core.percentEncode("@babel/core") == "%40babel%2Fcore")
        #expect(core.percentEncode("a b?c#d:e") == "a%20b%3Fc%23d%3Ae")
        #expect(core.percentEncode("Az09-._~") == "Az09-._~")
        #expect(core.percentEncode("é") == "%C3%A9")
        #expect(core.percentEncode("") == "")
        #expect(core.percentEncode("../../etc") == "..%2F..%2Fetc")
    }

    @Test func encodeRefusesASmallBuffer() {
        var out = [UInt8](repeating: 0, count: 5)
        let input = Array("ab".utf8)
        #expect(osva_pct_encode(input, input.count, &out, out.count) == -1)
    }
}
