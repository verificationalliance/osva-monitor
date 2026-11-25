import Foundation
import Testing
import OSVACore
@testable import OSVAKit
@testable import OSVAVerified

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
    }

    @Test("first fixed versions, per release branch", arguments: [
        // nginx names a fix per branch
        ("1.30.2", ["1.31.9", "1.30.7"], Core.Verdict.likely),
        ("1.30.7", ["1.31.9", "1.30.7"], .clear),             // at its branch's fix
        ("1.30.9", ["1.31.9", "1.30.7"], .clear),             // past its branch's fix
        ("1.31.0", ["1.31.9", "1.30.7"], .likely),
        ("1.29.0", ["1.31.9", "1.30.7"], .likely),            // a branch with no fix, below a fix
        ("1.32.0", ["1.31.9", "1.30.7"], .clear),             // at or above every fix
        // OpenSSL: three branches
        ("3.5.9", ["4.1.1", "4.0.4", "3.5.10"], .likely),
        ("3.5.10", ["4.1.1", "4.0.4", "3.5.10"], .clear),
        ("4.0.4", ["4.1.1", "4.0.4", "3.5.10"], .clear),
        // OpenSSH's portable releases
        ("10.6p1", ["10.6p2"], .likely),
        ("10.6p2", ["10.6p2"], .clear),
        ("9.9", [], .unstated),                               // nothing stated: never read as clear
    ])
    func firstFixed(_ installed: String, _ fixed: [String], _ expected: Core.Verdict) {
        #expect(core.verdicts(installed: installed, advisories: [CoreAdvisory(ranges: nil, fixed: fixed)]) == [expected])
    }

    @Test func aLikelyVersionAlwaysHasAFixAboveIt() {
        // Theorem 1 of Affected.lean, on a sample: whenever the first fixed versions say likely, one of them is newer.
        let versions = ["0.1", "1.29.9", "1.30.6", "1.30.8", "1.31.10", "3.4.0", "3.5.11", "4.0.0", "9.9p1", "10.0", "10.6", "1.0rc1", "2.0", "5"]
        for f in Self.firstFixedSets {
            for v in versions where core.verdicts(installed: v, advisories: [CoreAdvisory(ranges: nil, fixed: f)]) == [.likely] {
                #expect(f.contains { core.compareVersions($0, v) > 0 }, "\(v) with \(f)")
            }
        }
    }

    // MARK: Advisories: verdicts, upgrades, judgements (Decide.lean)

    /// PostgreSQL's advisory with its five published ranges, and advisories that name only first fixed versions.
    let pg = CoreAdvisory(ranges: RangesTests.pg, fixed: [])
    let ff1620 = CoreAdvisory(ranges: nil, fixed: ["16.20"])
    let ff10 = CoreAdvisory(ranges: nil, fixed: ["1.0"])
    let nginx = CoreAdvisory(ranges: nil, fixed: ["1.30.7", "1.31.9"])

    /// First fixed versions per release branch, the sample of `aLikelyVersionAlwaysHasAFixAboveIt`.
    static let firstFixedSets = [["1.31.9", "1.30.7"], ["4.1.1", "4.0.4", "3.5.10"], ["2.0"], ["10.6p2", "9.9p3"]]

    @Test func verdictsReadRangesThenFirstFixedVersions() {
        #expect(core.verdicts(installed: "16.14", advisories: [pg, nginx]) == [.inRange, .clear])
        #expect(core.verdicts(installed: "1.31.5", advisories: [nginx]) == [.likely])
        #expect(core.verdicts(installed: "1.0", advisories: [CoreAdvisory(ranges: [], fixed: ["2.0"])]) == [.likely])   // [] reads as no ranges
        #expect(core.verdicts(installed: "16.16", advisories: [CoreAdvisory(ranges: RangesTests.pg, fixed: ["99"])]) == [.clear])  // ranges decide
        #expect(core.verdicts(installed: "1.0", advisories: []) == [])
        // each advisory reads its own first fixed versions, not the ones before it
        #expect(core.verdicts(installed: "1.31.5", advisories: [ff10, nginx]) == [.clear, .likely])
        #expect(core.verdicts(installed: "1.31.5", advisories: [nginx, ff10]) == [.likely, .clear])
    }

    @Test func theCoresUpgradeLeavesEveryAdvisory() throws {
        let up = try #require(found(core.upgrade(from: "16.14", advisories: [pg, ff1620])))
        #expect(up.version == "16.20" && up.display == "16.20")
        #expect(up.fixes == [true, true] && up.fixCount == 2)                     // both flag 16.14, and 16.20 leaves both
        #expect(core.upgrade(from: "2.0", advisories: [CoreAdvisory(ranges: [AffectedRange(introduced: "1.5")], fixed: [])]) == .noUpgrade)
        #expect(core.upgrade(from: "1.0", advisories: []) == .noUpgrade)
        // each advisory's first fixed versions are its own
        let nginxUp = try #require(found(core.upgrade(from: "1.31.5", advisories: [ff10, nginx])))
        #expect(nginxUp.version == "1.31.9" && nginxUp.fixes == [false, true])   // 1.0 never flagged 1.31.5
        #expect(found(core.upgrade(from: "1.30.2", advisories: [ff10, nginx]))?.version == "1.30.7")
    }

    @Test func judgeSaysWhichAdvisoriesAnUpgradeLeaves() throws {
        let both = try #require(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [true, true]))
        #expect(both.leaves == [true, false] && both.upgrade?.version == "16.15")
        #expect(both.upgrade?.fixes == [true, false] && both.upgrade?.fixCount == 1)    // "fixes 1", from the core
        #expect(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [false, true])?.upgrade == nil)
        #expect(core.judge("16.15", from: "16.14", advisories: [pg, ff1620], flagged: [false, false])?.upgrade == nil)
        #expect(core.judge("16.14", from: "16.14", advisories: [pg, ff1620], flagged: [true, true]) == nil)     // not above
        #expect(core.judge("16.13", from: "16.14", advisories: [pg], flagged: [true]) == nil)
        let none = try #require(core.judge("2.0", from: "1.0", advisories: [], flagged: []))           // above, nothing to leave
        #expect(none.leaves == [] && none.upgrade == nil)
        #expect(core.judge("1.0", from: "1.0", advisories: [], flagged: []) == nil)
    }

    @Test func aCheckedUpgradeIsShownOnlyInTheWaysCoreSwiftKnows() throws {
        let java = CoreAdvisory(ranges: [AffectedRange(introduced: "8", lastAffected: "8.0.511")], fixed: [])
        let up = try #require(core.judge("8.0.512", from: "8.0.511", advisories: [java], flagged: [true])?.upgrade)
        #expect(up.version == "8.0.512" && up.display == "8.0.512")
        let shown = up.displayed(.java)
        #expect(shown.version == "8.0.512" && shown.display == "8u512" && shown.fixes == up.fixes)
        #expect(shown.displayed(.asChecked) == up)
    }

    @Test func anAdvisoryThatStatesNothingIsUnstated() throws {
        // neither usable ranges nor first fixed versions: reported, never clear, and no version is said to fix it
        let silent = CoreAdvisory(ranges: nil, fixed: []), empty = CoreAdvisory(ranges: [], fixed: [])
        #expect(core.verdicts(installed: "1.0", advisories: [silent, empty, ff10]) == [.unstated, .unstated, .clear])
        let j = try #require(core.judge("2.0", from: "1.0", advisories: [silent, nginx], flagged: [true, false]))
        #expect(j.leaves == [false, true] && j.upgrade == nil)
        #expect(found(core.upgrade(from: "1.31.5", advisories: [nginx]))?.version == "1.31.9")
    }

    @Test func theUpgradeLeavesOutAnAdvisoryThatStatesNothing() throws {
        // one silent advisory must not block every upgrade: upgrade leaves it out, and it is never among the fixes
        let silent = CoreAdvisory(ranges: nil, fixed: []), empty = CoreAdvisory(ranges: [], fixed: [])
        let up = try #require(found(core.upgrade(from: "1.31.5", advisories: [nginx, silent])))
        #expect(up.version == "1.31.9" && up.fixes == [true, false] && up.fixCount == 1)
        let mixed = try #require(found(core.upgrade(from: "16.14", advisories: [silent, pg, empty, ff1620])))
        #expect(mixed.version == "16.20" && mixed.fixes == [false, true, false, true])
        #expect(core.upgrade(from: "1.0", advisories: [silent, empty]) == .noUpgrade)
        // judge already says so: a silent advisory is never left
        #expect(core.judge("1.31.9", from: "1.31.5", advisories: [nginx, silent], flagged: [true, true])?.leaves == [true, false])
    }

    @Test func theUpgradeRefusesMoreWorkThanItsLimit() {
        // osva_upgrade_for checks every candidate above the installed version against every version string the advisories
        // are decided by, reading both: past the limit it is not asked
        let a = CoreAdvisory(ranges: [AffectedRange(introduced: "1", fixed: "2"), AffectedRange(introduced: "3")], fixed: ["4", "5"])
        #expect(core.upgradeWork(from: "0", [a]) == 3 * 3 + 3 * 3 + 8 * 3 * 3)       // candidates 2, 4, 5; bounds 1, 2, 3
        #expect(core.upgradeWork(from: "4", [a]) == 1 * 3 + 1 * 3 + 8 * 1 * 3)       // only 5 is above 4
        // first fixed versions count twice: the core reads each of them twice (Affected.lean's `affected`: a fix above,
        // then one on the same branch), and was measured at 78-86 ns a unit for them against 37-59 for ranges
        #expect(core.upgradeWork(from: "0", [CoreAdvisory(ranges: nil, fixed: ["10", "20"])]) == 2 * (2 * 4 + 4 * 2 + 8 * 2 * 2))
        #expect(core.upgradeWork(from: "0", [CoreAdvisory(ranges: [], fixed: ["10", "20"])]) == 2 * (2 * 4 + 4 * 2 + 8 * 2 * 2))   // [] reads as none
        // only the strings of the advisory without ranges count twice: candidates 2, 10, 20; strings 2 (ranged), then 10, 20 twice
        let both = [CoreAdvisory(ranges: [AffectedRange(fixed: "2")], fixed: []), CoreAdvisory(ranges: nil, fixed: ["10", "20"])]
        #expect(core.upgradeWork(from: "0", both) == 3 * (1 + 8 * 1 + 2 * 4 + 8 * 2 * 2) + 5 * (1 + 2 * 2))
        #expect(core.upgradeWork(from: "0", [CoreAdvisory(ranges: [AffectedRange()], fixed: ["7"])]) == 1 * 0 + 1 * 1 + 8 * 1 * 1)
        #expect(core.upgradeWork(from: "0", []) == 0 && core.upgradeWork(from: "0", [CoreAdvisory(ranges: nil, fixed: [])]) == 0)
        let one = CoreAdvisory(ranges: [AffectedRange(fixed: "2.0")], fixed: [])     // n of these: n candidates, n bounds
        func work(_ n: Int) -> Int { core.upgradeWork(from: "1.0", Array(repeating: one, count: n)) }
        #expect(work(10) == 3 * 10 * 10 + 3 * 10 * 10 + 8 * 10 * 10)
        var n = Int((Double(Core.upgradeWorkLimit) / 14).squareRoot())
        while work(n + 1) <= Core.upgradeWorkLimit { n += 1 }
        while work(n) > Core.upgradeWorkLimit { n -= 1 }
        #expect(found(core.upgrade(from: "1.0", advisories: Array(repeating: one, count: n)))?.version == "2.0")
        #expect(core.upgrade(from: "1.0", advisories: Array(repeating: one, count: n + 1)) == .refused)
        #expect(core.upgrade(from: "2.0", advisories: Array(repeating: one, count: n + 1)) == .noUpgrade)   // nothing above 2.0
    }

    @Test func verdictsAgreeWithTheReferenceOnASample() {
        // Decide.lean's theorems, on RangesTests' sample and first fixed versions, with the wrapper's own comparisons
        // as the reference, and Affected.lean's rule written again here
        let firstFixed = Self.firstFixedSets.map { CoreAdvisory(ranges: nil, fixed: $0) }
        let versions = RangesTests.sampleVersions + ["1.29.9", "1.30.7", "1.31.5", "1.31.9", "3.5.9", "4.0.4", "9.9p1", "10.6", "5"]
        func reference(_ a: CoreAdvisory, _ v: String) -> Core.Verdict {
            if let rs = a.ranges { return rs.contains { RangesTests.holds($0, v) } ? .inRange : .clear }
            return Self.firstFixedSaysAffected(v, a.fixed) ? .likely : .clear
        }
        for rs in RangesTests.sampleSets {
            let whole = [CoreAdvisory(ranges: rs, fixed: [])], split = rs.map { CoreAdvisory(ranges: [$0], fixed: []) }
            for advisories in [whole, split, whole + firstFixed, firstFixed + split] {
                for v in versions {
                    #expect(core.verdicts(installed: v, advisories: advisories) == advisories.map { reference($0, v) }, "\(v) in \(advisories)")
                    guard let u = found(core.upgrade(from: v, advisories: advisories)) else { continue }
                    #expect(core.compareVersions(v, u.version) < 0, "\(v) → \(u.version)")
                    #expect(advisories.allSatisfy { reference($0, u.version) == .clear }, "\(v) → \(u.version) in \(advisories)")
                    #expect(u.fixes == advisories.map { reference($0, v) != .clear })
                    let all = [Bool](repeating: true, count: advisories.count)
                    #expect(core.judge(u.version, from: v, advisories: advisories, flagged: all)?.leaves == all)
                }
            }
        }
    }

    /// Affected.lean's rule, written again with the wrapper's comparisons: some first fixed version is above `v`, and none
    /// on `v`'s branch is at or below it. A branch is a version's first two numbers before any word ("10.6p2" is 10.6,
    /// "1.0rc1" is 1.0, "2" is 2.0), after a leading "v" and before a "+".
    static func firstFixedSaysAffected(_ v: String, _ fixed: [String]) -> Bool {
        let core = Core.shared
        func branch(_ s: String) -> [Int] {
            var t = Substring(s.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            if t.first == "v" || t.first == "V", t.dropFirst().first?.isNumber == true { t = t.dropFirst() }
            var numbers: [Int] = [], digits = ""
            for c in t + "." {
                if c.isASCII && c.isNumber { digits.append(c); continue }
                if !digits.isEmpty { numbers.append(Int(digits.drop { $0 == "0" }.prefix(18)) ?? 0); digits = "" }
                if c.isLetter { break }
            }
            return Array((numbers + [0, 0]).prefix(2))
        }
        return fixed.contains { core.compareVersions(v, $0) < 0 }
            && !fixed.contains { core.compareVersions(v, $0) >= 0 && branch(v) == branch($0) }
    }

    @Test func versionUncertainNamesVersionsTheCoreMayMisorder() {
        // a word after a '-' that is neither the release itself nor after it: Maven and Composer may order it otherwise
        for v in ["33.7.2-jre", "31.1-jre", "2.0.0-incubating", "1.0.0-rc.1"] { #expect(core.versionUncertain(v), "\(v)") }
        for v in ["33.7.2", "2.4.6-p3", "1.0-SP1", "5.3.0-RELEASE", "1.2.3", "10.6p2", "1.0rc1", "7.1.1-41", "1.0+build-jre", ""] {
            #expect(!core.versionUncertain(v), "\(v)")
        }
    }

    /// The upgrade, when the core found one. A switch, so that a refusal is never read as "no upgrade" unseen.
    func found(_ answer: Core.UpgradeAnswer) -> CheckedUpgrade? {
        switch answer {
        case let .upgrade(u): return u
        case .noUpgrade, .refused: return nil
        }
    }

    @Test func privacyFilterMatchesBytesExactly() {
        let index = KeyList(["npm\u{1F}lodash", "PyPI\u{1F}urllib3", "project\u{1F}openssl"])
        let mask = core.select(inventory: ["npm\u{1F}lodash", "npm\u{1F}Lodash", "PyPI\u{1F}urllib3 ", "project\u{1F}openssl", "npm\u{1F}left-pad", ""], index: index)
        #expect(mask == [true, false, false, true, false, false])
        #expect(core.select(inventory: [], index: index) == [])
        #expect(core.select(inventory: ["npm\u{1F}lodash"], index: KeyList([])) == [false])
    }

    /// Keys laid out by hand (as the index reader does) are used as laid out, up to the last byte; a key that reaches
    /// past the bytes, or starts before them, stops the process at the KeyList, before the core could read past them.
    @Test func keysLaidOutByHandStayInsideTheirBytes() async {
        let bytes = Array("npm\u{1F}lodashPyPI\u{1F}urllib3".utf8)
        let index = KeyList(bytes: bytes, offsets: [0, 10, bytes.count], lengths: [10, 12, 0])
        #expect(core.select(inventory: ["npm\u{1F}lodash", "PyPI\u{1F}urllib3", "", "npm\u{1F}lodas"], index: index) == [true, true, true, false])
        await #expect(processExitsWith: .failure) { _ = KeyList(bytes: [1, 2, 3], offsets: [2], lengths: [2]) }
        await #expect(processExitsWith: .failure) { _ = KeyList(bytes: [1, 2, 3], offsets: [4], lengths: [0]) }
        await #expect(processExitsWith: .failure) { _ = KeyList(bytes: [1, 2, 3], offsets: [-1], lengths: [1]) }
        await #expect(processExitsWith: .failure) { _ = KeyList(bytes: [1, 2, 3], offsets: [1], lengths: [Int.max]) }
        await #expect(processExitsWith: .failure) { _ = KeyList(bytes: [1, 2, 3], offsets: [0, 1], lengths: [1]) }
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
