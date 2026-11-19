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
