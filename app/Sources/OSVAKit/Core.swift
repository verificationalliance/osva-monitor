import Foundation
import OSVACore

/// The only door to the verified core (`Sources/OSVACore`, declared in `osva_core.h`): the app calls the core here and
/// nowhere else.
///
/// Four kinds of decision would mislead the person using OSVA Monitor if they were wrong: which of two versions is
/// newer, whether an installed version is affected by an advisory (and which upgrade clears it), which installed
/// packages may be named to the server, and how a name is written into a URL. The core makes them where this file's
/// callers ask it to:
///   - version order (`compareVersions` and the helpers built on it);
///   - whether a version is affected by an advisory in a project's or product's record, by the issuer's ranges
///     (`affectedness(installed:ranges:)`) or, for an advisory without ranges, by its first fixed versions
///     (`affectedness(installed:fixedVersions:)`), and the upgrade that lies in none of the ranges
///     (`upgrade(from:ranges:)`): AdvisoryCheck, for Homebrew, MacPorts, Nix and conda packages, apps and the
///     libraries they bundle, and Java runtimes, and IssueCheck, for the site's "patch these first" list;
///   - which installed packages, projects and products may be named to the server (`select`: PrivacyFilter), and
///     which extensions are on the malicious list (BundleCheck);
///   - every path component and query value of the URLs SiteURL builds (`percentEncode`).
///
/// The rest is not the core's:
///   - Packages checked by exact version (`api/v1/check/batch`: registry packages, project folders' lockfiles, the
///     Electron inside apps, the packages inside Go and Rust programs and pipx and uv tools) are flagged on the
///     server's verdict, and their upgrade is the server's `plan.target`, which the app checks only for reading as a
///     version (FixSafety). FixAdvisor's partial fixes are the server's plans too.
///   - Only `upgrade(from:ranges:)` is proved to leave every range it is given behind. Without ranges the upgrade is
///     the nearest first fixed version above the installed one (`nearestVersion`); AdvisoryCheck proposes the newest
///     of the two paths' upgrades (`newestVersion`), and JavaCheck, when there is none, the vendor's own fixed build.
///   - An advisory whose ranges cannot be read is taken as having none (`ProjectResponse.Advisory`), so its first
///     fixed versions decide.
///   - The names in the body of `api/v1/check/batch` are written by JSONEncoder; the core encodes only URLs.
///   - Which Python or Homebrew folder is newest is read by `localizedStandardCompare` (PythonSource,
///     HomebrewReceipts), and the release tool orders its own versions (OSVARelease's Appcast).
///
/// The core asks to be started once and called from one thread at a time, so this wrapper starts it when first used
/// and makes every call on one serial queue.
public final class Core: @unchecked Sendable {   // the only state is the serial queue every call goes through
    public static let shared = Core()

    private let queue = DispatchQueue(label: "org.verificationalliance.osva-monitor.verified-core")

    private init() {
        let status = queue.sync { osva_core_init() }
        precondition(status == 0, "The verified core did not start (osva_core_init returned \(status)).")
    }

    // MARK: Version order

    /// -1, 0 or 1 as `a` is older than, the same as, or newer than `b`, in the core's one version order.
    public func compareVersions(_ a: String, _ b: String) -> Int {
        let x = Array(a.utf8), y = Array(b.utf8)
        return queue.sync {
            withBytes(x) { px, nx in withBytes(y) { py, ny in Int(osva_vcmp(px, nx, py, ny)) } }
        }
    }

    /// The versions, oldest first.
    public func sortedVersions(_ versions: [String]) -> [String] {
        versions.sorted { compareVersions($0, $1) < 0 }
    }

    /// The newest of the versions, or nil if there are none.
    public func newestVersion(_ versions: [String]) -> String? {
        versions.dropFirst().reduce(versions.first) { best, v in
            guard let best else { return v }
            return compareVersions(v, best) > 0 ? v : best
        }
    }

    /// The oldest of the versions that are newer than `version`: the nearest upgrade among them.
    public func nearestVersion(in versions: [String], above version: String) -> String? {
        sortedVersions(versions.filter { compareVersions($0, version) > 0 }).first
    }

    // MARK: Affectedness

    public enum Affectedness: Sendable, Equatable {
        /// Some fixed version is above the installed one and its own branch has no fix at or below it.
        case affected
        case notAffected
        /// The issuer names no fixed version.
        case unknown
    }

    /// Is `installed` affected, given the first fixed version the issuer names for each release branch? For advisories
    /// that carry only these (`fixed_hint`); `affectedness(installed:ranges:)` decides when the issuer's ranges are known.
    public func affectedness(installed: String, fixedVersions: [String]) -> Affectedness {
        let version = Array(installed.utf8)
        let fixed = KeyList(fixedVersions)
        let answer = queue.sync {
            withBytes(version) { pv, nv in
                fixed.withPointers { pointers, lengths, count in osva_affected(pv, nv, pointers, lengths, count) }
            }
        }
        switch answer {
        case 1: return .affected
        case 0: return .notAffected
        default: return .unknown
        }
    }

    /// Is `installed` affected, given the issuer's affected ranges? Affected exactly when it lies in one of them
    /// (Ranges.lean: sound and complete); `.unknown` when there are none.
    public func affectedness(installed: String, ranges: [AffectedRange]) -> Affectedness {
        let version = Array(installed.utf8)
        let list = RangeList(ranges)
        let answer = queue.sync {
            withBytes(version) { pv, nv in list.withRanges { p, n in osva_affected_ranges(pv, nv, p, n) } }
        }
        switch answer {
        case 1: return .affected
        case 0: return .notAffected
        default: return .unknown
        }
    }

    /// The upgrade that leaves every range behind: the lowest fixed version of any of `ranges` that is above `installed`
    /// and lies in none of them (Ranges.lean `upgradeIn`). Give it the ranges of every advisory weighed together, so the
    /// upgrade never lands in a flaw that starts later. Nil when there is none.
    public func upgrade(from installed: String, ranges: [AffectedRange]) -> String? {
        let version = Array(installed.utf8)
        let list = RangeList(ranges)
        var output = [UInt8](repeating: 0, count: max(list.longestFixed, 1))
        let length = queue.sync {
            withBytes(version) { pv, nv in
                list.withRanges { p, n in output.withUnsafeMutableBufferPointer { o in osva_upgrade_ranges(pv, nv, p, n, o.baseAddress!, o.count) } }
            }
        }
        precondition(length >= -1, "The verified core refused the ranges (osva_upgrade_ranges returned \(length)).")
        return length < 0 ? nil : String(decoding: output.prefix(length), as: UTF8.self)
    }

    // MARK: Privacy filter

    /// For each inventory key, whether it equals some key of the public index byte for byte. Only keys answered
    /// `true` may be sent anywhere. Keys are `"<ecosystem>\u{1F}<name>"` (see `PackageNames`).
    public func select(inventory: [String], index: KeyList) -> [Bool] {
        let keys = KeyList(inventory)
        var mask = [UInt8](repeating: 0, count: max(keys.count, 1))
        let status = queue.sync {
            index.withPointers { ip, il, ni in
                keys.withPointers { kp, kl, nk in
                    mask.withUnsafeMutableBufferPointer { m in osva_select(ip, il, ni, kp, kl, nk, m.baseAddress!) }
                }
            }
        }
        precondition(status == 0, "The verified core refused the privacy filter's arguments.")
        return mask.prefix(keys.count).map { $0 == 1 }
    }

    // MARK: URL encoding

    /// One URL path component (or query value), percent-encoded: only `A-Z a-z 0-9 - . _ ~` and `%XX` remain.
    public func percentEncode(_ component: String) -> String {
        let input = Array(component.utf8)
        var output = [UInt8](repeating: 0, count: max(3 * input.count, 1))
        let length = queue.sync {
            withBytes(input) { p, n in
                output.withUnsafeMutableBufferPointer { o in osva_pct_encode(p, n, o.baseAddress!, o.count) }
            }
        }
        precondition(length >= 0, "The verified core refused to encode a URL component.")
        return String(decoding: output.prefix(length), as: UTF8.self)
    }
}

/// One affected range as the issuer publishes it (the API's `ranges`): from `introduced` (nil: the first version) up to
/// but not including `fixed`, or up to and including `lastAffected` (neither: every later version).
public struct AffectedRange: Codable, Sendable, Hashable {
    public var introduced: String?
    public var fixed: String?
    public var lastAffected: String?

    public init(introduced: String? = nil, fixed: String? = nil, lastAffected: String? = nil) {
        self.introduced = introduced; self.fixed = fixed; self.lastAffected = lastAffected
    }

    enum CodingKeys: String, CodingKey { case introduced, fixed, lastAffected = "last_affected" }
}

/// Ranges laid out the way osva_affected_ranges wants them: their bounds in one buffer, an osva_range per range pointing
/// into it, and NULL for an absent bound.
private struct RangeList {
    private var bytes: [UInt8] = []
    private var bounds: [[(offset: Int, length: Int)?]] = []

    init(_ ranges: [AffectedRange]) {
        for r in ranges {
            bounds.append([r.introduced, r.fixed, r.lastAffected].map { s in
                guard let s else { return nil }
                let start = bytes.count
                bytes.append(contentsOf: s.utf8)
                return (start, bytes.count - start)
            })
        }
    }

    var longestFixed: Int { bounds.compactMap { $0[1]?.length }.max() ?? 0 }

    func withRanges<R>(_ body: (UnsafePointer<osva_range>, Int) -> R) -> R {
        let storage = bytes.isEmpty ? [0] : bytes                 // a present bound is never a null pointer, even when empty
        return storage.withUnsafeBufferPointer { buffer in
            let base = buffer.baseAddress!
            func pointer(_ b: (offset: Int, length: Int)?) -> UnsafePointer<UInt8>? { b.map { base + $0.offset } }
            var ranges = bounds.map { b in
                osva_range(introduced: pointer(b[0]), introduced_len: b[0]?.length ?? 0, fixed: pointer(b[1]), fixed_len: b[1]?.length ?? 0,
                           last_affected: pointer(b[2]), last_affected_len: b[2]?.length ?? 0)
            }
            let count = ranges.count
            if ranges.isEmpty { ranges = [osva_range()] }        // never hand the core a null base pointer
            return ranges.withUnsafeBufferPointer { body($0.baseAddress!, count) }
        }
    }
}

/// Byte strings laid out the way the core's list arguments want them: one buffer, a pointer and a length per string.
public struct KeyList: Sendable {
    private let bytes: [UInt8]
    private let offsets: [Int]
    private let lengths: [Int]

    public init(_ strings: [String]) {
        var bytes: [UInt8] = []
        var offsets: [Int] = [], lengths: [Int] = []
        offsets.reserveCapacity(strings.count); lengths.reserveCapacity(strings.count)
        for s in strings {
            offsets.append(bytes.count)
            bytes.append(contentsOf: s.utf8)
            lengths.append(bytes.count - offsets[offsets.count - 1])
        }
        self.bytes = bytes; self.offsets = offsets; self.lengths = lengths
    }

    /// Keys already laid out (the index reader builds them straight from the downloaded bytes).
    init(bytes: [UInt8], offsets: [Int], lengths: [Int]) {
        precondition(offsets.count == lengths.count)
        self.bytes = bytes; self.offsets = offsets; self.lengths = lengths
    }

    /// These keys followed by more.
    func appending(_ strings: [String]) -> KeyList {
        var bytes = self.bytes, offsets = self.offsets, lengths = self.lengths
        for s in strings {
            offsets.append(bytes.count)
            bytes.append(contentsOf: s.utf8)
            lengths.append(bytes.count - offsets[offsets.count - 1])
        }
        return KeyList(bytes: bytes, offsets: offsets, lengths: lengths)
    }

    public var count: Int { offsets.count }

    func withPointers<R>(_ body: (UnsafePointer<UnsafePointer<UInt8>?>, UnsafePointer<Int>, Int) -> R) -> R {
        let storage = bytes.isEmpty ? [0] : bytes                 // never hand the core a null base pointer
        return storage.withUnsafeBufferPointer { buffer in
            let base = buffer.baseAddress!
            let pointers: [UnsafePointer<UInt8>?] = offsets.isEmpty ? [base] : offsets.map { base + $0 }
            let sizes = lengths.isEmpty ? [0] : lengths
            return pointers.withUnsafeBufferPointer { p in
                sizes.withUnsafeBufferPointer { l in body(p.baseAddress!, l.baseAddress!, count) }
            }
        }
    }
}

private func withBytes<R>(_ bytes: [UInt8], _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
    let storage = bytes.isEmpty ? [0] : bytes                     // never hand the core a null pointer
    return storage.withUnsafeBufferPointer { body($0.baseAddress!, bytes.count) }
}
