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
/// For one package's advisories at a time, the core also decides what each says about a version (`verdicts`: inside a
/// published range, likely affected by its first fixed versions, or neither), the upgrade that leaves every one of them
/// (`upgrade(from:advisories:)`), and which of them an upgrade it did not pick leaves (`judge`). Only these make a
/// `CheckedUpgrade`. `versionUncertain` names the versions whose order Maven or Composer may not share. The scan and fix
/// paths do not ask them yet: until they do, the paths below decide as they say.
///
/// The rest is not the core's:
///   - Packages checked by exact version (`api/v1/check/batch`: registry packages, project folders' lockfiles, the
///     Electron inside apps, the packages inside Go and Rust programs and pipx and uv tools) are flagged on the
///     server's verdict, and their upgrade is the server's `plan.target`, which the app checks only for reading as a
///     version (FixSafety). FixAdvisor's partial fixes are the server's plans too.
///   - Only `upgrade(from:ranges:)` is proved to leave every range it is given behind. Without ranges the upgrade is
///     the nearest first fixed version above the installed one (`nearestVersion`); AdvisoryCheck proposes the newest
///     of the two paths' upgrades (`newestVersion`), and JavaCheck, when there is none, the vendor's own fixed build.
///   - An advisory whose ranges cannot be read is taken as having none (`ProjectResponse.Advisory`, which marks it
///     `rangesUnreadable`), so its first fixed versions decide.
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

    /// Whether the core's version order may not be the ecosystem's for `version`: it has a word right after a '-' that
    /// is neither the release itself (ga, final, release) nor after it (p, patch, pl, sp, r, post, rev), such as Maven's
    /// "33.7.2-jre" or "1.0.0-rc.1". Maven and Composer may order such a version otherwise than the core does, so the
    /// app does not decide their advisories by it (Version.lean `versionUncertain`).
    public func versionUncertain(_ version: String) -> Bool {
        let bytes = Array(version.utf8)
        let answer = queue.sync { withBytes(bytes) { p, n in osva_version_uncertain(p, n) } }
        precondition(answer >= 0, "The verified core refused a version (osva_version_uncertain returned \(answer)).")
        return answer == 1
    }

    // MARK: Advisories, and the upgrades that leave them (Decide.lean)

    /// What one advisory says about an installed version (osva_verdicts).
    public enum Verdict: UInt8, Sendable {
        /// Not inside a published range, or not affected by the first fixed versions. Never evidence of a fix: an
        /// advisory that states neither is `.clear` for every version. Ask `judge` whether a version fixes it.
        case clear = 0
        /// Inside one of the advisory's published ranges (`verdict_inRange_sound`, `verdict_inRange_complete`).
        case inRange = 1
        /// The advisory publishes no ranges (nil or []), and its first fixed versions say the version is affected.
        case likely = 2
    }

    /// The most advisories `upgrade(from:advisories:)` asks the core about at once. osva_upgrade_for checks every
    /// candidate against every advisory, so its cost grows with the square of their number (seconds at 1,000). One
    /// package's advisories fit; more are refused, and their caller reports them as not checked.
    public static let upgradeAdvisoryLimit = 200

    /// One verdict per advisory, in order: ranges decide when an advisory has them, its first fixed versions otherwise.
    public func verdicts(installed: String, advisories: [CoreAdvisory]) -> [Verdict] {
        let version = Array(installed.utf8)
        let list = AdvisoryList(advisories)
        var out = [UInt8](repeating: 0, count: max(advisories.count, 1))
        let status = queue.sync {
            withBytes(version) { pv, nv in
                list.withAdvisories { a, n in out.withUnsafeMutableBufferPointer { o in osva_verdicts(pv, nv, a, n, o.baseAddress!) } }
            }
        }
        precondition(status == 0, "The verified core refused the advisories (osva_verdicts returned \(status)).")
        return out.prefix(advisories.count).map { byte in
            guard let verdict = Verdict(rawValue: byte) else { preconditionFailure("osva_verdicts wrote \(byte), not 0, 1 or 2.") }
            return verdict
        }
    }

    /// The upgrade the app suggests: the lowest release the advisories name as fixed (in their ranges, or as first
    /// fixed versions) that is above `installed` and clear of every one of them, with evidence (Decide.lean
    /// `upgradeFor_leaves`, `upgradeFor_nearest`). An advisory that states neither ranges nor fixed versions is clear of
    /// no version, so given one there is none. Nil when there is none, or when there are more than
    /// `upgradeAdvisoryLimit` advisories.
    public func upgrade(from installed: String, advisories: [CoreAdvisory]) -> CheckedUpgrade? {
        guard advisories.count <= Self.upgradeAdvisoryLimit else { return nil }
        let version = Array(installed.utf8)
        let list = AdvisoryList(advisories)
        var output = [UInt8](repeating: 0, count: max(list.longestFixed, 1))
        let length = queue.sync {
            withBytes(version) { pv, nv in
                list.withAdvisories { a, n in
                    output.withUnsafeMutableBufferPointer { o in osva_upgrade_for(pv, nv, a, n, o.baseAddress!, o.count) }
                }
            }
        }
        precondition(length >= -1, "The verified core refused the advisories (osva_upgrade_for returned \(length)).")
        return length < 0 ? nil : CheckedUpgrade(String(decoding: output.prefix(length), as: UTF8.self))
    }

    /// Checks an upgrade the core did not pick (the server's target, a vendor's build, pip's choice): for each
    /// advisory, whether `candidate` is clear of it, with evidence (Decide.lean `judge_spec`). Nil when `candidate` is
    /// not above `installed`. The judgement's upgrade is `candidate` only if it leaves at least one of the advisories
    /// `flagged` names (by index).
    public func judge(_ candidate: String, from installed: String, advisories: [CoreAdvisory], flagged: Set<Int>) -> Judgement? {
        let version = Array(installed.utf8), upgrade = Array(candidate.utf8)
        let list = AdvisoryList(advisories)
        var out = [UInt8](repeating: 0, count: max(advisories.count, 1))
        let status = queue.sync {
            withBytes(version) { pv, nv in
                withBytes(upgrade) { pu, nu in
                    list.withAdvisories { a, n in out.withUnsafeMutableBufferPointer { o in osva_judge(pv, nv, pu, nu, a, n, o.baseAddress!) } }
                }
            }
        }
        precondition(status == 0 || status == 1, "The verified core refused the advisories (osva_judge returned \(status)).")
        guard status == 1 else { return nil }
        let leaves = out.prefix(advisories.count).map { $0 == 1 }
        let fixesAFlagged = flagged.contains { leaves.indices.contains($0) && leaves[$0] }
        return Judgement(leaves: leaves, upgrade: fixesAFlagged ? CheckedUpgrade(candidate) : nil)
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
///
/// Read strictly, since a bound read wrongly widens the range: a range with any key but `introduced`, `fixed` and
/// `last_affected`, or a bound that is not a string (null included), does not decode. `{}` is every version.
public struct AffectedRange: Codable, Sendable, Hashable {
    public var introduced: String?
    public var fixed: String?
    public var lastAffected: String?

    public init(introduced: String? = nil, fixed: String? = nil, lastAffected: String? = nil) {
        self.introduced = introduced; self.fixed = fixed; self.lastAffected = lastAffected
    }

    enum CodingKeys: String, CodingKey { case introduced, fixed, lastAffected = "last_affected" }

    public init(from decoder: Decoder) throws {
        let any = try decoder.container(keyedBy: AnyKey.self)
        if let other = any.allKeys.first(where: { CodingKeys(stringValue: $0.stringValue) == nil }) {
            throw DecodingError.dataCorruptedError(forKey: other, in: any, debugDescription: "An affected range has no bound named \(other.stringValue).")
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func bound(_ key: CodingKeys) throws -> String? {
            guard c.contains(key) else { return nil }
            return try c.decode(String.self, forKey: key)                  // a null or a number throws
        }
        introduced = try bound(.introduced); fixed = try bound(.fixed); lastAffected = try bound(.lastAffected)
    }

    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    /// An advisory's or flaw's `ranges`, as the API sends them or the cache kept them: absent or null is nil; a list
    /// that reads strictly is kept; anything else is nil and unreadable, never a wider range. `unreadableKey` is where
    /// the cache's copy says it was unreadable.
    static func read<K: CodingKey>(_ c: KeyedDecodingContainer<K>, _ key: K, unreadableKey: K) -> (ranges: [AffectedRange]?, unreadable: Bool) {
        if (try? c.decodeIfPresent(Bool.self, forKey: unreadableKey)) == true { return (nil, true) }
        guard c.contains(key), (try? c.decodeNil(forKey: key)) != true else { return (nil, false) }
        guard let ranges = try? c.decode([AffectedRange].self, forKey: key) else { return (nil, true) }
        return (ranges, false)
    }
}

/// One advisory as the core weighs it: the ranges the site publishes for it (nil: none it can read; [] reads the same),
/// and the first fixed versions its issuer names, which decide only without ranges.
public struct CoreAdvisory: Sendable, Hashable {
    public var ranges: [AffectedRange]?
    public var fixed: [String]

    public init(ranges: [AffectedRange]?, fixed: [String]) { self.ranges = ranges; self.fixed = fixed }
}

/// A version the core has checked as an upgrade: `Core.upgrade(from:advisories:)` picked it, or `Core.judge` found it
/// above the installed version and clear of an advisory the app flags. Only Core.swift can make one, so a version the
/// app suggests can only come from the core.
public struct CheckedUpgrade: Sendable, Hashable {
    /// The version, as the core checked it.
    public let version: String
    /// How the app shows it (Java's "8u511" for 8.0.511); `version` unless `displayed` says otherwise.
    public let display: String

    fileprivate init(_ version: String) { self.version = version; self.display = version }
    private init(version: String, display: String) { self.version = version; self.display = display }

    /// The same checked version, shown as `shown` writes it.
    public func displayed(_ shown: (String) -> String) -> CheckedUpgrade { CheckedUpgrade(version: version, display: shown(version)) }
}

/// The core's answer about a candidate upgrade above the installed version.
public struct Judgement: Sendable, Equatable {
    /// One per advisory, in order: whether the candidate is clear of it, with evidence.
    public let leaves: [Bool]
    /// The candidate, when it leaves at least one flagged advisory; nil when it leaves none of them.
    public let upgrade: CheckedUpgrade?

    fileprivate init(leaves: [Bool], upgrade: CheckedUpgrade?) { self.leaves = leaves; self.upgrade = upgrade }
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

/// Advisories laid out the way osva_verdicts, osva_upgrade_for and osva_judge want them, as RangeList lays out ranges:
/// every bound and fixed version in one buffer, then one array of osva_range, one of fixed-version pointers and one of
/// their lengths, each advisory's osva_advisory pointing at its own run of them. NULL only for an absent bound.
private struct AdvisoryList {
    private typealias Span = (offset: Int, length: Int)
    private var bytes: [UInt8] = []
    private var bounds: [[Span?]] = []                         // per range: introduced, fixed, last_affected
    private var fixed: [Span] = []                              // per first fixed version
    private var entries: [(hasRanges: Bool, ranges: Range<Int>, fixed: Range<Int>)] = []

    init(_ advisories: [CoreAdvisory]) {
        func span(_ s: String) -> Span {
            let start = bytes.count
            bytes.append(contentsOf: s.utf8)
            return (start, bytes.count - start)
        }
        for a in advisories {
            let firstRange = bounds.count, firstFixed = fixed.count
            for r in a.ranges ?? [] { bounds.append([r.introduced, r.fixed, r.lastAffected].map { $0.map(span) }) }
            for f in a.fixed { fixed.append(span(f)) }
            entries.append((a.ranges != nil, firstRange..<bounds.count, firstFixed..<fixed.count))
        }
    }

    /// The longest version osva_upgrade_for may write: every candidate is a range's fixed bound or a first fixed version.
    var longestFixed: Int { (bounds.compactMap { $0[1]?.length } + fixed.map(\.length)).max() ?? 0 }

    func withAdvisories<R>(_ body: (UnsafePointer<osva_advisory>, Int) -> R) -> R {
        let storage = bytes.isEmpty ? [0] : bytes                 // a present bound is never a null pointer, even when empty
        return storage.withUnsafeBufferPointer { buffer in
            let base = buffer.baseAddress!
            func pointer(_ b: Span?) -> UnsafePointer<UInt8>? { b.map { base + $0.offset } }
            var ranges = bounds.map { b in
                osva_range(introduced: pointer(b[0]), introduced_len: b[0]?.length ?? 0, fixed: pointer(b[1]), fixed_len: b[1]?.length ?? 0,
                           last_affected: pointer(b[2]), last_affected_len: b[2]?.length ?? 0)
            }
            if ranges.isEmpty { ranges = [osva_range()] }        // never hand the core a null base pointer
            var pointers: [UnsafePointer<UInt8>?] = fixed.map { base + $0.offset }, lengths = fixed.map(\.length)
            if pointers.isEmpty { pointers = [base]; lengths = [0] }
            return ranges.withUnsafeBufferPointer { r in
                pointers.withUnsafeBufferPointer { p in
                    lengths.withUnsafeBufferPointer { l in
                        var advisories = entries.map { e in
                            osva_advisory(has_ranges: e.hasRanges ? 1 : 0, ranges: r.baseAddress! + e.ranges.lowerBound, n_ranges: e.ranges.count,
                                          fixed: p.baseAddress! + e.fixed.lowerBound, fixed_len: l.baseAddress! + e.fixed.lowerBound,
                                          n_fixed: e.fixed.count)
                        }
                        let count = advisories.count
                        if advisories.isEmpty { advisories = [osva_advisory()] }
                        return advisories.withUnsafeBufferPointer { body($0.baseAddress!, count) }
                    }
                }
            }
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
