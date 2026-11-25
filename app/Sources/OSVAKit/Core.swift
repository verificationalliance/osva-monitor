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
///   - whether a version is affected by an advisory, and which upgrade leaves it (below);
///   - which installed packages, projects and products may be named to the server (`select`: PrivacyFilter), and
///     which extensions are on the malicious list (BundleCheck);
///   - every path component and query value of the URLs SiteURL builds (`percentEncode`).
///
/// For one package's advisories at a time, the core also decides what each says about a version (`verdicts`: inside a
/// published range, likely affected by its first fixed versions, or outside with evidence; this wrapper marks
/// `.unstated` an advisory that states nothing to decide by, which is "reported, not checked"), the upgrade that leaves
/// every one of them that states something (`upgrade(from:advisories:)`, refused past a measured amount of work), and
/// which of them an upgrade it did not pick leaves (`judge`). Only these make a `CheckedUpgrade` or a `Judgement`.
/// `versionUncertain` names the versions whose order Maven or Composer may not share. Packages checked by exact version
/// (`api/v1/check/batch`: registry packages, project folders' lockfiles, the Electron inside apps, the packages inside
/// Go and Rust programs and pipx and uv tools) ask them (BatchCheck): a flaw is affected only inside its published
/// ranges, and the server's `plan.target` is shown only when `judge` confirms it. So do the advisories of a project's or
/// product's record (AdvisoryCheck: Homebrew, MacPorts, Nix and conda packages, apps and the libraries they bundle, Java
/// runtimes) and the site's "patch these first" list (IssueCheck): an advisory is affected only inside its published
/// ranges, likely affected by its first fixed versions without them, reported when they cannot be read, and the
/// upgrade is `upgrade(from:advisories:)`'s; a Java vendor's own build is named only when `judge` confirms it. So do the
/// fix paths: a partial fix's version is proposed only when `judge` confirms it (FixAdvisor), pip's version in an upgrade
/// together must leave every advisory the fix leaves (PipSetGuard), and every command's version is a `CheckedUpgrade`
/// (UpgradeCommand.Inputs). A command that names none is a removal, Homebrew's own upgrade, or a program's or tool's
/// rebuild, never while its own part is flagged with no checked upgrade (ProgramFindings).
///
/// The rest is not the core's:
///   - Which version a package manager installs for a command that names none (`brew upgrade`, a rebuild), or within a
///     range it is given (`npm install x@^1.2.3`, `poetry add 'x>=1.2.3'`).
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

    /// Whether the core's version order may not be the ecosystem's for `version`: it has a word right after a '-' that
    /// is neither the release itself (ga, final, release) nor after it (p, patch, pl, sp, r, post, rev), such as Maven's
    /// "33.7.2-jre" or "1.0.0-rc.1". Maven and Composer may order such a version otherwise than the core does, so the
    /// app does not decide their advisories by it (Version.lean `versionUncertain`).
    public func versionUncertain(_ version: String) -> Bool {
        let bytes = Array(version.utf8)
        let answer = queue.sync { withBytes(bytes) { p, n in osva_version_uncertain(p, n) } }
        precondition(answer == 0 || answer == 1, "The verified core refused a version (osva_version_uncertain returned \(answer)).")
        return answer == 1
    }

    // MARK: Advisories, and the upgrades that leave them (Decide.lean)

    /// What one advisory says about an installed version.
    public enum Verdict: Sendable, Hashable {
        /// Outside, with evidence: the version lies in none of the advisory's published ranges or, when it publishes
        /// none, its first fixed versions say the version is not affected (Decide.lean `clearOf`).
        case clear
        /// Inside one of the advisory's published ranges (`verdict_inRange_sound`, `verdict_inRange_complete`).
        case inRange
        /// The advisory publishes no ranges (nil or []), and its first fixed versions say the version is affected.
        case likely
        /// The advisory states nothing to decide by: no ranges (nil or []) and no first fixed versions (Decide.lean's
        /// `decided` is false). The core answers 0 for it, as for `.clear`; this wrapper tells the two apart. Such an
        /// advisory is "reported, not checked": `upgrade(from:advisories:)` leaves it out (the core would find no upgrade
        /// for a list that holds one) and never counts it among the fixes, and `judge` never says it is left.
        case unstated
    }

    /// What `upgrade(from:advisories:)` found.
    public enum UpgradeAnswer: Sendable, Hashable {
        /// The core's upgrade.
        case upgrade(CheckedUpgrade)
        /// No candidate is above the installed version and clear of every advisory, with evidence.
        case noUpgrade
        /// More work than `upgradeWorkLimit`: the core was not asked, so the advisories are reported, not decided.
        case refused
    }

    /// A bound on the work osva_upgrade_for does for `advisories` above `installed`, in bytes compared: it checks every
    /// candidate above `installed` (each range's fixed version and each first fixed version, repeats included) against
    /// every version string an advisory is decided by (its ranges' bounds or, without ranges, its first fixed versions),
    /// and each such comparison reads both strings. So: for every such pair, the two lengths plus 8 for the comparison
    /// itself. A first fixed version counts twice, as the core reads it twice (Affected.lean `affected`: once for a fix
    /// above the candidate, once for one on its branch at or below it). Candidates at or below `installed` cost one
    /// comparison each and are not counted.
    func upgradeWork(from installed: String, _ advisories: [CoreAdvisory]) -> Int {
        var above = 0, aboveBytes = 0, strings = 0, stringBytes = 0
        for a in advisories {
            let ranges = a.ranges ?? []
            for c in ranges.compactMap(\.fixed) + a.fixed where compareVersions(c, installed) > 0 {
                above += 1; aboveBytes += c.utf8.count
            }
            if ranges.isEmpty {
                strings += 2 * a.fixed.count; stringBytes += 2 * a.fixed.reduce(0) { $0 + $1.utf8.count }
            } else {
                for r in ranges {
                    let bounds = [r.introduced, r.fixed, r.lastAffected].compactMap { $0 }
                    strings += max(bounds.count, 1); stringBytes += bounds.reduce(0) { $0 + $1.utf8.count }
                }
            }
        }
        // above * (stringBytes + 8 * strings) + aboveBytes * strings, saturating
        let (pairs, o1) = above.multipliedReportingOverflow(by: strings)
        let (eight, o2) = pairs.multipliedReportingOverflow(by: 8)
        let (left, o3) = above.multipliedReportingOverflow(by: stringBytes)
        let (right, o4) = aboveBytes.multipliedReportingOverflow(by: strings)
        let (sum1, o5) = eight.addingReportingOverflow(left)
        let (work, o6) = sum1.addingReportingOverflow(right)
        return o1 || o2 || o3 || o4 || o5 || o6 ? .max : work
    }

    /// The most work (`upgradeWork`) one call of `upgrade(from:advisories:)` may ask of the core. Measured on an Apple
    /// M1 (hq-mac, 2026-11-25) in the slowest shapes tried (every candidate above the installed version and clear of
    /// every advisory, versions up to 80 bytes): 37-59 ns per unit for ranges, and 78-86 ns per unit for first fixed
    /// versions counted once, so 39-43 ns now that they count twice. About 0.25 s at the limit, 0.3 s in the slowest
    /// shape; real records do less, since most candidates fail an early check (PostgreSQL's 68 critical and high
    /// advisories: up to 4.6 million units, 0.1 s). One package's advisories fit.
    public static let upgradeWorkLimit = 5_000_000

    /// One verdict per advisory, in order: ranges decide when an advisory has them, its first fixed versions otherwise,
    /// and `.unstated` when it has neither.
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
        return zip(advisories, out).map { a, byte in
            switch byte {
            case 0: return a.states ? .clear : .unstated
            case 1 where a.states: return .inRange
            case 2 where a.states: return .likely
            default: preconditionFailure("osva_verdicts wrote \(byte) for an advisory that \(a.states ? "states" : "states nothing").")
            }
        }
    }

    /// The upgrade the app suggests: the lowest release the advisories name as fixed (in their ranges, or as first
    /// fixed versions) that is above `installed` and clear of every one of them that states something, with evidence
    /// (Decide.lean `upgradeFor_leaves`, `upgradeFor_nearest`). An `.unstated` advisory is left out, so that it cannot
    /// block every upgrade, and is never among the fixes: it stays reported. Give it one package's advisories, and call
    /// it off the main thread. Refused, without asking the core, past `upgradeWorkLimit`. The upgrade's `fixes` are the
    /// advisories whose verdict for `installed` is `.inRange` or `.likely`.
    public func upgrade(from installed: String, advisories: [CoreAdvisory]) -> UpgradeAnswer {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let stated = advisories.filter(\.states)                // the core finds no upgrade for a list with an unstated one
        guard upgradeWork(from: installed, stated) <= Self.upgradeWorkLimit else { return .refused }
        let version = Array(installed.utf8)
        let list = AdvisoryList(stated)
        var output = [UInt8](repeating: 0, count: max(list.longestFixed, 1))
        let length = queue.sync {
            withBytes(version) { pv, nv in
                list.withAdvisories { a, n in
                    output.withUnsafeMutableBufferPointer { o in osva_upgrade_for(pv, nv, a, n, o.baseAddress!, o.count) }
                }
            }
        }
        precondition(length >= -1, "The verified core refused the advisories (osva_upgrade_for returned \(length)).")
        guard length >= 0 else { return .noUpgrade }
        let fixes = verdicts(installed: installed, advisories: advisories).map { $0 == .inRange || $0 == .likely }
        return .upgrade(CheckedUpgrade(String(decoding: output.prefix(length), as: UTF8.self), fixes: fixes))
    }

    /// Checks an upgrade the core did not pick (the server's target, a vendor's build, pip's choice): for each
    /// advisory, whether `candidate` is clear of it, with evidence (Decide.lean `judge_spec`). `flagged` says, for each
    /// advisory in the same order, whether the app flags it. Nil when `candidate` is not above `installed`. The
    /// judgement's upgrade is `candidate` only if it leaves at least one flagged advisory; its `fixes` are those.
    /// Call it off the main thread.
    public func judge(_ candidate: String, from installed: String, advisories: [CoreAdvisory], flagged: [Bool]) -> Judgement? {
        dispatchPrecondition(condition: .notOnQueue(.main))
        precondition(flagged.count == advisories.count, "judge needs one flag per advisory (\(flagged.count) for \(advisories.count)).")
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
        let fixes = zip(leaves, flagged).map { $0 && $1 }
        return Judgement(leaves: leaves, upgrade: fixes.contains(true) ? CheckedUpgrade(candidate, fixes: fixes) : nil)   // claims-mutant: unchecked-target
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
        if let other = any.allKeys.first(where: { CodingKeys(stringValue: $0.stringValue) == nil }) {   // claims-mutant: lenient-decoding
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
}

/// One advisory as the core weighs it: the ranges the site publishes for it (nil: none it can read; [] reads the same),
/// and the first fixed versions its issuer names, which decide only without ranges.
public struct CoreAdvisory: Sendable, Hashable {
    public var ranges: [AffectedRange]?
    public var fixed: [String]

    public init(ranges: [AffectedRange]?, fixed: [String]) { self.ranges = ranges; self.fixed = fixed }

    /// It states something to decide by: published ranges, or else first fixed versions (Decide.lean `decided`).
    var states: Bool { !(ranges ?? []).isEmpty || !fixed.isEmpty }
}

/// A version the core has checked as an upgrade: `Core.upgrade(from:advisories:)` picked it, or `Core.judge` found it
/// above the installed version and clear of an advisory the app flags. Its storage is private and its initialisers
/// file-private, so only Core.swift can make one, and a version the app suggests can only come from the core.
public struct CheckedUpgrade: Sendable, Hashable {
    /// The ways a checked version may be shown: the version itself, written as its ecosystem writes it. Closed: a
    /// style carries no text of its own, so what the app shows is always the checked version, rewritten only by these.
    public enum Display: Sendable, Hashable {
        /// As the core checked it.
        case asChecked
        /// As Java names it: "8u511" for 8.0.511, the canonical form from 9 on (`JavaVersion.shown`).
        case java
        /// As a program's parts are shown (`FindingBuilder.Component.shown`): Go's "v0.33.0" as "0.33.0", and a
        /// pseudo-version as its base and date.
        case program
    }

    private let checked: String
    private let style: Display
    private let fixesByAdvisory: [Bool]

    fileprivate init(_ version: String, fixes: [Bool]) { checked = version; style = .asChecked; fixesByAdvisory = fixes }
    private init(_ other: CheckedUpgrade, style: Display) { checked = other.checked; self.style = style; fixesByAdvisory = other.fixesByAdvisory }

    /// The version, as the core checked it.
    public var version: String { checked }

    /// How the app shows it.
    public var display: String {
        switch style {
        case .asChecked: return checked
        case .java: return JavaVersion.shown(checked)
        case .program: return FindingBuilder.Component.shown(checked)
        }
    }

    /// One per advisory the core was given, in order: whether the app flags it and the core says this version is clear
    /// of it, with evidence. So "fixes N" is the core's count.
    public var fixes: [Bool] { fixesByAdvisory }

    /// How many advisories it fixes.
    public var fixCount: Int { fixesByAdvisory.count(where: { $0 }) }

    /// The same checked version, shown in `style`.
    public func displayed(_ style: Display) -> CheckedUpgrade { CheckedUpgrade(self, style: style) }
}

/// The core's answer about a candidate upgrade above the installed version. Only Core.swift can make one.
public struct Judgement: Sendable, Equatable {
    private let answers: [Bool]
    private let checked: CheckedUpgrade?

    fileprivate init(leaves: [Bool], upgrade: CheckedUpgrade?) { answers = leaves; checked = upgrade }

    /// One per advisory, in order: whether the candidate is clear of it, with evidence.
    public var leaves: [Bool] { answers }
    /// The candidate, when it leaves at least one flagged advisory; nil when it leaves none of them.
    public var upgrade: CheckedUpgrade? { checked }
}

/// Advisories laid out the way osva_verdicts, osva_upgrade_for and osva_judge want them: every bound and fixed version
/// in one buffer, then one array of osva_range, one of fixed-version pointers and one of their lengths, each advisory's
/// osva_advisory pointing at its own run of them. NULL only for an absent bound.
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
