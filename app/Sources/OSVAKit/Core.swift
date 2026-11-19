import Foundation
import OSVACore

/// The only door to the verified core (`Sources/OSVACore`, declared in `osva_core.h`).
///
/// Four kinds of decision would mislead the person using OSVA Monitor if they were wrong: which of two versions is
/// newer, whether an installed version is affected by an advisory, which installed packages may be named to the
/// server, and how a name is written into a URL. The verified core makes all four, and nothing else in the app
/// compares versions, decides affectedness, filters the inventory or percent-encodes.
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

    /// Is `installed` affected, given the first fixed version the issuer names for each release branch?
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
