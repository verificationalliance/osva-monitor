import Compression
import Foundation

/// The crate list cargo-auditable writes into a Rust binary: a `.dep-v0` section (in `__DATA` on macOS) holding
/// zlib-compressed JSON, `{"packages": [{"name", "version", "source", "kind"?, "root"?, "dependencies"?}], "format": 1}`.
/// `source` is "crates.io", "git", "local", "registry" (another registry) or something else; only crates.io's can be
/// checked against crates.io's advisories.
public enum RustAudit {
    public struct Crate: Equatable, Sendable {
        public var name: String
        public var version: String
        public var source: String
        /// Build-time only (build scripts, proc macros): not part of the program that runs.
        public var buildOnly: Bool
        /// The program's own crate.
        public var root: Bool

        public init(name: String, version: String, source: String, buildOnly: Bool = false, root: Bool = false) {
            self.name = name; self.version = version; self.source = source; self.buildOnly = buildOnly; self.root = root
        }

        public var onCratesIO: Bool { source == "crates.io" }
    }

    static let sectionName = ".dep-v0"
    /// Caps: the compressed section and the JSON it inflates to (a program with a thousand crates is ~100 KB).
    static let maxCompressed = 4 << 20
    static let maxInflated = 16 << 20
    static let maxCrates = 20_000

    /// The crates of a binary built with cargo-auditable, or nil when it has none (or they cannot be read).
    static func read(_ macho: MachO) -> [Crate]? {
        guard let s = macho.section(named: sectionName) else { return nil }
        let compressed = macho.read(s, cap: maxCompressed)
        guard !compressed.isEmpty, UInt64(compressed.count) == s.size, let json = inflate(zlib: compressed, cap: maxInflated) else { return nil }
        return parse(json)
    }

    /// The `.dep-v0` JSON.
    public static func parse(_ json: [UInt8]) -> [Crate]? {
        guard let root = try? JSONSerialization.jsonObject(with: Data(json)) as? [String: Any],
              let packages = root["packages"] as? [Any] else { return nil }
        var out: [Crate] = []
        for p in packages.prefix(maxCrates) {
            guard let d = p as? [String: Any], let name = d["name"] as? String, let version = d["version"] as? String,
                  !name.isEmpty, !version.isEmpty else { continue }
            out.append(Crate(name: name, version: version, source: d["source"] as? String ?? "",
                             buildOnly: (d["kind"] as? String) == "build", root: (d["root"] as? Bool) == true))
        }
        return out
    }

    /// zlib (RFC 1950: a 2-byte header, raw deflate, an Adler-32 checksum) inflated into at most `cap` bytes. Nil if it
    /// is not zlib, is damaged, or inflates to more than `cap`.
    public static func inflate(zlib bytes: [UInt8], cap: Int) -> [UInt8]? {
        guard bytes.count > 6 else { return nil }
        let cmf = bytes[0], flg = bytes[1]
        guard cmf & 0x0F == 8, cmf >> 4 <= 7, (UInt16(cmf) << 8 | UInt16(flg)) % 31 == 0, flg & 0x20 == 0 else { return nil }
        let raw = Array(bytes[2...])
        // COMPRESSION_ZLIB is raw deflate. Inflated 64 KB at a time, so a bomb stops at the cap, not after it.
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }
        guard compression_stream_init(stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }
        let chunk = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { buffer.deallocate() }
        var out: [UInt8] = []
        let complete: Bool = raw.withUnsafeBufferPointer { src in
            stream.pointee.src_ptr = src.baseAddress!
            stream.pointee.src_size = src.count
            while true {
                stream.pointee.dst_ptr = buffer
                stream.pointee.dst_size = chunk
                let status = compression_stream_process(stream, Int32(bitPattern: COMPRESSION_STREAM_FINALIZE.rawValue))
                guard status != COMPRESSION_STATUS_ERROR else { return false }
                let produced = chunk - stream.pointee.dst_size
                guard out.count + produced <= cap else { return false }
                out.append(contentsOf: UnsafeBufferPointer(start: buffer, count: produced))
                if status == COMPRESSION_STATUS_END { return true }
                if produced == 0 && stream.pointee.src_size == 0 { return false }     // the input ended before the stream did
            }
        }
        guard complete, !out.isEmpty else { return nil }
        // The checksum at the end says whether this is what was compressed.
        let inflated = out
        let trailer = bytes.suffix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return adler32(inflated) == trailer ? inflated : nil
    }

    /// zlib's Adler-32 checksum.
    static func adler32(_ data: [UInt8]) -> UInt32 {
        var a: UInt32 = 1, b: UInt32 = 0, i = 0
        while i < data.count {
            let end = Swift.min(i + 5552, data.count)            // the most bytes before b can overflow
            while i < end { a += UInt32(data[i]); b += a; i += 1 }
            a %= 65521; b %= 65521
        }
        return b << 16 | a
    }

    /// Whether a binary without the section is plainly Rust: Rust's standard library names the RUST_BACKTRACE
    /// variable, and its panic locations name /rustc/<commit>/library. Only the constant-data sections are read, at
    /// most `budget` bytes, so a large non-Rust binary costs little.
    static func looksLikeRust(_ macho: MachO, budget: Int = 16 << 20) -> Bool {
        let sections = [("__TEXT", "__const"), ("__TEXT", "__cstring"), ("__DATA_CONST", "__const")]
        return macho.contains(anyOf: [Array("RUST_BACKTRACE".utf8), Array("/rustc/".utf8)], inSections: sections, budget: budget)
    }
}
