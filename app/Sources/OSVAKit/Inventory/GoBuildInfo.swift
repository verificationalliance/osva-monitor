import Foundation

/// What the Go toolchain writes into every binary it links: the Go version, the main package and module, and every
/// module the program was built with. Read straight from the file, the way `debug/buildinfo` reads it (no Go needed,
/// nothing run).
///
/// The blob starts with the 14-byte magic `\xff Go buildinf:`, 16-byte aligned, at the start of the
/// `__go_buildinfo` section (older linkers: somewhere at the start of the first writable segment). Byte 14 is the
/// pointer size, byte 15 the flags. Since Go 1.18 (flag bit 2 set) the two strings follow the 32-byte header inline,
/// each prefixed by its length as a varint. Before, the header holds two pointers to Go string headers
/// (data pointer, length), in the byte order flag bit 1 names.
public struct GoBuildInfo: Equatable, Sendable {
    public struct Module: Equatable, Sendable {
        public var path: String
        /// "v0.23.0", "v0.0.0-20210226172049-e18ecbb05110", "(devel)" for a main module built from a checkout.
        public var version: String
        /// What it was replaced with (`replace` in go.mod), which is the code that was actually built.
        public var replacement: Replacement?

        public enum Replacement: Equatable, Sendable {
            case module(path: String, version: String)
            /// A local directory: not a published module, so nothing to check it against.
            case directory(String)
        }

        public init(path: String, version: String, replacement: Replacement? = nil) {
            self.path = path; self.version = version; self.replacement = replacement
        }

        /// The module and version that was compiled in, or nil for a local directory.
        public var effective: (path: String, version: String)? {
            switch replacement {
            case nil: return (path, version)
            case let .module(path, version)?: return (path, version)
            case .directory?: return nil
            }
        }
    }

    /// "go1.22.3" (possibly followed by " X:boringcrypto" or similar).
    public var goVersion: String
    /// The main package's import path ("github.com/cli/cli/v2/cmd/gh").
    public var path: String?
    public var main: Module?
    public var deps: [Module]

    /// The toolchain as OSV's Go advisories write the standard library's versions: "go1.22.3" is "1.22.3", "go1.22"
    /// is "1.22.0", "go1.21rc2" is "1.21.0-rc.2". Nil for a development toolchain, which no advisory can place.
    public var stdlibVersion: String? { Self.semver(goVersion) }

    static let magic: [UInt8] = [0xFF] + Array(" Go buildinf:".utf8)
    static let headerSize = 32
    /// Where the blob is looked for in a binary without a `__go_buildinfo` section.
    static let searchLimit = 1 << 20
    static let maxVersionLength = 256
    static let maxModinfoLength = 4 << 20

    /// The build info of a Go executable, or nil when it is not one (or the blob is damaged).
    static func read(_ macho: MachO) -> GoBuildInfo? {
        guard let (version, modinfo) = readStrings(macho) else { return nil }
        var info = parseModinfo(modinfo)
        info.goVersion = version
        return info
    }

    /// Whether the binary has the sections the Go linker writes: a cheap test before looking for the blob.
    static func isGo(_ macho: MachO) -> Bool {
        macho.sections.contains { $0.name == "__go_buildinfo" || $0.name == "__gopclntab" }
    }

    static func readStrings(_ macho: MachO) -> (version: String, modinfo: String)? {
        let region: (addr: UInt64, bytes: [UInt8])
        if let s = macho.section(named: "__go_buildinfo") {
            region = (s.addr, macho.read(s, cap: maxModinfoLength + 4096))
        } else if isGo(macho), let seg = macho.segments.first(where: { $0.initprot & 3 == 3 && $0.maxprot & 3 == 3 && $0.vmaddr != 0 && $0.filesize != 0 }) {
            region = (seg.vmaddr, macho.readSlice(at: seg.fileoff, count: Int(min(seg.filesize, UInt64(searchLimit)))))
        } else {
            return nil
        }
        let data = region.bytes
        guard let start = data.firstIndex(of: magic, alignedTo: 16), data.count - start >= headerSize else { return nil }
        let ptrSize = Int(data[start + 14]), flags = data[start + 15]
        // Kept as bytes until the framing is taken off: the sentinels are not UTF-8.
        let version: [UInt8]?, modinfo: [UInt8]?
        if flags & 2 != 0 {
            // Go 1.18 and later: two varint-prefixed strings right after the header.
            var at = start + headerSize
            version = inlineString(data, &at, limit: maxVersionLength)
            modinfo = version == nil ? nil : inlineString(data, &at, limit: maxModinfoLength)
        } else {
            // Before Go 1.18: pointers to the two strings' headers.
            guard ptrSize == 4 || ptrSize == 8 else { return nil }
            let r = ByteReader(bytes: Array(data[start..<(start + headerSize)]), bigEndian: flags & 1 != 0)
            func pointer(_ bytes: ByteReader, _ at: Int) -> UInt64? { ptrSize == 8 ? bytes.u64(at) : bytes.u32(at).map(UInt64.init) }
            func string(at headerAddress: UInt64?, limit: Int) -> [UInt8]? {
                guard let headerAddress else { return nil }
                let h = ByteReader(bytes: macho.read(vmaddr: headerAddress, count: 2 * ptrSize), bigEndian: r.bigEndian)
                guard let address = pointer(h, 0), let length = pointer(h, ptrSize), length <= UInt64(limit) else { return nil }
                let bytes = macho.read(vmaddr: address, count: Int(length))
                return bytes.count == Int(length) ? bytes : nil
            }
            version = string(at: pointer(r, 16), limit: maxVersionLength)
            modinfo = string(at: pointer(r, 16 + ptrSize), limit: maxModinfoLength)
        }
        guard let version, !version.isEmpty, version.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }) else { return nil }
        // The module information is framed by two 16-byte sentinels; the end one starts after a newline.
        var mod = modinfo ?? []
        if mod.count >= 33, mod[mod.count - 17] == UInt8(ascii: "\n") { mod = Array(mod[16..<(mod.count - 16)]) } else { mod = [] }
        return (String(decoding: version, as: UTF8.self), String(decoding: mod, as: UTF8.self))
    }

    /// A varint length, then that many bytes, all inside `data`.
    private static func inlineString(_ data: [UInt8], _ at: inout Int, limit: Int) -> [UInt8]? {
        var length: UInt64 = 0, shift: UInt64 = 0, i = at
        while true {
            guard i < data.count, shift <= 63 else { return nil }
            let b = data[i]; i += 1
            length |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { break }
            shift += 7
        }
        guard length <= UInt64(limit), length <= UInt64(data.count - i) else { return nil }
        let end = i + Int(length)
        defer { at = end }
        return Array(data[i..<end])
    }

    /// The module lines, as `debug.BuildInfo.String` writes them:
    ///
    ///     path    github.com/cli/cli/v2/cmd/gh
    ///     mod     github.com/cli/cli/v2   (devel)
    ///     dep     golang.org/x/net        v0.23.0 h1:…
    ///     dep     golang.org/x/text       v0.14.0
    ///     =>      golang.org/x/text       v0.3.7  h1:…       (the line above, replaced)
    ///     build   -trimpath=true
    ///
    /// Lines it does not understand are skipped.
    public static func parseModinfo(_ text: String) -> GoBuildInfo {
        var info = GoBuildInfo(goVersion: "", path: nil, main: nil, deps: [])
        enum Last { case none, main, dep }
        var last = Last.none
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            switch f[0] {
            case "path" where f.count >= 2:
                info.path = f[1]; last = .none
            case "mod" where f.count >= 3 && !f[1].isEmpty:
                info.main = Module(path: f[1], version: f[2]); last = .main
            case "dep" where f.count >= 3 && !f[1].isEmpty && !f[2].isEmpty:
                info.deps.append(Module(path: f[1], version: f[2])); last = .dep
            case "=>" where f.count >= 2 && !f[1].isEmpty:
                let version = f.count >= 3 ? f[2] : ""
                let replacement: Module.Replacement = version.isEmpty || version == "(devel)" ? .directory(f[1]) : .module(path: f[1], version: version)
                switch last {
                case .main: info.main?.replacement = replacement
                case .dep: info.deps[info.deps.count - 1].replacement = replacement
                case .none: break
                }
                last = .none
            default:
                last = .none
            }
        }
        return info
    }

    private static let release = Regex(#"^go([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:(rc|beta)([0-9]+))?$"#)

    /// "go1.22.3" -> "1.22.3", "go1.22" -> "1.22.0", "go1.21rc2" -> "1.21.0-rc.2"; nil for anything else.
    public static func semver(_ goVersion: String) -> String? {
        let first = goVersion.split(separator: " ").first.map(String.init) ?? ""
        guard let m = release.firstMatch(first), let major = m[1], let minor = m[2] else { return nil }
        let base = "\(major).\(minor).\(m[3] ?? "0")"
        if let kind = m[4], let n = m[5] { return "\(base)-\(kind).\(n)" }
        return base
    }
}
