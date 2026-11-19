import Foundation

// Readers for what is inside app bundles and extension folders. Any app or extension can write those files, so every
// read here is bounded (bytes, entries, depth) and every parser takes its input as hostile: garbage gives nil, never a
// crash, a hang, or a read past its limit.

/// Reads regular files only, and only up to a limit.
enum BoundedFile {
    /// The whole file, or nil when it is not a regular file (a FIFO, a device, a directory), cannot be opened, or is
    /// larger than `limit`. Symbolic links are followed: frameworks link Resources to Versions/Current/Resources.
    static func read(_ url: URL, limit: Int) -> Data? {
        withRegularFile(url.path) { fd, size in size <= limit ? pread(fd, offset: 0, length: size) : nil }
    }

    /// At most `length` bytes from `offset` (fewer at the end of the file).
    static func read(_ url: URL, offset: Int, length: Int) -> Data? {
        withRegularFile(url.path) { fd, size in
            guard offset >= 0, length >= 0, offset <= size else { return nil }
            return pread(fd, offset: offset, length: min(length, size - offset))
        }
    }

    /// The size of a regular file.
    static func size(_ url: URL) -> Int? { withRegularFile(url.path) { _, size in size } }

    /// Opens without blocking (a FIFO named like a plist would otherwise wait for a writer forever), then checks on
    /// the open descriptor that it is a regular file.
    static func withRegularFile<R>(_ path: String, _ body: (Int32, Int) -> R?) -> R? {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size >= 0 else { return nil }
        return body(fd, Int(st.st_size))
    }

    private static func pread(_ fd: Int32, offset: Int, length: Int) -> Data? {
        guard length > 0 else { return Data() }
        var data = Data(count: length)
        var done = 0
        let ok = data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Bool in
            guard let base = buffer.baseAddress else { return false }
            while done < length {
                let n = Darwin.pread(fd, base + done, length - done, off_t(offset + done))
                if n < 0 { if errno == EINTR { continue }; return false }
                if n == 0 { break }
                done += n
            }
            return true
        }
        guard ok else { return nil }
        if done < length { data.removeSubrange(done..<length) }
        return data
    }
}

/// Directory listings with a limit on how many entries are read.
enum Directory {
    /// Names in the directory (not "." or ".."), at most `limit` of them, sorted. Hidden names are skipped unless asked.
    static func entries(_ url: URL, limit: Int, hidden: Bool = false) -> [String] {
        guard let dir = opendir(url.path) else { return [] }
        defer { closedir(dir) }
        var out: [String] = []
        while out.count < limit, let entry = readdir(dir) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> String in
                let bytes = raw.bindMemory(to: UInt8.self)
                let n = Int(entry.pointee.d_namlen)
                return String(decoding: UnsafeBufferPointer(rebasing: bytes.prefix(n)), as: UTF8.self)
            }
            if name == "." || name == ".." || (!hidden && name.hasPrefix(".")) { continue }
            out.append(name)
        }
        return out.sorted()
    }

    /// Whether the path is a directory (following symbolic links), and not a symbolic link itself when `noLinks`.
    static func isDirectory(_ url: URL, noLinks: Bool = false) -> Bool {
        var st = stat()
        if noLinks {
            guard lstat(url.path, &st) == 0 else { return false }
        } else {
            guard stat(url.path, &st) == 0 else { return false }
        }
        return (st.st_mode & S_IFMT) == S_IFDIR
    }
}

/// Property lists and JSON from files, bounded.
enum Documents {
    static func plist(_ url: URL, limit: Int = 1 << 20) -> [String: Any]? {
        guard let data = BoundedFile.read(url, limit: limit) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    static func json(_ url: URL, limit: Int) -> Any? {
        guard let data = BoundedFile.read(url, limit: limit) else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    /// A string value, cleaned for showing: control characters removed, at most `max` characters.
    static func string(_ dict: [String: Any], _ key: String, max: Int = 128) -> String? {
        (dict[key] as? String).flatMap { ProductIndex.clean($0, max: max) }
    }
}

/// Versions as apps and libraries write them.
enum VersionText {
    private static let leadingPattern = Regex("^\\s*[vV]?([0-9]{1,9}(?:\\.[0-9]{1,9}){0,5}(?:-?(?:[Aa]lpha|[Bb]eta|[Rr][Cc]|[Pp]re|[Pp]review|[Dd]ev|a|b)\\.?[0-9]{0,9})?)")

    /// The version at the start of what an app or a framework writes in its Info.plist: "6.6.10 (69071)" is
    /// 6.6.10; "3.11.15, (c) 2001-2023 Python Software Foundation." is 3.11.15; a `git describe` suffix
    /// ("2.10.1-3254-g0858e9bc") is dropped; a pre-release ("2.5.0-beta.1", "3.0b2") is kept.
    static func leading(_ raw: String) -> String? {
        guard raw.utf8.count <= 256, let m = leadingPattern.firstMatch(raw), let v = m[1], !v.isEmpty else { return nil }
        return v
    }

    /// A Mach-O version number, xxxx.yy.zz.
    static func machO(_ v: UInt32) -> String { "\(v >> 16).\((v >> 8) & 0xFF).\(v & 0xFF)" }

    private static let releaseToken = Regex("^[0-9]{1,9}(\\.[0-9]{1,9}){1,4}[a-z]{0,2}$")

    /// The release a binary prints after its name: "OpenSSL 3.0.13 30 Jan 2024" gives 3.0.13, "OpenSSL 1.1.1v" 1.1.1v,
    /// "FFmpeg version n7.1" 7.1. A git build ("N-111721-g132a3b7340") is not a release and gives nothing. Looks at
    /// the first 64 places a needle occurs and prefers a three-part version over a two-part one.
    static func embedded(in data: Data, needles: [String]) -> String? {
        var twoPart: String?
        for needle in needles where !needle.isEmpty {
            let n = Data(needle.utf8)
            var from = data.startIndex, hits = 0
            while hits < 64, from < data.endIndex, let r = data.range(of: n, in: from..<data.endIndex) {
                hits += 1
                from = r.upperBound
                var end = r.upperBound
                while end < data.endIndex, end - r.upperBound < 32, isTokenByte(data[end]) { end += 1 }
                var token = String(decoding: data[r.upperBound..<end], as: UTF8.self)
                if let f = token.first, "vVn".contains(f), token.dropFirst().first?.isNumber == true { token.removeFirst() }
                while token.hasSuffix(".") { token.removeLast() }
                guard releaseToken.test(token) else { continue }
                if token.filter({ $0 == "." }).count >= 2 { return token }
                if twoPart == nil { twoPart = token }
            }
        }
        return twoPart
    }

    private static func isTokenByte(_ b: UInt8) -> Bool {
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || b == 0x2E
    }
}

/// The little a Mach-O file says about its version: the install name's current and compatibility versions
/// (LC_ID_DYLIB), and where its C strings are (__TEXT,__cstring), for a bounded search of a printed release.
enum MachO {
    struct Info: Equatable {
        var current: UInt32?
        var compatibility: UInt32?
        /// Byte range of __TEXT,__cstring in the file.
        var cstrings: Range<Int>?
    }

    /// At most this much of a slice's load commands is read.
    static let maxLoadCommands = 1 << 20
    static let maxSlices = 16

    static func read(_ url: URL) -> Info? {
        guard let size = BoundedFile.size(url) else { return nil }
        return parse(size: size) { offset, length in BoundedFile.read(url, offset: offset, length: length) }
    }

    /// `read(offset, length)` returns the file's bytes there (or fewer at its end).
    static func parse(size: Int, read: (Int, Int) -> Data?) -> Info? {
        guard size >= 8, let head = read(0, 8), head.count == 8 else { return nil }
        let magic = head.u32be(0)
        guard magic == 0xCAFE_BABE || magic == 0xCAFE_BABF else { return thin(base: 0, size: size, read: read) }
        // A universal binary: big-endian table of slices. Prefer arm64, then x86_64, then the first.
        let count = Int(head.u32be(4)), wide = magic == 0xCAFE_BABF, entry = wide ? 32 : 20
        guard count >= 1, count <= maxSlices, let table = read(8, count * entry), table.count == count * entry else { return nil }
        var slices: [(cpu: UInt32, offset: Int, size: Int)] = []
        for i in 0..<count {
            let e = i * entry
            let offset = wide ? table.u64be(e + 8) : UInt64(table.u32be(e + 8))
            let length = wide ? table.u64be(e + 16) : UInt64(table.u32be(e + 12))
            guard offset < UInt64(size), length <= UInt64(size) - offset else { continue }
            slices.append((table.u32be(e), Int(offset), Int(length)))
        }
        let pick = slices.first { $0.cpu == 0x0100_000C } ?? slices.first { $0.cpu == 0x0100_0007 } ?? slices.first
        guard let s = pick else { return nil }
        return thin(base: s.offset, size: s.size, read: read)
    }

    private static func thin(base: Int, size: Int, read: (Int, Int) -> Data?) -> Info? {
        guard size >= 28, let header = read(base, 32), header.count >= 28 else { return nil }
        let magic = header.u32le(0)
        let is64: Bool
        switch magic {
        case 0xFEED_FACF: is64 = true
        case 0xFEED_FACE: is64 = false
        default: return nil                           // not Mach-O, or a big-endian (PowerPC) one
        }
        let headerSize = is64 ? 32 : 28
        let ncmds = Int(header.u32le(16)), sizeofcmds = Int(header.u32le(20))
        guard header.count >= headerSize, ncmds <= 65_536, sizeofcmds <= maxLoadCommands, headerSize + sizeofcmds <= size,
              let cmds = read(base + headerSize, sizeofcmds), cmds.count == sizeofcmds else { return nil }
        var info = Info(), off = 0
        for _ in 0..<ncmds {
            guard off + 8 <= cmds.count else { break }
            let cmd = cmds.u32le(off), cmdsize = Int(cmds.u32le(off + 4))
            guard cmdsize >= 8, cmdsize <= cmds.count - off else { break }       // a zero size would loop forever
            switch cmd {
            case 0xD where cmdsize >= 24:                                       // LC_ID_DYLIB
                info.current = cmds.u32le(off + 16)
                info.compatibility = cmds.u32le(off + 20)
            case 0x19 where cmdsize >= 72:                                      // LC_SEGMENT_64
                let nsects = Int(cmds.u32le(off + 64))
                guard nsects <= (cmdsize - 72) / 80 else { break }
                for i in 0..<nsects {
                    let s = off + 72 + i * 80
                    if cmds.name(s) == "__cstring" && cmds.name(s + 16) == "__TEXT" {
                        info.cstrings = range(base: base, slice: size, offset: UInt64(cmds.u32le(s + 48)), length: cmds.u64le(s + 40))
                    }
                }
            case 0x1 where cmdsize >= 56:                                       // LC_SEGMENT
                let nsects = Int(cmds.u32le(off + 48))
                guard nsects <= (cmdsize - 56) / 68 else { break }
                for i in 0..<nsects {
                    let s = off + 56 + i * 68
                    if cmds.name(s) == "__cstring" && cmds.name(s + 16) == "__TEXT" {
                        info.cstrings = range(base: base, slice: size, offset: UInt64(cmds.u32le(s + 40)), length: UInt64(cmds.u32le(s + 36)))
                    }
                }
            default:
                break
            }
            off += cmdsize
        }
        return info
    }

    private static func range(base: Int, slice: Int, offset: UInt64, length: UInt64) -> Range<Int>? {
        guard offset <= UInt64(slice), length <= UInt64(slice) - offset, length > 0 else { return nil }
        return (base + Int(offset))..<(base + Int(offset) + Int(length))
    }
}

/// A Java runtime's `release` file: `JAVA_VERSION="17.0.9"`.
enum JavaRelease {
    static func version(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline).prefix(200) {
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2, parts[0].trimmingCharacters(in: .whitespaces) == "JAVA_VERSION" else { continue }
            let value = parts[1].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            return PackageNames.isPlausibleVersion(value) && value.first?.isNumber == true && value.count <= 40 ? value : nil
        }
        return nil
    }
}

extension Data {
    fileprivate func u32le(_ i: Int) -> UInt32 {
        guard i >= 0, i + 4 <= count else { return 0 }
        let b = startIndex + i
        return UInt32(self[b]) | UInt32(self[b + 1]) << 8 | UInt32(self[b + 2]) << 16 | UInt32(self[b + 3]) << 24
    }
    fileprivate func u64le(_ i: Int) -> UInt64 { UInt64(u32le(i)) | UInt64(u32le(i + 4)) << 32 }
    fileprivate func u32be(_ i: Int) -> UInt32 {
        guard i >= 0, i + 4 <= count else { return 0 }
        let b = startIndex + i
        return UInt32(self[b]) << 24 | UInt32(self[b + 1]) << 16 | UInt32(self[b + 2]) << 8 | UInt32(self[b + 3])
    }
    fileprivate func u64be(_ i: Int) -> UInt64 { UInt64(u32be(i)) << 32 | UInt64(u32be(i + 4)) }
    /// A 16-byte, NUL-padded name (segment and section names).
    fileprivate func name(_ i: Int) -> String {
        guard i >= 0, i + 16 <= count else { return "" }
        let bytes = self[(startIndex + i)..<(startIndex + i + 16)]
        return String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
    }
}
