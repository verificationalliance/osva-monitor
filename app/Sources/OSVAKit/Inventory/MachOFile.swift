import Foundation

/// Bytes that can be read at an offset: a file on disk, or (in tests) an array.
protocol ByteSource {
    var size: UInt64 { get }
    /// At most `count` bytes at `offset`: fewer at the end, none past it.
    func read(at offset: UInt64, count: Int) -> [UInt8]
}

extension Array: ByteSource where Element == UInt8 {
    var size: UInt64 { UInt64(count) }
    func read(at offset: UInt64, count n: Int) -> [UInt8] {
        guard n > 0, offset < UInt64(count) else { return [] }
        let start = Int(offset)
        return Array(self[start..<(start + Swift.min(n, count - start))])
    }
}

/// A regular file opened read-only for reads at offsets. It is never executed, never mapped, and never read whole:
/// each read is as long as the parser asks for, and the parsers ask for little.
final class ReadOnlyFile: ByteSource {
    let size: UInt64
    /// The file's device and inode: the same file reached by two paths is read once.
    let identity: FileIdentity
    private let fd: Int32

    struct FileIdentity: Hashable { var device: UInt64; var inode: UInt64 }

    /// Opens `path`, which must be a regular file: not a FIFO or device (O_NONBLOCK keeps one from hanging the open;
    /// fstat then refuses it), and not a symbolic link unless `followingLinks` (the program reader follows links
    /// itself, once).
    init?(path: String, followingLinks: Bool = false) {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | (followingLinks ? 0 : O_NOFOLLOW))
        guard fd >= 0 else { return nil }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size >= 0 else { close(fd); return nil }
        self.fd = fd
        size = UInt64(st.st_size)
        identity = FileIdentity(device: UInt64(UInt32(bitPattern: st.st_dev)), inode: UInt64(st.st_ino))
    }

    deinit { close(fd) }

    /// The first `max` bytes of a small file (a config, a METADATA, a JSON record), or nil if it is not a regular file.
    static func head(_ path: String, max: Int) -> [UInt8]? {
        ReadOnlyFile(path: path, followingLinks: true).map { $0.read(at: 0, count: max) }
    }

    func read(at offset: UInt64, count: Int) -> [UInt8] {
        guard count > 0, offset < size else { return [] }
        let n = Int(min(UInt64(count), size - offset))
        var buffer = [UInt8](repeating: 0, count: n)
        var got = 0
        while got < n {
            let r = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress! + got, n - got, off_t(offset) + off_t(got)) }
            if r > 0 { got += r } else if r < 0 && errno == EINTR { continue } else { break }
        }
        return got == n ? buffer : Array(buffer.prefix(got))
    }
}

/// Little- and big-endian integers out of a byte array, bounds-checked: a read past the end gives nil.
struct ByteReader {
    let bytes: [UInt8]
    let bigEndian: Bool

    func u32(_ at: Int) -> UInt32? {
        guard at >= 0, at <= bytes.count - 4 else { return nil }
        let b = (UInt32(bytes[at]), UInt32(bytes[at + 1]), UInt32(bytes[at + 2]), UInt32(bytes[at + 3]))
        return bigEndian ? b.0 << 24 | b.1 << 16 | b.2 << 8 | b.3 : b.3 << 24 | b.2 << 16 | b.1 << 8 | b.0
    }

    func u64(_ at: Int) -> UInt64? {
        guard let a = u32(at), let b = u32(at + 4) else { return nil }
        return bigEndian ? UInt64(a) << 32 | UInt64(b) : UInt64(b) << 32 | UInt64(a)
    }

    /// A fixed-size, NUL-padded name (segment and section names are 16 bytes).
    func name(_ at: Int, length: Int = 16) -> String? {
        guard at >= 0, at <= bytes.count - length else { return nil }
        let raw = bytes[at..<(at + length)]
        return String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
    }
}

/// The parts of a Mach-O executable the program readers need: its segments and sections, and reads of their bytes.
/// Everything read from the file is checked against the file's and the slice's size before it is used.
struct MachOFile {
    struct Segment: Equatable {
        var name: String
        var vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64
        var maxprot: UInt32, initprot: UInt32
    }

    struct Section: Equatable {
        var name: String, segment: String
        var addr: UInt64, size: UInt64
        /// Offset in the slice (not in a universal file).
        var offset: UInt64
    }

    static let mhExecute: UInt32 = 2
    static let cpuARM64: UInt32 = 0x0100_000C
    static let cpuX86_64: UInt32 = 0x0100_0007

    /// Caps on what is read from a header: real executables stay far below them.
    static let maxLoadCommandBytes = 4 << 20
    static let maxLoadCommands = 8192
    static let maxFatArchitectures = 64

    let source: ByteSource
    /// Where the slice starts in the file, and its length (the whole file for a thin binary).
    let sliceOffset: UInt64
    let sliceSize: UInt64
    let filetype: UInt32
    let cputype: UInt32
    let segments: [Segment]
    let sections: [Section]

    /// Whether the bytes start like a Mach-O file, thin or universal.
    static func looksLikeMachO(_ head: [UInt8]) -> Bool {
        guard head.count >= 4 else { return false }
        let m = Array(head.prefix(4))
        return [[0xCF, 0xFA, 0xED, 0xFE], [0xCE, 0xFA, 0xED, 0xFE], [0xFE, 0xED, 0xFA, 0xCF], [0xFE, 0xED, 0xFA, 0xCE],
                [0xCA, 0xFE, 0xBA, 0xBE], [0xCA, 0xFE, 0xBA, 0xBF]].contains(m)
    }

    /// Parses the file: a thin Mach-O, or a universal one (then the slice for this Mac's processor, else the first).
    static func parse(_ source: ByteSource, preferring cpu: UInt32 = nativeCPU) -> MachOFile? {
        let head = source.read(at: 0, count: 8)
        guard head.count >= 8 else { return nil }
        if head[0] == 0xCA, head[1] == 0xFE, head[2] == 0xBA, head[3] == 0xBE || head[3] == 0xBF {
            return parseFat(source, wide: head[3] == 0xBF, preferring: cpu)
        }
        return parseThin(source, at: 0, size: source.size)
    }

    static var nativeCPU: UInt32 {
        #if arch(arm64)
        return cpuARM64
        #else
        return cpuX86_64
        #endif
    }

    private static func parseFat(_ source: ByteSource, wide: Bool, preferring cpu: UInt32) -> MachOFile? {
        let header = ByteReader(bytes: source.read(at: 0, count: 8), bigEndian: true)
        guard let n = header.u32(4), n > 0, n <= UInt32(maxFatArchitectures) else { return nil }
        let entrySize = wide ? 32 : 20
        let table = ByteReader(bytes: source.read(at: 8, count: Int(n) * entrySize), bigEndian: true)
        var slices: [(cpu: UInt32, offset: UInt64, size: UInt64)] = []
        for i in 0..<Int(n) {
            let at = i * entrySize
            guard let type = table.u32(at) else { break }
            let offset: UInt64?, size: UInt64?
            if wide { offset = table.u64(at + 8); size = table.u64(at + 16) }
            else { offset = table.u32(at + 8).map(UInt64.init); size = table.u32(at + 12).map(UInt64.init) }
            guard let offset, let size, size > 0, offset >= 8, offset <= source.size, size <= source.size - offset else { continue }
            slices.append((type, offset, size))
        }
        let ordered = slices.filter { $0.cpu == cpu } + slices.filter { $0.cpu != cpu }
        for s in ordered {
            if let m = parseThin(source, at: s.offset, size: s.size) { return m }
        }
        return nil
    }

    private static func parseThin(_ source: ByteSource, at base: UInt64, size: UInt64) -> MachOFile? {
        let magic = source.read(at: base, count: 4)
        guard magic.count == 4 else { return nil }
        let is64: Bool, bigEndian: Bool
        switch (magic[0], magic[1], magic[2], magic[3]) {
        case (0xCF, 0xFA, 0xED, 0xFE): is64 = true; bigEndian = false
        case (0xCE, 0xFA, 0xED, 0xFE): is64 = false; bigEndian = false
        case (0xFE, 0xED, 0xFA, 0xCF): is64 = true; bigEndian = true
        case (0xFE, 0xED, 0xFA, 0xCE): is64 = false; bigEndian = true
        default: return nil
        }
        let headerSize = is64 ? 32 : 28
        let header = ByteReader(bytes: source.read(at: base, count: headerSize), bigEndian: bigEndian)
        guard let cputype = header.u32(4), let filetype = header.u32(12), let ncmds = header.u32(16), let sizeofcmds = header.u32(20),
              ncmds <= UInt32(maxLoadCommands), sizeofcmds <= UInt32(maxLoadCommandBytes),
              UInt64(headerSize) + UInt64(sizeofcmds) <= size else { return nil }
        let commands = source.read(at: base + UInt64(headerSize), count: Int(sizeofcmds))
        guard commands.count == Int(sizeofcmds) else { return nil }
        let r = ByteReader(bytes: commands, bigEndian: bigEndian)
        var segments: [Segment] = [], sections: [Section] = []
        var at = 0
        for _ in 0..<Int(ncmds) {
            guard let cmd = r.u32(at), let cmdsize = r.u32(at + 4), cmdsize >= 8, Int(cmdsize) <= commands.count - at else { break }
            if cmd == 0x19, is64, cmdsize >= 72 {                                        // LC_SEGMENT_64
                if let seg = segment64(r, at), let nsects = r.u32(at + 64), UInt64(nsects) * 80 <= UInt64(cmdsize) - 72 {
                    segments.append(seg)
                    for i in 0..<Int(nsects) {
                        if let s = section64(r, at + 72 + i * 80) { sections.append(s) }
                    }
                }
            } else if cmd == 0x1, !is64, cmdsize >= 56 {                                 // LC_SEGMENT
                if let seg = segment32(r, at), let nsects = r.u32(at + 48), UInt64(nsects) * 68 <= UInt64(cmdsize) - 56 {
                    segments.append(seg)
                    for i in 0..<Int(nsects) {
                        if let s = section32(r, at + 56 + i * 68) { sections.append(s) }
                    }
                }
            }
            at += Int(cmdsize)
        }
        return MachOFile(source: source, sliceOffset: base, sliceSize: size, filetype: filetype, cputype: cputype,
                     segments: segments, sections: sections)
    }

    private static func segment64(_ r: ByteReader, _ at: Int) -> Segment? {
        guard let name = r.name(at + 8), let vmaddr = r.u64(at + 24), let vmsize = r.u64(at + 32), let fileoff = r.u64(at + 40),
              let filesize = r.u64(at + 48), let maxprot = r.u32(at + 56), let initprot = r.u32(at + 60) else { return nil }
        return Segment(name: name, vmaddr: vmaddr, vmsize: vmsize, fileoff: fileoff, filesize: filesize, maxprot: maxprot, initprot: initprot)
    }

    private static func section64(_ r: ByteReader, _ at: Int) -> Section? {
        guard let name = r.name(at), let segment = r.name(at + 16), let addr = r.u64(at + 32), let size = r.u64(at + 40),
              let offset = r.u32(at + 48) else { return nil }
        return Section(name: name, segment: segment, addr: addr, size: size, offset: UInt64(offset))
    }

    private static func segment32(_ r: ByteReader, _ at: Int) -> Segment? {
        guard let name = r.name(at + 8), let vmaddr = r.u32(at + 24), let vmsize = r.u32(at + 28), let fileoff = r.u32(at + 32),
              let filesize = r.u32(at + 36), let maxprot = r.u32(at + 40), let initprot = r.u32(at + 44) else { return nil }
        return Segment(name: name, vmaddr: UInt64(vmaddr), vmsize: UInt64(vmsize), fileoff: UInt64(fileoff), filesize: UInt64(filesize),
                       maxprot: maxprot, initprot: initprot)
    }

    private static func section32(_ r: ByteReader, _ at: Int) -> Section? {
        guard let name = r.name(at), let segment = r.name(at + 16), let addr = r.u32(at + 32), let size = r.u32(at + 36),
              let offset = r.u32(at + 40) else { return nil }
        return Section(name: name, segment: segment, addr: UInt64(addr), size: UInt64(size), offset: UInt64(offset))
    }

    // MARK: Reading

    func section(named name: String, segment: String? = nil) -> Section? {
        sections.first { $0.name == name && (segment == nil || $0.segment == segment) }
    }

    /// At most `count` bytes at `offset` within the slice; nothing outside it.
    func readSlice(at offset: UInt64, count: Int) -> [UInt8] {
        guard count > 0, offset < sliceSize else { return [] }
        let n = Int(min(UInt64(count), sliceSize - offset))
        return source.read(at: sliceOffset + offset, count: n)
    }

    /// A section's bytes, at most `cap` of them. A zero-fill section has none on disk.
    func read(_ section: Section, cap: Int) -> [UInt8] {
        guard section.offset != 0 else { return [] }
        return readSlice(at: section.offset, count: Int(min(section.size, UInt64(cap))))
    }

    /// At most `count` bytes at a virtual address, from the segment whose file-backed part holds it.
    func read(vmaddr addr: UInt64, count: Int) -> [UInt8] {
        for seg in segments where seg.name != "__PAGEZERO" && seg.filesize > 0 {
            guard addr >= seg.vmaddr, addr - seg.vmaddr < seg.filesize else { continue }
            let delta = addr - seg.vmaddr
            guard seg.fileoff <= UInt64.max - delta else { return [] }
            return readSlice(at: seg.fileoff + delta, count: Int(min(UInt64(count), seg.filesize - delta)))
        }
        return []
    }

    /// Whether one of `needles` occurs in the named sections, reading at most `budget` bytes of them in all.
    func contains(anyOf needles: [[UInt8]], inSections names: [(segment: String, section: String)], budget: Int) -> Bool {
        var left = budget
        for (segment, name) in names {
            guard left > 0, let s = section(named: name, segment: segment) else { continue }
            let bytes = read(s, cap: left)
            left -= bytes.count
            if needles.contains(where: { bytes.contains(bytes: $0) }) { return true }
        }
        return false
    }
}

extension Array where Element == UInt8 {
    /// Whether `needle` occurs anywhere in these bytes (memmem).
    func contains(bytes needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= count else { return false }
        return withUnsafeBytes { h in needle.withUnsafeBytes { n in memmem(h.baseAddress!, h.count, n.baseAddress!, n.count) != nil } }
    }

    /// The first occurrence of `needle` at an index that is a multiple of `alignment`.
    func firstIndex(of needle: [UInt8], alignedTo alignment: Int) -> Int? {
        guard !needle.isEmpty, needle.count <= count else { return nil }
        var i = 0
        while i <= count - needle.count {
            if self[i] == needle[0], self[i..<(i + needle.count)].elementsEqual(needle) { return i }
            i += alignment
        }
        return nil
    }
}
