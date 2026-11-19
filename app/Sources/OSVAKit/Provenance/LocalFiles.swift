import Foundation

/// Reading the Mac's own metadata files for provenance, bounded: at most a given number of bytes, only regular files,
/// and only inside the roots given. A symbolic link that points out of a package's root (a METADATA that is really
/// ~/.ssh/id_ed25519) is not read. Nothing read here leaves the Mac.
enum LocalFiles {
    /// The real path of each root, for the containment test.
    static func roots(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.map(Paths.realPath).filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Whether `path`, with every link resolved, is one of `roots` or inside one (roots already real).
    static func isInside(_ path: String, _ roots: [String]) -> Bool {
        let real = Paths.realPath(path)
        return roots.contains { real == $0 || real.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }
    }

    /// At most `limit` bytes of the regular file at `path`, if it lies inside `roots`.
    static func read(_ path: String, limit: Int, within roots: [String]) -> Data? {
        let real = Paths.realPath(path)
        guard roots.contains(where: { real == $0 || real.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) else { return nil }
        let fd = open(real, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)         // a link swapped in after realpath is refused
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }   // no fifos, devices, folders
        let wanted = min(limit, max(Int(st.st_size), 0))
        guard wanted > 0 else { return Data() }
        var data = Data(count: wanted)
        let got = data.withUnsafeMutableBytes { buffer -> Int in
            var total = 0
            while total < wanted {
                let n = Darwin.read(fd, buffer.baseAddress! + total, wanted - total)
                if n <= 0 { break }
                total += n
            }
            return total
        }
        return data.prefix(got)
    }

    static func text(_ path: String, limit: Int, within roots: [String]) -> String? {
        read(path, limit: limit, within: roots).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Up to `limit` entries of a directory, sorted (none when it is not a readable directory).
    static func list(_ path: String, limit: Int) -> [String] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: path) else { return [] }
        return Array(names.sorted().prefix(limit))
    }

    /// The modification time of a file or folder, without following a link at the end of the path.
    static func modified(_ path: String) -> Date? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))
    }

    static func exists(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0
    }

    static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}
