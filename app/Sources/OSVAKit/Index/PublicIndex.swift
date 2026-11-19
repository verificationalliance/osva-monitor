import Foundation

/// The site's public app index, https://verificationalliance.org/data/app-index.tsv: every package that has ever had
/// an advisory or a malicious report (all time), and every project the site grades. Downloading it tells the server
/// nothing about this Mac; it is what lets the app decide, locally, which packages are worth asking about.
///
/// Format, tab-separated, one record per line (unknown record types are ignored, so the server can add some):
///
///     #osva-app-index  1  <generated_at>  <n packages>  <n projects>
///     P  <slug>  <name>  <repo>          a graded project
///     K  <ecosystem>  <name>             a package (PyPI names normalised, others as OSV writes them)
///     R  <manager>  <package>  <slug>    a system package manager's package that is a graded project's software
///                                        (manager: "macports", "nix" or "conda"); matched on the Mac, never sent
public struct PublicIndex: Sendable {
    public struct Project: Hashable, Sendable {
        public var slug: String
        public var name: String
        /// "github.com/openssl/openssl", "gitlab.freedesktop.org/poppler/poppler", ...; may be empty.
        public var repo: String
        public init(slug: String, name: String, repo: String) { self.slug = slug; self.name = name; self.repo = repo }
    }

    public let generatedAt: String
    public let projects: [Project]
    public let packageCount: Int
    /// Every package's and every project's key, laid out for `osva_select`.
    public let keys: KeyList

    private let projectsBySlug: [String: Project]
    private let projectsByRepo: [String: Project]
    /// "<manager>\u{1F}<package>" -> project slug, from the R lines.
    private let managedProjects: [String: String]

    /// For tests and previews: an index of these packages and projects.
    public init(generatedAt: String, packages: [(Ecosystem, String)], projects: [Project], managed: [(manager: String, package: String, slug: String)] = []) {
        self.init(generatedAt: generatedAt, packageKeys: KeyList(packages.map { PackageNames.key($0.0, $0.1) }), packageCount: packages.count, projects: projects,
                  managed: Dictionary(managed.map { ($0.manager + "\u{1F}" + $0.package, $0.slug) }, uniquingKeysWith: { a, _ in a }))
    }

    init(generatedAt: String, packageKeys: KeyList, packageCount: Int, projects: [Project], managed: [String: String] = [:]) {
        self.generatedAt = generatedAt; self.projects = projects; self.packageCount = packageCount
        managedProjects = managed
        projectsBySlug = Dictionary(projects.map { ($0.slug, $0) }, uniquingKeysWith: { a, _ in a })
        projectsByRepo = Dictionary(projects.filter { !$0.repo.isEmpty }.map { ($0.repo.lowercased(), $0) }, uniquingKeysWith: { a, _ in a })
        keys = packageKeys.appending(projects.map { PackageNames.projectKey($0.slug) })
    }

    public func project(slug: String) -> Project? { projectsBySlug[slug] }
    /// The project whose repository is exactly this key ("github.com/owner/repo", lowercase).
    public func project(repo: String) -> Project? { projectsByRepo[repo.lowercased()] }
    /// The graded project a MacPorts, Nix or conda package is (its R line), if the index has that project.
    public func project(manager: String, package: String) -> Project? {
        managedProjects[manager + "\u{1F}" + package].flatMap { projectsBySlug[$0] }
    }
    /// How many R lines the index has.
    public var managedCount: Int { managedProjects.count }

    public enum DecodeError: Error, Equatable { case notAnIndex(String) }

    /// Reads app-index.tsv. Package lines (hundreds of thousands) are read as bytes, straight into the key list.
    public static func decode(_ data: Data) throws -> PublicIndex {
        let header = Array("#osva-app-index\t".utf8)
        guard data.count > header.count, data.prefix(header.count).elementsEqual(header) else {
            throw DecodeError.notAnIndex("app-index.tsv does not start with #osva-app-index")
        }
        var keyBytes: [UInt8] = [], offsets: [Int] = [], lengths: [Int] = []
        keyBytes.reserveCapacity(data.count)
        var projects: [Project] = [], managed: [String: String] = [:], generatedAt = "", formatOK = false
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var start = 0
            while start < bytes.count {
                var end = start
                while end < bytes.count && bytes[end] != 0x0A { end += 1 }
                var lineEnd = end
                if lineEnd > start && bytes[lineEnd - 1] == 0x0D { lineEnd -= 1 }      // tolerate CRLF
                if lineEnd > start {
                    let first = bytes[start]
                    if first == UInt8(ascii: "K"), lineEnd - start > 2, bytes[start + 1] == 0x09 {
                        // "K\t<eco>\t<name>" -> key "<eco>\u{1F}<name>"
                        var tab = start + 2
                        while tab < lineEnd && bytes[tab] != 0x09 { tab += 1 }
                        if tab < lineEnd, tab > start + 2, lineEnd > tab + 1 {
                            var nameEnd = tab + 1
                            while nameEnd < lineEnd && bytes[nameEnd] != 0x09 { nameEnd += 1 }   // ignore extra columns
                            offsets.append(keyBytes.count)
                            keyBytes.append(contentsOf: bytes[(start + 2)..<tab])
                            keyBytes.append(0x1F)
                            keyBytes.append(contentsOf: bytes[(tab + 1)..<nameEnd])
                            lengths.append(keyBytes.count - offsets[offsets.count - 1])
                        }
                    } else if first == UInt8(ascii: "P") || first == UInt8(ascii: "#") || first == UInt8(ascii: "R") {
                        let fields = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<lineEnd]), as: UTF8.self)
                            .split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
                        if fields[0] == "R", fields.count >= 4, !fields[1].isEmpty, !fields[2].isEmpty, !fields[3].isEmpty {
                            managed[fields[1] + "\u{1F}" + fields[2]] = managed[fields[1] + "\u{1F}" + fields[2]] ?? fields[3]
                        } else if fields[0] == "P", fields.count >= 3, !fields[1].isEmpty {
                            projects.append(Project(slug: fields[1], name: fields[2].isEmpty ? fields[1] : fields[2], repo: fields.count > 3 ? fields[3] : ""))
                        } else if fields[0] == "#osva-app-index", fields.count >= 3 {
                            formatOK = fields[1] == "1"
                            generatedAt = fields[2]
                        }
                    }
                }
                start = end + 1
            }
        }
        guard formatOK else { throw DecodeError.notAnIndex("app-index.tsv is not format 1") }
        return PublicIndex(generatedAt: generatedAt, packageKeys: KeyList(bytes: keyBytes, offsets: offsets, lengths: lengths),
                           packageCount: offsets.count, projects: projects, managed: managed)
    }
}
