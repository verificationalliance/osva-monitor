import Foundation

/// One Python's installed distributions, read from the `.dist-info` and `.egg-info` folders of its site-packages
/// directories: who asked for each (pip's REQUESTED), which tool installed it (INSTALLER), whether it is an editable
/// or folder install (direct_url.json), when it was installed, and what each requires (Requires-Dist), so who needs whom.
///
/// Bounded: at most `maxDistributions` folders per directory and `maxMetadataBytes` of each file; only files inside the
/// directories given (and, for a Homebrew Python, Homebrew's Cellar, where Homebrew keeps the packages it links in).
/// Garbage is skipped; when anything could not be read, `complete` is false and nobody claims that nothing needs a
/// package.
///
/// A requirement only for an extra ("…; extra == 'standard'") counts when an installed package asks for that extra
/// ("uvicorn[standard]"); pip does not record the extras a person asked for themselves, so a package named by any
/// extra is never called unused.
public struct SitePackages: Sendable {
    public struct Requirement: Hashable, Sendable {
        /// As the dependent writes it ("Starlette").
        public var name: String
        /// Normalised as PEP 503 says ("starlette").
        public var key: String
        /// "<0.49.0,>=0.40.0" as written (spaces removed); "" when any version will do.
        public var specifier: String
        /// The environment marker, when there is one that is not obviously false on this Mac.
        public var marker: String?
        /// The extras it asks of the package it names: ["standard"] for "uvicorn[standard]".
        public var extras: [String] = []
        /// The dependent's own extras it belongs to (normalised); empty when it always applies.
        public var forExtras: [String] = []
    }

    /// What direct_url.json says about where a distribution came from.
    public enum Source: Hashable, Sendable {
        /// `pip install -e <folder>`: your own project, live from its folder.
        case editable(folder: String?)
        /// `pip install <folder>`.
        case folder(String?)
        /// From a version-control URL.
        case vcs
        /// From an archive or wheel file or URL.
        case archive
    }

    public struct Distribution: Hashable, Sendable {
        /// As its METADATA writes it.
        public var name: String
        public var key: String
        public var version: String
        /// Its `.dist-info` or `.egg-info`.
        public var metadataPath: String
        public var site: String
        public var requirements: [Requirement]
        /// True when REQUESTED is there (someone asked for it by name); false when its installer writes REQUESTED and
        /// did not; nil when that cannot be told.
        public var requested: Bool?
        /// INSTALLER's first line: "pip", "uv", "Poetry 2.3.2", "brew".
        public var installer: String?
        public var source: Source?
        /// The metadata folder's modification time: when it was installed.
        public var installed: Date?

        /// Your own project: installed editable, or from a folder.
        public var isProject: Bool {
            switch source { case .editable?, .folder?: return true; default: return false }
        }

        public var projectFolder: String? {
            switch source { case let .editable(f)?: return f; case let .folder(f)?: return f; default: return nil }
        }
    }

    public static let maxDistributions = 5000
    public static let maxMetadataBytes = 256 * 1024
    static let maxRequirements = 1000
    static let maxRecordBytes = 512 * 1024

    public let sites: [String]
    public let distributions: [Distribution]
    /// False when some metadata could not be read or made no sense.
    public let complete: Bool
    let roots: [String]
    private let byKey: [String: [Int]]
    private let dependentsByKey: [String: [(index: Int, requirement: Requirement)]]
    /// Packages that some installed package names for an extra nobody here is known to have asked for.
    private let namedByExtras: Set<String>

    /// Reads the distributions in these directories (one Python's site-packages, its user site).
    public init(sites: [String]) {
        var seenSites = Set<String>()
        let sites = sites.filter { !$0.isEmpty && seenSites.insert(($0 as NSString).standardizingPath).inserted }
        self.sites = sites
        let roots = LocalFiles.roots(sites + sites.compactMap(Self.homebrewCellar))
        self.roots = roots
        var dists: [Distribution] = [], complete = true
        for site in sites {
            let entries = LocalFiles.list(site, limit: Self.maxDistributions * 4)
            let metadata = entries.filter { $0.hasSuffix(".dist-info") || $0.hasSuffix(".egg-info") }
            if metadata.count > Self.maxDistributions { complete = false }
            // Each folder is read on its own, side by side.
            let folders = Array(metadata.prefix(Self.maxDistributions))
            var results = [Read?](repeating: nil, count: folders.count)
            results.withUnsafeMutableBufferPointer { out in
                let buffer = out
                DispatchQueue.concurrentPerform(iterations: folders.count) { i in
                    buffer[i] = Self.read((site as NSString).appendingPathComponent(folders[i]), site: site, roots: roots)
                }
            }
            var siteDists: [Distribution] = []
            for r in results {
                switch r {
                case let .distribution(d)?: siteDists.append(d)
                case .unreadable?: complete = false
                case nil: break                                  // no METADATA: a half-removed folder pip ignores too
                }
            }
            // An installer that writes REQUESTED (pip since 20.2) wrote none here: the site predates it, so its absence
            // says nothing.
            if !siteDists.contains(where: { $0.requested == true }) {
                for i in siteDists.indices where siteDists[i].requested == false { siteDists[i].requested = nil }
            }
            dists += siteDists
        }
        distributions = dists
        self.complete = complete
        // The extras in use: those installed packages ask for, and those their own active requirements ask for.
        var active: [String: Set<String>] = [:]
        func applies(_ r: Requirement, of d: Distribution) -> Bool {
            r.forExtras.isEmpty || r.forExtras.contains { active[d.key]?.contains($0) == true }
        }
        for _ in 0..<20 {
            var changed = false
            for d in dists {
                for r in d.requirements where !r.extras.isEmpty && applies(r, of: d) {
                    for x in r.extras where active[r.key, default: []].insert(Self.key(x)).inserted { changed = true }
                }
            }
            if !changed { break }
        }
        var byKey: [String: [Int]] = [:], dependents: [String: [(Int, Requirement)]] = [:], namedByExtras = Set<String>()
        for (i, d) in dists.enumerated() {
            byKey[d.key, default: []].append(i)
            for r in d.requirements where r.key != d.key {
                if applies(r, of: d) { dependents[r.key, default: []].append((i, r)) } else { namedByExtras.insert(r.key) }
            }
        }
        self.byKey = byKey
        dependentsByKey = dependents.mapValues { list in
            list.sorted { (dists[$0.0].key, $0.1.specifier) < (dists[$1.0].key, $1.1.specifier) }
        }
        self.namedByExtras = namedByExtras
    }

    /// For a site inside a Homebrew prefix, that prefix's Cellar: Homebrew links the Python packages a formula installs
    /// from there.
    static func homebrewCellar(_ site: String) -> String? {
        for prefix in ["/opt/homebrew/", "/usr/local/"] where site.hasPrefix(prefix) { return prefix + "Cellar" }
        return nil
    }

    // MARK: Questions

    /// Whether an installed package names it for one of its extras that nobody here is known to use: it may be in use.
    public func isNamedByAnExtra(_ name: String) -> Bool { namedByExtras.contains(Self.key(name)) }

    /// The installed distribution of this name (any spelling), at this version when given.
    public func distribution(_ name: String, version: String? = nil) -> Distribution? {
        distribution(key: Self.key(name), version: version)
    }

    func distribution(key: String, version: String? = nil) -> Distribution? {
        let candidates = (byKey[key] ?? []).map { distributions[$0] }
        return candidates.first { version == nil || $0.version == version } ?? (version == nil ? nil : candidates.first)
    }

    /// The distributions that require `name`, each with its requirement (one per requirement line: a dependent may
    /// list the package twice, under different markers).
    public func dependents(of name: String) -> [(distribution: Distribution, requirement: Requirement)] {
        dependents(key: Self.key(name))
    }

    func dependents(key: String) -> [(distribution: Distribution, requirement: Requirement)] {
        (dependentsByKey[key] ?? []).map { (distributions[$0.index], $0.requirement) }
    }

    /// The chain of dependents from `name` up to whoever asked for it: your own project (an editable or folder
    /// install) wherever it is within `maxDepth`, else the nearest package installed by name, else something nothing
    /// needs. `chain` starts with what needs the package directly. Nil when nothing needs it.
    public func chainToTop(of name: String, maxDepth: Int = 8, maxVisited: Int = 5000) -> (chain: [Distribution], top: ProvenanceText.Top)? {
        let start = Self.key(name)
        var parent: [String: String] = [:], visited: Set<String> = [start], frontier = [start]
        var project: String?, requested: String?, fallback: String?
        func path(to key: String) -> [Distribution] {
            var keys: [String] = [], k = key
            while k != start, keys.count <= maxDepth + 1 { keys.append(k); k = parent[k] ?? start }
            return keys.reversed().compactMap { distribution(key: $0) }
        }
        for _ in 0..<maxDepth where !frontier.isEmpty && project == nil && visited.count < maxVisited {
            var next: [String] = []
            for k in frontier {
                for (d, _) in dependents(key: k) where visited.insert(d.key).inserted {
                    parent[d.key] = k
                    next.append(d.key)
                }
            }
            project = project ?? next.first { distribution(key: $0)?.isProject == true }
            requested = requested ?? next.first { distribution(key: $0)?.requested == true }
            fallback = fallback ?? next.first { dependentsByKey[$0]?.isEmpty ?? true }
            frontier = next
        }
        if let p = project { return (path(to: p), .project) }
        if let r = requested { return (path(to: r), .requested) }
        if let f = fallback { return (path(to: f), .unknown) }
        guard let first = dependents(of: name).first else { return nil }
        return ([first.distribution], .unknown)
    }

    /// The package's own folder (or module file) in its site, from top_level.txt, else RECORD, else its name; its
    /// metadata folder when none is there.
    public func location(of d: Distribution) -> String {
        let meta = d.metadataPath
        var candidates: [String] = []
        if let top = LocalFiles.text((meta as NSString).appendingPathComponent("top_level.txt"), limit: 8 * 1024, within: roots) {
            candidates = top.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.contains("..") }.prefix(50).map { String($0) }
        }
        if candidates.isEmpty, let record = LocalFiles.text((meta as NSString).appendingPathComponent("RECORD"), limit: Self.maxRecordBytes, within: roots) {
            var counts: [String: Int] = [:], order: [String] = []
            for line in record.split(whereSeparator: \.isNewline).prefix(50_000) {
                guard let first = line.split(separator: ",", maxSplits: 1).first?.split(separator: "/").first.map(String.init),
                      !first.isEmpty, first != "..", first != "__pycache__", !first.hasSuffix(".dist-info"), !first.hasSuffix(".egg-info"),
                      !first.hasSuffix(".data"), !first.hasSuffix(".pth") else { continue }
                let top = first.hasSuffix(".py") ? String(first.dropLast(3)) : first
                if counts[top] == nil { order.append(top) }
                counts[top, default: 0] += 1
            }
            candidates = order.sorted { counts[$0]! > counts[$1]! }
        }
        candidates += [d.name, d.name.replacingOccurrences(of: "-", with: "_"), d.name.replacingOccurrences(of: "-", with: "_").lowercased()]
        let ranked = candidates.filter { Self.key($0) == d.key } + candidates.filter { !$0.hasPrefix("_") } + candidates
        for c in ranked {
            for file in [c, c + ".py"] {
                let p = (d.site as NSString).appendingPathComponent(file)
                guard LocalFiles.exists(p) else { continue }
                // A folder shared with other packages ("google" for protobuf): the package's own folder inside it.
                if file == c, Self.key(c) != d.key, let inner = namespaceMember(of: d, in: c), LocalFiles.isDirectory(p + "/" + inner) {
                    return p + "/" + inner
                }
                return p
            }
        }
        return meta
    }

    /// The one folder inside a namespace folder that holds (nearly) all of the package's files, by its RECORD.
    func namespaceMember(of d: Distribution, in folder: String) -> String? {
        guard let record = LocalFiles.text((d.metadataPath as NSString).appendingPathComponent("RECORD"), limit: Self.maxRecordBytes, within: roots)
        else { return nil }
        var counts: [String: Int] = [:], total = 0
        for line in record.split(whereSeparator: \.isNewline).prefix(50_000) {
            let path = line.split(separator: ",", maxSplits: 1).first ?? ""
            let parts = path.split(separator: "/")
            guard parts.count >= 2, parts[0] == folder else { continue }
            total += 1
            if parts.count >= 3, parts[1] != "__pycache__" { counts[String(parts[1]), default: 0] += 1 }
        }
        guard let (inner, n) = counts.max(by: { $0.value < $1.value }), total > 0, Double(n) >= 0.9 * Double(total) else { return nil }
        return inner
    }

    // MARK: Reading

    /// PEP 503: lowercase, every run of "-", "_" and "." one "-" (what PackageNames.indexName does for PyPI, without a
    /// regular expression: it runs for every name and requirement read).
    static func key(_ name: String) -> String {
        guard name.utf8.allSatisfy({ $0 < 0x80 }) else { return PackageNames.indexName(name, in: .pypi) }   // not ASCII: rare
        var out = [UInt8](), inRun = false
        out.reserveCapacity(name.utf8.count)
        for b in name.utf8 {
            if b == 0x2D || b == 0x5F || b == 0x2E {                     // - _ .
                if !inRun { out.append(0x2D); inRun = true }
            } else {
                out.append(b >= 0x41 && b <= 0x5A ? b + 0x20 : b); inRun = false
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    enum Read { case distribution(Distribution), unreadable }

    /// One metadata folder: a distribution, or unreadable (no permission, not text, no name); nil when it has no
    /// METADATA at all.
    static func read(_ path: String, site: String, roots: [String]) -> Read? {
        let entry = (path as NSString).lastPathComponent
        let isDist = entry.hasSuffix(".dist-info")
        let stem = String(entry.dropLast(isDist ? 10 : 9))
        let parts = stem.split(separator: "-", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        var name = parts.first ?? "", version = parts.count > 1 ? parts[1] : ""
        var requirements: [Requirement] = []
        let isFolder = LocalFiles.isDirectory(path)
        guard isFolder || !isDist else { return .unreadable }
        let headersFile = isDist ? "METADATA" : "PKG-INFO"
        let headersPath = isFolder ? (path as NSString).appendingPathComponent(headersFile) : path
        guard LocalFiles.exists(headersPath) else { return nil }
        guard let text = readHeaders(headersPath, roots: roots) else { return .unreadable }
        let headers = parseHeaders(text)
        if let n = headers.first(where: { $0.0 == "name" })?.1, isPlausibleName(n) { name = n }
        if let v = headers.first(where: { $0.0 == "version" })?.1, !v.isEmpty, v.count <= 100 { version = v }
        guard isPlausibleName(name), !version.isEmpty else { return .unreadable }
        if isDist {
            requirements = headers.lazy.filter { $0.0 == "requires-dist" }.prefix(maxRequirements).compactMap { requirement($0.1) }
        } else if isFolder, let requires = LocalFiles.text((path as NSString).appendingPathComponent("requires.txt"), limit: maxMetadataBytes, within: roots) {
            requirements = eggRequirements(requires)
        }
        var installer: String?, requested: Bool?, source: Source?
        if isFolder {
            installer = LocalFiles.text((path as NSString).appendingPathComponent("INSTALLER"), limit: 256, within: roots)?
                .split(whereSeparator: \.isNewline).first.map { $0.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
            if LocalFiles.exists((path as NSString).appendingPathComponent("REQUESTED")) {
                requested = true
            } else if let i = installer?.lowercased(), i == "pip" || i == "uv" {
                requested = false
            }
            if let data = LocalFiles.read((path as NSString).appendingPathComponent("direct_url.json"), limit: 64 * 1024, within: roots) {
                source = directURL(data)
            }
        }
        return .distribution(Distribution(name: name, key: key(name), version: version, metadataPath: path, site: site,
                                          requirements: requirements, requested: requested, installer: installer, source: source,
                                          installed: LocalFiles.modified(path)))
    }

    /// The distribution in one metadata folder, if it could be read.
    static func distribution(at path: String, site: String, roots: [String]) -> Distribution? {
        if case let .distribution(d)? = read(path, site: site, roots: roots) { return d }
        return nil
    }

    /// The header block of a METADATA or PKG-INFO (everything before the first empty line), at most maxMetadataBytes.
    static func readHeaders(_ path: String, roots: [String]) -> String? {
        let blank = Data("\n\n".utf8)
        guard var data = LocalFiles.read(path, limit: 16 * 1024, within: roots) else { return nil }
        var end = data.range(of: blank)
        if end == nil, data.count == 16 * 1024 {
            data = LocalFiles.read(path, limit: maxMetadataBytes, within: roots) ?? data
            end = data.range(of: blank)
        }
        let headers = end.map { data[..<$0.lowerBound] } ?? data[...]
        guard !headers.contains(0) else { return nil }                                  // not text
        return String(decoding: headers, as: UTF8.self)
    }

    /// RFC 822 headers: "Key: value", a line starting with white space continuing the one before. Keys lowercased.
    static func parseHeaders(_ text: String) -> [(String, String)] {
        var out: [(String, String)] = []
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            let line = raw.hasSuffix("\r") ? raw.dropLast() : raw[...]
            if let first = line.first, first == " " || first == "\t" {
                if !out.isEmpty { out[out.count - 1].1 += " " + line.trimmingCharacters(in: .whitespaces) }
                continue
            }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            guard !key.isEmpty, key.count <= 40 else { continue }
            out.append((key, line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)))
        }
        return out
    }

    private static let nameAtStart = Regex(#"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?)"#)

    static func isPlausibleName(_ s: String) -> Bool {
        guard let m = nameAtStart.firstMatch(s), let n = m[1] else { return false }
        return n == s.trimmingCharacters(in: .whitespaces)
    }

    /// One Requires-Dist (PEP 508): "starlette<0.49.0,>=0.40.0", "starlette (>=0.30.0,<1.0.0)", "uvicorn[standard]>=0.29",
    /// "pywin32; sys_platform == 'win32'", "pytest; extra == 'dev'". Nil under a marker that is obviously false on this
    /// Mac; one only for an extra keeps the extras it is for in `forExtras`.
    static func requirement(_ raw: String) -> Requirement? {
        let parts = raw.split(separator: ";", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let spec = parts.first, let m = nameAtStart.firstMatch(spec), let name = m[1] else { return nil }
        let marker = parts.count > 1 && !parts[1].isEmpty ? parts[1] : nil
        if let marker, obviouslyFalse(marker) { return nil }
        var rest = spec.dropFirst(m[0]!.count).trimmingCharacters(in: .whitespaces)
        var extras: [String] = []
        if rest.hasPrefix("["), let close = rest.firstIndex(of: "]") {
            extras = rest[rest.index(after: rest.startIndex)..<close].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }.prefix(20).map { String($0) }
            rest = rest[rest.index(after: close)...].trimmingCharacters(in: .whitespaces)
        }
        if rest.hasPrefix("("), rest.hasSuffix(")") { rest = String(rest.dropFirst().dropLast()) }
        if !rest.hasPrefix("@") { rest = rest.replacingOccurrences(of: " ", with: "") }
        let forExtras = marker.map { extraName.allMatches($0).compactMap { $0[1].map(key) } } ?? []
        return Requirement(name: name, key: key(name), specifier: String(rest.prefix(200)), marker: marker, extras: extras, forExtras: forExtras)
    }

    /// An egg-info's requires.txt: unconditional lines first, then "[extra]", "[extra:marker]" and "[:marker]" sections.
    static func eggRequirements(_ text: String) -> [Requirement] {
        var out: [Requirement] = [], section: (extra: String?, marker: String?) = (nil, nil)
        for raw in text.split(whereSeparator: \.isNewline).prefix(maxRequirements) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                let inner = line.dropFirst().dropLast()
                let bits = inner.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
                section = ((bits.first ?? "").isEmpty ? nil : bits[0], bits.count > 1 && !bits[1].isEmpty ? bits[1] : nil)
                continue
            }
            let conditions = [section.marker.map { "(\($0))" }, section.extra.map { "extra == \"\($0)\"" }].compactMap { $0 }
            if let r = requirement(conditions.isEmpty ? line : "\(line); " + conditions.joined(separator: " and ")) { out.append(r) }
        }
        return out
    }

    private static let extraClause = Regex(#"\bextra\s*(==|!=)"#)
    private static let extraName = Regex(#"\bextra\s*==\s*["']([^"']+)["']"#)
    private static let platformClause = Regex(#"\b(sys_platform|platform_system|os_name)\s*(==|!=)\s*["']([^"']*)["']"#)
    private static let disjunction = Regex(#"\bor\b"#)

    /// A requirement only for an extra ("…; extra == 'serving'"): not installed unless asked for.
    static func onlyForExtras(_ marker: String) -> Bool { extraClause.test(marker) }

    /// Only the plainly false: a conjunction with a clause naming another platform ("sys_platform == 'win32'",
    /// "platform_system != 'Darwin'", "os_name == 'nt'"). Anything with "or", or about Python versions, is kept.
    static func obviouslyFalse(_ marker: String) -> Bool {
        guard !disjunction.test(marker) else { return false }
        let here = ["sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix"]
        for m in platformClause.allMatches(marker) {
            guard let variable = m[1], let op = m[2], let value = m[3], let actual = here[variable] else { continue }
            if (op == "==") != (value == actual) { return true }
        }
        return false
    }

    /// direct_url.json (PEP 610).
    static func directURL(_ data: Data) -> Source? {
        guard let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let url = j["url"] as? String else { return nil }
        let folder = URL(string: url).flatMap { $0.isFileURL ? $0.path : nil }
        if let dir = j["dir_info"] as? [String: Any] {
            return (dir["editable"] as? Bool) == true ? .editable(folder: folder) : .folder(folder)
        }
        if j["vcs_info"] != nil { return .vcs }
        if j["archive_info"] != nil { return .archive }
        return nil
    }
}

/// The installed packages that need a PyPI package, with what each accepts: what a fix must not break.
public struct ReverseDependency: Hashable, Sendable {
    /// The dependent's name, as its METADATA writes it.
    public var dependent: String
    public var version: String
    /// What it accepts, as it writes it ("<0.49.0,>=0.40.0"); "" for any version.
    public var specifier: String
    /// Its environment marker, when it has one that is not obviously false here (kept: it may apply).
    public var marker: String?
    /// True when someone asked for the dependent by name (REQUESTED); false when its installer would have said so and
    /// did not; nil when not known.
    public var requestedByUser: Bool?
    /// The dependent is your own project, installed editable or from a folder.
    public var isProject: Bool
    public var site: String
}

public enum ReverseDependencies {
    /// What, among the distributions installed in `sitePackages` (one Python's site-packages directories, its user
    /// site included), requires `package`; read now, from the files. One entry per requirement line.
    public static func `for`(package: String, in sitePackages: [String]) -> [ReverseDependency] {
        of(package, in: SitePackages(sites: sitePackages))
    }

    public static func of(_ package: String, in site: SitePackages) -> [ReverseDependency] {
        site.dependents(of: package).map { d, r in
            ReverseDependency(dependent: d.name, version: d.version, specifier: r.specifier, marker: r.marker,
                              requestedByUser: d.requested, isProject: d.isProject, site: d.site)
        }
    }

    /// The site-packages directories pip reported for this Python (by its executable) in the inventory.
    public static func sitePackages(of python: PythonEnvironment, in inventory: Inventory) -> [String] {
        var seen = Set<String>(), out: [String] = []
        for p in inventory.packages {
            guard case let .pip(env, _, _) = p.origin, env.executable == python.executable, let site = p.provenance?.path,
                  seen.insert(site).inserted else { continue }
            out.append(site)
        }
        if let user = python.userSite, LocalFiles.isDirectory(user), seen.insert(user).inserted { out.append(user) }
        return out
    }
}
