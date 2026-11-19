import Foundation

/// A package the verified core's privacy filter found in the public index, and so may be named to the API.
///
/// Its initialiser is private to this file: the only way to get one is `PrivacyFilter.approve`, which asks
/// `osva_select`. The API client accepts nothing else, so an inventory item that the filter did not pass cannot be
/// put into a request.
public struct ApprovedPackage: Hashable, Sendable {
    public let ecosystem: Ecosystem
    /// The name as the index writes it (byte for byte the index's key).
    public let name: String
    public let version: String
    /// For a PyPI package, the version of the Python it is installed in ("3.9.6"): the server's plan then names only
    /// versions that Python can install. Nil for other ecosystems and for lockfiles.
    public let python: String?
    /// "macos" for software installed on this Mac (its flaws for other systems do not affect it); nil for a project
    /// folder's dependencies, which are usually deployed elsewhere, so every platform's flaws matter.
    public let platform: String?

    fileprivate init(ecosystem: Ecosystem, name: String, version: String, python: String?, platform: String?) {
        self.ecosystem = ecosystem; self.name = name; self.version = version; self.python = python; self.platform = platform
    }

    /// "PyPI urllib3 1.26.5 · Python 3.9.6 · macOS", as listed under "What leaves your Mac".
    public var sentDescription: String {
        "\(ecosystem) \(name) \(version)" + (python.map { " · Python \($0)" } ?? "") + (platform == "macos" ? " · macOS" : "")
    }
    public var cacheKey: String { "\(ecosystem)\u{1F}\(name)\u{1F}\(version)\u{1F}\(python ?? "")\u{1F}\(platform ?? "")" }
    /// The same package and version, whatever the Python (the server answers per package and version).
    public var versionKey: String { "\(ecosystem)\u{1F}\(name)\u{1F}\(version)" }
}

/// A project slug the privacy filter found in the public index.
public struct ApprovedProject: Hashable, Sendable {
    public let slug: String
    fileprivate init(slug: String) { self.slug = slug }
    public var sentDescription: String { "project \(slug)" }
}

/// Decides, through the verified core, what may leave this Mac.
public struct PrivacyFilter: Sendable {
    public let index: PublicIndex
    public init(index: PublicIndex) { self.index = index }

    public struct Result: Sendable {
        /// Each approved package with every installed copy it stands for.
        public var approved: [ApprovedPackage: [InstalledPackage]]
        /// Installed packages that stay on this Mac: not in the index, or with a version no registry would have.
        public var withheld: [InstalledPackage]
    }

    public func approve(_ packages: [InstalledPackage]) -> Result {
        let candidates = packages.filter { Ecosystem.checkable.contains($0.ecosystem) && PackageNames.isPlausibleVersion($0.version) }
        let mask = Core.shared.select(inventory: candidates.map { PackageNames.key($0.ecosystem, $0.name) }, index: index.keys)
        var approved: [ApprovedPackage: [InstalledPackage]] = [:]
        var passed = Set<InstalledPackage>()
        for (p, ok) in zip(candidates, mask) where ok {
            let a = ApprovedPackage(ecosystem: p.ecosystem, name: PackageNames.indexName(p.name, in: p.ecosystem), version: p.version,
                                    python: p.ecosystem == .pypi ? p.origin.pythonVersion : nil,
                                    platform: p.origin.kind == .folders ? nil : "macos")
            approved[a, default: []].append(p)
            passed.insert(p)
        }
        return Result(approved: approved, withheld: packages.filter { !passed.contains($0) })
    }

    public func approve(projects slugs: [String]) -> [ApprovedProject] {
        let unique = Array(Set(slugs)).sorted()
        let mask = Core.shared.select(inventory: unique.map(PackageNames.projectKey), index: index.keys)
        return zip(unique, mask).filter(\.1).map { ApprovedProject(slug: $0.0) }
    }
}
