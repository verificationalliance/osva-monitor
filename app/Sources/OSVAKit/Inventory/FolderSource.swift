import Foundation

/// Lockfiles in the project folders the person asked us to watch.
public struct FolderSource: Sendable {
    /// The lockfiles the site's scanner reads, by exact file name (plus requirements*.txt).
    public static let lockfileNames: Set<String> = [
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
        "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock",
    ]

    /// Folders never descended into: installed dependencies (their own lockfiles describe them, not the project),
    /// version control, virtual environments, caches and build output.
    public static let skippedFolders: Set<String> = [
        "node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "Carthage",
        ".git", ".hg", ".svn", "venv", ".venv", "env", ".tox", ".nox", "__pycache__", "site-packages",
        "build", "dist", "out", "target", ".build", "DerivedData", ".next", ".nuxt", ".svelte-kit", ".output",
        ".cache", ".gradle", ".terraform", "coverage", ".turbo", ".parcel-cache",
    ]

    public static let maxDepth = 6
    /// A lockfile larger than this is not read (no real lockfile is this large; a mistake should not stall a scan).
    public static let maxFileSize = 32 * 1024 * 1024

    public static func isLockfile(_ fileName: String) -> Bool {
        lockfileNames.contains(fileName) || (fileName.hasPrefix("requirements") && fileName.hasSuffix(".txt"))
    }

    let roots: [URL]
    public init(roots: [URL]) { self.roots = roots }

    public func collect() -> (packages: [InstalledPackage], report: SourceReport) {
        var packages: [InstalledPackage] = [], lockfiles = 0
        for root in roots {
            for file in Self.lockfiles(in: root) {
                lockfiles += 1
                packages += Self.packages(in: file, root: root)
            }
        }
        let detail = roots.isEmpty ? "no folders chosen"
            : "\(GlobalPackageSources.count(roots.count, "folder")), \(GlobalPackageSources.count(lockfiles, "lockfile"))"
        return (packages, SourceReport(kind: .folders, available: !roots.isEmpty, count: packages.count, detail: detail))
    }

    /// The packages one lockfile pins.
    public static func packages(in file: URL, root: URL) -> [InstalledPackage] {
        guard let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= maxFileSize,
              let data = try? Data(contentsOf: file) else { return [] }
        let parsed = LockfileParser.parse(String(decoding: data, as: UTF8.self), filename: file.lastPathComponent)
        let direct = Manifests.directNames(forLockfile: file)
        return parsed.dependencies.map { dep in
            InstalledPackage(ecosystem: dep.ecosystem, name: dep.name, version: dep.version,
                             origin: .folder(root: root.path, lockfile: file.path, direct: direct.map { Manifests.isDirect(dep.name, dep.ecosystem, in: $0) }))
        }
    }

    /// Lockfiles under `root`, at most `maxDepth` folders down, skipping `skippedFolders`, hidden folders, app bundles
    /// and symbolic links.
    public static func lockfiles(in root: URL, maxDepth: Int = maxDepth) -> [URL] {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey]
        guard let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: keys,
                                                     options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { return [] }
        var out: [URL] = []
        while let url = e.nextObject() as? URL {
            let values = try? url.resourceValues(forKeys: Set(keys))
            if values?.isSymbolicLink == true { continue }
            if values?.isDirectory == true {
                if skippedFolders.contains(url.lastPathComponent) || e.level >= maxDepth { e.skipDescendants() }
                continue
            }
            if isLockfile(url.lastPathComponent) {
                // keep the folder as the person chose it ("/var/…", not "/private/var/…")
                out.append(URL(fileURLWithPath: Paths.underGivenRoot(url.path, root: root.path)))
            }
        }
        return out.sorted { $0.path < $1.path }
    }
}
