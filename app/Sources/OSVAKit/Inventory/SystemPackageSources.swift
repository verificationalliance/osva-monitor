import Foundation
import SQLite3

/// MacPorts: the installed, active ports, read from MacPorts' registry database read-only (no `port` run, no lock
/// taken). If the database cannot be read, `port -q installed` is asked instead.
public struct MacPortsSource: Sendable {
    let environment: ToolEnvironment
    let prefix: String

    public init(environment: ToolEnvironment, prefix: String = "/opt/local") {
        self.environment = environment; self.prefix = prefix
    }

    var registry: String { prefix + "/var/macports/registry/registry.db" }

    public func collect() async -> (managed: [ManagedPackage], report: SourceReport) {
        let clock = ContinuousClock(), start = clock.now
        let port = prefix + "/bin/port"
        guard environment.isExecutable(port) else {
            return ([], SourceReport(kind: .macports, available: false, count: 0, detail: "MacPorts not found", seconds: (clock.now - start).seconds))
        }
        var ports = Self.readRegistry(registry), error: String?
        if ports == nil {
            do {
                let r = try await environment.run(port, ["-q", "installed"], timeout: 60)
                if r.status == 0 { ports = Self.parsePortInstalled(String(decoding: r.stdout, as: UTF8.self)) }
                else { error = r.errorText.isEmpty ? "port exited with \(r.status)" : r.errorText }
            } catch let e { error = e.localizedDescription }
        }
        let managed = (ports ?? []).map { ManagedPackage(manager: .macports, name: $0.name, version: $0.version, origin: .macports(port: $0.name)) }
        return (managed, SourceReport(kind: .macports, available: true, count: managed.count, detail: GlobalPackageSources.count(managed.count, "port"),
                                      error: error.map { String($0.prefix(200)) }, seconds: (clock.now - start).seconds))
    }

    /// The registry's active ports (state "installed"; an inactive one is "imaged"). Nil if it cannot be read.
    static func readRegistry(_ path: String) -> [(name: String, version: String)]? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        var db: OpaquePointer?
        let uri = "file:" + (path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "?#%"))) ?? path) + "?mode=ro"
        guard sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK, let db else {
            sqlite3_close(db); return nil
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 2000)
        // MacPorts declares its version column with its own collation; the query does not sort by it, but SQLite wants
        // the name to exist.
        sqlite3_create_collation_v2(db, "VERSION", SQLITE_UTF8, nil, { _, n1, p1, n2, p2 in
            let c = memcmp(p1, p2, Int(min(n1, n2)))
            return c != 0 ? c : n1 - n2
        }, nil)
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT name, version FROM ports WHERE state = 'installed' LIMIT 20000", -1, &stmt, nil) == SQLITE_OK else {
            return nil
        }
        defer { sqlite3_finalize(stmt) }
        var out: [(String, String)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let n = sqlite3_column_text(stmt, 0), let v = sqlite3_column_text(stmt, 1) else { continue }
            let name = String(cString: n), version = String(cString: v)
            if !name.isEmpty, !version.isEmpty { out.append((name, version)) }
        }
        return out
    }

    private static let installedLine = Regex(#"^\s+(\S+) @([^_+\s]+)(?:_[0-9]+)?\S* \(active\)"#)

    /// `port -q installed`: "  curl @8.11.0_0+ssl (active)"; inactive versions are not listed as active.
    public static func parsePortInstalled(_ text: String) -> [(name: String, version: String)] {
        text.split(whereSeparator: \.isNewline).compactMap { line in
            guard let m = installedLine.firstMatch(String(line)), let name = m[1], let version = m[2] else { return nil }
            return (name, version)
        }
    }
}

/// Nix: the packages in this person's Nix profiles and the machine's default profile, from each profile's manifest
/// (manifest.json for `nix profile`, manifest.nix for `nix-env`). Nothing is run.
public struct NixSource: Sendable {
    let environment: ToolEnvironment
    let profiles: [(path: String, shared: Bool)]

    public init(environment: ToolEnvironment, profiles: [(path: String, shared: Bool)]? = nil) {
        self.environment = environment
        self.profiles = profiles ?? Self.defaultProfiles(environment)
    }

    static func defaultProfiles(_ environment: ToolEnvironment) -> [(path: String, shared: Bool)] {
        let home = environment.home.path, user = NSUserName()
        return [(home + "/.nix-profile", false), (home + "/.local/state/nix/profiles/profile", false),
                ("/nix/var/nix/profiles/per-user/\(user)/profile", false), ("/nix/var/nix/profiles/default", true)]
    }

    public func collect() -> (managed: [ManagedPackage], unchecked: [UncheckedItem], report: SourceReport) {
        let clock = ContinuousClock(), start = clock.now
        let nix = environment.firstExecutable(["/nix/var/nix/profiles/default/bin/nix-env", "~/.nix-profile/bin/nix-env",
                                               "/run/current-system/sw/bin/nix-env"] + profiles.map { $0.path + "/bin/nix-env" })
        guard nix != nil else {
            return ([], [], SourceReport(kind: .nix, available: false, count: 0, detail: "Nix not found", seconds: (clock.now - start).seconds))
        }
        var managed: [ManagedPackage] = [], unchecked: [UncheckedItem] = [], seen = Set<String>(), read = 0
        for (path, shared) in profiles {
            let real = Paths.realPath(path)
            guard seen.insert(real).inserted else { continue }
            let elements: [(element: String, storePath: String)]
            let style: NixProfile.Style
            if let json = ReadOnlyFile.head(real + "/manifest.json", max: 16 << 20) {
                elements = Self.parseManifestJSON(json); style = .profile
            } else if let expr = ReadOnlyFile.head(real + "/manifest.nix", max: 16 << 20) {
                elements = Self.parseManifestNix(String(decoding: expr, as: UTF8.self)); style = .env
            } else { continue }
            read += 1
            let profile = NixProfile(path: path, style: style, shared: shared)
            var inProfile = Set<String>()
            for e in elements {
                guard let (name, version) = Self.nameAndVersion(storePath: e.storePath), inProfile.insert(name + "\u{1F}" + version).inserted else { continue }
                if Self.isSnapshot(name: name, version: version) {
                    unchecked.append(UncheckedItem(kind: .nix, bucket: "Nix packages built from a snapshot", item: "\(name) \(version)"))
                    continue
                }
                managed.append(ManagedPackage(manager: .nix, name: name, version: version,
                                              origin: .nix(profile: profile, element: style == .env ? name : e.element)))
            }
        }
        return (managed, unchecked, SourceReport(kind: .nix, available: true, count: managed.count,
                                      detail: "\(GlobalPackageSources.count(managed.count + unchecked.count, "package")) in \(GlobalPackageSources.count(read, "profile"))",
                                      seconds: (clock.now - start).seconds))
    }

    /// manifest.json: version 3 keeps elements by name, versions 1 and 2 in a list (named by index then).
    public static func parseManifestJSON(_ bytes: [UInt8]) -> [(element: String, storePath: String)] {
        guard let root = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else { return [] }
        func store(_ e: Any) -> String? {
            guard let d = e as? [String: Any], (d["active"] as? Bool) ?? true else { return nil }
            return (d["storePaths"] as? [Any])?.first as? String
        }
        if let named = root["elements"] as? [String: Any] {
            return named.keys.sorted().compactMap { k in store(named[k]!).map { (k, $0) } }
        }
        if let list = root["elements"] as? [Any] {
            return list.enumerated().compactMap { i, e in store(e).map { (String(i), $0) } }
        }
        return []
    }

    private static let outPath = Regex(#"outPath = "(/nix/store/[^"]+)""#)

    /// manifest.nix, the list nix-env writes: each derivation's `outPath = "/nix/store/<hash>-<name>-<version>"`.
    public static func parseManifestNix(_ text: String) -> [(element: String, storePath: String)] {
        outPath.allMatches(text).compactMap { m in m[1].map { ("", $0) } }
    }

    static let outputs: Set<String> = ["bin", "dev", "out", "lib", "man", "doc", "info", "devdoc", "debug", "static", "terminfo"]

    /// "/nix/store/<32-char hash>-openssl-3.0.12-bin" -> ("openssl", "3.0.12"), split as Nix splits a derivation name:
    /// the version starts after the first "-" that is not followed by a letter. An output's suffix is not part of it.
    public static func nameAndVersion(storePath: String) -> (name: String, version: String)? {
        let base = (storePath as NSString).lastPathComponent
        guard base.count > 33, base.dropFirst(32).first == "-" else { return nil }
        let full = Array(String(base.dropFirst(33)).utf8)
        guard let i = full.indices.first(where: { full[$0] == UInt8(ascii: "-") && $0 + 1 < full.count && !isLetter(full[$0 + 1]) }) else { return nil }
        let name = String(decoding: full[..<i], as: UTF8.self)
        var version = String(decoding: full[(i + 1)...], as: UTF8.self)
        if let dash = version.lastIndex(of: "-"), outputs.contains(String(version[version.index(after: dash)...])) {
            version = String(version[..<dash])
        }
        guard !name.isEmpty, let first = version.first, first.isNumber, PackageNames.isPlausibleVersion(version) else { return nil }
        return (name, version)
    }

    /// A build of some commit ("foo-unstable-2024-01-01", "bar-0-unstable-2024-01-01"): its version is a date, not a
    /// release a fix can be compared with.
    static func isSnapshot(name: String, version: String) -> Bool {
        name.hasSuffix("-unstable") || version.contains("unstable") || version.contains("-pre")
    }

    private static func isLetter(_ b: UInt8) -> Bool { (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) }
}
