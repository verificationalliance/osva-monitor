import Foundation

/// One pinned dependency read from a lockfile.
public struct Dependency: Hashable, Codable, Sendable {
    public var ecosystem: Ecosystem
    public var name: String
    public var version: String
    public init(ecosystem: Ecosystem, name: String, version: String) { self.ecosystem = ecosystem; self.name = name; self.version = version }
}

/// Reads lockfiles exactly as the site's own scanner does: this is a line-by-line port of `parseDeps` in
/// site/formalinformer/app.js, so a lockfile gives the same packages in the app as on the site's "Scan dependencies"
/// page. Tests compare its output with what the JavaScript function gives for every fixture
/// (Tests/OSVAKitTests/Fixtures/lockfiles, expectations made by make-lockfile-expectations.mjs).
/// When parseDeps changes, change this to match.
public enum LockfileParser {
    public struct Parsed: Sendable {
        public var dependencies: [Dependency]
        /// Package URLs of ecosystems the site does not check ("name@version"), from SBOMs.
        public var skipped: [String]
    }

    public static func parse(_ text: String, filename: String) -> Parsed {
        var out = OrderedDependencies(), skipped: [String] = []
        let f = filename.lowercased()

        // JSON lockfiles and SBOMs
        var json: Any?
        if Regex("^\\s*[\\{\\[]").test(text), let data = text.data(using: .utf8) {
            json = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        }
        if let j = json as? [String: Any] {
            parseJSON(j, into: &out, skipped: &skipped)
            return Parsed(dependencies: out.values, skipped: skipped)
        }
        if json != nil { return Parsed(dependencies: [], skipped: []) }     // valid JSON, but not an object

        // pnpm-lock.yaml
        if Regex("^lockfileVersion:", multiline: true).test(text) || f.contains("pnpm-lock") {
            for m in Regex(#"^ {2}['"]?/?((?:@[^@/\s'"]+/)?[^@/\s'"(]+)@([^():'"\s]+)"#, multiline: true).allMatches(text) {
                out.add(.npm, m[1], m[2])
            }
            return Parsed(dependencies: out.values, skipped: [])
        }
        // yarn.lock (v1 and Berry)
        if Regex("^# yarn lockfile|^__metadata:", multiline: true).test(text) || f.contains("yarn.lock") {
            let head = Regex(#"^"?((?:@[^@/\s"]+/)?[^@/\s",]+)@"#)
            let version = Regex(#"^\s+version:?\s+"?([^"\s]+)"?"#, multiline: true)
            for block in Regex(#"\n(?=\S)"#).split(text) {
                if let h = head.firstMatch(block), let v = version.firstMatch(block) { out.add(.npm, h[1], v[1]) }
            }
            return Parsed(dependencies: out.values, skipped: [])
        }
        // Cargo.lock and poetry.lock
        if text.contains("[[package]]") {
            let ecosystem: Ecosystem = f.contains("cargo") || Regex(#"^source = "registry\+https://github.com/rust-lang"#, multiline: true).test(text) ? .crates : .pypi
            let name = Regex(#"^name\s*=\s*"([^"]+)""#, multiline: true)
            let version = Regex(#"^version\s*=\s*"([^"]+)""#, multiline: true)
            let registry = Regex(#"^source\s*=\s*"registry\+"#, multiline: true)
            for block in text.components(separatedBy: "[[package]]").dropFirst() {
                // local and git crates are not on crates.io
                if let n = name.firstMatch(block), let v = version.firstMatch(block), ecosystem != .crates || registry.test(block) {
                    out.add(ecosystem, n[1], v[1])
                }
            }
            return Parsed(dependencies: out.values, skipped: [])
        }
        // go.mod and go.sum
        if Regex(#"^module\s+\S+"#, multiline: true).test(text) || f.hasSuffix("go.mod") || f.hasSuffix("go.sum") {
            for m in Regex(#"^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/[^\s]+)\s+(v[^\s/]+?)(?:/go\.mod)?(?:\s|$)"#, multiline: true).allMatches(text) {
                out.add(.go, m[1], m[2])
            }
            if let tc = Regex(#"^(?:toolchain go|go )(\d+\.\d+(?:\.\d+)?)\s*$"#, multiline: true).firstMatch(text), let v = tc[1] {
                out.add(.go, "stdlib", v.split(separator: ".").count == 2 ? v + ".0" : v)
            }
            return Parsed(dependencies: out.values, skipped: [])
        }
        // Gemfile.lock
        if Regex(#"^GEM$|^ {4}\S+ \(\d"#, multiline: true).test(text) {
            for m in Regex(#"^ {4}([A-Za-z0-9_.-]+) \(([^)\s,]+)\)"#, multiline: true).allMatches(text) { out.add(.rubygems, m[1], m[2]) }
            return Parsed(dependencies: out.values, skipped: [])
        }
        // requirements*.txt (anything else is read as one)
        let requirement = Regex(#"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)"#)
        for line in text.components(separatedBy: "\n") {
            if let m = requirement.firstMatch(line) { out.add(.pypi, m[1], m[2]) }
        }
        return Parsed(dependencies: out.values, skipped: [])
    }

    private static func parseJSON(_ j: [String: Any], into out: inout OrderedDependencies, skipped: inout [String]) {
        func purl(_ p: Any?) {
            guard let s = p as? String, let m = Regex(#"^pkg:([a-z]+)/(.+?)@([^?#]+)"#).firstMatch(s), let kind = m[1], let rawName = m[2], let rawVersion = m[3] else { return }
            let map: [String: Ecosystem] = ["npm": .npm, "pypi": .pypi, "cargo": .crates, "golang": .go, "maven": .maven, "gem": .rubygems,
                                            "composer": .packagist, "nuget": .nuget, "pub": .pub, "hex": .hex]
            let name = decodeURIComponent(rawName), version = decodeURIComponent(rawVersion)
            guard let ecosystem = map[kind] else { skipped.append(name + "@" + version); return }
            out.add(ecosystem, ecosystem == .maven ? replacingFirst("/", with: ":", in: name) : name, version)
        }

        if let packages = j["packages"] as? [String: Any], truthy(j["lockfileVersion"]) {             // package-lock v2, v3
            for k in packages.keys.sorted() {
                guard let v = packages[k] as? [String: Any], k.contains("node_modules/"), truthy(v["version"]), !truthy(v["link"]),
                      !((v["resolved"] as? String) ?? "").hasPrefix("file:") else { continue }
                let name = truthy(v["name"]) ? jsString(v["name"]) : k.components(separatedBy: "node_modules/").last
                out.add(.npm, name, jsString(v["version"]))
            }
        } else if truthy(j["dependencies"]), truthy(j["lockfileVersion"]) {                         // package-lock v1, shrinkwrap
            func walk(_ d: Any?) {
                guard let deps = d as? [String: Any] else { return }
                for k in deps.keys.sorted() {
                    let v = deps[k] as? [String: Any] ?? [:]
                    if truthy(v["version"]) { out.add(.npm, k, jsString(v["version"])) }
                    walk(v["dependencies"])
                }
            }
            walk(j["dependencies"])
        } else if truthy(j["default"]) || truthy(j["develop"]) {                                     // Pipfile.lock
            for section in [j["default"], j["develop"]] {
                guard let s = section as? [String: Any] else { continue }
                for k in s.keys.sorted() {
                    let v = (s[k] as? [String: Any])?["version"]
                    var version = truthy(v) ? jsString(v) ?? "" : ""
                    if version.hasPrefix("==") { version.removeFirst(2) }
                    out.add(.pypi, k, version)
                }
            }
        } else if let packages = j["packages"] as? [Any], truthy(j["packages-dev"]) || truthy(j["content-hash"]) {   // composer.lock
            for p in packages + (j["packages-dev"] as? [Any] ?? []) {
                guard let p = p as? [String: Any], var version = jsString(p["version"]) else { continue }
                if version.hasPrefix("v") { version.removeFirst() }
                out.add(.packagist, jsString(p["name"]), version)
            }
        } else if truthy(j["components"]) {                                                          // CycloneDX
            func walk(_ cs: Any?) {
                for c in cs as? [Any] ?? [] {
                    guard let c = c as? [String: Any] else { continue }
                    purl(c["purl"]); walk(c["components"])
                }
            }
            walk(j["components"])
        } else if truthy(j["spdxVersion"]) {                                                         // SPDX
            for p in j["packages"] as? [Any] ?? [] {
                for r in (p as? [String: Any])?["externalRefs"] as? [Any] ?? [] {
                    if let r = r as? [String: Any], r["referenceType"] as? String == "purl" { purl(r["referenceLocator"]) }
                }
            }
        }
    }

    // JavaScript's truthiness and String(), for values from JSONSerialization.
    private static func truthy(_ v: Any?) -> Bool {
        switch v {
        case nil, is NSNull: return false
        case let s as String: return !s.isEmpty
        case let n as NSNumber: return n.doubleValue != 0 && !n.doubleValue.isNaN
        default: return true
        }
    }

    private static func jsString(_ v: Any?) -> String? {
        switch v {
        case let s as String: return s
        case let n as NSNumber: return CFGetTypeID(n) == CFBooleanGetTypeID() ? (n.boolValue ? "true" : "false") : n.stringValue
        default: return nil
        }
    }

    /// Like JavaScript's decodeURIComponent, except that malformed input is kept as it is instead of throwing.
    private static func decodeURIComponent(_ s: String) -> String { s.removingPercentEncoding ?? s }

    private static func replacingFirst(_ target: String, with replacement: String, in s: String) -> String {
        guard let r = s.range(of: target) else { return s }
        return s.replacingCharacters(in: r, with: replacement)
    }
}

/// parseDeps' `Map` keyed by `${eco}|${name}|${version}`: first occurrence wins its place, duplicates are dropped.
struct OrderedDependencies {
    private(set) var values: [Dependency] = []
    private var seen = Set<Dependency>()

    mutating func add(_ ecosystem: Ecosystem, _ name: String?, _ version: String?) {
        guard let name, !name.isEmpty, let version, PackageNames.matchesSiteVersionPattern(version) else { return }
        let d = Dependency(ecosystem: ecosystem, name: name, version: version)
        if seen.insert(d).inserted { values.append(d) }
    }
}
