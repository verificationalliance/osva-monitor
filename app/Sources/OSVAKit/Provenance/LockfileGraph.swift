import Foundation

/// The dependency graph a lockfile records, read from its own structure, so an indirect dependency can be explained as
/// "Needed by body-parser → express (in package.json)". Reads package-lock.json v2/v3 (`packages`), yarn.lock (v1
/// and Berry), pnpm-lock.yaml (v5 to v9), poetry.lock, Cargo.lock, Gemfile.lock, composer.lock, and requirements
/// files compiled by pip-tools ("# via"). Other lockfiles have no graph (nil).
///
/// Bounded: at most `maxNodes` packages, and the search for a chain visits each package once.
public struct LockfileGraph: Sendable {
    public struct Node: Hashable, Sendable {
        public var name: String
        public var version: String
        public var dependencies: [Int]
    }

    public static let maxNodes = 200_000

    public private(set) var nodes: [Node] = []
    /// The project's own (direct) dependencies.
    public private(set) var roots: [Int] = []
    /// package-lock.json only: where each package is installed under the project ("node_modules/a/node_modules/b").
    public private(set) var installPaths: [Int: String] = [:]
    let ecosystem: Ecosystem

    /// The graph of a lockfile's text. `direct` is the manifest's names (Manifests.directNames), for the formats whose
    /// lockfile does not say which packages are the project's own.
    public static func read(_ text: String, filename: String, direct: Set<String>?) -> LockfileGraph? {
        let f = filename.lowercased()
        var g: LockfileGraph?
        switch f {
        case "package-lock.json", "npm-shrinkwrap.json": g = npm(text)
        case "yarn.lock": g = yarn(text, direct: direct)
        case "pnpm-lock.yaml": g = pnpm(text)
        case "poetry.lock": g = toml(text, ecosystem: .pypi, direct: direct)
        case "cargo.lock": g = toml(text, ecosystem: .crates, direct: nil)
        case "gemfile.lock": g = gemfile(text)
        case "composer.lock": g = composer(text, direct: direct)
        default: if f.hasPrefix("requirements") && f.hasSuffix(".txt") { g = pipCompile(text) }
        }
        guard let g, !g.nodes.isEmpty else { return nil }
        return g
    }

    // MARK: Questions

    func same(_ a: String, _ b: String) -> Bool {
        switch ecosystem {
        case .pypi: return PackageNames.indexName(a, in: .pypi) == PackageNames.indexName(b, in: .pypi)
        case .crates: return a.replacingOccurrences(of: "_", with: "-") == b.replacingOccurrences(of: "_", with: "-")
        case .packagist: return a.lowercased() == b.lowercased()
        default: return a == b
        }
    }

    func targets(_ name: String, _ version: String) -> [Int] {
        let exact = nodes.indices.filter { same(nodes[$0].name, name) && nodes[$0].version == version }
        return exact.isEmpty ? nodes.indices.filter { same(nodes[$0].name, name) } : exact
    }

    /// The shortest chain from one of the project's direct dependencies down to the package's parent: ["express",
    /// "body-parser"] for qs. [] when the package is a direct dependency itself; nil when the lockfile does not connect it.
    public func chain(to name: String, version: String) -> [String]? {
        let goal = Set(targets(name, version))
        guard !goal.isEmpty, !roots.isEmpty else { return nil }
        if roots.contains(where: goal.contains) { return [] }
        var parent: [Int: Int] = [:], visited = Set(roots), frontier = roots
        while !frontier.isEmpty {
            var next: [Int] = []
            for n in frontier {
                for d in nodes[n].dependencies where visited.insert(d).inserted {
                    parent[d] = n
                    if goal.contains(d) {
                        var out: [String] = [], x = n
                        while true {
                            out.append(nodes[x].name)
                            guard let p = parent[x] else { break }
                            x = p
                        }
                        return out.reversed()
                    }
                    next.append(d)
                }
            }
            frontier = next
        }
        return nil
    }

    /// package-lock.json: where the package is installed under the project folder.
    public func installPath(of name: String, version: String) -> String? {
        targets(name, version).lazy.compactMap { installPaths[$0] }.min { $0.count < $1.count }
    }

    // MARK: Building

    private struct Builder {
        var graph: LockfileGraph
        var ids: [String: Int] = [:]
        var byName: [String: [Int]] = [:]
        var full = false
        init(_ ecosystem: Ecosystem) { graph = LockfileGraph(ecosystem: ecosystem) }

        mutating func node(_ id: String, name: String, version: String) -> Int? {
            if let i = ids[id] { return i }
            guard graph.nodes.count < LockfileGraph.maxNodes, !name.isEmpty else { full = true; return nil }
            graph.nodes.append(Node(name: name, version: version, dependencies: []))
            let i = graph.nodes.count - 1
            ids[id] = i
            byName[normal(name), default: []].append(i)
            return i
        }

        func normal(_ name: String) -> String {
            switch graph.ecosystem {
            case .pypi: return PackageNames.indexName(name, in: .pypi)
            case .crates: return name.replacingOccurrences(of: "_", with: "-")
            case .packagist: return name.lowercased()
            default: return name
            }
        }

        func named(_ name: String) -> [Int] { byName[normal(name)] ?? [] }

        mutating func edge(_ from: Int, _ to: Int?) {
            guard let to, from != to, !graph.nodes[from].dependencies.contains(to) else { return }
            graph.nodes[from].dependencies.append(to)
        }

        mutating func root(_ i: Int?) {
            guard let i, !graph.roots.contains(i) else { return }
            graph.roots.append(i)
        }
    }

    private init(ecosystem: Ecosystem) { self.ecosystem = ecosystem }

    // package-lock.json v2/v3: "packages" keyed by install path; node's own resolution finds each dependency.
    static func npm(_ text: String) -> LockfileGraph? {
        guard let j = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any],
              let packages = j["packages"] as? [String: Any] else { return nil }
        var b = Builder(.npm)
        let entries = packages.compactMapValues { $0 as? [String: Any] }
        func depNames(_ v: [String: Any], dev: Bool) -> [String] {
            let kinds = ["dependencies", "optionalDependencies", "peerDependencies"] + (dev ? ["devDependencies"] : [])
            return kinds.flatMap { ((v[$0] as? [String: Any]) ?? [:]).keys.sorted() }
        }
        func parent(_ key: String) -> String? {
            if key.isEmpty { return nil }
            if let r = key.range(of: "/node_modules/", options: .backwards) { return String(key[..<r.lowerBound]) }
            return ""
        }
        /// Node's lookup: <here>/node_modules/<name>, then each folder up.
        func resolve(_ from: String, _ name: String) -> String? {
            var base: String? = from
            while let b0 = base {
                let candidate = b0.isEmpty ? "node_modules/" + name : b0 + "/node_modules/" + name
                if let e = entries[candidate] {
                    if e["link"] as? Bool == true, let target = e["resolved"] as? String, entries[target] != nil { return target }
                    return candidate
                }
                base = parent(b0)
            }
            return nil
        }
        func nodeFor(_ key: String) -> Int? {
            guard let v = entries[key] else { return nil }
            let name = (v["name"] as? String) ?? key.components(separatedBy: "node_modules/").last ?? key
            let i = b.node(key, name: name, version: (v["version"] as? String) ?? "")
            if let i, key.contains("node_modules/") { b.graph.installPaths[i] = key }
            return i
        }
        for key in entries.keys.sorted() where !key.isEmpty { _ = nodeFor(key) }
        for key in entries.keys.sorted() where !key.isEmpty {
            guard let from = b.ids[key], let v = entries[key] else { continue }
            for n in depNames(v, dev: false) { b.edge(from, resolve(key, n).flatMap { b.ids[$0] }) }
        }
        // The project and its workspaces (entries outside node_modules) name the direct dependencies.
        let tops = [""] + entries.keys.filter { !$0.isEmpty && !$0.contains("node_modules/") }.sorted()
        for top in tops {
            guard let v = entries[top] else { continue }
            for n in depNames(v, dev: true) { b.root(resolve(top, n).flatMap { b.ids[$0] }) }
        }
        return b.graph
    }

    /// "@babel/core@npm:^7.0.0" -> "@babel/core": the name ends at the first "@" after the first character.
    static func descriptorName(_ d: String) -> String {
        guard d.count > 1, let at = d.dropFirst().firstIndex(of: "@") else { return d }
        return String(d[..<at])
    }

    static func unquote(_ s: Substring) -> String { unquote(String(s)) }
    static func unquote(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespaces)
        if t.count >= 2, let f = t.first, f == "\"" || f == "'", t.last == f { t = String(t.dropFirst().dropLast()) }
        return t
    }

    // yarn.lock, v1 ('lodash@^4.17.0, lodash@^4.17.21:' / '  version "4.17.21"' / '    dep "^1"') and Berry
    // ('"lodash@npm:^4.17.0":' / '  version: 4.17.21' / '    dep: "npm:^1"', with the workspace as an entry).
    static func yarn(_ text: String, direct: Set<String>?) -> LockfileGraph? {
        struct Block { var descriptors: [String]; var version = ""; var deps: [(String, String)] = [] }
        var blocks: [Block] = [], inDeps = false, skipping = true
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.hasSuffix("\r") ? raw.dropLast() : raw
            if line.isEmpty || line.hasPrefix("#") { continue }
            let indent = line.prefix { $0 == " " }.count
            let body = line.dropFirst(indent)
            if indent == 0 {
                inDeps = false
                skipping = !line.hasSuffix(":") || line.hasPrefix("__metadata")
                guard !skipping else { continue }
                let descriptors = line.dropLast().split(separator: ",").map { unquote($0) }.filter { !$0.isEmpty }
                blocks.append(Block(descriptors: descriptors))
            } else if skipping {
                continue
            } else if indent == 2, !blocks.isEmpty {
                if body.hasPrefix("version") {
                    blocks[blocks.count - 1].version = unquote(body.dropFirst(7).drop { $0 == ":" || $0 == " " })
                    inDeps = false
                } else {
                    inDeps = body == "dependencies:" || body == "optionalDependencies:"
                }
            } else if indent >= 4, inDeps, !blocks.isEmpty {
                // v1: 'name "range"' or '"@s/name" "range"'; Berry: 'name: "npm:range"'.
                let s = String(body)
                var name = "", range = ""
                if s.hasPrefix("\""), let close = s.dropFirst().firstIndex(of: "\"") {
                    name = String(s[s.index(after: s.startIndex)..<close])
                    range = unquote(s[s.index(after: close)...].drop { $0 == ":" || $0 == " " })
                } else if let sep = s.firstIndex(where: { $0 == " " || $0 == ":" }) {
                    name = String(s[..<sep])
                    range = unquote(s[sep...].drop { $0 == ":" || $0 == " " })
                }
                if !name.isEmpty { blocks[blocks.count - 1].deps.append((name, range)) }
            }
        }
        guard !blocks.isEmpty else { return nil }
        var b = Builder(.npm), byDescriptor: [String: Int] = [:]
        for (i, block) in blocks.enumerated() {
            guard let first = block.descriptors.first, let n = b.node("\(i)", name: descriptorName(first), version: block.version) else { continue }
            for d in block.descriptors { byDescriptor[d] = n }
        }
        func resolve(_ name: String, _ range: String) -> Int? {
            byDescriptor["\(name)@\(range)"] ?? byDescriptor["\(name)@npm:\(range)"] ?? b.named(name).first
        }
        var workspaces: [Int] = []
        for (i, block) in blocks.enumerated() {
            guard let from = b.ids["\(i)"] else { continue }
            for (name, range) in block.deps { b.edge(from, resolve(name, range)) }
            if block.descriptors.contains(where: { $0.contains("@workspace:") }) { workspaces.append(from) }
        }
        if !workspaces.isEmpty {
            for w in workspaces { for d in b.graph.nodes[w].dependencies where !workspaces.contains(d) { b.root(d) } }
        } else if let direct {
            for name in direct.sorted() { for n in b.named(name) { b.root(n) } }
        }
        return b.graph
    }

    /// A pnpm package key, any version of the format: "/lodash/4.17.21" (v5), "/lodash@4.17.21" (v6),
    /// "'@babel/core@7.0.0(supports-color@5.5.0)'" (v9), "/foo/1.0.0_bar@2.0.0" (v5 with peers).
    static func pnpmKey(_ raw: String) -> (name: String, version: String)? {
        var k = unquote(raw)
        if k.hasPrefix("/") { k.removeFirst() }
        if let p = k.firstIndex(of: "(") { k = String(k[..<p]) }
        guard !k.isEmpty else { return nil }
        func cutPeers(_ v: Substring) -> String { String(v.split(separator: "_", maxSplits: 1).first ?? "") }
        // v6 and later: "name@version"; the name has no "/" unless it is scoped ("@s/name").
        if let at = k.dropFirst().firstIndex(of: "@") {
            let name = String(k[..<at]), slashes = name.filter { $0 == "/" }.count
            if slashes == 0 || (name.hasPrefix("@") && slashes == 1) { return (name, cutPeers(k[k.index(after: at)...])) }
        }
        // v5: "name/version", the version the segment after the last "/" that starts with a digit.
        guard let slash = k.indices.reversed().first(where: { i in
            k[i] == "/" && i != k.startIndex && k.index(after: i) < k.endIndex && k[k.index(after: i)].isNumber
        }) else { return nil }
        return (String(k[..<slash]), cutPeers(k[k.index(after: slash)...]))
    }

    /// A pnpm dependency's value ("1.20.1", "1.20.1(supports-color@5.5.0)", "1.0.0_react@18.0.0", "/alias/1.0.0") as
    /// the name and version of the package it points to. Links and local files are not packages.
    static func pnpmTarget(_ name: String, _ raw: String) -> (name: String, version: String)? {
        let v = unquote(raw)
        guard !v.isEmpty, !v.hasPrefix("link:"), !v.hasPrefix("file:"), !v.hasPrefix("workspace:") else { return nil }
        // A version starts with a digit ("1.0.0_peer@2" is a version with its peers); "/x/1.0.0" and "x@1.0.0" are aliases.
        if v.first?.isNumber != true, v.hasPrefix("/") || v.dropFirst().contains("@"), let k = pnpmKey(v) { return k }
        var version = v
        if let p = version.firstIndex(of: "(") { version = String(version[..<p]) }
        return (name, String(version.split(separator: "_", maxSplits: 1).first ?? ""))
    }

    static func pnpm(_ text: String) -> LockfileGraph? {
        var b = Builder(.npm)
        var section = "", current: Int?, inDeps = false, depKind = false, pending: String?
        var rootDeps: [(String, String)] = [], edges: [(Int, String, String)] = []
        func keyValue(_ s: Substring) -> (String, String) {
            // 'name: value', '"@s/name": value', "'@s/name@1.0.0':" (a key that itself contains ":" is quoted)
            let t = String(s)
            if let q = t.first, q == "'" || q == "\"", let close = t.dropFirst().firstIndex(of: q) {
                let key = String(t[t.index(after: t.startIndex)..<close])
                return (key, t[t.index(after: close)...].drop { $0 == ":" || $0 == " " }.trimmingCharacters(in: .whitespaces))
            }
            guard let colon = t.firstIndex(of: ":") else { return (t, "") }
            return (String(t[..<colon]), unquote(t[t.index(after: colon)...]))
        }
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.hasSuffix("\r") ? raw.dropLast() : raw
            let indent = line.prefix { $0 == " " }.count
            let body = line.dropFirst(indent)
            if body.isEmpty || body.hasPrefix("#") { continue }
            if indent == 0 { section = String(body.split(separator: ":").first ?? ""); current = nil; inDeps = false; depKind = false; pending = nil; continue }
            switch section {
            case "importers":
                if indent == 2 { depKind = false; pending = nil }
                else if indent == 4 { depKind = ["dependencies:", "devDependencies:", "optionalDependencies:"].contains(String(body)); pending = nil }
                else if indent == 6, depKind { let (k, v) = keyValue(body); if v.isEmpty { pending = k } else { rootDeps.append((k, v)); pending = nil } }
                else if indent == 8, let p = pending, body.hasPrefix("version:") { rootDeps.append((p, keyValue(body).1)); pending = nil }
            case "dependencies", "devDependencies", "optionalDependencies":
                if indent == 2 { let (k, v) = keyValue(body); if v.isEmpty { pending = k } else { rootDeps.append((k, v)); pending = nil } }
                else if indent == 4, let p = pending, body.hasPrefix("version:") { rootDeps.append((p, keyValue(body).1)); pending = nil }
            case "packages", "snapshots":
                if indent == 2 {
                    inDeps = false
                    current = pnpmKey(keyValue(body).0).flatMap { b.node("\($0.name)@\($0.version)", name: $0.name, version: $0.version) }
                } else if indent == 4 {
                    inDeps = body == "dependencies:" || body == "optionalDependencies:"
                } else if indent == 6, inDeps, let c = current {
                    let (k, v) = keyValue(body)
                    edges.append((c, k, v))
                }
            default: break
            }
        }
        func lookup(_ name: String, _ value: String) -> Int? {
            guard let t = pnpmTarget(name, value) else { return nil }
            return b.ids["\(t.name)@\(t.version)"] ?? b.node("\(t.name)@\(t.version)", name: t.name, version: t.version)
        }
        for (from, k, v) in edges { b.edge(from, lookup(k, v)) }
        for (k, v) in rootDeps { b.root(lookup(k, v)) }
        return b.graph
    }

    // poetry.lock and Cargo.lock: [[package]] tables. Poetry lists each package's dependencies in
    // [package.dependencies]; Cargo in a `dependencies = ["name", "name version", "name version (source)"]` array, and
    // the project's own crates are the packages without a `source`.
    static func toml(_ text: String, ecosystem: Ecosystem, direct: Set<String>?) -> LockfileGraph? {
        struct Package { var name = "", version = "", source: String?, deps: [String] = [] }
        var packages: [Package] = [], table = "", inArray = false
        let keyLine = Regex(#"^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*="#)
        let stringValue = Regex(#"=\s*"([^"]*)""#)
        let quoted = Regex(#""([^"]*)""#)
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw).trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && !inArray {
                table = line
                if line == "[[package]]" { packages.append(Package()) }
                continue
            }
            guard !packages.isEmpty else { continue }
            if inArray {
                for m in quoted.allMatches(line) { if let v = m[1] { packages[packages.count - 1].deps.append(v) } }
                if line.contains("]") { inArray = false }
                continue
            }
            if table == "[[package]]" {
                if line.hasPrefix("name"), let v = stringValue.firstMatch(line)?[1] { packages[packages.count - 1].name = v }
                else if line.hasPrefix("version"), let v = stringValue.firstMatch(line)?[1] { packages[packages.count - 1].version = v }
                else if line.hasPrefix("source"), let v = stringValue.firstMatch(line)?[1] { packages[packages.count - 1].source = v }
                else if line.hasPrefix("dependencies"), line.contains("[") {
                    let after = line[line.firstIndex(of: "[")!...]
                    for m in quoted.allMatches(String(after)) { if let v = m[1] { packages[packages.count - 1].deps.append(v) } }
                    inArray = !after.contains("]")
                }
            } else if table == "[package.dependencies]", let k = keyLine.firstMatch(line)?[1] {
                packages[packages.count - 1].deps.append(k)
            }
        }
        guard !packages.isEmpty else { return nil }
        var b = Builder(ecosystem)
        for (i, p) in packages.enumerated() { _ = b.node("\(i)", name: p.name, version: p.version) }
        for (i, p) in packages.enumerated() {
            guard let from = b.ids["\(i)"] else { continue }
            for d in p.deps {
                let parts = d.split(separator: " ").map(String.init)
                guard let name = parts.first else { continue }
                let candidates = b.named(name)
                let to = parts.count > 1 ? (candidates.first { b.graph.nodes[$0].version == parts[1] } ?? candidates.first) : candidates.first
                b.edge(from, to)
            }
        }
        if ecosystem == .crates {
            for (i, p) in packages.enumerated() where p.source == nil {
                guard let member = b.ids["\(i)"] else { continue }
                for d in b.graph.nodes[member].dependencies { b.root(d) }
            }
        } else if let direct {
            for name in direct.sorted() { for n in b.named(name) { b.root(n) } }
        }
        return b.graph
    }

    // Gemfile.lock: "    name (version)" under specs, its dependencies at six spaces; DEPENDENCIES names the
    // project's own.
    static func gemfile(_ text: String) -> LockfileGraph? {
        var b = Builder(.rubygems), current: Int?, section = "", direct: [String] = [], edges: [(Int, String)] = []
        let spec = Regex(#"^    ([A-Za-z0-9_.-]+) \(([^)\s,]+)\)"#), dep = Regex(#"^      ([A-Za-z0-9_.-]+)"#)
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw.hasSuffix("\r") ? raw.dropLast() : raw)
            if !line.hasPrefix(" ") { section = line; current = nil; continue }
            if section == "DEPENDENCIES" {
                if let n = line.trimmingCharacters(in: .whitespaces).split(separator: " ").first { direct.append(String(n).trimmingCharacters(in: CharacterSet(charactersIn: "!"))) }
            } else if let m = spec.firstMatch(line), let n = m[1], let v = m[2] {
                let version = String(v.split(separator: "-", maxSplits: 1).first ?? "")
                current = b.node("\(n)@\(version)", name: n, version: version)
            } else if let c = current, let m = dep.firstMatch(line), let n = m[1] {
                edges.append((c, n))
            }
        }
        for (from, n) in edges { b.edge(from, b.named(n).first) }
        for n in direct { for i in b.named(n) { b.root(i) } }
        return b.graph
    }

    // composer.lock: each package's "require"; composer.json names the project's own.
    static func composer(_ text: String, direct: Set<String>?) -> LockfileGraph? {
        guard let j = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return nil }
        let packages = ((j["packages"] as? [Any] ?? []) + (j["packages-dev"] as? [Any] ?? [])).compactMap { $0 as? [String: Any] }
        var b = Builder(.packagist)
        for p in packages {
            guard let n = p["name"] as? String else { continue }
            var v = (p["version"] as? String) ?? ""
            if v.hasPrefix("v") { v.removeFirst() }
            _ = b.node(n.lowercased(), name: n, version: v)
        }
        for p in packages {
            guard let n = p["name"] as? String, let from = b.ids[n.lowercased()] else { continue }
            for r in ((p["require"] as? [String: Any]) ?? [:]).keys.sorted() { b.edge(from, b.ids[r.lowercased()]) }
        }
        for name in (direct ?? []).sorted() { b.root(b.ids[name.lowercased()]) }
        return b.graph
    }

    // requirements.txt from pip-compile: "name==version" then "    # via parent" or "    # via" and "    #   parent"
    // lines; "-r requirements.in" (or no "via") marks one the project asks for.
    static func pipCompile(_ text: String) -> LockfileGraph? {
        guard text.contains("# via") else { return nil }
        let requirement = Regex(#"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)"#)
        var b = Builder(.pypi), current: Int?, inVia = false, via: [Int: [String]] = [:]
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if let m = requirement.firstMatch(line), let n = m[1], let v = m[2] {
                current = b.node(PackageNames.indexName(n, in: .pypi), name: n, version: v); inVia = false
                if let c = current { via[c] = via[c] ?? [] }
                continue
            }
            let t = line.trimmingCharacters(in: .whitespaces)
            guard let c = current, t.hasPrefix("#") else { inVia = false; continue }
            let comment = t.dropFirst().trimmingCharacters(in: .whitespaces)
            if comment.hasPrefix("via") {
                let rest = comment.dropFirst(3).trimmingCharacters(in: .whitespaces)
                inVia = rest.isEmpty
                if !rest.isEmpty { via[c, default: []] += rest.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
            } else if inVia, !comment.isEmpty {
                via[c, default: []].append(comment)
            }
        }
        for (child, parents) in via {
            if parents.isEmpty || parents.contains(where: { $0.hasPrefix("-r") || $0.hasPrefix("-c") || $0.contains(".in") || $0.contains(".toml") }) {
                b.root(child)
            }
            for p in parents where !p.hasPrefix("-") {
                for from in b.named(p.split(separator: " ").first.map(String.init) ?? p) { b.edge(from, child) }
            }
        }
        b.graph.roots.sort()
        return b.graph
    }
}
