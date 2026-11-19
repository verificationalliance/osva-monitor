import Foundation

/// Which packages a project names itself (direct dependencies), read from the manifest beside its lockfile. A direct
/// dependency is upgraded by changing what the project asks for; an indirect one by updating within its parent's
/// range, or by an override. Nil when there is no manifest to tell.
public enum Manifests {
    public static func directNames(forLockfile lockfile: URL) -> Set<String>? {
        let dir = lockfile.deletingLastPathComponent()
        func read(_ name: String) -> String? {
            (try? Data(contentsOf: dir.appendingPathComponent(name))).map { String(decoding: $0, as: UTF8.self) }
        }
        let file = lockfile.lastPathComponent
        switch file {
        case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
            return read("package.json").flatMap { jsonKeys($0, ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) }
        case "composer.lock":
            return read("composer.json").flatMap { jsonKeys($0, ["require", "require-dev"]) }
                .map { Set($0.map { $0.lowercased() }.filter { $0 != "php" && !$0.hasPrefix("ext-") && !$0.hasPrefix("lib-") }) }
        case "poetry.lock":
            return read("pyproject.toml").map { normalizedPyPI(pyproject($0)) }
        case "Pipfile.lock":
            return read("Pipfile").map { normalizedPyPI(tomlKeys($0, sections: { $0 == "packages" || $0 == "dev-packages" })) }
        case "Cargo.lock":
            return read("Cargo.toml").map { cargo($0) }
        case "go.sum":
            return read("go.mod").map(goDirect)
        case "Gemfile.lock":
            return read(file).map(gemfileLockDependencies)
        default:
            if file.hasPrefix("requirements") && file.hasSuffix(".txt") {             // a requirements file is the manifest
                return read(file).map { text in normalizedPyPI(Set(LockfileParser.parse(text, filename: file).dependencies.map(\.name))) }
            }
            return nil
        }
    }

    /// Whether `name` (of `ecosystem`) is among the direct names, compared as the registry compares names.
    public static func isDirect(_ name: String, _ ecosystem: Ecosystem, in names: Set<String>) -> Bool {
        switch ecosystem {
        case .pypi: return names.contains(PackageNames.indexName(name, in: .pypi))
        case .crates: return names.contains(name.replacingOccurrences(of: "_", with: "-"))
        case .packagist: return names.contains(name.lowercased())
        default: return names.contains(name)
        }
    }

    // MARK: Readers

    static func jsonKeys(_ text: String, _ fields: [String]) -> Set<String>? {
        guard let root = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return nil }
        return Set(fields.flatMap { ((root[$0] as? [String: Any]) ?? [:]).keys })
    }

    private static let sectionHeader = Regex(#"^\s*\[+\s*([^\]]+?)\s*\]+\s*(?:#.*)?$"#)
    private static let keyLine = Regex(#"^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*="#)
    private static let requirementName = Regex(#"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"#)
    private static let quoted = Regex(#""([^"]*)"|'([^']*)'"#)

    /// The keys of the TOML tables whose names pass `sections`.
    static func tomlKeys(_ text: String, sections: (String) -> Bool) -> Set<String> {
        var out = Set<String>(), current = ""
        for line in text.components(separatedBy: "\n") {
            if let m = sectionHeader.firstMatch(line), let s = m[1] { current = s.replacingOccurrences(of: "\"", with: ""); continue }
            if sections(current), let m = keyLine.firstMatch(line), let k = m[1] { out.insert(k) }
        }
        return out
    }

    /// pyproject.toml: PEP 621 `dependencies` and `optional-dependencies` arrays, and Poetry's dependency tables.
    static func pyproject(_ text: String) -> Set<String> {
        var out = tomlKeys(text) { s in
            s == "tool.poetry.dependencies" || s == "tool.poetry.dev-dependencies"
                || (s.hasPrefix("tool.poetry.group.") && s.hasSuffix(".dependencies"))
        }
        out.remove("python")
        var current = "", inArray = false
        for line in text.components(separatedBy: "\n") {
            if !inArray, let m = sectionHeader.firstMatch(line), let s = m[1] { current = s; continue }
            let arrayStart = (current == "project" && line.range(of: #"^\s*dependencies\s*=\s*\["#, options: .regularExpression) != nil)
                || (current == "project.optional-dependencies" && line.range(of: #"^\s*[A-Za-z0-9_.-]+\s*=\s*\["#, options: .regularExpression) != nil)
            if arrayStart || inArray {
                for m in quoted.allMatches(line) {
                    if let req = m[1] ?? m[2], let n = requirementName.firstMatch(req)?[1] { out.insert(n) }
                }
                inArray = !line.contains("]")
            }
        }
        return out
    }

    /// Cargo.toml: [dependencies], [dev-dependencies], [build-dependencies], target and workspace forms, and
    /// [dependencies.<name>] tables.
    static func cargo(_ text: String) -> Set<String> {
        let tables = ["dependencies", "dev-dependencies", "build-dependencies"]
        var out = tomlKeys(text) { s in tables.contains { t in s == t || s.hasSuffix("." + t) } }
        for line in text.components(separatedBy: "\n") {
            if let m = sectionHeader.firstMatch(line), let s = m[1] {
                for t in tables where s.hasPrefix(t + ".") { out.insert(String(s.dropFirst(t.count + 1))) }
            }
        }
        return Set(out.map { $0.replacingOccurrences(of: "_", with: "-") })
    }

    /// go.mod: required modules not marked `// indirect`.
    static func goDirect(_ text: String) -> Set<String> {
        var out = Set<String>(), inBlock = false
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("require (") { inBlock = true; continue }
            if inBlock && line.hasPrefix(")") { inBlock = false; continue }
            let body = inBlock ? line : (line.hasPrefix("require ") ? String(line.dropFirst(8)) : "")
            guard !body.isEmpty, !body.contains("// indirect"), let module = body.split(separator: " ").first else { continue }
            out.insert(String(module))
        }
        return out
    }

    /// Gemfile.lock's DEPENDENCIES section: the gems the Gemfile names.
    static func gemfileLockDependencies(_ text: String) -> Set<String> {
        var out = Set<String>(), inSection = false
        for line in text.components(separatedBy: "\n") {
            if line == "DEPENDENCIES" { inSection = true; continue }
            if inSection {
                guard line.hasPrefix("  ") else { if !line.isEmpty { inSection = false }; continue }
                if let name = line.trimmingCharacters(in: .whitespaces).split(separator: " ").first {
                    out.insert(String(name).trimmingCharacters(in: CharacterSet(charactersIn: "!")))
                }
            }
        }
        return out
    }

    static func normalizedPyPI(_ names: Set<String>) -> Set<String> { Set(names.map { PackageNames.indexName($0, in: .pypi) }) }
}
