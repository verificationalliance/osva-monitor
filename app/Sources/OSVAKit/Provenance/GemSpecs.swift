import Foundation

/// The gems installed in one RubyGems' paths (`gem env gempath`), from their installed gemspecs: where each is, and
/// which gems need which (their runtime dependencies). Bounded by `maxSpecs` files of `maxSpecBytes` each.
struct GemSpecs: Sendable {
    struct Gem: Hashable, Sendable {
        var name: String, version: String
        /// The gem's folder ("…/gems/nokogiri-1.13.8"), else its gemspec.
        var path: String
        /// A default gem: part of Ruby's own standard library (specifications/default).
        var isDefault: Bool
        var installed: Date?
        var dependencies: [(name: String, specifier: String)]
        static func == (a: Gem, b: Gem) -> Bool { a.name == b.name && a.version == b.version && a.path == b.path }
        func hash(into h: inout Hasher) { h.combine(name); h.combine(version); h.combine(path) }
    }

    static let maxSpecs = 5000
    static let maxSpecBytes = 64 * 1024

    let gems: [Gem]
    let complete: Bool

    init(paths: [String]) {
        var gems: [Gem] = [], complete = true, seen = 0
        for base in paths where !base.isEmpty {
            let roots = LocalFiles.roots([base])
            for dir in [base + "/specifications", base + "/specifications/default"] {
                for file in LocalFiles.list(dir, limit: Self.maxSpecs) where file.hasSuffix(".gemspec") {
                    seen += 1
                    guard seen <= Self.maxSpecs else { complete = false; break }
                    let stem = String(file.dropLast(8))
                    guard let text = LocalFiles.text(dir + "/" + file, limit: Self.maxSpecBytes, within: roots),
                          let (name, version) = Self.nameAndVersion(stem) else { complete = false; continue }
                    let folder = base + "/gems/" + stem
                    let path = LocalFiles.isDirectory(folder) ? folder : dir + "/" + file
                    gems.append(Gem(name: name, version: version, path: path, isDefault: dir.hasSuffix("/default"),
                                    installed: ProvenanceText.plausible(LocalFiles.modified(path)),
                                    dependencies: Self.dependencies(text)))
                }
            }
        }
        self.gems = gems
        self.complete = complete
    }

    /// "nokogiri-1.13.8-arm64-darwin" -> ("nokogiri", "1.13.8"): the version is the first part that starts with a digit.
    static func nameAndVersion(_ stem: String) -> (String, String)? {
        let parts = stem.split(separator: "-").map(String.init)
        guard let i = parts.indices.dropFirst().first(where: { parts[$0].first?.isNumber == true }) else { return nil }
        return (parts[..<i].joined(separator: "-"), parts[i])
    }

    private static let dependency = Regex(#"add_(runtime_)?dependency\s*\(?\s*(?:%q<([^>]+)>|"([^"]+)"|'([^']+)')(?:\.freeze)?\s*(?:,\s*\[?([^\])\n]*))?"#)

    /// Runtime dependencies, as RubyGems writes them into an installed gemspec
    /// (`s.add_runtime_dependency(%q<racc>.freeze, ["~> 1.4"])`). Development dependencies are not runtime ones. Older
    /// RubyGems wrote every dependency twice, in `if s.respond_to? :add_runtime_dependency` and again as plain
    /// `add_dependency` (development ones too) for RubyGems too old to tell them apart: in such a file only the
    /// `add_runtime_dependency` lines are runtime ones.
    static func dependencies(_ text: String) -> [(name: String, specifier: String)] {
        let typed = text.contains("add_runtime_dependency") || text.contains("add_development_dependency")
        var out: [(String, String)] = [], seen = Set<String>()
        for m in dependency.allMatches(text) where !typed || m[1] != nil {
            guard let name = m[2] ?? m[3] ?? m[4], seen.insert(name).inserted else { continue }
            let spec = (m[5] ?? "").replacingOccurrences(of: "\"", with: "").replacingOccurrences(of: ".freeze", with: "")
                .trimmingCharacters(in: CharacterSet(charactersIn: " )]"))
            out.append((name, spec == ">= 0" ? "" : spec))
        }
        return out
    }

    func gem(_ name: String, version: String) -> Gem? {
        gems.first { $0.name == name && $0.version == version } ?? gems.first { $0.name == name }
    }

    func dependents(of name: String) -> [(gem: Gem, specifier: String)] {
        var seen = Set<String>(), out: [(Gem, String)] = []
        for g in gems where g.name != name {
            if let d = g.dependencies.first(where: { $0.name == name }), seen.insert(g.name).inserted { out.append((g, d.specifier)) }
        }
        return out.sorted { $0.0.name < $1.0.name }
    }
}

/// `~/.cargo/.crates2.json`: what `cargo install` put where.
enum CargoInstalls {
    /// The programs a crate installed ("rg" for ripgrep), from its entry in .crates2.json.
    static func programs(of name: String, version: String, cargoHome: String) -> [String] {
        let roots = LocalFiles.roots([cargoHome])
        guard let data = LocalFiles.read(cargoHome + "/.crates2.json", limit: 8 * 1024 * 1024, within: roots),
              let installs = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["installs"] as? [String: Any] else { return [] }
        guard let entry = installs.first(where: { $0.key.hasPrefix("\(name) \(version) ") })?.value as? [String: Any] else { return [] }
        return (entry["bins"] as? [Any] ?? []).compactMap { $0 as? String }.filter { !$0.contains("/") }.sorted()
    }
}
