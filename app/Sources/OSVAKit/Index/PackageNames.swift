import Foundation

/// Package names as the public index writes them, and the keys the privacy filter compares.
public enum PackageNames {
    private static let pypiSeparators = Regex("[-_.]+")

    /// The index writes names as OSV does and normalises only PyPI, the way the site's pipeline does
    /// (`pypi_norm` in formalinformer/pipeline/fi/build.py, after PEP 503): lowercase, every run of `-`, `_` and `.`
    /// collapsed to one `-`. Other registries' names are kept byte for byte, as their lockfiles and tools write them.
    public static func indexName(_ name: String, in ecosystem: Ecosystem) -> String {
        guard ecosystem == .pypi else { return name }
        return pypiSeparators.replacing(in: name, with: "-").lowercased()
    }

    /// `"<ecosystem>\u{1F}<name>"`, the key `osva_select` compares.
    public static func key(_ ecosystem: Ecosystem, _ name: String) -> String {
        ecosystem.rawValue + "\u{1F}" + indexName(name, in: ecosystem)
    }

    /// The key of a project our site grades. "project" is not an OSV ecosystem, so it cannot collide with a package.
    public static func projectKey(_ slug: String) -> String { "project\u{1F}" + slug }

    /// Versions the site's scanner accepts (`add` in parseDeps): letters, digits and `_ . + ~ ^ : -`, at most 80
    /// characters (the API's limit). Anything else is never sent.
    public static func isPlausibleVersion(_ v: String) -> Bool {
        v.utf8.count <= 80 && matchesSiteVersionPattern(v)
    }

    /// `/^[\w.+~^:-]+$/`, the version test in the site's parseDeps.
    static func matchesSiteVersionPattern(_ v: String) -> Bool {
        !v.isEmpty && v.unicodeScalars.allSatisfy { versionScalars.contains($0) }
    }

    private static let versionScalars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+~^:-")
}
