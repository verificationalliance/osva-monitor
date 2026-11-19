import Foundation

/// A package registry, named as OSV and our index name it ("npm", "PyPI", "crates.io", "RubyGems", ...).
public struct Ecosystem: RawRepresentable, Hashable, Comparable, Codable, Sendable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(_ rawValue: String) { self.rawValue = rawValue }

    public static let npm = Ecosystem("npm")
    public static let pypi = Ecosystem("PyPI")
    public static let crates = Ecosystem("crates.io")
    public static let rubygems = Ecosystem("RubyGems")
    public static let go = Ecosystem("Go")
    public static let packagist = Ecosystem("Packagist")
    public static let maven = Ecosystem("Maven")
    public static let nuget = Ecosystem("NuGet")
    public static let pub = Ecosystem("Pub")
    public static let hex = Ecosystem("Hex")

    /// The ecosystems the API's exact-version check accepts (`ECOSYSTEMS` in formalinformer/api/server.py).
    public static let checkable: Set<Ecosystem> = Set(["npm", "PyPI", "crates.io", "Go", "Maven", "RubyGems", "Packagist",
        "NuGet", "Pub", "Hex", "GitHub Actions", "SwiftURL", "Hackage", "CRAN"].map { Ecosystem($0) })

    public var description: String { rawValue }
    public static func < (a: Ecosystem, b: Ecosystem) -> Bool { a.rawValue < b.rawValue }

    public init(from decoder: Decoder) throws { rawValue = try decoder.singleValueContainer().decode(String.self) }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(rawValue) }
}
