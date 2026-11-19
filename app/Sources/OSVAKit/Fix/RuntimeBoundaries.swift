import Foundation

/// Upgrades known to remove or change what other packages use, in ways no version specifier shows (research rule 4.5:
/// A-R9, B-R15). `pip check` cannot see them: pyannote.audio 3.3.2 accepts any torchaudio from 2.2 on, imports cleanly
/// under pip's eyes, and fails at run time on torchaudio 2.9, which removed `AudioMetaData`. An upgrade that crosses one
/// of these while something installed depends on the package is not offered.
public enum RuntimeBoundaries {
    public struct Boundary: Equatable, Sendable {
        /// The package, in normal form.
        public var package: String
        /// The first release past the boundary ("2.9" is 2.9.0 and everything after it).
        public var version: String
        /// What it removed or changed, for the one line ("removed AudioMetaData").
        public var change: String
        /// Only when this installed package is below this version (Pillow 13 breaks imageio below 2.38.2 only).
        public var onlyWith: (package: String, below: String)?

        public static func == (a: Boundary, b: Boundary) -> Bool {
            a.package == b.package && a.version == b.version && a.change == b.change
                && a.onlyWith?.package == b.onlyWith?.package && a.onlyWith?.below == b.onlyWith?.below
        }
    }

    public static let table: [Boundary] = [
        Boundary(package: "torch", version: "2.9", change: "goes with torchaudio 2.9, which removed AudioMetaData"),
        Boundary(package: "torchaudio", version: "2.9", change: "removed AudioMetaData"),
        Boundary(package: "huggingface-hub", version: "1.0", change: "removed use_auth_token"),
        Boundary(package: "pyopenssl", version: "26.2", change: "removed X509Extension"),
        Boundary(package: "setuptools", version: "82", change: "removed pkg_resources"),
        Boundary(package: "starlette", version: "1.0", change: "removed APIs of the 0.x series"),
        Boundary(package: "numpy", version: "2", change: "changed its binary interface"),
        Boundary(package: "pydantic", version: "2", change: "replaced its 1.x API"),
        Boundary(package: "urllib3", version: "2", change: "removed APIs of the 1.x series"),
        Boundary(package: "protobuf", version: "4", change: "changed the runtime generated code needs"),
        Boundary(package: "pillow", version: "13", change: "removed what imageio below 2.38.2 uses", onlyWith: ("imageio", "2.38.2")),
        Boundary(package: "lightning", version: "2.6", change: "changed the weights_only default for loading checkpoints"),
        Boundary(package: "pytorch-lightning", version: "2.6", change: "changed the weights_only default for loading checkpoints"),
    ]

    /// The boundary an upgrade of `package` from `installed` to `target` crosses, if any: installed below it, target at
    /// or above it (versions ordered by the verified core, PEP 440 padding).
    public static func crossed(_ package: String, from installed: String, to target: String, in site: PythonSite? = nil) -> Boundary? {
        let key = PythonNames.normal(package)
        let (a, b) = (PythonSpecifier.plain(installed), PythonSpecifier.plain(target))
        guard PythonSpecifier.readable(a), PythonSpecifier.readable(b) else { return nil }
        return table.first { boundary in
            guard boundary.package == key, PythonSpecifier.compare(a, boundary.version) < 0, PythonSpecifier.compare(b, boundary.version) >= 0 else { return false }
            guard let only = boundary.onlyWith else { return true }
            guard let other = site?.live(only.package) else { return false }
            return PythonSpecifier.compare(PythonSpecifier.plain(other.version), only.below) < 0
        }
    }
}
