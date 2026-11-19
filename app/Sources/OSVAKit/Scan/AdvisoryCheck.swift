import Foundation

/// Which of a project's or a product's advisories an installed version is affected by, and the one upgrade that clears
/// them. Used for Homebrew formulae and casks (projects), and for apps and the libraries they bundle (products). Only
/// critical and high advisories, and any exploited in the wild, are weighed (`FindingBuilder.weighed`).
///
/// Each advisory is decided by the verified core on one of two paths, and `Hit.basis` records which:
///   - `.ranges`: the advisory carries the issuer's affected ranges, so `osva_affected_ranges` decides (Ranges.lean: the
///     version is flagged exactly when it lies in one of them). This is the path whenever `ranges` is present, even [].
///   - `.firstFixed`: the advisory has no ranges (an older server, or a record the server cannot read as ranges exactly),
///     so `osva_affected` decides on its first fixed versions per release branch (Affected.lean), as before ranges.
public struct AdvisoryCheck: Sendable {
    public enum Basis: Sendable, Equatable { case ranges, firstFixed }

    public struct Hit: Sendable {
        public var advisory: ProjectResponse.Advisory
        public var basis: Basis
    }

    public var installed: String
    public var hits: [Hit]
    /// The one upgrade that clears them all: the newest of the upgrades each path proposes.
    public var target: String?

    public var advisories: [ProjectResponse.Advisory] { hits.map(\.advisory) }
    public var exploited: Bool { hits.contains { $0.advisory.kev } }
    public var severity: Severity? { hits.compactMap { Severity(api: $0.advisory.severity) }.max() }

    /// What the finding says about how it was decided: "affected" when the issuer's ranges include the version,
    /// "likely affected" when only first fixed versions were there to decide by.
    public var note: String? {
        if hits.allSatisfy({ $0.basis == .ranges }) {
            return target.map { "The issuer lists \(installed) as affected and \($0) as fixed." }
                ?? "The issuer lists \(installed) as affected. No fixed release yet."
        }
        return target.map { "Likely affected: the issuer names \($0) as fixed." }
    }

    /// Nil when no weighed advisory affects `installed`.
    public static func decide(_ installed: String, _ recent: [ProjectResponse.Advisory]) -> AdvisoryCheck? {
        let core = Core.shared
        let weighed = recent.filter(FindingBuilder.weighed)
        var hits: [Hit] = [], upgrades: [String] = []
        for a in weighed {
            if let ranges = a.ranges {
                // Ranges path: the issuer's own ranges decide; first fixed versions are not consulted.
                if core.affectedness(installed: installed, ranges: ranges) == .affected { hits.append(Hit(advisory: a, basis: .ranges)) }
            } else if core.affectedness(installed: installed, fixedVersions: a.fixedHint) == .affected {
                // First-fixed path, only for an advisory without ranges: its nearest fix above the installed version.
                hits.append(Hit(advisory: a, basis: .firstFixed))
                if let fix = core.nearestVersion(in: a.fixedHint, above: installed) { upgrades.append(fix) }
            }
        }
        guard !hits.isEmpty else { return nil }
        if hits.contains(where: { $0.basis == .ranges }),
           // every weighed advisory's ranges at once, so the upgrade lies in none of them, not even a flaw that starts later
           let up = core.upgrade(from: installed, ranges: weighed.compactMap(\.ranges).flatMap { $0 }) {
            upgrades.append(up)
        }
        return AdvisoryCheck(installed: installed, hits: hits, target: core.newestVersion(upgrades))
    }
}
