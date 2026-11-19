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
    /// With no upgrade known: the newest last affected version of the ranges the version lies in, when every one of
    /// them ends at a last affected version rather than a fixed one (Oracle names the newest affected update of each
    /// line, never the fix). Nil when one of them has no end: then nothing is fixed yet.
    public var lastAffected: String? = nil

    public var advisories: [ProjectResponse.Advisory] { hits.map(\.advisory) }
    public var exploited: Bool { hits.contains { $0.advisory.kev } }
    public var severity: Severity? { hits.compactMap { Severity(api: $0.advisory.severity) }.max() }

    /// What the finding says about how it was decided: "affected" when the issuer's ranges include the version,
    /// "likely affected" when only first fixed versions were there to decide by.
    public var note: String? { note() }

    /// The note with each version written as `shown` writes it (Java's "8u511" for 8.0.511).
    public func note(showing shown: (String) -> String = { $0 }) -> String? {
        let v = shown(installed)
        if hits.allSatisfy({ $0.basis == .ranges }) {
            if let t = target { return "The issuer lists \(v) as affected and \(shown(t)) as fixed." }
            if let last = lastAffected {
                if Core.shared.compareVersions(last, installed) == 0 { return "The issuer lists \(v) as the newest affected version; it names no fixed release." }
                return "The issuer lists \(v) as affected, up to \(shown(last)); it names no fixed release."
            }
            return "The issuer lists \(v) as affected. No fixed release yet."
        }
        return target.map { "Likely affected: the issuer names \(shown($0)) as fixed." }
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
        let target = core.newestVersion(upgrades)
        var last: String?
        if target == nil {
            // the ranges this version lies in, each asked of the core alone
            let holding = hits.compactMap(\.advisory.ranges).flatMap { $0 }.filter { core.affectedness(installed: installed, ranges: [$0]) == .affected }
            if !holding.isEmpty, holding.allSatisfy({ $0.fixed == nil && $0.lastAffected != nil }) { last = core.newestVersion(holding.compactMap(\.lastAffected)) }
        }
        return AdvisoryCheck(installed: installed, hits: hits, target: target, lastAffected: last)
    }
}

/// An item of the site's "patch these first" list, decided like the project's own advisories: by the issuer's ranges
/// when the project's record has them for every advisory on the item, else by the list's first fixed versions.
struct IssueCheck {
    private let core = Core.shared
    /// The ranges of each advisory on the item, or nil when the first fixed versions decide.
    let ranges: [[AffectedRange]]?
    let fixedIn: [String]

    init(_ issue: StateResponse.BigIssue, project: ProjectResponse?) {
        let listed = project?.recent.filter { a in issue.ids.contains(a.id) || a.cve.map(issue.ids.contains) == true } ?? []
        let covered = Set(listed.flatMap { [$0.id] + ($0.cve.map { [$0] } ?? []) })
        let sets = listed.compactMap(\.ranges)
        ranges = !listed.isEmpty && sets.count == listed.count && issue.ids.allSatisfy(covered.contains) ? sets : nil
        fixedIn = issue.fixedIn
    }

    func affects(_ installed: String) -> Bool {
        if let ranges { return ranges.contains { core.affectedness(installed: installed, ranges: $0) == .affected } }
        return core.affectedness(installed: installed, fixedVersions: fixedIn) == .affected
    }

    func fix(_ installed: String) -> String? {
        if let ranges { return core.upgrade(from: installed, ranges: ranges.flatMap { $0 }) }
        return core.nearestVersion(in: fixedIn, above: installed)
    }

    func note(_ installed: String, _ target: String?) -> String? {
        if ranges != nil {
            return target.map { "The issuer lists \(installed) as affected and \($0) as fixed." } ?? "The issuer lists \(installed) as affected. No fixed release yet."
        }
        return target.map { "Likely affected: the issuer names \($0) as fixed." }
    }
}
