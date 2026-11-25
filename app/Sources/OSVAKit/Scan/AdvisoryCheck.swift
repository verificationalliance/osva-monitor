import Foundation

/// Which of a project's or a product's advisories an installed version is affected by, and the one upgrade to propose.
/// Used for Homebrew formulae and casks (projects), for MacPorts, Nix and conda packages matched to them, for apps and
/// the libraries they bundle (products), and for Java runtimes. Only critical and high advisories, and any exploited in
/// the wild, are weighed (`FindingBuilder.weighed`).
///
/// The verified core decides each weighed advisory (`Core.verdicts`, Decide.lean) from what can be read of it
/// (`weighedAs`), and `Hit.basis` records how:
///   - `.ranges`: the version lies inside one of the ranges the site publishes for it (`.inRange`): **affected**;
///   - `.firstFixed`: it publishes no ranges (nil or []), and its first fixed versions say the version is affected
///     (`.likely`): **likely affected**, never counted;
///   - `.unreadable`: its ranges could not be read, and its first fixed versions say the version is affected:
///     **reported, not checked**;
///   - `.unstated`: nothing the core can decide by can be read of it, neither ranges nor first fixed versions: **not
///     checked**, whatever the version, and evidence about no version in particular. One exploited in the wild is never
///     dropped: it is said and marked, and makes a reported finding when nothing else does, so that a re-check is never
///     "fixed" over it. A critical one beside a finding made for other reasons is named in its note and marked
///     (`urgent`); the others there are counted. On their own they make none: records that state no versions for most
///     of their advisories (OpenJDK's, nginx's, CPython's) would otherwise put a finding on every version.
/// The finding is affected when any advisory is, else likely, else reported (`check`), and is shown for those hits
/// only (`shown`); the others are said in its note, and the most urgent of them kept as `notChecked`.
///
/// The upgrade is the core's (`Core.upgrade(from:advisories:)`) over every weighed advisory, so it lies outside the
/// published ranges of each one that has them and clear of the first fixed versions of the rest, not even landing in a
/// flaw that starts later. It is shown only when it reads as a version (FixSafety); one the core was not asked for
/// (more work than it may take) or that does not read as one is `withheld`, and then no command runs for it either.
public struct AdvisoryCheck: Sendable {
    public enum Basis: Sendable, Equatable { case ranges, firstFixed, unreadable, unstated }

    public struct Hit: Sendable {
        public var advisory: ProjectResponse.Advisory
        public var basis: Basis
    }

    /// Why the finding names no upgrade although the advisories may have one.
    public enum Withheld: Sendable, Equatable {
        /// More work than the core may be asked for (`Core.upgradeWorkLimit`): not decided.
        case refused
        /// The core's upgrade does not read as a version and nothing else (FixSafety).
        case notAVersion
    }

    public var installed: String
    public var hits: [Hit]
    /// The core's upgrade: above the installed version and clear of every weighed advisory, with evidence. Nil for a
    /// finding that is only reported, and when withheld.
    public var target: CheckedUpgrade?
    public var withheld: Withheld? = nil
    /// With no upgrade known: the newest last affected version of the ranges the version lies in, when every one of
    /// them ends at a last affected version rather than a fixed one (Oracle names the newest affected update of each
    /// line, never the fix). Nil when one of them has no end: then nothing is fixed yet.
    public var lastAffected: String? = nil

    /// Exploited in the wild, or critical: named and marked beside a finding.
    static func urgent(_ a: ProjectResponse.Advisory) -> Bool { a.kev || Severity(api: a.severity) == .critical }

    /// The advisories the finding names: every one that affects the version, likely affects it or is reported, and
    /// those that state nothing when urgent. The others that state nothing are only counted.
    public var advisories: [ProjectResponse.Advisory] { hits.filter { $0.basis != .unstated || Self.urgent($0.advisory) }.map(\.advisory) }

    /// Affected when the published ranges of any advisory hold the version, else likely, else reported.
    public var check: Finding.Check {
        hits.contains { $0.basis == .ranges } ? .affected : hits.contains { $0.basis == .firstFixed } ? .likely : .reported
    }

    /// The hits the finding is shown for: its affected ones, else its likely ones, else its reported ones and the
    /// exploited ones that state nothing.
    public var shown: [Hit] {
        switch check {
        case .affected: return hits.filter { $0.basis == .ranges }
        case .likely: return hits.filter { $0.basis == .firstFixed }
        case .reported: return hits.filter { $0.basis == .unreadable || ($0.basis == .unstated && $0.advisory.kev) }
        }
    }

    public var flawCount: Int { shown.count }
    public var exploited: Bool { shown.contains { $0.advisory.kev } }
    public var severity: Severity? { shown.compactMap { Severity(api: $0.advisory.severity) }.max() }

    /// Today's groups for an affected finding; likely and reported ones are never counted.
    public var group: Finding.Group {
        switch check {
        case .affected: return exploited ? .exploited : .criticalHigh
        case .likely: return .likely
        case .reported: return .reported
        }
    }

    /// The most urgent advisory not checked against published ranges (likely, reported, or stating nothing), when it is
    /// exploited in the wild or critical.
    public var notChecked: Finding.NotChecked? { Self.alert(hits.filter { $0.basis != .ranges }) }

    /// What the finding says about how it was decided.
    public var note: String? { note() }

    /// The note with each version written as `shown` writes it (Java's "8u511" for 8.0.511). `offLine`: the versioned
    /// formula the upgrade is not a release of, when it is not one (`target` is then not offered).
    public func note(showing shown: (String) -> String = { $0 }, offLine formula: String? = nil) -> String? {
        let v = shown(installed)
        let t = target.map { shown($0.version) }
        let why: String?
        switch withheld {
        case .refused?: why = Self.notChecked
        case .notAVersion?: why = Self.notAVersion
        case nil: why = nil
        }
        let likely = hits.filter { $0.basis == .firstFixed }, unread = hits.filter { $0.basis == .unreadable }
        let unstated = hits.filter { $0.basis == .unstated }
        let moreUnread = Self.more(unread.count, "is reported, not checked", "are reported, not checked", naming: Self.alert(unread))
        func moreUnstated(_ hs: [Hit]) -> String? {
            Self.more(hs.count, "states no affected versions; not checked", "state no affected versions; not checked", naming: Self.alert(hs))
        }
        switch check {
        case .affected:
            let lead: String
            if let t, let formula { lead = "The issuer lists \(v) as affected; its fix, \(t), is not a \(formula) release." }
            else if let t { lead = "The issuer lists \(v) as affected and \(t) as fixed." }
            else if let why { lead = "The issuer lists \(v) as affected. " + why }
            else if let last = lastAffected {
                lead = Core.shared.compareVersions(last, installed) == 0 ? "The issuer lists \(v) as the newest affected version; it names no fixed release."
                    : "The issuer lists \(v) as affected, up to \(shown(last)); it names no fixed release."
            } else { lead = "The issuer lists \(v) as affected. No fixed release yet." }
            return FindingBuilder.sentences(lead, Self.more(likely.count, "without published ranges likely affects it too",
                                                                  "without published ranges likely affect it too", naming: Self.alert(likely)),
                                            moreUnread, moreUnstated(unstated))
        case .likely:
            let lead: String
            if let t, let formula { lead = "Likely affected: the site publishes no affected ranges; the issuer's fix, \(t), is not a \(formula) release." }
            else if let t { lead = "Likely affected: the site publishes no affected ranges, and the issuer names \(t) as fixed." }
            else if let why { lead = "Likely affected: the site publishes no affected ranges. " + why }
            else { lead = "Likely affected: the site publishes no affected ranges; no fixed version clears it." }
            return FindingBuilder.sentences(lead, moreUnread, moreUnstated(unstated))
        case .reported:
            let reported = self.shown, worst = Self.mostUrgent(reported)
            let id = worst?.advisory.id ?? "it"
            let why: String
            switch (worst?.basis, worst?.advisory) {
            case let (.unstated?, a?) where a.fixedHintUnreadable && !a.rangesUnreadable: why = "the app could not read the fixed versions it names for \(id)"
            case let (.unstated?, a?) where !a.rangesUnreadable: why = "it publishes no affected versions for \(id)"
            default: why = "the app could not read its affected ranges for \(id)"
            }
            let more = reported.count - 1
            return FindingBuilder.sentences("Reported by the site, not checked: \(why)" + (more > 0 ? " (and \(more) more)." : "."),
                                            moreUnstated(unstated.filter { !$0.advisory.kev }))
        }
    }

    /// The place's advice for this finding: none for a finding only reported; for an upgrade the core withheld, no
    /// command (Homebrew's included), and no note that is about one.
    public func advice(_ full: UpgradeCommand.Advice) -> UpgradeCommand.Advice {
        if check == .reported { return UpgradeCommand.Advice(command: nil) }
        if withheld != nil { return UpgradeCommand.Advice(command: nil, note: full.command == nil ? full.note : nil) }
        return full
    }

    static let notChecked = "No checked fixed version yet; see the site."
    static let notAVersion = "The server named a fixed version the app does not accept as a version; see the site."

    /// The advisory as the core weighs it: what can be read of it. Ranges that read decide; ranges that do not read are
    /// none, and then its first fixed versions decide, unless they do not read either ([]), and it states nothing.
    static func weighedAs(_ a: ProjectResponse.Advisory) -> CoreAdvisory {
        CoreAdvisory(ranges: a.rangesUnreadable ? nil : a.ranges, fixed: a.fixedHintUnreadable ? [] : a.fixedHint)
    }

    /// "1 more advisory without published ranges likely affects it too: B, critical.", "2 more advisories are
    /// reported, not checked."; nil when there are none.
    static func more(_ count: Int, _ one: String, _ many: String, naming alert: Finding.NotChecked?) -> String? {
        switch count {
        case 0: return nil
        case 1: return "1 more advisory \(one)" + BatchCheck.naming(alert, count: 1) + "."
        case let k: return "\(k) more advisories \(many)" + BatchCheck.naming(alert, count: k) + "."
        }
    }

    /// The core's upgrade, as a finding may show it: only a version that reads as one; otherwise why there is none.
    static func shown(_ answer: Core.UpgradeAnswer) -> (upgrade: CheckedUpgrade?, withheld: Withheld?) {
        switch answer {
        case let .upgrade(u): return FixSafety.isSafeVersion(u.version) ? (u, nil) : (nil, .notAVersion)
        case .noUpgrade: return (nil, nil)
        case .refused: return (nil, .refused)
        }
    }

    /// The most urgent of these hits: exploited first, then the most severe, then the first.
    static func mostUrgent(_ hits: [Hit]) -> Hit? {
        func rank(_ h: Hit) -> (Int, Int) {
            (h.advisory.kev ? 0 : 1, -(Severity(api: h.advisory.severity).map { Severity.allCases.firstIndex(of: $0)! } ?? -1))
        }
        return hits.enumerated().min { a, b in
            let (ra, rb) = (rank(a.element), rank(b.element))
            return (ra.0, ra.1, a.offset) < (rb.0, rb.1, b.offset)
        }?.element
    }

    /// The most urgent of these hits, when it is exploited in the wild or critical.
    static func alert(_ hits: [Hit]) -> Finding.NotChecked? {
        hits.reduce(nil) { best, h in
            let a = Finding.NotChecked(id: h.advisory.id, exploited: h.advisory.kev, critical: Severity(api: h.advisory.severity) == .critical)
            return a.exploited || a.critical ? .worse(best, a) : best
        }
    }

    /// The newest last affected version of the published ranges holding `installed` among these hits, when every one of
    /// those ranges ends at one (each range asked of the core alone).
    static func lastAffected(_ installed: String, _ hits: [Hit]) -> String? {
        let core = Core.shared
        let ranges = hits.filter { $0.basis == .ranges }.compactMap { weighedAs($0.advisory).ranges }.flatMap { $0 }
        let verdicts = core.verdicts(installed: installed, advisories: ranges.map { CoreAdvisory(ranges: [$0], fixed: []) })
        let holding = zip(ranges, verdicts).filter { $0.1 == .inRange }.map(\.0)
        guard !holding.isEmpty, holding.allSatisfy({ $0.fixed == nil && $0.lastAffected != nil }) else { return nil }
        return core.newestVersion(holding.compactMap(\.lastAffected))
    }

    /// Nil when no weighed advisory affects `installed`, likely affects it, or is reported for it, and none that states
    /// nothing is exploited in the wild. Call it off the main thread: it asks the core for the upgrade.
    public static func decide(_ installed: String, _ recent: [ProjectResponse.Advisory]) -> AdvisoryCheck? {
        let core = Core.shared
        let weighed = recent.filter(FindingBuilder.weighed)
        let advisories = weighed.map(weighedAs)
        var hits: [Hit] = []
        for (a, v) in zip(weighed, core.verdicts(installed: installed, advisories: advisories)) {
            switch v {
            case .inRange: hits.append(Hit(advisory: a, basis: .ranges))
            case .likely: hits.append(Hit(advisory: a, basis: a.rangesUnreadable ? .unreadable : .firstFixed))
            case .unstated: hits.append(Hit(advisory: a, basis: .unstated))
            case .clear: break
            }
        }
        guard hits.contains(where: { $0.basis != .unstated || $0.advisory.kev }) else { return nil }
        var d = AdvisoryCheck(installed: installed, hits: hits, target: nil)
        guard d.check != .reported else { return d }                            // reported: no version, no command
        (d.target, d.withheld) = shown(core.upgrade(from: installed, advisories: advisories))
        if d.target == nil && d.withheld == nil { d.lastAffected = lastAffected(installed, hits) }
        return d
    }

    /// This decision with a "patch these first" item whose published ranges hold the version (`IssueCheck.verdict` is
    /// `.affected`): the item is counted as an affected advisory, at the item's severity and exploited when it is, unless
    /// its advisory is one already, which then takes the item's word. The upgrade stays only when the core finds it
    /// clear of the item's published ranges too; otherwise it is the item's (`IssueCheck.fix`), or none. Call it off the
    /// main thread.
    func promoted(by issue: StateResponse.BigIssue, _ item: IssueCheck) -> AdvisoryCheck {
        let holding = item.holding(installed)
        guard let first = holding.first else { return self }
        var d = self
        if let k = d.hits.firstIndex(where: { h in h.basis == .ranges && holding.contains { $0.id == h.advisory.id } }) {
            d.hits[k].advisory = Self.raised(d.hits[k].advisory, by: issue)
        } else {
            d.hits.removeAll { h in holding.contains { $0.id == h.advisory.id } }
            d.hits.append(Hit(advisory: Self.raised(first, by: issue), basis: .ranges))
        }
        if let t = d.target, item.leaves(t.version, from: installed) {
            // the finding's own upgrade leaves the item too
        } else {
            (d.target, d.withheld) = item.fix(installed)
        }
        d.lastAffected = d.target == nil && d.withheld == nil ? Self.lastAffected(installed, d.hits) : nil
        return d
    }

    /// The decision of a finding a "patch these first" item makes on its own, by its verdict: affected by the published
    /// ranges of its advisory, or likely by its own first fixed versions; the upgrade is the item's (`IssueCheck.fix`).
    /// Call it off the main thread.
    static func forItem(_ issue: StateResponse.BigIssue, _ item: IssueCheck, verdict: Finding.Check, installed: String) -> AdvisoryCheck {
        let hit = verdict == .affected
            ? item.holding(installed).first.map { Hit(advisory: raised($0, by: issue), basis: .ranges) }
            : nil
        var d = AdvisoryCheck(installed: installed, hits: [hit ?? Hit(advisory: ProjectResponse.Advisory(item: issue), basis: .firstFixed)], target: nil)
        (d.target, d.withheld) = item.fix(installed)
        if d.target == nil && d.withheld == nil { d.lastAffected = lastAffected(installed, d.hits) }
        return d
    }

    /// An advisory with an item's word on it: exploited when the item is, and at the item's severity when higher.
    static func raised(_ a: ProjectResponse.Advisory, by issue: StateResponse.BigIssue) -> ProjectResponse.Advisory {
        var a = a
        a.kev = a.kev || issue.exploited
        if let s = Severity(api: issue.severity), Severity(api: a.severity).map({ s > $0 }) ?? true { a.severity = s.rawValue }
        return a
    }
}

extension ProjectResponse.Advisory {
    /// A "patch these first" item as an advisory of its own: its first fixed versions, its severity, exploited when it
    /// is; no published ranges.
    init(item issue: StateResponse.BigIssue) {
        id = issue.ids.first ?? issue.name; date = issue.date; severity = issue.severity ?? ""; title = issue.title
        fixedHint = issue.fixedIn; fixedHintUnreadable = false; kev = issue.exploited; cve = nil
        ranges = nil; rangesNote = nil; rangesUnreadable = false; fixedBuilds = []
    }
}

/// An item of the site's "patch these first" list, decided like the project's own advisories (`verdict`): affected
/// when the published ranges of an advisory on it hold the version; when it has an advisory without published ranges,
/// likely affected when its first fixed versions say so. Its upgrade is the core's, over the item and the project's
/// weighed advisories (`upgrade`).
struct IssueCheck {
    private let core = Core.shared
    /// The advisories of the project's record on the item that have published ranges the app can read.
    let rangedAdvisories: [ProjectResponse.Advisory]
    /// Those, as the core weighs them.
    var ranged: [CoreAdvisory] { rangedAdvisories.map(AdvisoryCheck.weighedAs) }
    /// Every id on the item is an advisory of the project's record with published ranges: they alone decide.
    let covered: Bool
    let fixedIn: [String]
    /// The project's weighed advisories, which the upgrade must leave too.
    let weighed: [CoreAdvisory]

    init(_ issue: StateResponse.BigIssue, project: ProjectResponse?) {
        let listed = project?.recent.filter { a in issue.ids.contains(a.id) || a.cve.map(issue.ids.contains) == true } ?? []
        let withRanges = listed.filter { !(AdvisoryCheck.weighedAs($0).ranges ?? []).isEmpty }
        let coveredIDs = Set(withRanges.flatMap { [$0.id] + ($0.cve.map { [$0] } ?? []) })
        rangedAdvisories = withRanges
        covered = !withRanges.isEmpty && withRanges.count == listed.count && issue.ids.allSatisfy(coveredIDs.contains)
        fixedIn = issue.fixedIn
        weighed = (project?.recent ?? []).filter(FindingBuilder.weighed).map(AdvisoryCheck.weighedAs)
    }

    /// The advisories on the item whose published ranges hold `installed`.
    func holding(_ installed: String) -> [ProjectResponse.Advisory] {
        zip(rangedAdvisories, core.verdicts(installed: installed, advisories: ranged)).filter { $0.1 == .inRange }.map(\.0)
    }

    /// `.affected` when an advisory on the item has published ranges that hold `installed`; `.likely` when the item
    /// has an advisory without them and its first fixed versions say `installed` is affected; else nil.
    func verdict(_ installed: String) -> Finding.Check? {
        if !holding(installed).isEmpty { return .affected }
        guard !covered else { return nil }
        return core.verdicts(installed: installed, advisories: [CoreAdvisory(ranges: nil, fixed: fixedIn)]) == [.likely] ? .likely : nil
    }

    /// Whether the core finds `candidate` above `installed` and clear of every advisory on the item that has published
    /// ranges (Decide.lean `judge_spec`). Call it off the main thread.
    func leaves(_ candidate: String, from installed: String) -> Bool {
        guard FixSafety.isSafeVersion(candidate),
              let j = core.judge(candidate, from: installed, advisories: ranged, flagged: [Bool](repeating: true, count: ranged.count)) else { return false }
        return j.leaves.allSatisfy { $0 }
    }

    /// The core's upgrade over the item's advisories and the project's weighed ones, each once (so the work the core may
    /// do is not spent twice on one). Call it off the main thread.
    func upgrade(_ installed: String) -> Core.UpgradeAnswer {
        var seen = Set<CoreAdvisory>()
        let advisories = (weighed + ranged + (covered ? [] : [CoreAdvisory(ranges: nil, fixed: fixedIn)])).filter { seen.insert($0).inserted }
        return core.upgrade(from: installed, advisories: advisories)
    }

    /// That upgrade, as a finding may show it (`AdvisoryCheck.shown`).
    func fix(_ installed: String) -> (upgrade: CheckedUpgrade?, withheld: AdvisoryCheck.Withheld?) { AdvisoryCheck.shown(upgrade(installed)) }
}
