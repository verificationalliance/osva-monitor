import Foundation

/// One package's answer from api/v1/check/batch, decided flaw by flaw by the verified core (Decide.lean, through
/// Core.swift), never by the server's verdict alone:
///   - **affected**: the installed version lies inside one of the ranges the site publishes for the flaw (`.inRange`);
///   - **likely affected**: the site publishes no ranges for it, and its first fixed versions say the version is
///     affected (`.likely`);
///   - **reported**: every other flaw the server matched. Its ranges leave the version out (the core checked it and
///     found the version clear, though the ecosystem may order a boundary differently: never "not checked", never an
///     alert, said in the note only), or, not checked: it has no ranges and its first fixed versions do not flag the
///     version, its ranges or fixed versions could not be read, it is a Maven or Packagist flaw whose versions the core
///     may order otherwise (`Core.versionUncertain`), or it is past the flaws the server lists (`unlisted`).
/// Malicious flaws are none of these: the malware record flags the package itself (FindingBuilder).
///
/// The server's plan is read only through the core. Its target is the upgrade only when `Core.judge` finds it above the
/// installed version, clear of at least one affected or likely flaw, and inside the published ranges of no other flaw
/// (`unflagged`: a version the installed one is outside of may still land in one); the flaws it fixes are the ones the
/// core says it leaves; and a remaining flaw's fixed version is named only when the core says it clears that flaw. Every version
/// judged must first read as a version and nothing else (FixSafety). The core is called off the main thread.
struct BatchCheck: Sendable {
    /// Why a flaw is reported rather than decided.
    enum Reason: Equatable, Sendable {
        /// The site publishes no ranges for it (nil or []), and its first fixed versions do not say the version is
        /// affected, or it names none.
        case noRanges
        /// The ranges the site publishes leave the installed version out, in the core's version order.
        case outsideRanges
        /// The app could not read its ranges or its fixed versions.
        case unreadable
        /// A Maven or Packagist flaw whose installed version, bounds or fixed versions the core may not order as the
        /// ecosystem does (`Core.versionUncertain`).
        case uncertainOrder
    }

    struct Reported: Equatable, Sendable {
        var flaw: BatchResponse.Flaw
        var reason: Reason
    }

    /// What became of the target the server's plan names.
    enum Target: Equatable, Sendable {
        /// The answer has no plan, or its plan names no target.
        case none
        /// It does not read as a version and nothing else (FixSafety): never judged, never shown.
        case notAVersion
        /// The core does not confirm it: it is not above the installed version, leaves no affected or likely flaw, or
        /// lands inside the published ranges of another flaw.
        case unconfirmed
        /// The core confirmed it: `upgrade`.
        case confirmed
    }

    /// An affected or likely flaw the upgrade does not leave.
    struct NotFixed: Equatable, Sendable {
        var flaw: BatchResponse.Flaw
        /// Why the server's plan leaves it, when the plan lists it as remaining.
        var reason: BatchResponse.Plan.Remaining.Reason?
        /// The plan's detail for it ("Python >=3.10", "Windows").
        var detail: String?
        /// The remaining entry's `fixed_in`, only when the core finds it above the installed version and clear of this flaw.
        var fixedIn: CheckedUpgrade?
    }

    let installed: String
    /// Flaws whose published ranges hold the installed version. Malicious flaws are never here.
    let affected: [BatchResponse.Flaw]
    /// Flaws without published ranges whose first fixed versions say the installed version is affected.
    let likely: [BatchResponse.Flaw]
    let reported: [Reported]
    /// Flaws the server counts (`distinct_flaws`) but does not list: reported, not checked.
    let unlisted: Int
    /// The answer's exploited CVEs (`exploited`) that no listed flaw carries as its id or an alias: flaws past the list
    /// that are exploited in the wild.
    let unlistedExploited: [String]
    /// The answer's worst severity, when flaws are past the list and no listed flaw is that severe: one of them is.
    let unlistedWorst: Severity?
    /// The server's target, when the core confirms it leaves at least one affected or likely flaw.
    let upgrade: CheckedUpgrade?
    let target: Target
    /// The ids of the affected and likely flaws `upgrade` leaves, in the answer's order. Empty without an upgrade.
    let fixed: [String]
    /// The other affected and likely flaws, in the answer's order.
    let notFixed: [NotFixed]
    /// The affected and likely flaws, in the answer's order, and what the core weighs them by: `upgrade` and `judge` are
    /// asked about these, with every one flagged.
    let flagged: [BatchResponse.Flaw]
    private let advisories: [CoreAdvisory]
    /// Every other flaw with published ranges the app can read that applies where the package runs (not another
    /// platform's, for software on this Mac), in the answer's order: the installed version lies outside them (or is one
    /// whose order the core may not share with the ecosystem). `upgrade` and `judge` are asked about these too, none
    /// flagged: a version that lands inside any of them is never the upgrade, as the core's own upgrades (AdvisoryCheck)
    /// never are.
    let unflagged: [BatchResponse.Flaw]
    private let others: [CoreAdvisory]

    /// The finding's state: affected when any flaw is, else likely when any flaw is, else reported.
    var check: Finding.Check { !affected.isEmpty ? .affected : !likely.isEmpty ? .likely : .reported }

    /// Reads the answer for `installed` (the version asked about). `onThisMac`: the package runs on this Mac (installed
    /// software), so a flaw of another platform cannot block its upgrade; false for a project folder's dependencies,
    /// which run wherever the project is deployed.
    static func read(_ verdict: BatchResponse.Result, installed: String, onThisMac: Bool = true) -> BatchCheck {
        let core = Core.shared
        let ecosystem = Ecosystem(verdict.ecosystem)
        let orderMayDiffer = ecosystem == .maven || ecosystem == .packagist
        let installedUncertain = orderMayDiffer && core.versionUncertain(installed)

        enum Decision { case affected, likely, reported(Reason) }
        let flaws = verdict.flaws
        var decisions = [Decision?](repeating: nil, count: flaws.count)          // nil: a malicious flaw, decided by its record
        var asked: [(at: Int, advisory: CoreAdvisory)] = []
        for (i, f) in flaws.enumerated() where !f.malicious {
            guard let a = f.coreAdvisory else { decisions[i] = .reported(.unreadable); continue }
            if orderMayDiffer {
                let named = (a.ranges ?? []).flatMap { [$0.introduced, $0.fixed, $0.lastAffected].compactMap { $0 } } + a.fixed
                if installedUncertain || named.contains(where: core.versionUncertain) { decisions[i] = .reported(.uncertainOrder); continue }
            }
            asked.append((i, a))
        }
        let verdicts = core.verdicts(installed: installed, advisories: asked.map(\.advisory))
        for ((i, a), v) in zip(asked, verdicts) {
            switch v {
            case .inRange: decisions[i] = .affected                     // claims-mutant: likely-as-flagged
            case .likely: decisions[i] = .likely
            case .clear: decisions[i] = .reported((a.ranges ?? []).isEmpty ? .noRanges : .outsideRanges)
            case .unstated: decisions[i] = .reported(.noRanges)
            }
        }

        var affected: [BatchResponse.Flaw] = [], likely: [BatchResponse.Flaw] = [], reported: [Reported] = []
        var flagged: [BatchResponse.Flaw] = [], advisories: [CoreAdvisory] = []
        let weighed = Dictionary(uniqueKeysWithValues: asked.map { ($0.at, $0.advisory) })
        for (i, f) in flaws.enumerated() {
            switch decisions[i] {
            case .affected?: affected.append(f); flagged.append(f); advisories.append(weighed[i]!)
            case .likely?: likely.append(f); flagged.append(f); advisories.append(weighed[i]!)
            case let .reported(reason)?: reported.append(Reported(flaw: f, reason: reason))
            case nil: break
            }
        }

        // Every other flaw with published ranges that applies where the package runs: a suggested version must land
        // inside none of them. A Windows-only flaw's range never blocks an upgrade of software on this Mac.
        var unflagged: [BatchResponse.Flaw] = [], others: [CoreAdvisory] = []
        let applies = { (f: BatchResponse.Flaw) in !onThisMac || f.affectsThisMac }   // claims-mutant: elsewhere-range-blocks
        for r in reported where applies(r.flaw) { if let a = r.flaw.coreAdvisory, !(a.ranges ?? []).isEmpty { unflagged.append(r.flaw); others.append(a) } }   // claims-mutant: flagged-only-judge

        // The server's target, judged against every affected and likely flaw (one leaves[i] per flagged[i]) and every
        // other flaw with published ranges, which it must leave too.
        let planned = verdict.plan?.unjudgedTarget
        let judged = flagged.isEmpty ? nil : planned.flatMap { Self.judge($0, from: installed, advisories, others) }
        let upgrade = judged.flatMap { Self.landsInside($0, flagged: advisories.count) ? nil : $0.upgrade }
        let target: Target = planned.map { FixSafety.isSafeVersion($0) ? (upgrade == nil ? .unconfirmed : .confirmed) : .notAVersion } ?? .none
        let leaves = upgrade == nil ? [Bool](repeating: false, count: flagged.count) : Array(judged!.leaves.prefix(flagged.count))
        let remaining = verdict.plan?.remaining ?? []
        var fixed: [String] = [], notFixed: [NotFixed] = []
        for (k, f) in flagged.enumerated() {
            if leaves[k] { fixed.append(f.id); continue }
            let r = remaining.first { $0.id == f.id && $0.reason != .malicious }
            let fixedIn = r?.fixedIn.flatMap { Self.judge($0, from: installed, [advisories[k]], [])?.upgrade }   // claims-mutant: fixed-in-for-another-flaw
            notFixed.append(NotFixed(flaw: f, reason: r?.reason, detail: r?.detail, fixedIn: fixedIn))
        }
        let unlisted = max(verdict.distinctFlaws - flaws.count, 0)
        let listedIDs = Set(flaws.flatMap { [$0.id] + $0.aliases })
        // what the answer says of all its flaws, beyond what it lists: past the list, a flaw is exploited when the answer
        // names it exploited and no listed flaw carries its id, and as severe as the answer's worst when none listed is
        let listedWorst = flaws.compactMap { Severity(api: $0.severity) }.max()
        let worst = Severity(api: verdict.worstSeverity).flatMap { w in (listedWorst.map { w > $0 } ?? true) ? w : nil }
        return BatchCheck(installed: installed, affected: affected, likely: likely, reported: reported, unlisted: unlisted,
                          unlistedExploited: unlisted > 0 ? verdict.exploited.filter { !listedIDs.contains($0) } : [],
                          unlistedWorst: unlisted > 0 ? worst : nil,
                          upgrade: upgrade, target: target, fixed: fixed, notFixed: notFixed,
                          flagged: flagged, advisories: advisories, unflagged: unflagged, others: others)
    }

    /// The upgrade a finding shown for the flaws `here` names: the confirmed target, only when it leaves at least one of
    /// them. A target that leaves only flaws the finding is not shown for (another platform's) is not that finding's fix.
    func upgrade(for here: Set<String>) -> CheckedUpgrade? { fixed.contains(where: here.contains) ? upgrade : nil }

    /// What became of the target for a finding shown for the flaws `here`: confirmed only as `upgrade(for:)` is.
    func target(for here: Set<String>) -> Target { target == .confirmed && upgrade(for: here) == nil ? .unconfirmed : target }

    /// The core's answer about a version the app did not pick (Task 7's partial fixes and pip's choice): its `leaves` are
    /// one per affected or likely flaw (`flagged`), all flagged, then one per other flaw with published ranges
    /// (`unflagged`), none flagged. Nil when it is not above the installed version, or does not read as a version and
    /// nothing else.
    func judge(_ candidate: String) -> Judgement? { Self.judge(candidate, from: installed, advisories, others) }

    /// Whether a judged version lands inside the published ranges of a flaw the app does not flag: never an upgrade.
    func landsInside(_ judgement: Judgement) -> Bool { Self.landsInside(judgement, flagged: advisories.count) }

    private static func judge(_ candidate: String, from installed: String, _ flagged: [CoreAdvisory], _ others: [CoreAdvisory]) -> Judgement? {
        guard FixSafety.isSafeVersion(candidate) else { return nil }
        return Core.shared.judge(candidate, from: installed, advisories: flagged + others,
                                 flagged: [Bool](repeating: true, count: flagged.count) + [Bool](repeating: false, count: others.count))
    }

    private static func landsInside(_ judgement: Judgement, flagged: Int) -> Bool { judgement.leaves.dropFirst(flagged).contains(false) }
}

// MARK: What a finding says about its flaws

extension BatchCheck {
    /// The reported flaws a finding is shown for: for software on this Mac (`onThisMac`), those that can affect it; for a
    /// project folder's dependencies, which run wherever the project is deployed, all of them (FindingBuilder.state).
    func reported(onThisMac: Bool) -> [Reported] { onThisMac ? reported.filter(\.flaw.affectsThisMac) : reported }

    /// The reported flaw to name among these: exploited first, then the most severe, then the first listed.
    static func worst(_ reported: [Reported]) -> Reported? {
        func rank(_ r: Reported) -> (Int, Int) {
            (r.flaw.exploitedSince == nil ? 1 : 0, -(Severity(api: r.flaw.severity).map { Severity.allCases.firstIndex(of: $0)! } ?? -1))
        }
        return reported.enumerated().min { a, b in
            let (ra, rb) = (rank(a.element), rank(b.element))
            return (ra.0, ra.1, a.offset) < (rb.0, rb.1, b.offset)
        }?.element
    }

    /// The note of a finding whose every flaw is reported: why the worst of the flaws it is shown for is not checked,
    /// and how many more it counts (those and the ones past the list, as its flaw count does); then the flaws whose
    /// published ranges leave the version out, which the core did check.
    /// "Reported by the site, not checked: it publishes no affected ranges for CVE-X (and 2 more)."
    /// "Reported by the site; its published ranges for CVE-Y do not include 1.2.3."
    func reportedNote(ecosystem: String, onThisMac: Bool) -> String {
        let here = reported(onThisMac: onThisMac)
        let unchecked = here.filter { $0.reason != .outsideRanges }, outside = here.filter { $0.reason == .outsideRanges }
        guard let worst = Self.worst(unchecked) else {
            if unlisted == 0, let first = Self.worst(outside) {
                return "Reported by the site; its published ranges for \(first.flaw.id) do not include \(installed)"
                    + (outside.count > 1 ? " (and \(outside.count - 1) more)." : ".")
            }
            return FindingBuilder.sentences("Reported by the site, not checked: " + (unlisted == 1 ? "1 flaw is not listed." : "\(unlisted) flaws are not listed."),
                                            Self.moreOutside(outside.count))!
        }
        let id = worst.flaw.id
        let why: String
        switch worst.reason {
        case .noRanges: why = "it publishes no affected ranges for \(id)"
        case .outsideRanges: why = "the affected ranges it publishes for \(id) do not include \(installed)"
        case .unreadable: why = "the app could not read its affected ranges for \(id)"
        case .uncertainOrder: why = "\(ecosystem) may order \(installed) and the versions it names for \(id) otherwise than the app does"
        }
        let more = unchecked.count + unlisted - 1
        return FindingBuilder.sentences("Reported by the site, not checked: \(why)" + (more > 0 ? " (and \(more) more)." : "."),
                                        Self.moreOutside(outside.count))!
    }

    /// Appended to a finding's note: the reported flaws whose published ranges leave the installed version out. The core
    /// checked them and found the version clear, so they are never "not checked" and never an alert. Nil when none.
    static func moreOutside(_ count: Int) -> String? {
        switch count {
        case 0: return nil
        case 1: return "1 more flaw is reported by the site; its published ranges do not include this version."
        case let n: return "\(n) more flaws are reported by the site; their published ranges do not include this version."
        }
    }

    /// For a finding shown as likely affected: what decided it. With the upgrade's version as shown; without one, why:
    /// the server's plan names no fix (`.none`), or names one the core does not confirm or the app cannot read as a
    /// version, which the note's next sentence says.
    func likelySentence(upgrade shown: String?) -> String {
        if let shown { return "Likely affected: the site publishes no affected ranges, and the issuer names \(shown) as fixed." }
        return target == .none ? "Likely affected: the site publishes no affected ranges; no fixed version clears it."
            : "Likely affected: the site publishes no affected ranges."
    }

    /// The most urgent of these flaws (and, with `unlisted`, of those past the list), when it is exploited or critical.
    func alert(_ flaws: [BatchResponse.Flaw], unlisted withUnlisted: Bool) -> Finding.NotChecked? {
        var best: Finding.NotChecked?
        for f in flaws {
            let a = Finding.NotChecked(id: f.id, exploited: f.exploitedSince != nil, critical: Severity(api: f.severity) == .critical)
            if a.exploited || a.critical { best = .worse(best, a) }
        }
        guard withUnlisted else { return best }
        if let id = unlistedExploited.first { best = .worse(best, Finding.NotChecked(id: id, exploited: true, critical: false)) }
        if unlistedWorst == .critical { best = .worse(best, Finding.NotChecked(id: nil, exploited: false, critical: true)) }
        return best
    }

    /// Appended to an affected finding's note: the likely flaws it also has, naming the most urgent. Nil when none.
    static func moreLikely(_ count: Int, naming alert: Finding.NotChecked?) -> String? {
        switch count {
        case 0: return nil
        case 1: return "1 more flaw without published ranges likely affects it too" + naming(alert, count: 1) + "."
        case let k: return "\(k) more flaws without published ranges likely affect it too" + naming(alert, count: k) + "."
        }
    }

    /// Appended to an affected or likely finding's note: the reported flaws it also has, naming the most urgent. Nil
    /// when none.
    static func moreReported(_ count: Int, naming alert: Finding.NotChecked?) -> String? {
        switch count {
        case 0: return nil
        case 1: return "1 more flaw is reported, not checked" + naming(alert, count: 1) + "."
        case let n: return "\(n) more flaws are reported, not checked" + naming(alert, count: n) + "."
        }
    }

    /// ": CVE-X, exploited in the wild", ", among them CVE-X, critical"; "" without an alert.
    static func naming(_ alert: Finding.NotChecked?, count: Int) -> String {
        guard let alert else { return "" }
        guard let id = alert.id else { return count == 1 ? ": a critical one" : ", one of them critical" }
        return (count == 1 ? ": " : ", among them ") + "\(id), \(alert.words)"
    }

    /// " (CVE-X, exploited in the wild)", " (one of them critical)": a program sentence's way of naming it.
    static func parenthetical(_ alert: Finding.NotChecked?, count: Int) -> String {
        guard let alert else { return "" }
        guard let id = alert.id else { return count == 1 ? " (critical)" : " (one of them critical)" }
        return " (\(id), \(alert.words))"
    }
}

// MARK: A "patch these first" item in a package's answer

extension BatchCheck {
    /// `verdict` with a "patch these first" item the core finds affected (`IssueCheck.verdict`) as one of its flaws, so
    /// that the finding is decided with it like any other: the listed flaw that is the item (by id or alias), decided by
    /// the published ranges of the item's advisories (`ranges`) unless its own already hold the version, at the item's
    /// severity and exploited when the item is; else the item as a flaw of its own. The answer's target is `target`:
    /// the core judges it against every flaw, the item's included.
    static func promoting(_ verdict: BatchResponse.Result, by issue: StateResponse.BigIssue, ranges: [AffectedRange], target: String?,
                          installed: String) -> BatchResponse.Result {
        var v = verdict
        let item = BatchResponse.Flaw(item: issue, ranges: ranges)
        if let k = v.flaws.firstIndex(where: { f in !f.malicious && ([f.id] + f.aliases).contains(where: issue.ids.contains) }) {
            var f = v.flaws[k]
            let holds = f.coreAdvisory.map { Core.shared.verdicts(installed: installed, advisories: [$0]) == [.inRange] } ?? false
            if !holds {
                f.ranges = ranges; f.rangesUnreadable = false; f.rangesNote = nil
                if f.fixedInUnreadable { f.fixedIn = []; f.fixedInUnreadable = false }
            }
            if let s = Severity(api: issue.severity), Severity(api: f.severity).map({ s > $0 }) ?? true { f.severity = issue.severity }
            if issue.exploited && f.exploitedSince == nil { f.exploitedSince = item.exploitedSince }
            v.flaws[k] = f
        } else {
            v.flaws.append(item)
            v.distinctFlaws += 1
        }
        v.advisories += issue.ids.filter { !v.advisories.contains($0) }
        var plan = v.plan ?? BatchResponse.Plan(target: nil, remaining: [])
        plan.unjudgedTarget = target
        v.plan = plan
        return v
    }
}

extension BatchResponse.Flaw {
    /// A "patch these first" item as a flaw: the published ranges of its advisories, its severity, exploited when it is.
    init(item issue: StateResponse.BigIssue, ranges: [AffectedRange]) {
        id = issue.ids.first ?? issue.name; aliases = Array(issue.ids.dropFirst()); severity = issue.severity
        summary = issue.title.isEmpty ? nil : issue.title
        fixedIn = []; fixedInUnreadable = false; fixForYou = nil; platform = nil
        exploitedSince = issue.exploited ? (issue.date.isEmpty ? "yes" : issue.date) : nil
        malicious = false; self.ranges = ranges; rangesNote = nil; rangesUnreadable = false
    }
}

extension BatchResponse.Plan {
    init(target: String?, remaining: [Remaining]) {
        unjudgedTarget = target; fixes = []; self.remaining = remaining; requiresPython = nil; newestInstallable = nil
    }
}
