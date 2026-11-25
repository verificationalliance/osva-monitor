import Foundation

/// One package's answer from api/v1/check/batch, decided flaw by flaw by the verified core (Decide.lean, through
/// Core.swift), never by the server's verdict alone:
///   - **affected**: the installed version lies inside one of the ranges the site publishes for the flaw (`.inRange`);
///   - **likely affected**: the site publishes no ranges for it, and its first fixed versions say the version is
///     affected (`.likely`);
///   - **reported, not checked**: every other flaw the server matched. Its ranges leave the version out (the core and
///     the ecosystem may order a boundary differently), it has no ranges and its first fixed versions do not flag the
///     version, its ranges or fixed versions could not be read, it is a Maven or Packagist flaw whose versions the core
///     may order otherwise (`Core.versionUncertain`), or it is past the flaws the server lists (`unlisted`).
/// Malicious flaws are none of these: the malware record flags the package itself (FindingBuilder).
///
/// The server's plan is read only through the core. Its target is the upgrade only when `Core.judge` finds it above the
/// installed version and clear of at least one affected or likely flaw; the flaws it fixes are the ones the core says
/// it leaves; and a remaining flaw's fixed version is named only when the core says it clears that flaw. Every version
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
        /// The core does not confirm it: it is not above the installed version, or leaves no affected or likely flaw.
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

    /// The finding's state: affected when any flaw is, else likely when any flaw is, else reported.
    var check: Finding.Check { !affected.isEmpty ? .affected : !likely.isEmpty ? .likely : .reported }

    /// Reads the answer for `installed` (the version asked about).
    static func read(_ verdict: BatchResponse.Result, installed: String) -> BatchCheck {
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

        // The server's target, judged against every affected and likely flaw: one leaves[i] per flagged[i].
        let planned = verdict.plan?.target
        let judged = flagged.isEmpty ? nil : planned.flatMap { Self.judge($0, from: installed, advisories) }
        let upgrade = judged?.upgrade
        let target: Target = planned.map { FixSafety.isSafeVersion($0) ? (upgrade == nil ? .unconfirmed : .confirmed) : .notAVersion } ?? .none
        let leaves = upgrade == nil ? [Bool](repeating: false, count: flagged.count) : judged!.leaves
        let remaining = verdict.plan?.remaining ?? []
        var fixed: [String] = [], notFixed: [NotFixed] = []
        for (k, f) in flagged.enumerated() {
            if leaves[k] { fixed.append(f.id); continue }
            let r = remaining.first { $0.id == f.id && $0.reason != .malicious }
            let fixedIn = r?.fixedIn.flatMap { Self.judge($0, from: installed, [advisories[k]])?.upgrade }
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
                          flagged: flagged, advisories: advisories)
    }

    /// The upgrade a finding shown for the flaws `here` names: the confirmed target, only when it leaves at least one of
    /// them. A target that leaves only flaws the finding is not shown for (another platform's) is not that finding's fix.
    func upgrade(for here: Set<String>) -> CheckedUpgrade? { fixed.contains(where: here.contains) ? upgrade : nil }

    /// What became of the target for a finding shown for the flaws `here`: confirmed only as `upgrade(for:)` is.
    func target(for here: Set<String>) -> Target { target == .confirmed && upgrade(for: here) == nil ? .unconfirmed : target }

    /// The core's answer about a version the app did not pick (Task 7's partial fixes and pip's choice), over the
    /// affected and likely flaws, all flagged. Nil when it is not above the installed version, or does not read as a
    /// version and nothing else.
    func judge(_ candidate: String) -> Judgement? { Self.judge(candidate, from: installed, advisories) }

    private static func judge(_ candidate: String, from installed: String, _ advisories: [CoreAdvisory]) -> Judgement? {
        guard FixSafety.isSafeVersion(candidate) else { return nil }
        return Core.shared.judge(candidate, from: installed, advisories: advisories, flagged: [Bool](repeating: true, count: advisories.count))
    }
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
    /// and how many more it counts (those and the ones past the list, as its flaw count does).
    /// "Reported by the site, not checked: it publishes no affected ranges for CVE-X (and 2 more)."
    func reportedNote(ecosystem: String, onThisMac: Bool) -> String {
        let here = reported(onThisMac: onThisMac)
        guard let worst = Self.worst(here) else {
            return "Reported by the site, not checked: " + (unlisted == 1 ? "1 flaw is not listed." : "\(unlisted) flaws are not listed.")
        }
        let id = worst.flaw.id
        let why: String
        switch worst.reason {
        case .noRanges: why = "it publishes no affected ranges for \(id)"
        case .outsideRanges: why = "the affected ranges it publishes for \(id) do not include \(installed)"
        case .unreadable: why = "the app could not read its affected ranges for \(id)"
        case .uncertainOrder: why = "\(ecosystem) may order \(installed) and the versions it names for \(id) otherwise than the app does"
        }
        let more = here.count + unlisted - 1
        return "Reported by the site, not checked: \(why)" + (more > 0 ? " (and \(more) more)." : ".")
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
