import Foundation

/// Turns the API's answers into findings. Pure: everything it needs is passed in, so the tests drive it directly.
/// Every flaw and advisory is decided by the verified core from the ranges the site publishes: affected only inside
/// them, likely affected by first fixed versions without them, and otherwise reported, not checked. For a project's or
/// product's advisories the upgrade is the core's (AdvisoryCheck, IssueCheck); for packages checked by exact version,
/// the server's target is the upgrade only when the core confirms it (BatchCheck, `packageFindings`). Call it off the
/// main thread: the core's upgrades and judgements must not block it.
public struct FindingBuilder: Sendable {
    public let index: PublicIndex
    private let core = Core.shared

    public init(index: PublicIndex) { self.index = index }

    /// A Homebrew formula or cask matched to a project.
    public struct BrewMatch: Sendable {
        public var item: HomebrewItem
        public var project: PublicIndex.Project
        public init(item: HomebrewItem, project: PublicIndex.Project) { self.item = item; self.project = project }
    }

    public func findings(approved all: [ApprovedPackage: [InstalledPackage]],
                         verdicts: [ApprovedPackage: BatchResponse.Result],
                         brew: [BrewMatch],
                         projects: [String: ProjectResponse],
                         bigIssues: [StateResponse.BigIssue],
                         managed: [ManagedMatch] = []) -> [Finding] {
        // Packages inside Go and Rust programs and pipx and uv tools are reported per program (ProgramFindings.swift).
        let (approved, programs) = Self.separatingPrograms(all)
        var out = packageFindings(approved: approved, verdicts: verdicts)
        out += projectFindings(brew: brew, projects: projects)
        out += managedFindings(managed, projects: projects)
        applyBigIssues(bigIssues, to: &out, approved: approved, brew: brew, projects: projects)
        applyBigIssues(bigIssues, toManaged: managed, findings: &out, projects: projects)
        programFindings(programs, verdicts: verdicts, into: &out)
        return out.sorted(by: Self.precedes)
    }

    /// The order findings are listed in: by group, worst severity first, then by title.
    public static func precedes(_ a: Finding, _ b: Finding) -> Bool {
        (a.group, -(a.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), a.title.lowercased(), a.id)
            < (b.group, -(b.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), b.title.lowercased(), b.id)
    }

    // MARK: Packages (exact versions, from api/v1/check/batch)

    /// What one package's answer makes of its finding (BatchCheck decides each flaw): the group, how serious, and how
    /// many flaws it is shown for, and the flaws on this Mac it is not shown for, which its note says and its mark shows.
    /// A malicious package is flagged from the malware record itself, as before.
    struct PackageState {
        /// Nil for a malicious package.
        var check: Finding.Check?
        var group: Finding.Group
        var severity: Severity?
        var exploited: Bool
        var malicious: Bool
        var flawCount: Int
        /// Every flaw is of another platform: listed, not urgent, nothing to do on this Mac.
        var onlyElsewhere: Bool
        /// The ids of the flaws the finding is shown for that can affect where the package runs.
        var here: Set<String>
        /// The likely flaws on this Mac an affected finding also has, and the most urgent of them.
        var moreLikely = 0, likelyAlert: Finding.NotChecked? = nil
        /// The reported flaws on this Mac (and past the list) an affected or likely finding also has, and the most urgent.
        var moreReported = 0, reportedAlert: Finding.NotChecked? = nil
        /// Its most urgent flaw on this Mac not checked against published ranges, when exploited or critical.
        var notChecked: Finding.NotChecked? = nil
    }

    /// The finding's state, from the most certain flaws that can affect where the package runs: affected ones by today's
    /// groups, else likely ones, else reported ones (and those past the list). For software on this Mac (`onThisMac`),
    /// flaws of another platform do not make the finding urgent; when every flaw is of another platform it is listed in
    /// Other, with nothing to do. A project folder's dependencies run wherever the project is deployed: every flaw
    /// counts. Flaws on this Mac that are not checked are never silent: counted in the note, and the most urgent of them
    /// kept as `notChecked`. `program`: a part of a program or tool, where a malicious package's unlisted flaws count too.
    static func state(_ verdict: BatchResponse.Result, _ check: BatchCheck, onThisMac: Bool, program: Bool = false) -> PackageState {
        let flaws = verdict.flaws
        func onThisMacOnly(_ fs: [BatchResponse.Flaw]) -> [BatchResponse.Flaw] { onThisMac ? fs.filter(\.affectsThisMac) : fs }
        func worst(_ fs: [BatchResponse.Flaw]) -> Severity? { fs.compactMap { Severity(api: $0.severity) }.max() }
        func exploited(_ fs: [BatchResponse.Flaw]) -> Bool { fs.contains { $0.exploitedSince != nil } }
        func ids(_ fs: [BatchResponse.Flaw]) -> Set<String> { Set(fs.map(\.id)) }
        let malicious = verdict.malicious || flaws.contains(where: \.malicious) || verdict.plan?.remaining.contains { $0.reason == .malicious } == true
        if malicious {
            let here = onThisMacOnly(flaws)
            let count = flaws.isEmpty ? max(verdict.distinctFlaws, 0) : here.count + (program ? check.unlisted : 0)
            return PackageState(check: nil, group: .malicious, severity: nil,
                                exploited: flaws.isEmpty ? !verdict.exploited.isEmpty : exploited(here),
                                malicious: true, flawCount: count, onlyElsewhere: false, here: ids(here))
        }
        let affected = onThisMacOnly(check.affected), likely = onThisMacOnly(check.likely), reported = onThisMacOnly(check.reported.map(\.flaw))
        let likelyAlert = check.alert(likely, unlisted: false), reportedAlert = check.alert(reported, unlisted: true)
        let moreReported = reported.count + check.unlisted
        if !affected.isEmpty {
            // Today's groups, applied to the affected flaws on this Mac only.
            let severity = worst(affected)
            let group: Finding.Group = exploited(affected) ? .exploited : (severity ?? .low) >= .high ? .criticalHigh : .other
            return PackageState(check: .affected, group: group, severity: severity, exploited: exploited(affected), malicious: false,
                                flawCount: affected.count, onlyElsewhere: false, here: ids(affected), moreLikely: likely.count, likelyAlert: likelyAlert,
                                moreReported: moreReported, reportedAlert: reportedAlert, notChecked: .worse(likelyAlert, reportedAlert))
        }
        if !likely.isEmpty {
            return PackageState(check: .likely, group: .likely, severity: worst(likely), exploited: exploited(likely), malicious: false,
                                flawCount: likely.count, onlyElsewhere: false, here: ids(likely), moreReported: moreReported, reportedAlert: reportedAlert,
                                notChecked: .worse(likelyAlert, reportedAlert))
        }
        if !reported.isEmpty || check.unlisted > 0 || flaws.isEmpty {
            // Never counted and never fixed by a version; how serious it would be stays visible, past the list too.
            let severity = [worst(reported), check.unlistedWorst].compactMap { $0 }.max() ?? (flaws.isEmpty ? Severity(api: verdict.worstSeverity) : nil)
            let isExploited = exploited(reported) || !check.unlistedExploited.isEmpty || (flaws.isEmpty && !verdict.exploited.isEmpty)
            return PackageState(check: .reported, group: .reported, severity: severity, exploited: isExploited, malicious: false,
                                flawCount: max(moreReported, 1), onlyElsewhere: false, here: ids(reported), notChecked: reportedAlert)
        }
        let shown = check.check == .affected ? check.affected : check.check == .likely ? check.likely : check.reported.map(\.flaw)
        return PackageState(check: check.check, group: .other, severity: worst(shown), exploited: false, malicious: false, flawCount: shown.count,
                            onlyElsewhere: true, here: [])
    }

    /// The flaws an upgrade leaves the package with, as the core decided them (BatchCheck.notFixed). Without an upgrade
    /// shown, only those with a reason of their own (a newer Python, another platform, no fix yet): "not fixed by this
    /// upgrade" needs an upgrade.
    static func unresolved(_ check: BatchCheck, upgrade: CheckedUpgrade?, python: String?, onThisMac: Bool) -> [UnresolvedFlaw] {
        let all = check.notFixed.map { n in
            let elsewhere = n.reason == nil && !n.flaw.affectsThisMac
            return UnresolvedFlaw(id: n.flaw.id, severity: Severity(api: n.flaw.severity), fixedIn: n.fixedIn?.display,
                                  reason: n.reason.map(Self.reason) ?? (elsewhere ? .otherPlatform : .unknown),
                                  detail: n.detail ?? (elsewhere ? n.flaw.platform : nil), python: python, onThisMac: onThisMac,
                                  summary: Self.shortSummary(n.flaw.summary))
        }
        return upgrade == nil ? all.filter { $0.reason != .unknown } : all
    }

    /// "fixes N here": the flaws the finding is shown for (its affected ones, or its likely ones) that can affect where
    /// the package runs and the upgrade leaves. An affected finding's likely flaws are not counted, as its flaw count
    /// does not count them.
    static func fixesCount(_ check: BatchCheck, _ state: PackageState, upgrade: CheckedUpgrade?, plan: BatchResponse.Plan?) -> Int? {
        guard upgrade != nil else { return plan.map { _ in 0 } }
        return check.fixed.filter(state.here.contains).count
    }

    func packageFindings(approved: [ApprovedPackage: [InstalledPackage]], verdicts: [ApprovedPackage: BatchResponse.Result]) -> [Finding] {
        var out: [Finding] = []
        for (package, verdict) in verdicts {
            let installs = approved[package] ?? []
            guard !installs.isEmpty else { continue }
            let onThisMac = package.platform == "macos"
            let check = BatchCheck.read(verdict, installed: package.version)
            let state = Self.state(verdict, check, onThisMac: onThisMac)
            let malicious = state.malicious, onlyElsewhere = state.onlyElsewhere
            // The server's target only as the core confirmed it, and only if it reads as a version (BatchCheck), and
            // leaves a flaw the finding is shown for (`here`). One the core does not confirm leaves no version, and no
            // command that would install it.
            let target = onlyElsewhere ? check.target : check.target(for: state.here)
            let upgrade = malicious || state.check == .reported ? nil : onlyElsewhere ? check.upgrade : check.upgrade(for: state.here)
            let rejected = !malicious && target == .notAVersion
            let unconfirmed = !malicious && state.check != .reported && target == .unconfirmed
            let unresolved = malicious
                ? (verdict.plan?.remaining ?? []).filter { $0.reason != .malicious }.map { r in
                    let flaw = verdict.flaws.first { $0.id == r.id }
                    return UnresolvedFlaw(id: r.id, severity: Severity(api: flaw?.severity), fixedIn: r.fixedIn, reason: Self.reason(r.reason),
                                          detail: r.detail, python: package.python, onThisMac: onThisMac, summary: Self.shortSummary(flaw?.summary))
                }
                : state.check == .reported ? [] : Self.unresolved(check, upgrade: upgrade, python: package.python, onThisMac: onThisMac)
            // A command needs a version the core checked, unless Homebrew picks it (`brew upgrade`, whose versions the
            // person already takes): never npm's @latest, `cargo install x` or `gem update x` on the server's word.
            let withheld = !malicious && (rejected || unconfirmed || state.check == .reported || onlyElsewhere)
            let page = SiteURL.packagePage(package.ecosystem, package.name, version: package.version)

            // An app that bundles Electron is its own finding (it is updated on its own), and so is an extension that
            // bundles the package; other copies share one.
            let apps = installs.filter { $0.origin.kind == .electron }
            let extensions = installs.filter { $0.origin.kind == .extensions }
            let others = installs.filter { $0.origin.kind != .electron && $0.origin.kind != .extensions }
            func finding(id: String, title: String, component: String?, origins: [Origin], spelledAs: String) -> Finding {
                let inputs = UpgradeCommand.Inputs(origin: origins[0], name: spelledAs, ecosystem: package.ecosystem, target: upgrade?.version,
                                                   malicious: malicious)
                let full = UpgradeCommand.advice(inputs)
                let unchecked = !malicious && upgrade == nil && full.command.map { !UpgradeCommand.isHomebrewUpgrade($0) } == true
                // without a command, a note that does not depend on one stays ("Update GitLens in VS Code: …")
                let advice = withheld || unchecked ? UpgradeCommand.Advice(command: nil, note: full.command == nil ? full.note : nil) : full
                let rejectedNote = "The server named a fixed version the app does not accept as a version; see the site."
                let noChecked = "No checked fixed version yet; see the site."
                let more = Self.sentences(BatchCheck.moreLikely(state.moreLikely, naming: state.likelyAlert),
                                          BatchCheck.moreReported(state.moreReported, naming: state.reportedAlert))
                let note: String?
                switch state.check {
                case nil:
                    note = "Remove it, then rotate every secret it could read."
                case _ where onlyElsewhere:
                    note = nil
                case .affected?:
                    let why: String?
                    if rejected { why = rejectedNote }
                    else if unconfirmed { why = noChecked }
                    else if verdict.plan != nil && target == .none && unresolved.isEmpty { why = "No fixed release yet." }
                    else if unchecked { why = noChecked }
                    else { why = advice.note }
                    note = Self.sentences(why, more)
                case .likely?:
                    let how = rejected ? rejectedNote : unconfirmed ? noChecked : advice.note
                    note = Self.sentences(check.likelySentence(upgrade: upgrade?.display), how, more)
                case .reported?:
                    note = check.reportedNote(ecosystem: verdict.ecosystem, onThisMac: onThisMac)
                }
                return Finding(id: id, group: state.group, subject: .package(ecosystem: package.ecosystem, name: package.name), title: title,
                               component: component, installedVersion: package.version, upgrade: upgrade,
                               severity: state.severity, advisoryIDs: verdict.advisories, flawCount: state.flawCount,
                               exploited: state.exploited, malicious: malicious, note: note, bigIssue: nil, origins: origins, pageURL: page,
                               upgradeCommand: advice.command, verification: .none, grade: nil,
                               fixesCount: Self.fixesCount(check, state, upgrade: upgrade, plan: verdict.plan), unresolved: unresolved,
                               commandInputs: advice.command == nil ? nil : inputs, notChecked: state.notChecked)
            }
            for app in apps {
                guard case let .electronApp(name, path, _) = app.origin else { continue }
                out.append(finding(id: "app|\(path)|\(package.version)", title: name, component: "Electron", origins: [app.origin], spelledAs: app.name))
            }
            for e in extensions {
                guard case let .addOn(_, _, name, _, path) = e.origin else { continue }
                out.append(finding(id: "ext|\(path)|\(package.name)|\(package.version)", title: name, component: e.name, origins: [e.origin], spelledAs: e.name))
            }
            if !others.isEmpty {
                var seen = Set<Origin>()
                let origins = others.map(\.origin).filter { seen.insert($0).inserted }
                let id = "pkg|\(package.ecosystem)|\(package.name)|\(package.version)" + (package.python.map { "|py\($0)" } ?? "")
                out.append(finding(id: id, title: others[0].name, component: nil, origins: origins, spelledAs: others[0].name))
            }
        }
        return out
    }

    /// Sentences joined into one note; nil when there are none.
    static func sentences(_ parts: String?...) -> String? {
        let present = parts.compactMap { $0 }
        return present.isEmpty ? nil : present.joined(separator: " ")
    }

    /// An advisory summary short enough for one or two lines in the panel.
    static func shortSummary(_ s: String?) -> String? {
        guard let s = s?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
        let line = s.components(separatedBy: .newlines).joined(separator: " ")
        return line.count <= 110 ? line : String(line.prefix(108)).trimmingCharacters(in: .whitespaces) + "…"
    }

    static func reason(_ r: BatchResponse.Plan.Remaining.Reason) -> UnresolvedFlaw.Reason {
        switch r {
        case .needsPython: return .needsPython
        case .otherPlatform: return .otherPlatform
        case .noFix: return .noFix
        case .malicious, .unknown, .blockedByConstraint: return .unknown
        }
    }

    // MARK: Projects (Homebrew, from api/v1/project/<slug>)

    /// Advisories the app weighs for a project: critical and high ones, and any exploited in the wild.
    static func weighed(_ a: ProjectResponse.Advisory) -> Bool { (Severity(api: a.severity) ?? .low) >= .high || a.kev }

    func projectFindings(brew: [BrewMatch], projects: [String: ProjectResponse]) -> [Finding] {
        var out: [Finding] = []
        for match in brew {
            guard let project = projects[match.project.slug] else { continue }
            let (compared, installed) = Self.versions(match.item, slug: project.slug)
            // Each weighed advisory decided by the core: affected inside its published ranges, likely by its first fixed
            // versions without them, reported when they cannot be read; the upgrade is the core's (AdvisoryCheck).
            guard let d = AdvisoryCheck.decide(compared, project.recent) else { continue }
            // A versioned formula never leaves its line: `brew upgrade python@3.11` cannot install 3.12.9, so a fix only on
            // another line is said, not offered as a command that would do nothing.
            let offLine = d.target.map { t in Self.formulaLine(match.item).map { !Self.isOnLine(t.version, $0) } ?? false } ?? false
            let upgrade = offLine ? nil : d.target?.displayed(Self.display(slug: project.slug))
            let note = d.note(showing: Self.shownVersion(slug: project.slug), offLine: offLine ? match.item.name : nil)
            // Homebrew picks its own version; still no command for a finding only reported, or whose upgrade the core withheld
            let inputs = Self.inputs(match.item.origin, match.item.name, nil, upgrade?.display)
            let command = offLine ? nil : d.advice(UpgradeCommand.advice(inputs)).command
            out.append(Finding(
                id: "brew|\(match.item.name)|\(match.item.version)", group: d.group,
                subject: .project(slug: project.slug, name: project.name, installedAs: match.item.name), title: project.name,
                installedVersion: installed, upgrade: upgrade, severity: d.severity,
                advisoryIDs: d.advisories.map(\.id), flawCount: d.flawCount, exploited: d.exploited, malicious: false,
                note: note, bigIssue: nil, origins: [match.item.origin],
                pageURL: SiteURL.projectPage(slug: project.slug), upgradeCommand: command,
                verification: project.verificationMark, grade: project.grade,
                commandInputs: command == nil ? nil : inputs, notChecked: d.notChecked))
        }
        return out
    }

    /// The version a formula is compared with its project's advisories in, and the one its row shows. OpenJDK's
    /// advisories use Java's canonical versions (JavaVersion), so openjdk@8's "1.8.0-511" is compared as 8.0.511 and
    /// shown as Java names it, 8u511, like the Java runtimes' own rows; every other formula's version is its own.
    static func versions(_ item: HomebrewItem, slug: String) -> (compared: String, shown: String) {
        guard slug == JavaCheck.openJDK, let c = JavaVersion.canonical(item.version) else { return (item.version, item.version) }
        return (c, JavaVersion.shown(c))
    }

    /// How the project's versions are shown: Java's way for OpenJDK, as they are for the rest.
    static func shownVersion(slug: String) -> (String) -> String {
        if slug == JavaCheck.openJDK { return { JavaVersion.shown($0) } }
        return { $0 }
    }

    /// How the project's upgrade is shown, the same way.
    static func display(slug: String) -> CheckedUpgrade.Display { slug == JavaCheck.openJDK ? .java : .asChecked }

    /// The release line a versioned formula stays on: "python@3.11" → 3.11, "postgresql@16" → 16, "openssl@3" → 3. Nil for
    /// an unversioned formula or a cask, which may move to any release.
    static func formulaLine(_ item: HomebrewItem) -> [Int]? {
        guard item.kind == .formula, let at = item.name.lastIndex(of: "@") else { return nil }
        let parts = item.name[item.name.index(after: at)...].split(separator: ".", omittingEmptySubsequences: false)
        let numbers = parts.compactMap { $0.allSatisfy(\.isNumber) ? Int($0) : nil }
        return !parts.isEmpty && numbers.count == parts.count ? numbers : nil
    }

    /// Whether a version's first numbers are the line's ("3.11.18" is on 3.11, "3.12.9" is not).
    static func isOnLine(_ version: String, _ line: [Int]) -> Bool {
        let numbers = version.drop { $0 == "v" || $0 == "V" }.split(separator: ".").prefix(line.count).map { Int($0.prefix { $0.isNumber }) }
        return numbers.count == line.count && zip(numbers, line).allSatisfy { $0 == $1 }
    }

    /// The inputs of an upgrade command, with a version from the server only if it reads as one.
    static func inputs(_ origin: Origin, _ name: String, _ ecosystem: Ecosystem?, _ target: String?) -> UpgradeCommand.Inputs {
        UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: ecosystem, target: target.flatMap { FixSafety.isSafeVersion($0) ? $0 : nil },
                              malicious: false)
    }

    // MARK: "Patch these first" (api/v1/state big_issues)

    /// The label of a finding on the site's "patch these first" list.
    static func label(_ issue: StateResponse.BigIssue) -> String {
        "On the site's “patch these first” list: \(issue.title.isEmpty ? issue.name : issue.title)"
    }

    /// Today's group, for a finding the item's published ranges hold.
    static func group(_ issue: StateResponse.BigIssue) -> Finding.Group {
        issue.exploited ? .exploited : (Severity(api: issue.severity) ?? .low) >= .high ? .criticalHigh : .other
    }

    /// The mark an item leaves where the core did not find it affected, when it is exploited in the wild or critical.
    static func signal(_ issue: StateResponse.BigIssue) -> Finding.NotChecked? {
        let critical = Severity(api: issue.severity) == .critical
        return issue.exploited || critical ? Finding.NotChecked(id: issue.ids.first, exploited: issue.exploited, critical: critical) : nil
    }

    /// An item on a finding another path made: it labels it, and promotes it only when the core found the item's
    /// published ranges hold the version (`.affected`). A likely item marks it instead, when exploited or critical. It
    /// never names a version for it.
    static func mark(_ finding: inout Finding, with issue: StateResponse.BigIssue, verdict: Finding.Check) {
        finding.bigIssue = label(issue)
        guard verdict == .affected else {
            finding.notChecked = .worse(finding.notChecked, signal(issue))
            return
        }
        let severity = Severity(api: issue.severity)
        if issue.exploited { finding.exploited = true }
        if group(issue) < finding.group { finding.group = group(issue) }
        if finding.severity == nil || (severity.map { $0 > finding.severity! } ?? false) { finding.severity = severity }
    }

    /// Items decided like the project's own advisories (IssueCheck): affected only inside published ranges, likely by
    /// the list's first fixed versions otherwise. A finding an item makes is in today's groups only when affected, and
    /// in Likely otherwise; its version is the core's, shown only when it reads as one.
    func applyBigIssues(_ issues: [StateResponse.BigIssue], to findings: inout [Finding], approved: [ApprovedPackage: [InstalledPackage]],
                        brew: [BrewMatch], projects: [String: ProjectResponse]) {
        for issue in issues where !issue.fixedIn.isEmpty {
            let check = IssueCheck(issue, project: projects[issue.slug])
            let severity = Severity(api: issue.severity)
            func group(_ verdict: Finding.Check) -> Finding.Group { verdict == .affected ? Self.group(issue) : .likely }
            func signal(_ verdict: Finding.Check) -> Finding.NotChecked? { verdict == .affected ? nil : Self.signal(issue) }
            // Homebrew formulae and casks of the project
            for match in brew where match.project.slug == issue.slug {
                let (v, installed) = Self.versions(match.item, slug: issue.slug)
                guard let verdict = check.verdict(v) else { continue }
                let id = "brew|\(match.item.name)|\(match.item.version)"
                if let i = findings.firstIndex(where: { $0.id == id }) { Self.mark(&findings[i], with: issue, verdict: verdict); continue }
                let project = projects[issue.slug]
                let fix = check.fix(v)
                let upgrade = fix.upgrade?.displayed(Self.display(slug: issue.slug))
                let inputs = Self.inputs(match.item.origin, match.item.name, nil, upgrade?.display)
                // Homebrew picks its own version; none for one the core withheld
                let command = fix.withheld == nil ? UpgradeCommand.advice(inputs).command : nil
                findings.append(Finding(id: id, group: group(verdict),
                                        subject: .project(slug: issue.slug, name: project?.name ?? match.project.name, installedAs: match.item.name),
                                        title: project?.name ?? match.project.name, installedVersion: installed, upgrade: upgrade, severity: severity,
                                        advisoryIDs: issue.ids, flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                                        note: check.note(verdict, installed: v, fix: fix, showing: Self.shownVersion(slug: issue.slug)), bigIssue: Self.label(issue),
                                        origins: [match.item.origin], pageURL: SiteURL.projectPage(slug: issue.slug), upgradeCommand: command,
                                        verification: project?.verificationMark ?? .none, grade: project?.grade,
                                        commandInputs: command == nil ? nil : inputs, notChecked: signal(verdict)))
            }
            // Registry packages that belong to the project (the index's project column), Electron apps for "electron".
            for (package, installs) in approved {
                let belongs = issue.slug == "electron" && package.ecosystem == .npm && package.name == "electron"
                guard belongs, let verdict = check.verdict(package.version) else { continue }
                var asked: (upgrade: CheckedUpgrade?, withheld: AdvisoryCheck.Withheld?)?
                for install in installs {
                    let isApp = install.origin.kind == .electron
                    let id: String
                    if case let .electronApp(_, path, _) = install.origin { id = "app|\(path)|\(package.version)" }
                    else { id = "pkg|\(package.ecosystem)|\(package.name)|\(package.version)" + (package.python.map { "|py\($0)" } ?? "") }
                    if let i = findings.firstIndex(where: { $0.id == id }) { Self.mark(&findings[i], with: issue, verdict: verdict); continue }
                    let fix = asked ?? check.fix(package.version)
                    asked = fix
                    let inputs = Self.inputs(install.origin, install.name, package.ecosystem, fix.upgrade?.version)
                    // no version the core checked: only Homebrew's own upgrade; none at all for one the core withheld
                    let command = fix.withheld != nil ? nil
                        : UpgradeCommand.advice(inputs).command.flatMap { fix.upgrade != nil || UpgradeCommand.isHomebrewUpgrade($0) ? $0 : nil }
                    findings.append(Finding(id: id, group: group(verdict), subject: .package(ecosystem: package.ecosystem, name: package.name),
                                            title: isApp ? install.origin.label : install.name, component: isApp ? "Electron" : nil,
                                            installedVersion: package.version, upgrade: fix.upgrade, severity: severity, advisoryIDs: issue.ids,
                                            flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                                            note: check.note(verdict, installed: package.version, fix: fix), bigIssue: Self.label(issue),
                                            origins: [install.origin], pageURL: SiteURL.packagePage(package.ecosystem, package.name, version: package.version),
                                            upgradeCommand: command,
                                            verification: projects[issue.slug]?.verificationMark ?? .none, grade: projects[issue.slug]?.grade,
                                            commandInputs: command == nil ? nil : inputs, notChecked: signal(verdict)))
                }
            }
        }
    }
}
