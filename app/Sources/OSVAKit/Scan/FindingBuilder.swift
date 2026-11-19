import Foundation

/// Turns the API's answers into findings. Pure: everything it needs is passed in, so the tests drive it directly.
/// Affectedness and version choices are the verified core's.
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

    func packageFindings(approved: [ApprovedPackage: [InstalledPackage]], verdicts: [ApprovedPackage: BatchResponse.Result]) -> [Finding] {
        var out: [Finding] = []
        for (package, verdict) in verdicts {
            let installs = approved[package] ?? []
            guard !installs.isEmpty else { continue }
            let flaws = verdict.flaws
            // For software on this Mac, flaws of another platform are listed but do not make the finding urgent. A
            // project folder's dependencies run wherever the project is deployed: every flaw counts.
            let onThisMac = package.platform == "macos"
            let here = onThisMac ? flaws.filter(\.affectsThisMac) : flaws
            let malicious = verdict.malicious || flaws.contains(where: \.malicious) || verdict.plan?.remaining.contains { $0.reason == .malicious } == true
            let exploited = flaws.isEmpty ? !verdict.exploited.isEmpty : here.contains { $0.exploitedSince != nil }
            let severityHere = flaws.isEmpty ? Severity(api: verdict.worstSeverity) : here.compactMap { Severity(api: $0.severity) }.max()
            let severityAnywhere = severityHere ?? flaws.compactMap { Severity(api: $0.severity) }.max()
            let onlyElsewhere = !flaws.isEmpty && here.isEmpty && !malicious
            let group: Finding.Group = malicious ? .malicious : onlyElsewhere ? .other : exploited ? .exploited
                : (severityHere ?? .low) >= .high ? .criticalHigh : .other
            // A version from the server goes into a command only if it reads as a version and nothing else (FixSafety).
            let planned = malicious ? nil : verdict.plan?.target
            let target = planned.flatMap { FixSafety.isSafeVersion($0) ? $0 : nil }
            let rejected = planned != nil && target == nil
            let unresolved = (verdict.plan?.remaining ?? []).filter { $0.reason != .malicious }.map { r in
                // The API lists at most 40 flaws per package: a remaining one may have no entry, and is then named by its id.
                let flaw = flaws.first { $0.id == r.id }
                return UnresolvedFlaw(id: r.id, severity: Severity(api: flaw?.severity), fixedIn: r.fixedIn,
                                      reason: Self.reason(r.reason), detail: r.detail, python: package.python, onThisMac: onThisMac,
                                      summary: Self.shortSummary(flaw?.summary))
            }
            let page = SiteURL.packagePage(package.ecosystem, package.name, version: package.version)

            // An app that bundles Electron is its own finding (it is updated on its own), and so is an extension that
            // bundles the package; other copies share one.
            let apps = installs.filter { $0.origin.kind == .electron }
            let extensions = installs.filter { $0.origin.kind == .extensions }
            let others = installs.filter { $0.origin.kind != .electron && $0.origin.kind != .extensions }
            func finding(id: String, title: String, component: String?, origins: [Origin], spelledAs: String) -> Finding {
                let inputs = UpgradeCommand.Inputs(origin: origins[0], name: spelledAs, ecosystem: package.ecosystem, target: target, malicious: malicious)
                let advice = rejected ? UpgradeCommand.Advice(command: nil) : UpgradeCommand.advice(inputs)
                let note = malicious ? "Remove it, then rotate every secret it could read."
                    : onlyElsewhere ? nil
                    : rejected ? "The server named a fixed version the app does not accept as a version; see the site."
                    : (verdict.plan != nil && target == nil && unresolved.isEmpty ? "No fixed release yet." : advice.note)
                return Finding(id: id, group: group, subject: .package(ecosystem: package.ecosystem, name: package.name), title: title,
                               component: component, installedVersion: package.version, fixedVersion: target,
                               severity: malicious ? nil : severityAnywhere, advisoryIDs: verdict.advisories,
                               flawCount: flaws.isEmpty ? max(verdict.distinctFlaws, malicious ? 0 : 1) : max(here.count, onlyElsewhere ? flaws.count : 0),
                               exploited: exploited, malicious: malicious, note: note, bigIssue: nil, origins: origins, pageURL: page,
                               upgradeCommand: onlyElsewhere ? nil : advice.command, verification: .none, grade: nil,
                               fixesCount: verdict.plan.map { $0.fixes.count }, unresolved: unresolved,
                               commandInputs: onlyElsewhere || advice.command == nil ? nil : inputs)
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
            let shown = Self.shownVersion(slug: project.slug)
            // Each advisory by the issuer's ranges when it has them, else by its first fixed versions (AdvisoryCheck).
            guard let d = AdvisoryCheck.decide(compared, project.recent) else { continue }
            var target = d.target.map(shown), note = d.note(showing: shown)
            // A versioned formula never leaves its line: `brew upgrade python@3.11` cannot install 3.12.9, so a fix only on
            // another line is said, not offered as a command that would do nothing.
            let offLine = target.map { t in Self.formulaLine(match.item).map { !Self.isOnLine(t, $0) } ?? false } ?? false
            if offLine, let t = target {
                note = "The issuer lists \(installed) as affected; its fix, \(t), is not a \(match.item.name) release."
                target = nil
            }
            out.append(Finding(
                id: "brew|\(match.item.name)|\(match.item.version)", group: d.exploited ? .exploited : .criticalHigh,
                subject: .project(slug: project.slug, name: project.name, installedAs: match.item.name), title: project.name,
                installedVersion: installed, fixedVersion: target, severity: d.severity,
                advisoryIDs: d.advisories.map(\.id), flawCount: d.hits.count, exploited: d.exploited, malicious: false,
                note: note, bigIssue: nil, origins: [match.item.origin],
                pageURL: SiteURL.projectPage(slug: project.slug),
                upgradeCommand: offLine ? nil : UpgradeCommand.advice(Self.inputs(match.item.origin, match.item.name, nil, target)).command,
                verification: project.verificationMark, grade: project.grade,
                commandInputs: offLine ? nil : Self.inputs(match.item.origin, match.item.name, nil, target)))
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

    func applyBigIssues(_ issues: [StateResponse.BigIssue], to findings: inout [Finding], approved: [ApprovedPackage: [InstalledPackage]],
                        brew: [BrewMatch], projects: [String: ProjectResponse]) {
        for issue in issues where !issue.fixedIn.isEmpty {
            let label = "On the site's “patch these first” list: \(issue.title.isEmpty ? issue.name : issue.title)"
            // The project's ranges decide when its record has them for every advisory on the item (IssueCheck).
            let check = IssueCheck(issue, project: projects[issue.slug])
            let firstFix = { (v: String) in self.core.nearestVersion(in: issue.fixedIn, above: v) }
            let fix = { (v: String) in check.fix(v) }
            let severity = Severity(api: issue.severity)
            let group: Finding.Group = issue.exploited ? .exploited : (severity ?? .low) >= .high ? .criticalHigh : .other
            func mark(id: String, fix: (String) -> String?, make: () -> Finding) {
                if let i = findings.firstIndex(where: { $0.id == id }) {
                    findings[i].bigIssue = label
                    if issue.exploited { findings[i].exploited = true }
                    if group < findings[i].group { findings[i].group = group }
                    if findings[i].severity == nil || (severity.map { $0 > findings[i].severity! } ?? false) { findings[i].severity = severity }
                    if findings[i].fixedVersion == nil { findings[i].fixedVersion = fix(findings[i].installedVersion) }
                } else {
                    findings.append(make())
                }
            }
            // Homebrew formulae and casks of the project
            for match in brew where match.project.slug == issue.slug {
                let (v, installed) = Self.versions(match.item, slug: issue.slug)
                guard check.affects(v) else { continue }
                let project = projects[issue.slug]
                let shown = Self.shownVersion(slug: issue.slug)
                let target = fix(v).map(shown)
                mark(id: "brew|\(match.item.name)|\(match.item.version)", fix: { _ in target }) {
                    Finding(id: "brew|\(match.item.name)|\(match.item.version)", group: group,
                            subject: .project(slug: issue.slug, name: project?.name ?? match.project.name, installedAs: match.item.name),
                            title: project?.name ?? match.project.name, installedVersion: installed, fixedVersion: target, severity: severity,
                            advisoryIDs: issue.ids, flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                            note: check.note(installed, target), bigIssue: label,
                            origins: [match.item.origin], pageURL: SiteURL.projectPage(slug: issue.slug),
                            upgradeCommand: UpgradeCommand.advice(Self.inputs(match.item.origin, match.item.name, nil, target)).command,
                            verification: project?.verificationMark ?? .none, grade: project?.grade,
                            commandInputs: Self.inputs(match.item.origin, match.item.name, nil, target))
                }
            }
            // Registry packages that belong to the project (the index's project column), Electron apps for "electron"
            for (package, installs) in approved {
                let belongs = issue.slug == "electron" && package.ecosystem == .npm && package.name == "electron"
                guard belongs, core.affectedness(installed: package.version, fixedVersions: issue.fixedIn) == .affected else { continue }
                let target = firstFix(package.version)
                for install in installs {
                    let isApp = install.origin.kind == .electron
                    let id: String
                    if case let .electronApp(_, path, _) = install.origin { id = "app|\(path)|\(package.version)" }
                    else { id = "pkg|\(package.ecosystem)|\(package.name)|\(package.version)" + (package.python.map { "|py\($0)" } ?? "") }
                    mark(id: id, fix: firstFix) {
                        Finding(id: id, group: group, subject: .package(ecosystem: package.ecosystem, name: package.name),
                                title: isApp ? install.origin.label : install.name, component: isApp ? "Electron" : nil,
                                installedVersion: package.version, fixedVersion: target, severity: severity, advisoryIDs: issue.ids,
                                flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                                note: target.map { "Likely affected: the issuer names \($0) as fixed." }, bigIssue: label,
                                origins: [install.origin], pageURL: SiteURL.packagePage(package.ecosystem, package.name, version: package.version),
                                upgradeCommand: UpgradeCommand.advice(Self.inputs(install.origin, install.name, package.ecosystem, target)).command,
                                verification: projects[issue.slug]?.verificationMark ?? .none, grade: projects[issue.slug]?.grade,
                                commandInputs: Self.inputs(install.origin, install.name, package.ecosystem, target))
                    }
                }
            }
        }
    }
}
