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
        case .malicious, .unknown: return .unknown
        }
    }

    // MARK: Projects (Homebrew, from api/v1/project/<slug>)

    /// Advisories the app weighs for a project: critical and high ones, and any exploited in the wild.
    static func weighed(_ a: ProjectResponse.Advisory) -> Bool { (Severity(api: a.severity) ?? .low) >= .high || a.kev }

    func projectFindings(brew: [BrewMatch], projects: [String: ProjectResponse]) -> [Finding] {
        var out: [Finding] = []
        for match in brew {
            guard let project = projects[match.project.slug] else { continue }
            let installed = match.item.version
            var hits: [(advisory: ProjectResponse.Advisory, fix: String?)] = []
            for a in project.recent where Self.weighed(a) {
                if core.affectedness(installed: installed, fixedVersions: a.fixedHint) == .affected {
                    hits.append((a, core.nearestVersion(in: a.fixedHint, above: installed)))
                }
            }
            guard !hits.isEmpty else { continue }
            // One upgrade that clears them all: the newest of the nearest fixes.
            let target = core.newestVersion(hits.compactMap(\.fix))
            let exploited = hits.contains { $0.advisory.kev }
            out.append(Finding(
                id: "brew|\(match.item.name)|\(installed)", group: exploited ? .exploited : .criticalHigh,
                subject: .project(slug: project.slug, name: project.name, installedAs: match.item.name), title: project.name,
                installedVersion: installed, fixedVersion: target, severity: hits.compactMap { Severity(api: $0.advisory.severity) }.max(),
                advisoryIDs: hits.map(\.advisory.id), flawCount: hits.count, exploited: exploited, malicious: false,
                note: target.map { "Likely affected: the issuer names \($0) as fixed." }, bigIssue: nil, origins: [match.item.origin],
                pageURL: SiteURL.projectPage(slug: project.slug),
                upgradeCommand: UpgradeCommand.advice(Self.inputs(match.item.origin, match.item.name, nil, target)).command,
                verification: project.verificationMark, grade: project.grade,
                commandInputs: Self.inputs(match.item.origin, match.item.name, nil, target)))
        }
        return out
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
            let fix = { (v: String) in self.core.nearestVersion(in: issue.fixedIn, above: v) }
            let severity = Severity(api: issue.severity)
            let group: Finding.Group = issue.exploited ? .exploited : (severity ?? .low) >= .high ? .criticalHigh : .other
            func mark(id: String, make: () -> Finding) {
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
                let v = match.item.version
                guard core.affectedness(installed: v, fixedVersions: issue.fixedIn) == .affected else { continue }
                let project = projects[issue.slug]
                let target = fix(v)
                mark(id: "brew|\(match.item.name)|\(v)") {
                    Finding(id: "brew|\(match.item.name)|\(v)", group: group,
                            subject: .project(slug: issue.slug, name: project?.name ?? match.project.name, installedAs: match.item.name),
                            title: project?.name ?? match.project.name, installedVersion: v, fixedVersion: target, severity: severity,
                            advisoryIDs: issue.ids, flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                            note: target.map { "Likely affected: the issuer names \($0) as fixed." }, bigIssue: label,
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
                let target = fix(package.version)
                for install in installs {
                    let isApp = install.origin.kind == .electron
                    let id: String
                    if case let .electronApp(_, path, _) = install.origin { id = "app|\(path)|\(package.version)" }
                    else { id = "pkg|\(package.ecosystem)|\(package.name)|\(package.version)" + (package.python.map { "|py\($0)" } ?? "") }
                    mark(id: id) {
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
