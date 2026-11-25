import Foundation

// Several pip changes run as one transaction: a batch (Fix all's one command per Python), or an upgrade together
// (FixProposal.together). Each is worked out by pip's own dry run with a JSON report of exactly what it would install,
// gated on the end state as a whole, and run as one exact-pinned command:
//   - every installed distribution's requirements (markers and active extras counted), the moved ones' new requirements
//     included, must still be met in the end state, unless they were already unmet before (rule 4.2; A-R4);
//   - no known runtime boundary may be crossed while something that does not move uses the package (rule 4.5);
//   - a project installed for development is never moved, and nothing it uses crosses a major version (rule 2.4);
//   - before and after, `pip check` is compared, as for a single fix (rule 6.2).

/// What pip's dry run would install, read from its `--report`: each distribution's new name, version and requirements.
public enum PipReport {
    /// The `install` list of `pip install --dry-run --report -`: one distribution per entry, its requirements those of the
    /// new version. Nil when the text is not such a report.
    public static func parse(_ data: Data) -> [PythonDistribution]? {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let install = root["install"] as? [[String: Any]] else { return nil }
        var out: [PythonDistribution] = []
        for item in install {
            guard let meta = item["metadata"] as? [String: Any], let name = meta["name"] as? String, let version = meta["version"] as? String
            else { return nil }
            out.append(PythonDistribution(name: name, version: version, requires: (meta["requires_dist"] as? [String]) ?? [],
                                          requested: item["requested"] as? Bool ?? false))
        }
        return out
    }

    /// "Would install starlette 1.10.0, fastapi 0.135.0": the review's line.
    public static func line(_ installs: [PythonDistribution]) -> String {
        "Would install " + installs.map { "\($0.name) \($0.version)" }.joined(separator: ", ")
    }
}

/// The checks on a set of pip changes as a whole.
public enum PipSetGuard {
    /// The site as it would be after `installs`: each one's new metadata in place of the old copy, or added.
    public static func endState(_ site: PythonSite, installs: [PythonDistribution]) -> PythonSite {
        var dists = site.distributions
        for d in installs {
            var new = d
            if let i = dists.firstIndex(where: { $0.key == d.key }) {
                new.path = dists[i].path; new.editable = false; new.requested = dists[i].requested
                dists[i] = new
            } else {
                dists.append(new)
            }
        }
        return PythonSite(distributions: dists, markers: site.markers)
    }

    /// Every requirement in the site that no installed distribution meets (markers and active extras counted): the
    /// package missing, or at a version its specifiers refuse.
    public static func unmet(_ site: PythonSite) -> [DependencyConflict] {
        let extras = site.activeExtras()
        var out: [DependencyConflict] = []
        for d in site.distributions {
            for line in d.requires {
                guard let r = PythonRequirement(line) else { continue }
                if let m = r.marker, PythonMarker.evaluate(m, environment: site.markers, extras: extras[d.key] ?? []) == false { continue }
                guard let dep = site.live(r.key) else {
                    out.append(DependencyConflict(dependent: d.name, dependentVersion: d.version, package: r.name, needs: "installed"))
                    continue
                }
                let refused = r.refuses(dep.version)
                if !refused.isEmpty {
                    out.append(DependencyConflict(dependent: d.name, dependentVersion: d.version, package: dep.name, needs: refused.joined(separator: ", ")))
                }
            }
        }
        return out
    }

    /// What `installs` would break: requirements unmet in the end state that were not unmet before (a moved package's
    /// new requirement included; one it shares, word for word, with the version before was already unmet).
    public static func breaks(_ site: PythonSite, installs: [PythonDistribution]) -> [DependencyConflict] {
        func key(_ c: DependencyConflict) -> String { "\(PythonNames.normal(c.dependent)) \(PythonNames.normal(c.package)) \(c.needs)" }
        let before = Set(unmet(site).map(key))
        return unmet(endState(site, installs: installs)).filter { !before.contains(key($0)) }
            .sorted { ($0.dependent.lowercased(), $0.package) < ($1.dependent.lowercased(), $1.package) }
    }

    /// Why the set may not run, in one line, or nil: a project of the person's moved, or one of its packages moved past
    /// a major version, or a requirement broken in the end state, or a runtime boundary crossed.
    public static func refusal(_ site: PythonSite, installs: [PythonDistribution]) -> String? {
        let moving = Set(installs.map(\.key))
        // a project installed for development is the person's: never replaced by a release from PyPI
        if let mine = installs.compactMap({ d in site.live(d.key).flatMap { $0.editable ? $0 : nil } }).first {
            return "It would replace \(mine.name), your project installed for development"
        }
        // nothing a project of the person's uses moves past a major version
        let extras = site.activeExtras()
        for project in site.distributions where project.editable {
            for line in project.requires {
                guard let r = PythonRequirement(line), let new = installs.first(where: { $0.key == r.key }), let old = site.live(r.key) else { continue }
                if let m = r.marker, PythonMarker.evaluate(m, environment: site.markers, extras: extras[project.key] ?? []) == false { continue }
                if let a = FixPlan.major(old.version), let b = FixPlan.major(new.version), a != b {
                    return "Your project \(project.name) uses \(old.name) \(a).x; this moves it to \(new.version). Update it there"
                }
            }
        }
        let broken = breaks(site, installs: installs)
        if let first = broken.first {
            if let project = site.live(first.dependent), project.editable {
                return "Your project \(project.name) requires \(first.package) \(first.needs.replacingOccurrences(of: " ", with: "")). Update it there"
            }
            let dependents = Set(broken.map { PythonNames.normal($0.dependent) })
            return first.line + (dependents.count > 1 ? ", and \(dependents.count - 1) more" : "")
        }
        for d in installs.sorted(by: { $0.key < $1.key }) {
            guard let now = site.live(d.key), let boundary = RuntimeBoundaries.crossed(d.key, from: now.version, to: d.version, in: site),
                  let user = PipGuard.users(of: [d.key], in: site, except: moving).first else { continue }
            return "\(now.name) \(boundary.version) \(boundary.change) — \(user.name) \(user.version) may rely on it"
        }
        return nil
    }

    /// Versions the set moves or adds, with the version before (nil: newly installed).
    public static func moves(_ site: PythonSite, installs: [PythonDistribution]) -> [(name: String, from: String?, to: String)] {
        installs.compactMap { d in
            let old = site.live(d.key)?.version
            return old == d.version ? nil : (d.name, old, d.version)
        }
    }

    /// What the site says of the versions the set moves, asked once (`server.flaws`): the line that refuses the set,
    /// or nil. It is refused when what it moves brings a flaw the version before did not have (or a new package any
    /// flaw), asked of the site as a single fix's target is (`newFlaw`); and when it would install an upgrade together's
    /// package at a version the core does not confirm fixes what its fix fixes (`keepsTheFix`). `only` limits the first
    /// to these packages (normal names); nil checks every one. `@concurrent`: it asks the core, which must never run on
    /// the main actor, whatever the caller's isolation and the compiler's default.
    @concurrent public static func review(_ site: PythonSite, installs: [PythonDistribution], only: Set<String>? = nil, together: [FixProposal.Together] = [],
                              python: PythonEnvironment, server: any FixServer) async -> Result<String?, FixServerError> {
        let moved = moves(site, installs: installs).filter { only?.contains(PythonNames.normal($0.name)) ?? true }
        var asked: [PackageVersion] = []
        func ask(_ name: String, _ version: String?) {
            guard let version else { return }
            let v = PackageVersion(name: name, version: version)
            if !asked.contains(v) { asked.append(v) }
        }
        for m in moved { ask(m.name, m.to); ask(m.name, m.from) }
        for t in together {
            let key = PythonNames.normal(t.package)
            ask(t.package, site.live(key)?.version); ask(t.package, installs.first { $0.key == key }?.version)
        }
        guard !asked.isEmpty else { return .success(nil) }
        switch await server.flaws(asked, python: python) {
        case let .failure(e): return .failure(e)
        case let .success(known):
            if let line = newFlaw(moved, known: known) { return .success(line) }
            for t in together {
                if let line = keepsTheFix(t.package, fix: t.fix, site: site, installs: installs, known: known) { return .success(line) }
            }
            return .success(nil)
        }
    }

    /// The first of `moved` whose new version has a flaw (id or alias) its version before did not have: the line that
    /// says so, or nil.
    static func newFlaw(_ moved: [(name: String, from: String?, to: String)], known: [PackageVersion: BatchResponse.Result]) -> String? {
        func ids(_ name: String, _ version: String?) -> Set<String> {
            guard let version, let r = known[PackageVersion(name: name, version: version)] else { return [] }
            return Set(r.flaws.flatMap { [$0.id] + $0.aliases })
        }
        for m in moved {
            if let flaw = ids(m.name, m.to).subtracting(ids(m.name, m.from)).sorted().first {
                return m.from.map { "\(m.name) \(m.to) has \(flaw), which \($0) does not" } ?? "\(m.name) \(m.to) would come with \(flaw)"
            }
        }
        return nil
    }

    /// Whether pip's version of an upgrade together's `package` fixes what `fix` fixes. The core judges both against
    /// the flaws the site reports at the installed version (BatchCheck: those it finds affected or likely affected, and
    /// every other one with published ranges): pip's must leave every one `fix` leaves, so it lands inside none `fix`
    /// stays out of. The line that refuses it, or nil. Without an answer for the installed version,
    /// the site knows no flaw there, and there is nothing to keep. Call it off the main thread.
    static func keepsTheFix(_ package: String, fix: String, site: PythonSite, installs: [PythonDistribution],
                            known: [PackageVersion: BatchResponse.Result]) -> String? {
        let key = PythonNames.normal(package)
        guard let installed = site.live(key)?.version, let own = installs.first(where: { $0.key == key })?.version, own != installed else {
            return "pip's set would not update \(package) to \(fix) or later"
        }
        guard let answer = known[PackageVersion(name: package, version: installed)] else { return nil }
        let check = BatchCheck.read(answer, installed: installed)
        let byFix = check.judge(fix)?.leaves ?? [], byOwn = check.judge(own)?.leaves ?? []
        let kept = byFix.indices.allSatisfy { !byFix[$0] || (byOwn.indices.contains($0) && byOwn[$0]) }
        return kept ? nil : "pip's set would install \(package) \(own), which the core does not confirm fixes what \(fix) fixes"
    }
}

/// A package at one version, as the site is asked about it.
public struct PackageVersion: Hashable, Sendable {
    /// In normal form.
    public var name: String
    public var version: String
    public init(name: String, version: String) { self.name = PythonNames.normal(name); self.version = version }
}

/// What a fix asks the site beyond the scan's own questions: a plan within constraints (a partial fix), and the flaws
/// of exact versions (that an upgrade together brings none, and fixes what its fix fixes). The answers are whole, their
/// flaws with the ranges the site publishes, so the core decides them as a scan's (BatchCheck). The app's questions go
/// through the privacy filter, and "What leaves your Mac" records what they named.
public protocol FixServer: Sendable {
    /// The site's answer for the finding's package at its installed version, its plan's target within these specifier
    /// sets. Nil when the site has nothing to say.
    func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Result?, FixServerError>
    /// The site's answer at each of these versions of PyPI packages, in this Python. A version without one (a missing
    /// key) has no flaws known: so has a package the public index does not list.
    func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: BatchResponse.Result], FixServerError>
}

public struct PipDryRunError: Error, Equatable, Sendable {
    public var message: String
    public init(_ message: String) { self.message = message }
}

public struct FixServerError: Error, Equatable, Sendable {
    public var message: String
    public init(_ message: String) { self.message = message }
}

/// Runs pip's dry run with a report.
public struct PipSetPreviewer: Sendable {
    let tools: ToolEnvironment
    public init(tools: ToolEnvironment) { self.tools = tools }

    /// `python -m pip install --dry-run --report - --quiet` for these requirements: exactly what pip would install, or
    /// why it cannot say. Wheels only: working out a source release would run its build code.
    public func dryRun(python: String, user: Bool, requirements: [String]) async -> Result<[PythonDistribution], PipDryRunError> {
        do {
            let r = try await tools.run(python, ["-m", "pip", "--version"], timeout: 30)
            guard r.status == 0, let v = FixPreviewer.pipVersion(String(decoding: r.stdout, as: UTF8.self)) else {
                return .failure(PipDryRunError("pip did not say its version"))
            }
            guard Core.shared.compareVersions(v, "22.2") >= 0 else { return .failure(PipDryRunError("this pip (\(v)) has no dry run: pip 22.2 added it")) }
        } catch {
            return .failure(PipDryRunError("pip did not answer (\(error.localizedDescription))"))
        }
        let args = Self.dryRunArguments(user: user, requirements: requirements)
        do {
            let r = try await tools.run(python, args, timeout: 120)
            guard r.status == 0 else {
                let err = r.errorText
                if err.contains("ResolutionImpossible") || err.contains("conflicting dependencies") || err.contains("Cannot install") {
                    return .failure(PipDryRunError("pip found no set of versions that fits"))
                }
                let first = err.split(whereSeparator: \.isNewline).first.map(String.init) ?? "exit status \(r.status)"
                return .failure(PipDryRunError("pip's dry run failed: \(String(first.prefix(160)))"))
            }
            guard let installs = PipReport.parse(r.stdout) else { return .failure(PipDryRunError("pip's dry run report did not read")) }
            guard installs.allSatisfy({ FixSafety.isSafeName($0.name) && FixSafety.isSafeVersion($0.version) }) else {
                return .failure(PipDryRunError("pip's dry run named a package or version the app does not put in a command"))
            }
            return .success(installs)
        } catch {
            return .failure(PipDryRunError("pip's dry run did not answer (\(error.localizedDescription))"))
        }
    }

    public static func dryRunArguments(user: Bool, requirements: [String]) -> [String] {
        ["-m", "pip", "install", "--dry-run", "--report", "-", "--quiet", "--only-binary=:all:", "--disable-pip-version-check", "--no-input"]
            + (user ? ["--user"] : []) + requirements
    }

    /// The command that runs the set: the same install as the dry run, without the dry run, every package it named
    /// pinned to the version it named.
    public static func invocation(python: String, user: Bool, pins: [String]) -> FixInvocation {
        FixInvocation(executable: python, arguments: ["-m", "pip", "install", "--disable-pip-version-check", "--no-input"] + (user ? ["--user"] : []) + pins)
    }
}
