import Foundation

/// A Fix button to show, and what Homebrew said when it is a `brew upgrade`.
public struct FixOffer: Equatable, Sendable {
    public var plan: FixPlan
    /// "Homebrew lists 1.30.7.", or why Homebrew's data could not be read.
    public var homebrew: String?
    /// Installed packages that pin this one exactly and move with it (torchaudio with torch): pip's dry run finds
    /// their versions at the review, and they go in the same pinned command.
    public var companions: [String]
    /// A fix that runs only with the person's OK: a partial fix (the plan targets its version), or an upgrade together.
    public var proposal: FixProposal?
    public init(plan: FixPlan, homebrew: String? = nil, companions: [String] = [], proposal: FixProposal? = nil) {
        self.plan = plan; self.homebrew = homebrew; self.companions = companions; self.proposal = proposal
    }

    /// The version a partial fix goes to, as the core checked it, for making its plan again.
    public var partialTarget: CheckedUpgrade? {
        if case let .partial(p)? = proposal { return p.target }
        return nil
    }
}

/// Whether a finding gets a Fix button, and why not.
public enum FixAssessment: Equatable, Sendable {
    case offer(FixOffer)
    /// No button, and the row says why ("Homebrew still ships 1.30.6; the fix is 1.30.7 upstream.").
    case withheld(String)
    /// No button because running it would break something installed: a dependent's specifier, a runtime boundary, a
    /// project's own requirement (or the copy Python loads is not the finding's). The row says why and shows no command
    /// to copy: that command is the one that broke fastapi in 0.2.0.
    case refused(String)
    /// Refused for the full fix (why), as `refused`, but with a proposal that runs with the person's OK: a partial fix, or
    /// an upgrade together. Never counted in Fix all; its review lists it, unticked.
    case propose(String, FixOffer)
    /// The upgrade needs an administrator's password (a cask's installer or kernel extension): only Terminal, where the
    /// person types it. Never counted in Fix all.
    case terminal(FixOffer, String)
    /// No button and nothing to say: the command is there to read and copy, or there is none.
    case none
}

/// Decides, for one finding, whether the app offers to run its command, and prepares the confirmation.
public struct FixAdvisor: Sendable {
    public let tools: ToolEnvironment
    public let home: String
    /// The site, for a partial fix's plan and the flaws of what an upgrade together moves; nil offers neither.
    public let server: (any FixServer)?

    public init(tools: ToolEnvironment = ToolEnvironment(), home: String = NSHomeDirectory(), server: (any FixServer)? = nil) {
        self.tools = tools; self.home = home; self.server = server
    }

    public func assess(_ finding: Finding) async -> FixAssessment {
        let plan: FixPlan
        switch FixPlan.make(for: finding, tools: tools, home: home) {
        case let .success(p): plan = p
        case let .failure(refusal): return refusal.explanation.map(FixAssessment.withheld) ?? .none
        }
        if let pip = plan.pip, plan.action == .upgrade {
            // what depends on it, from the installed packages' own metadata: no button for an upgrade that breaks one
            let site: PythonSite
            switch await PythonSite.read(python: pip.python, tools: tools) {
            case let .failure(e): return .withheld("Not offered: the app could not read what depends on \(pip.name) (\(e.message)).")
            case let .success(s): site = s
            }
            switch PipGuard.verdict(site, pip: pip) {
            case .clear: return .offer(FixOffer(plan: plan))
            case let .companions(names, _): return .offer(FixOffer(plan: plan, companions: names))
            case let .blocked(line, conflicts):
                if let offer = await proposal(finding, plan: plan, pip: pip, site: site, conflicts: conflicts) { return .propose(line + ".", offer) }
                return .refused(line + ".")
            case let .unknown(why): return .withheld("Not offered: the app \(why).")
            }
        }
        guard let brew = plan.homebrew, plan.action == .upgrade else { return .offer(FixOffer(plan: plan)) }
        switch await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target) {
        case let .available(line): return .offer(FixOffer(plan: plan, homebrew: line))
        case let .unavailable(why): return .withheld(why)
        case let .needsPassword(why): return .terminal(FixOffer(plan: plan), why)
        case let .unknown(why):
            // a cask whose record cannot be read may be an upgrade that changes nothing: never offered blind
            return brew.cask ? .withheld(why + " The app cannot tell whether the update changes anything.") : .offer(FixOffer(plan: plan, homebrew: why))
        }
    }

    /// What can be done when a dependent or a runtime boundary blocks the full fix (rules 4.7 and 4.3):
    ///   1. a partial fix: the site picks the best version within what blocks it (each blocking specifier, the boundary
    ///      as "<2.9"), and it is offered if the core confirms it leaves a flaw the finding is shown for (`partial`) and
    ///      it passes the same check as any target here;
    ///   2. otherwise, when dependents' specifiers block it, an upgrade together: the fix with what holds it back, which
    ///      pip's resolver works out at the review. Not when what holds it back is a project of the person's.
    /// `@concurrent`: it asks the core (`partial`), which must never run on the main actor.
    @concurrent func proposal(_ finding: Finding, plan: FixPlan, pip: FixPlan.Pip, site: PythonSite, conflicts: [DependencyConflict]) async -> FixOffer? {
        guard let server else { return nil }                   // without the site, neither can be checked
        if let constraints = PythonConstraints.blocking(pip.name, from: pip.installed, to: pip.target, in: site),
           case let .success(answer?) = await server.plan(finding, within: constraints.map(\.specifier)),
           let partial = Self.partial(answer, finding: finding),
           PythonSpecifier.readable(PythonSpecifier.plain(partial.target.version)),
           PythonSpecifier.compare(PythonSpecifier.plain(partial.target.version), PythonSpecifier.plain(pip.installed)) > 0,
           case let .success(made) = FixPlan.make(for: finding, tools: tools, home: home, target: partial.target), let p = made.pip {
            let blocked = (answer.plan?.remaining ?? []).filter { $0.reason == .blockedByConstraint }
            let blocker = blocked.compactMap { r in constraints.first { $0.specifier == r.constraint } }.first ?? constraints[0]
            let proposal = FixProposal.partial(.init(target: partial.target, fixes: partial.fixes, of: partial.of, blocker: blocker,
                                                     constraints: constraints.map(\.specifier)))
            switch PipGuard.verdict(site, pip: p) {
            case .clear: return FixOffer(plan: made, proposal: proposal)
            case let .companions(names, _): return FixOffer(plan: made, companions: names, proposal: proposal)
            default: break
            }
        }
        let blockers = Array(Set(conflicts.filter { !$0.exact }.map { PythonNames.normal($0.dependent) })).sorted()
        guard !blockers.isEmpty, blockers.allSatisfy(FixSafety.isSafeName) else { return nil }
        let live = blockers.compactMap { site.live($0) }
        guard live.count == blockers.count, !live.contains(where: \.editable) else { return nil }
        // the blockers' other dependents: named so pip keeps them whole; a project of the person's gives its range instead
        let extras = site.activeExtras()
        var others: [String] = [], held: [String: FixProposal.Together.Held] = [:]
        for d in site.distributions where !blockers.contains(d.key) && d.key != PythonNames.normal(pip.name) {
            for line in d.requires {
                guard let r = PythonRequirement(line), blockers.contains(r.key) else { continue }
                if let m = r.marker, PythonMarker.evaluate(m, environment: site.markers, extras: extras[d.key] ?? []) == false { continue }
                if d.editable {
                    guard !r.url, !r.unreadable else { return nil }
                    if r.specifiers.isEmpty { continue }
                    guard let spec = PythonConstraints.sendable(r.specifiers), held[r.key] == nil else { return nil }
                    held[r.key] = .init(project: d.name, specifier: spec)
                } else if !others.contains(d.name), FixSafety.isSafeName(d.name) {
                    others.append(d.name)
                }
            }
        }
        guard case let .pip(python, _, _)? = finding.commandInputs?.origin else { return nil }
        let together = FixProposal.Together(package: pip.name, fix: pip.target, blockers: live.map(\.name), others: others.sorted(), held: held,
                                            exploited: finding.exploited, python: python)
        return FixOffer(plan: plan, proposal: .together(together))
    }

    /// The partial fix in the site's answer within constraints, as the core decides the answer (BatchCheck, as a scan's):
    /// its target only when the core confirms it leaves at least one flaw the finding is shown for (affected, or likely,
    /// on this Mac), how many of those it leaves, and of how many. Nil otherwise. Call it off the main thread.
    static func partial(_ answer: BatchResponse.Result, finding: Finding) -> (target: CheckedUpgrade, fixes: Int, of: Int)? {
        let check = BatchCheck.read(answer, installed: finding.installedVersion)
        let state = FindingBuilder.state(answer, check, onThisMac: true)
        guard state.check == .affected || state.check == .likely, !state.onlyElsewhere, let target = check.upgrade(for: state.here) else { return nil }
        let fixes = check.fixed.filter(state.here.contains).count
        return (target, fixes, max(finding.flawCount, state.flawCount))
    }

    /// What else the fix changes, from the tool's dry run.
    /// For pip: nothing runs without the dry run; every package it would install is checked against what depends on
    /// it, and pinned to the version the dry run named, so the run installs exactly what was reviewed (companions
    /// that move with it included).
    public func preview(_ offer: FixOffer) async -> FixPreview {
        let plan = offer.plan
        if case let .together(t)? = offer.proposal { return await together(plan, t) }
        var preview = await FixPreviewer(tools: tools).preview(plan, companions: offer.companions)
        guard let pip = plan.pip, plan.action == .upgrade else { return preview }
        guard preview.unavailable == nil else {
            preview.blocked = "nothing runs without pip's dry run, which could not say what would change"
            return preview
        }
        guard !preview.installs.isEmpty else {
            preview.blocked = "pip's dry run says it would change nothing"
            return preview
        }
        let own = PythonNames.normal(pip.name)
        if let pinned = preview.installs[own], pinned != pip.target {
            preview.blocked = "pip's dry run would install \(pip.name) \(pinned), not \(pip.target)"
            return preview
        }
        let others = preview.installs.filter { $0.key != own }.sorted { $0.key < $1.key }
        guard others.allSatisfy({ FixSafety.isSafeName($0.key) && FixSafety.isSafeVersion($0.value) }) else {
            preview.blocked = "pip's dry run named a package or version the app does not put in a command"
            return preview
        }
        switch await PipGuard(tools: tools).check(pip, also: preview.installs) {
        case let .clear(site):
            preview.pins = others.map { "\($0.key)==\($0.value)" }
            if PipGuard.beyondPatch(from: pip.installed, to: pip.target) {
                let moving = Set(preview.installs.keys)
                preview.usedBy = PipGuard.users(of: moving, in: site, except: moving).map(\.name)
            }
        case .companions: preview.blocked = "what pins \(pip.name) would not move with it"
        case let .blocked(line, _): preview.blocked = line
        case let .unknown(why): preview.blocked = "the app \(why)"
        }
        return preview
    }

    /// An upgrade together's review: pip's resolver is asked for a consistent set (it asks PyPI about the names), and
    /// the set is accepted only if the end state holds for everything installed (specifiers, extras, markers, runtime
    /// boundaries), it moves no project of the person's nor anything such a project uses past a major version, nothing
    /// it moves brings a flaw the version before did not have, and the core confirms pip's version of the package
    /// leaves every flaw the fix leaves (PipSetGuard.review). Then every version in it is pinned.
    /// `@concurrent`, as `proposal`: the review asks the core.
    @concurrent func together(_ plan: FixPlan, _ t: FixProposal.Together) async -> FixPreview {
        guard let pip = plan.pip else { return .none("Nothing to ask pip about.") }
        let source = "pip install --dry-run --report (asks PyPI about \(t.asked.joined(separator: ", ")), installs nothing)"
        func refused(_ why: String, _ lines: [String] = []) -> FixPreview { FixPreview(source: source, lines: lines, blocked: why) }
        guard t.requirements.allSatisfy({ r in
            let name = r.prefix { $0 != "<" && $0 != ">" && $0 != "=" && $0 != "!" && $0 != "~" }
            return FixSafety.isSafeName(String(name)) && (name.count == r.count || PythonConstraints.isSendable(String(r.dropFirst(name.count))))
        }) else { return refused("an upgrade together named a package or range the app does not put in a command") }
        let site: PythonSite
        switch await PythonSite.read(python: pip.python, tools: tools) {
        case let .failure(e): return refused("the app could not read what is installed (\(e.message))")
        case let .success(s): site = s
        }
        let installs: [PythonDistribution]
        switch await PipSetPreviewer(tools: tools).dryRun(python: pip.python, user: pip.user, requirements: t.requirements) {
        case let .failure(why):
            // a project of the person's holds what blocks it: that is where to change it
            if let (blocker, h) = t.held.sorted(by: { $0.key < $1.key }).first {
                return refused("Your project \(h.project) requires \(site.live(blocker)?.name ?? blocker) \(h.specifier.replacingOccurrences(of: ",", with: ", ")). Update it there")
            }
            return refused(why.message)
        case let .success(i): installs = i
        }
        let lines = installs.isEmpty ? [] : [PipReport.line(installs)]
        guard let own = installs.first(where: { $0.key == PythonNames.normal(t.package) }),
              PythonSpecifier.compare(PythonSpecifier.plain(own.version), PythonSpecifier.plain(t.fix)) >= 0 else {
            return refused("pip's set would not update \(t.package) to \(t.fix) or later", lines)
        }
        if let why = PipSetGuard.refusal(site, installs: installs) { return refused(why, lines) }
        guard let server, let python = t.python else { return refused("the app could not ask the site about what the set moves", lines) }
        // nothing it moves brings a new flaw, and pip's version of the package fixes what the fix fixes, as the core judges it
        switch await PipSetGuard.review(site, installs: installs, together: [t], python: python, server: server) {
        case let .failure(e): return refused("the app could not check what the set moves (\(e.message))", lines)
        case let .success(why?): return refused(why, lines)
        case .success(nil): break
        }
        var preview = FixPreview(source: source, lines: lines, installs: Dictionary(installs.map { ($0.key, $0.version) }, uniquingKeysWith: { a, _ in a }))
        preview.pins = Self.ordered(installs, first: [t.package] + t.blockers + t.others).map { "\($0.name)==\($0.version)" }
        preview.report = installs
        preview.asks = t.asked
        let moving = Set(installs.map(\.key))
        preview.usedBy = PipGuard.users(of: moving, in: site, except: moving).map(\.name)
        return preview
    }

    /// The set in the order the command names it: the finding's package, what held it back, their dependents, then the
    /// rest by name.
    public static func ordered(_ installs: [PythonDistribution], first: [String]) -> [PythonDistribution] {
        let rank = Dictionary(first.map(PythonNames.normal).enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        return installs.sorted { a, b in
            let (x, y) = (rank[a.key] ?? Int.max, rank[b.key] ?? Int.max)
            return x != y ? x < y : a.key < b.key
        }
    }

    /// The same, for a plan alone (no companions).
    public func preview(_ plan: FixPlan) async -> FixPreview { await preview(FixOffer(plan: plan)) }

    /// Homebrew's answer read again (after a run), for the reason a `brew upgrade` left the finding as it was.
    public func homebrew(_ plan: FixPlan) async -> HomebrewAvailability? {
        guard let brew = plan.homebrew, plan.action == .upgrade else { return nil }
        return await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target)
    }
}
