import Foundation

/// A Fix button to show, and what Homebrew said when it is a `brew upgrade`.
public struct FixOffer: Equatable, Sendable {
    public var plan: FixPlan
    /// "Homebrew lists 1.30.7.", or why Homebrew's data could not be read.
    public var homebrew: String?
    /// Installed packages that pin this one exactly and move with it (torchaudio with torch): pip's dry run finds
    /// their versions at the review, and they go in the same pinned command.
    public var companions: [String]
    public init(plan: FixPlan, homebrew: String? = nil, companions: [String] = []) {
        self.plan = plan; self.homebrew = homebrew; self.companions = companions
    }
}

/// Whether a finding gets a Fix button, and why not.
public enum FixAssessment: Equatable, Sendable {
    case offer(FixOffer)
    /// No button, and the row says why ("Homebrew still ships 1.30.6; the fix is 1.30.7 upstream.").
    case withheld(String)
    /// No button and nothing to say: the command is there to read and copy, or there is none.
    case none
}

/// Decides, for one finding, whether the app offers to run its command, and prepares the confirmation.
public struct FixAdvisor: Sendable {
    public let tools: ToolEnvironment
    public let home: String

    public init(tools: ToolEnvironment = ToolEnvironment(), home: String = NSHomeDirectory()) {
        self.tools = tools; self.home = home
    }

    public func assess(_ finding: Finding) async -> FixAssessment {
        let plan: FixPlan
        switch FixPlan.make(for: finding, tools: tools, home: home) {
        case let .success(p): plan = p
        case let .failure(refusal): return refusal.explanation.map(FixAssessment.withheld) ?? .none
        }
        if let pip = plan.pip, plan.action == .upgrade {
            // what depends on it, from the installed packages' own metadata: no button for an upgrade that breaks one
            switch await PipGuard(tools: tools).check(pip) {
            case .clear: return .offer(FixOffer(plan: plan))
            case let .companions(names, _): return .offer(FixOffer(plan: plan, companions: names))
            case let .blocked(line, _): return .withheld(line + ".")
            case let .unknown(why): return .withheld("Not offered: the app \(why).")
            }
        }
        guard let brew = plan.homebrew, plan.action == .upgrade else { return .offer(FixOffer(plan: plan)) }
        switch await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target) {
        case let .available(line): return .offer(FixOffer(plan: plan, homebrew: line))
        case let .unavailable(why): return .withheld(why)
        case let .unknown(why): return .offer(FixOffer(plan: plan, homebrew: why))
        }
    }

    /// What else the fix changes, from the tool's dry run.
    /// For pip: nothing runs without the dry run; every package it would install is checked against what depends on
    /// it, and pinned to the version the dry run named, so the run installs exactly what was reviewed (companions
    /// that move with it included).
    public func preview(_ offer: FixOffer) async -> FixPreview {
        let plan = offer.plan
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
        case .clear: preview.pins = others.map { "\($0.key)==\($0.value)" }
        case .companions: preview.blocked = "what pins \(pip.name) would not move with it"
        case let .blocked(line, _): preview.blocked = line
        case let .unknown(why): preview.blocked = "the app \(why)"
        }
        return preview
    }

    /// The same, for a plan alone (no companions).
    public func preview(_ plan: FixPlan) async -> FixPreview { await preview(FixOffer(plan: plan)) }

    /// Homebrew's answer read again (after a run), for the reason a `brew upgrade` left the finding as it was.
    public func homebrew(_ plan: FixPlan) async -> HomebrewAvailability? {
        guard let brew = plan.homebrew, plan.action == .upgrade else { return nil }
        return await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target)
    }
}
