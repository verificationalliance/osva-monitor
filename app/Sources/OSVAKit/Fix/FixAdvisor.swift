import Foundation

/// A Fix button to show, and what Homebrew said when it is a `brew upgrade`.
public struct FixOffer: Equatable, Sendable {
    public var plan: FixPlan
    /// "Homebrew lists 1.30.7.", or why Homebrew's data could not be read.
    public var homebrew: String?
    public init(plan: FixPlan, homebrew: String? = nil) { self.plan = plan; self.homebrew = homebrew }
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
    /// For pip, the other packages its dry run would install are checked against what depends on them too.
    public func preview(_ plan: FixPlan) async -> FixPreview {
        var preview = await FixPreviewer(tools: tools).preview(plan)
        if let pip = plan.pip, plan.action == .upgrade, !preview.installs.isEmpty {
            switch await PipGuard(tools: tools).check(pip, also: preview.installs) {
            case .clear: break
            case let .blocked(line, _): preview.blocked = line
            case let .unknown(why): preview.blocked = "the app \(why)"
            }
        }
        return preview
    }

    /// Homebrew's answer read again (after a run), for the reason a `brew upgrade` left the finding as it was.
    public func homebrew(_ plan: FixPlan) async -> HomebrewAvailability? {
        guard let brew = plan.homebrew, plan.action == .upgrade else { return nil }
        return await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target)
    }
}
