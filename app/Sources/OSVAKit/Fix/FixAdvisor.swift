import Foundation

/// A Fix button to show, and what Homebrew said when it is a `brew upgrade`.
public struct FixOffer: Equatable, Sendable {
    public var plan: FixPlan
    /// "Homebrew lists 1.30.7.", or why Homebrew's data could not be read.
    public var homebrew: String?
    public init(plan: FixPlan, homebrew: String? = nil) { self.plan = plan; self.homebrew = homebrew }
}

/// Whether a finding gets a Fix button.
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
        guard let brew = plan.homebrew, plan.action == .upgrade else { return .offer(FixOffer(plan: plan)) }
        switch await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target) {
        case let .available(line): return .offer(FixOffer(plan: plan, homebrew: line))
        case let .unavailable(why): return .withheld(why)
        case let .unknown(why): return .offer(FixOffer(plan: plan, homebrew: why))
        }
    }

    /// What else the fix changes, from the tool's dry run.
    public func preview(_ plan: FixPlan) async -> FixPreview {
        await FixPreviewer(tools: tools).preview(plan)
    }

    /// Homebrew's answer read again (after a run), for the reason a `brew upgrade` left the finding as it was.
    public func homebrew(_ plan: FixPlan) async -> HomebrewAvailability? {
        guard let brew = plan.homebrew, plan.action == .upgrade else { return nil }
        return await HomebrewInfoReader(tools: tools).availability(brew, fixedVersion: plan.target)
    }
}
