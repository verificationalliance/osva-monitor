import Foundation
import OSVAKit

// Fix all: one review, then every fix the panel's rows offer, one at a time, each through the row's own loop
// (AppModel). Kept apart from the views so it can be tested and rendered from fixtures.
//
// What it plans is exactly what the rows offer (FixRowState.offeredFix): no other path decides. One command that fixes
// several findings (a formula that brings several vulnerable Python packages) is one step, run once. Steps go worst
// first: malicious removals, exploited in the wild, critical, high, the rest.

/// Fix all, from its review to its summary. It lives in AppModel, so a panel closed and opened again shows it as it was.
public struct FixAllState: Equatable, Sendable {
    public enum Phase: Equatable, Sendable { case review, running, done }

    /// One command and every finding it fixes; the first is the one it runs for, and its row shows the log.
    public struct Step: Equatable, Sendable, Identifiable {
        public enum Status: Equatable, Sendable {
            case waiting
            case running
            case done
            /// Checked again just before it ran, and not run: fixed by an earlier step, or no longer valid; why (the rows
            /// say how they are now).
            case skipped(String)
            /// Never started: Fix all stopped first.
            case notRun
        }

        public var findings: [Finding]
        /// Each finding's offer, as its row had it: one command.
        public var offers: [FixOffer]
        public var status: Status = .waiting
        /// How it ended for each finding, by id, as the finding's row says it.
        public var outcomes: [String: FixOutcome] = [:]

        public init(findings: [Finding], offers: [FixOffer], status: Status = .waiting, outcomes: [String: FixOutcome] = [:]) {
            self.findings = findings; self.offers = offers; self.status = status; self.outcomes = outcomes
        }

        public var id: String { findings[0].id }
        public var plan: FixPlan { offers[0].plan }

        /// What its one command updates, when it fixes several ("jupyterlab"); else the finding's name.
        public var name: String { findings.count > 1 ? (plan.homebrew?.label ?? plan.title) : findings[0].title }

        /// "Homebrew", "Python 3.11", "~/code/storefront".
        public var place: String { FixAll.place(findings[0], plan) }

        /// The compact line while it runs: "Updating nginx", "Removing axios".
        public var doing: String { "\(plan.doing) \(name)" }
    }

    /// A finding Fix all leaves alone, and the row's own reason.
    public struct Skip: Equatable, Sendable, Identifiable {
        public var finding: Finding
        public var reason: String
        public init(finding: Finding, reason: String) { self.finding = finding; self.reason = reason }
        public var id: String { finding.id }
    }

    public enum Ending: Equatable, Sendable {
        /// Every step had its turn.
        case finished
        /// Stop was pressed: the step running then was stopped, and the rest never started.
        case stopped
        /// A step broke what depends on what it changed ("fastapi 0.120.0"): nothing after it ran.
        case broke(step: Int, what: String)
    }

    public var phase: Phase
    public var steps: [Step]
    public var skipped: [Skip]
    /// The step under way.
    public var current: Int?
    public var ending: Ending?
    /// Stop was pressed: the current step ends as Stop ends it, and no other starts.
    public var stopRequested = false
    /// A step ran a command: each later step's findings are checked again before it (an earlier step may have fixed
    /// or changed them), and the sources are read again at the end.
    public var changedSomething = false

    public init(phase: Phase = .review, steps: [Step], skipped: [Skip], current: Int? = nil, ending: Ending? = nil) {
        self.phase = phase; self.steps = steps; self.skipped = skipped; self.current = current; self.ending = ending
    }

    /// Every finding the steps set out to fix.
    public var findingCount: Int { steps.reduce(0) { $0 + $1.findings.count } }

    public var currentStep: Step? { current.map { steps[$0] } }

    /// "3 of 7 · Updating nginx…"
    public var progressLine: String? {
        guard let i = current else { return nil }
        return "\(i + 1) of \(steps.count) · \(steps[i].doing)…"
    }

    // MARK: Summary

    public struct Tally: Equatable, Sendable {
        public var fixed = 0, failed = 0, needYou = 0, notRun = 0
        public init(fixed: Int = 0, failed: Int = 0, needYou: Int = 0, notRun: Int = 0) {
            self.fixed = fixed; self.failed = failed; self.needYou = needYou; self.notRun = notRun
        }
    }

    /// What became of the findings the steps set out to fix: fixed (or removed); failed (it ran and did not fix it, or
    /// broke something); need you (a password, a check the app could not make, or no longer safe to run); not run
    /// (stopped, or never started).
    public var tally: Tally {
        var t = Tally()
        for step in steps {
            if step.status == .notRun { t.notRun += step.findings.count; continue }
            for f in step.findings {
                guard let o = step.outcomes[f.id] else { continue }
                switch o {
                case .fixed, .fixedCheck, .removed, .undone: t.fixed += 1
                case .needsPassword, .blocked, .couldNotCheck: t.needYou += 1
                case .stopped: t.notRun += 1
                case .stillAffected, .failed, .couldNotOpen, .exitedWithError, .killed, .timedOut, .couldNotStart, .broke, .undoFailed:
                    t.failed += 1
                }
            }
        }
        return t
    }

    /// "Fixed 6 · 1 failed · 2 need you": what is not zero.
    public var summary: String {
        let t = tally
        let parts = [t.fixed > 0 ? "Fixed \(t.fixed)" : nil, t.failed > 0 ? "\(t.failed) failed" : nil,
                     t.needYou > 0 ? "\(t.needYou) need\(t.needYou == 1 ? "s" : "") you" : nil,
                     t.notRun > 0 ? "\(t.notRun) not run" : nil].compactMap { $0 }
        return parts.isEmpty ? "Nothing changed" : parts.joined(separator: " · ")
    }

    /// The step that broke something, with what it broke.
    public var broke: (step: Step, what: String)? {
        if case let .broke(i, what)? = ending { return (steps[i], what) }
        return nil
    }
}

/// The review, worked out from the report and the rows: what Fix all would do now, and what it would not.
public enum FixAll {
    /// The findings whose rows offer a fix now, worst first, each with its offer: exactly what Fix all counts and runs.
    public static func offered(_ findings: [Finding], fixes: [String: FixRowState]) -> [(Finding, FixOffer)] {
        ranked(findings).compactMap { f in fixes[f.id]?.offeredFix.map { (f, $0) } }
    }

    /// Fix all's order: malicious removals, exploited in the wild, critical, high, the rest; the panel's own order
    /// within each.
    public static func rank(_ f: Finding) -> Int {
        if f.malicious { return 0 }
        if f.exploited { return 1 }
        switch f.severity {
        case .critical?: return 2
        case .high?: return 3
        default: return 4
        }
    }

    static func ranked(_ findings: [Finding]) -> [Finding] {
        findings.enumerated().sorted { a, b in
            let (x, y) = (rank(a.element), rank(b.element))
            return x != y ? x < y : a.offset < b.offset
        }.map(\.element)
    }

    /// The review: one step per command (the findings it fixes in it, worst first), and what it leaves alone with the
    /// row's reason. A finding that needs action is always accounted for; a lower one is listed only when its row has
    /// something to say.
    public static func review(_ findings: [Finding], fixes: [String: FixRowState]) -> FixAllState {
        var steps: [FixAllState.Step] = [], skipped: [FixAllState.Skip] = []
        var byCommand: [FixInvocation: Int] = [:]
        for f in ranked(findings) {
            let state = fixes[f.id] ?? FixRowState()
            if let offer = state.offeredFix {
                if let i = byCommand[offer.plan.invocation] {
                    steps[i].findings.append(f); steps[i].offers.append(offer)
                } else {
                    byCommand[offer.plan.invocation] = steps.count
                    steps.append(FixAllState.Step(findings: [f], offers: [offer]))
                }
            } else if let why = reason(f, state) {
                skipped.append(FixAllState.Skip(finding: f, reason: why))
            }
        }
        return FixAllState(steps: steps, skipped: skipped)
    }

    /// Why a finding is left alone, in its row's own words; nil for a lower-severity one whose row says nothing.
    static func reason(_ f: Finding, _ s: FixRowState) -> String? {
        if s.outcome == .needsPassword { return "Needs your administrator password" }
        if s.isBusy { return "Running now" }
        if let o = s.outcome, o.isProblem, s.run != nil { return o.text }
        switch s.availability {
        case let .withheld(why?)?: return why
        case .checking?: return "Still being checked"
        default: break
        }
        guard f.group.needsAction else { return nil }
        if f.upgradeCommand != nil { return "Not a command the app runs: copy it from its row" }
        if f.malicious { return "Nothing the app can remove: see its row" }
        if f.fixedVersion == nil {
            return !f.unresolved.isEmpty && f.unresolved.allSatisfy({ !$0.affectsThisMac }) ? "Does not affect this Mac" : "No fixed release known"
        }
        return "Nothing the app can run here: see its row"
    }

    /// One finding's change: "1.30.2 → 1.30.7", "Electron 18.3.15 → 42.11.16", "1.14.1 → removed".
    public static func change(_ f: Finding, _ plan: FixPlan) -> String {
        if plan.action == .removal { return "\(f.installedLabel) → removed" }
        return "\(f.installedLabel) → \(plan.target ?? "newer")"
    }

    /// Where a fix runs, in a word or two: "Homebrew", "Python 3.11", "global npm", a project folder by its name
    /// ("storefront"; the review's line shows the whole path on hover).
    public static func place(_ f: Finding, _ plan: FixPlan) -> String {
        if plan.toolName == "brew" { return "Homebrew" }
        if plan.inProjectFolder { return (plan.place as NSString).lastPathComponent }
        switch f.commandInputs?.origin {
        case let .pip(python, _, _)?: return "Python \(python.minorVersion)"
        case let origin?: return origin.label
        case nil: return plan.toolLabel
        }
    }
}
