import Foundation
import OSVAKit

// Fix all: one review, then every fix the panel's rows offer, one command per tool and place (FixBatchKind): one
// `brew upgrade` for the formulae, one `brew upgrade --cask` for the casks, one exact-pinned `pip install` per Python,
// one `npm install -g`, and a command of its own for each removal and anything else. Kept apart from the views so it
// can be tested and rendered from fixtures.
//
// What it plans is exactly what the rows offer (FixRowState.offeredFix): no other path decides. A proposal (a partial
// fix, an upgrade together) is listed under "Can do with your OK", unticked; a ticked one joins its Python's batch.
// Batches go removals first, then Homebrew's formulae (they can replace Homebrew's own Pythons), casks, each Python, npm,
// the rest; within a batch, the most urgent first: malicious, exploited in the wild, critical, high, the rest.

/// Fix all, from its review to its summary. It lives in AppModel, so a panel closed and opened again shows it as it was.
public struct FixAllState: Equatable, Sendable {
    public enum Phase: Equatable, Sendable { case review, running, done }

    /// One thing a batch updates: the findings one row's command fixes (several when one formula brings several Python
    /// packages), with each finding's offer. The first finding's row is the one whose plan it runs.
    public struct Item: Equatable, Sendable, Identifiable {
        public var findings: [Finding]
        public var offers: [FixOffer]
        public init(findings: [Finding], offers: [FixOffer]) { self.findings = findings; self.offers = offers }

        public var id: String { findings[0].id }
        public var plan: FixPlan { offers[0].plan }
        /// A proposal the person ticked.
        public var proposal: FixProposal? { offers[0].proposal }
        /// What its command updates, when it fixes several ("jupyterlab"); else the finding's name.
        public var name: String { findings.count > 1 ? (plan.homebrew?.label ?? plan.title) : findings[0].title }
    }

    /// One command and every finding it fixes.
    public struct Batch: Equatable, Sendable, Identifiable {
        public enum Status: Equatable, Sendable {
            case waiting
            case running
            case done
            /// Checked again just before it ran, and not run: fixed by an earlier batch, or no longer valid; why.
            case skipped(String)
            /// Never started: Fix all stopped first.
            case notRun
        }

        /// How far a batch has got. Together first; if that breaks what depends on what it changed, it is put back, and
        /// its items run one at a time with the single fix's own gates, each that breaks it again put back at once.
        public enum Stage: Equatable, Sendable {
            case together
            /// Putting back what the batch changed: what it broke.
            case undoing(String)
            /// One at a time: the item running (or next), and why the batch could not run as one.
            case oneByOne(next: Int, why: String)
            /// Putting back what item `k` changed on its own: what it broke.
            case undoingItem(Int, String, why: String)
        }

        public var kind: FixBatchKind
        /// "Homebrew", "Homebrew casks", "Python 3.11", "npm", a project folder's name.
        public var label: String
        public var items: [Item]
        public var status: Status = .waiting
        public var stage: Stage = .together
        /// How it ended for each finding, by id, as the finding's row says it.
        public var outcomes: [String: FixOutcome] = [:]
        /// Findings that left it before its command ran (an earlier batch fixed them, or they changed): still its own,
        /// for the summary.
        public var left: [Finding] = []

        public init(kind: FixBatchKind, label: String, items: [Item], status: Status = .waiting, outcomes: [String: FixOutcome] = [:]) {
            self.kind = kind; self.label = label; self.items = items; self.status = status; self.outcomes = outcomes
        }

        public var id: String { items[0].id }
        /// What its command runs for now.
        public var members: [Finding] { items.flatMap(\.findings) }
        /// Every finding it set out to fix.
        public var findings: [Finding] { members + left }
        public var plan: FixPlan { items[0].plan }

        /// "9 packages", "3 formulae", "2 casks", "1 package"; a removal or a command of its own says what it does.
        public var count: String {
            let n = items.count
            switch kind {
            case .formulae: return n == 1 ? "1 formula" : "\(n) formulae"
            case .casks: return n == 1 ? "1 app" : "\(n) apps"
            case .pip, .npm: return n == 1 ? "1 package" : "\(n) packages"
            case .single: return items[0].plan.action == .removal ? "Remove \(items[0].name)" : items[0].name
            }
        }

        /// "Python 3.11: 9 packages", "storefront: Remove axios".
        public var line: String { "\(label): \(count)" }

        /// Why it was put back and run one at a time, once it was: "it broke httpx 0.27.0".
        public var isolated: String? {
            switch stage {
            case .together: return nil
            case let .undoing(why): return why
            case let .oneByOne(_, why), let .undoingItem(_, _, why): return why
            }
        }

        /// The command as one line, for the run's Copy and the review's hover.
        public var command: String {
            if case .single = kind { return items[0].plan.command }
            let args = items.compactMap { FixBatchKind.argument($0.plan) }
            let pins = items.compactMap { $0.plan.pip?.requirement }
            return kind.invocation(args, pins: pins).display
        }
    }

    /// A fix that runs only with the person's OK, and whether they gave it.
    public struct Proposal: Equatable, Sendable, Identifiable {
        public var finding: Finding
        public var offer: FixOffer
        public var ticked: Bool
        public init(finding: Finding, offer: FixOffer, ticked: Bool = false) { self.finding = finding; self.offer = offer; self.ticked = ticked }
        public var id: String { finding.id }
        /// "torch to 2.8.0 (6 of 14; whisperx needs below 2.9)".
        public var line: String { offer.proposal?.reviewLine(offer.plan) ?? offer.plan.summary }
        /// "pip asks PyPI about starlette, fastapi", for an upgrade together.
        public var asks: String? { offer.proposal?.asks }
    }

    /// A finding Fix all leaves alone, and the row's own reason.
    public struct Skip: Equatable, Sendable, Identifiable {
        public var finding: Finding
        public var reason: String
        public init(finding: Finding, reason: String) { self.finding = finding; self.reason = reason }
        public var id: String { finding.id }
    }

    public enum Ending: Equatable, Sendable {
        /// Every batch had its turn.
        case finished
        /// Stop was pressed: the batch running then was stopped, and the rest never started.
        case stopped
        /// A batch broke what depends on what it changed, and putting it back did not finish: nothing after it ran.
        case broke(batch: Int, what: String)
    }

    public var phase: Phase
    public var batches: [Batch]
    public var proposals: [Proposal]
    public var skipped: [Skip]
    /// The batch under way.
    public var current: Int?
    public var ending: Ending?
    /// Stop was pressed: the current batch ends as Stop ends it, and no other starts.
    public var stopRequested = false
    /// A batch ran a command: each later batch's findings are checked again before it, and the sources are read
    /// again at the end.
    public var changedSomething = false

    public init(phase: Phase = .review, batches: [Batch], proposals: [Proposal] = [], skipped: [Skip], current: Int? = nil, ending: Ending? = nil) {
        self.phase = phase; self.batches = batches; self.proposals = proposals; self.skipped = skipped; self.current = current; self.ending = ending
    }

    /// Every finding the batches set out to fix.
    public var findingCount: Int { batches.reduce(0) { $0 + $1.findings.count } }

    public var currentBatch: Batch? { current.map { batches[$0] } }

    /// The proposals ticked, by finding id.
    public var ticked: Set<String> { Set(proposals.filter(\.ticked).map(\.id)) }

    /// "Batch 2 of 4 · Python 3.11: 9 packages"; one at a time, "Batch 2 of 4 · Python 3.11, one at a time: starlette".
    public var progressLine: String? {
        guard let i = current else { return nil }
        let b = batches[i]
        let head = batches.count == 1 ? "" : "Batch \(i + 1) of \(batches.count) · "
        switch b.stage {
        case .together: return head + b.line
        case .undoing: return head + "\(b.label): putting it back"
        case let .oneByOne(k, _):
            let n = min(k, b.items.count - 1)
            return head + "\(b.label), one at a time: \(n + 1) of \(b.items.count) · \(b.items[n].name)"
        case let .undoingItem(k, _, _): return head + "\(b.label): putting \(b.items[k].name) back"
        }
    }

    // MARK: Summary

    public struct Tally: Equatable, Sendable {
        public var fixed = 0, partly = 0, failed = 0, needYou = 0, notRun = 0
        public init(fixed: Int = 0, partly: Int = 0, failed: Int = 0, needYou: Int = 0, notRun: Int = 0) {
            self.fixed = fixed; self.partly = partly; self.failed = failed; self.needYou = needYou; self.notRun = notRun
        }
    }

    /// Whether an outcome needs the person: a password, a check the app could not make, or no longer safe to run.
    public static func needsYou(_ o: FixOutcome) -> Bool {
        switch o {
        case .needsPassword, .blocked, .couldNotCheck: return true
        default: return false
        }
    }

    /// What became of the findings the batches set out to fix: fixed (or removed); partly fixed; failed (it ran and did
    /// not fix it, or broke something and was put back); need you; not run (stopped, or never started).
    public var tally: Tally {
        var t = Tally()
        for b in batches {
            if b.status == .notRun { t.notRun += b.findings.count; continue }
            for f in b.findings {
                guard let o = b.outcomes[f.id] else { continue }
                switch o {
                case .fixed, .fixedCheck, .removed, .undone: t.fixed += 1
                case .partlyFixed: t.partly += 1
                case .needsPassword, .blocked, .couldNotCheck: t.needYou += 1
                case .stopped: t.notRun += 1
                case .stillAffected, .failed, .couldNotOpen, .exitedWithError, .killed, .timedOut, .couldNotStart, .broke, .undoFailed, .putBack:
                    t.failed += 1
                }
            }
        }
        return t
    }

    /// "Fixed 6 · 1 partly fixed · 1 failed · 2 need you": what is not zero.
    public var summary: String {
        let t = tally
        let parts = [t.fixed > 0 ? "Fixed \(t.fixed)" : nil, t.partly > 0 ? "\(t.partly) partly fixed" : nil,
                     t.failed > 0 ? "\(t.failed) failed" : nil,
                     t.needYou > 0 ? "\(t.needYou) need\(t.needYou == 1 ? "s" : "") you" : nil,
                     t.notRun > 0 ? "\(t.notRun) not run" : nil].compactMap { $0 }
        return parts.isEmpty ? "Nothing changed" : parts.joined(separator: " · ")
    }

    /// Each finding that did not land: it ran and failed, or broke something and was put back. The summary names them.
    public var failedItems: [(finding: Finding, outcome: FixOutcome)] {
        batches.flatMap { b in b.findings.compactMap { f in
            b.outcomes[f.id].flatMap { o in o.isProblem && !Self.needsYou(o) && !Self.isStopped(o) ? (f, o) : nil }
        } }
    }

    static func isStopped(_ o: FixOutcome) -> Bool { if case .stopped = o { return true } else { return false } }

    /// Each finding that needs the person, with its outcome: the summary lists them with their reasons and a way on.
    public var needYou: [(finding: Finding, outcome: FixOutcome)] {
        batches.flatMap { b in b.findings.compactMap { f in b.outcomes[f.id].flatMap { Self.needsYou($0) ? (f, $0) : nil } } }
    }

    /// The batches that were put back and run one at a time, with what they broke together.
    public var isolatedBatches: [(label: String, why: String)] {
        batches.compactMap { b in b.isolated.map { (b.label, $0) } }
    }

    /// The batch that broke something and could not be put back, with what it broke.
    public var broke: (batch: Batch, what: String)? {
        if case let .broke(i, what)? = ending { return (batches[i], what) }
        return nil
    }
}

/// The review, worked out from the report and the rows: what Fix all would do now, and what it would not.
public enum FixAll {
    /// The findings whose rows offer a fix now, worst first, each with its offer: exactly what Fix all counts and runs.
    public static func offered(_ findings: [Finding], fixes: [String: FixRowState]) -> [(Finding, FixOffer)] {
        ranked(findings).compactMap { f in fixes[f.id]?.offeredFix.map { (f, $0) } }
    }

    /// Fix all's urgency: malicious removals, exploited in the wild, critical, high, the rest; the panel's own order
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

    /// The review: one batch per tool and place (its items worst first), the proposals with the ticks given, and what it
    /// leaves alone with the row's reason. A finding that needs action is always accounted for; a lower one is listed
    /// only when its row has something to say.
    public static func review(_ findings: [Finding], fixes: [String: FixRowState], ticked: Set<String> = []) -> FixAllState {
        var items: [FixAllState.Item] = [], proposals: [FixAllState.Proposal] = [], skipped: [FixAllState.Skip] = []
        var byCommand: [FixInvocation: Int] = [:]
        for f in ranked(findings) {
            let state = fixes[f.id] ?? FixRowState()
            if let offer = state.offeredFix {
                if let i = byCommand[offer.plan.invocation] {
                    items[i].findings.append(f); items[i].offers.append(offer)
                } else {
                    byCommand[offer.plan.invocation] = items.count
                    items.append(FixAllState.Item(findings: [f], offers: [offer]))
                }
            } else if let offer = state.offeredProposal {
                let p = FixAllState.Proposal(finding: f, offer: offer, ticked: ticked.contains(f.id))
                proposals.append(p)
                if p.ticked { items.append(FixAllState.Item(findings: [f], offers: [offer])) }
            } else if let why = reason(f, state) {
                skipped.append(FixAllState.Skip(finding: f, reason: why))
            }
        }
        return FixAllState(batches: batches(items), proposals: proposals, skipped: skipped)
    }

    /// Items into batches: one per tool and place, in the batches' order, each batch's items in the order given (worst
    /// first); a removal and a command of another shape are each a batch of their own.
    public static func batches(_ items: [FixAllState.Item]) -> [FixAllState.Batch] {
        var out: [FixAllState.Batch] = []
        var byKind: [FixBatchKind: Int] = [:]
        for item in items {
            let kind = FixBatchKind.of(item.plan)
            if case .single = kind {
                out.append(FixAllState.Batch(kind: kind, label: place(item.findings[0], item.plan), items: [item]))
            } else if let i = byKind[kind] {
                out[i].items.append(item)
            } else {
                byKind[kind] = out.count
                out.append(FixAllState.Batch(kind: kind, label: label(kind, item), items: [item]))
            }
        }
        // stable: within one rank, the batch whose most urgent item comes first goes first
        return out.enumerated().sorted { a, b in
            let (x, y) = (a.element.kind.order(removal: a.element.plan.action == .removal), b.element.kind.order(removal: b.element.plan.action == .removal))
            return x != y ? x < y : a.offset < b.offset
        }.map(\.element)
    }

    /// "Homebrew", "Homebrew casks", "Python 3.11", "Python 3.11, your user site", "npm".
    static func label(_ kind: FixBatchKind, _ item: FixAllState.Item) -> String {
        switch kind {
        case .formulae: return "Homebrew"
        case .casks: return "Homebrew casks"
        case let .pip(_, user):
            return place(item.findings[0], item.plan) + (user ? ", your user site" : "")
        case .npm: return "global npm"
        case .single: return place(item.findings[0], item.plan)
        }
    }

    /// Why a finding is left alone, in its row's own words; nil for a lower-severity one whose row says nothing.
    static func reason(_ f: Finding, _ s: FixRowState) -> String? {
        if s.outcome == .needsPassword { return "Needs your administrator password" }
        if s.isBusy { return "Running now" }
        if let o = s.outcome, o.isProblem, s.run != nil { return o.text }
        switch s.availability {
        case let .withheld(why?)?: return why
        case let .terminal(_, why)?: return why
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

    // MARK: The header's breakdown

    /// What "N need action" is made of, in the app's own terms: what Fix all fixes here, what needs the person's OK or
    /// password, what waits for a fixed release, what something installed blocks, and what is the person's to decide.
    public struct Breakdown: Equatable, Sendable {
        public var fixable = 0, withOK = 0, password = 0, noFix = 0, blocked = 0, yours = 0
        /// Lower-severity findings Fix all fixes too: not among "N need action", but in its count.
        public var lower = 0
        public init(fixable: Int = 0, withOK: Int = 0, password: Int = 0, noFix: Int = 0, blocked: Int = 0, yours: Int = 0, lower: Int = 0) {
            self.fixable = fixable; self.withOK = withOK; self.password = password; self.noFix = noFix; self.blocked = blocked; self.yours = yours
            self.lower = lower
        }

        /// The findings that need action, each in one bucket.
        public var total: Int { fixable + withOK + password + noFix + blocked + yours }

        /// "2 fixable here · 40 no fix yet · 12 blocked · 19 yours to decide": the buckets that are not empty;
        /// "16 fixable here (+1 lower)" when Fix all's count takes in a lower-severity one too.
        public var line: String? {
            let fix = lower > 0 ? "fixable here (+\(lower) lower)" : "fixable here"
            let parts = [(fixable, fix), (withOK, "need your OK"), (password, "need a password"), (noFix, "no fix yet"),
                         (blocked, "blocked"), (yours, "yours to decide")].filter { $0.0 > 0 || ($0.1 == fix && lower > 0) }
                .map { "\($0.0) \($0.1)" }
            return parts.count < 2 && fixable == total && lower == 0 ? nil : parts.joined(separator: " · ")
        }
    }

    /// Each finding that needs action, in one bucket. Nil while some row is still being decided.
    public static func breakdown(_ findings: [Finding], fixes: [String: FixRowState]) -> Breakdown? {
        var b = Breakdown()
        b.lower = findings.filter { !$0.group.needsAction && fixes[$0.id]?.offeredFix != nil }.count
        for f in findings where f.group.needsAction {
            let s = fixes[f.id] ?? FixRowState()
            if s.availability == .checking { return nil }
            if s.offeredFix != nil || s.isBusy { b.fixable += 1; continue }
            if s.offeredProposal != nil { b.withOK += 1; continue }
            if s.outcome == .needsPassword { b.password += 1; continue }
            if case .terminal? = s.availability { b.password += 1; continue }
            if !f.malicious && f.fixedVersion == nil { b.noFix += 1; continue }
            switch s.hold {
            case .noFix?: b.noFix += 1
            case .blocked?: b.blocked += 1
            case .yours?, nil: b.yours += 1
            }
        }
        return b
    }
}
