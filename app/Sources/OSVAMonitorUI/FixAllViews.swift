import OSVAKit
import SwiftUI

// Fix all on the panel: the header's button (FixButton, the rows' own), and one card under the header for its review,
// its run and how it went. The card is a PanelCard, like the groups; the run inside it is the rows' own FixRunCard.
// Colour comes only from Theme.swift. Every state is one short line and its action; each row keeps its own outcome.

/// What the panel shows of Fix all.
public struct FixAllPanel: Equatable, Sendable {
    /// How many findings it would fix now: exactly the rows that offer a fix (FixRowState.offeredFix).
    public var count: Int
    /// What is running ("nginx"): one fix at a time, so the button waits.
    public var waitingFor: String?
    /// Some rows' buttons are still being decided (Homebrew asked, a Python's dependents read): the count may grow.
    public var checking: Bool
    public var batch: FixAllState?
    /// The current run, as its rows have it: the steps, the time, the live log.
    public var run: FixRunState?
    /// After a batch broke something and could not be put back: what puts it back.
    public var undo: PipUndo?
    /// What "N need action" is made of: "2 fixable here · 40 no fix yet · 12 blocked · 19 yours to decide".
    public var breakdown: String?

    public init(count: Int = 0, waitingFor: String? = nil, checking: Bool = false, batch: FixAllState? = nil, run: FixRunState? = nil,
                undo: PipUndo? = nil, breakdown: String? = nil) {
        self.count = count; self.waitingFor = waitingFor; self.checking = checking; self.batch = batch; self.run = run; self.undo = undo
        self.breakdown = breakdown
    }

    public static let none = FixAllPanel()

    /// Why the button waits, in one line, when it does.
    public var why: String? {
        if let w = waitingFor { return FixButton.waiting(w) }
        return checking ? "Checking what can be fixed…" : nil
    }
}

/// What Fix all's button and card can ask the app to do.
public struct FixAllActions {
    /// The header's button: the review opens.
    public var open: () -> Void
    /// The review's Cancel, the summary's Close.
    public var close: () -> Void
    /// The review's Fix all.
    public var run: () -> Void
    /// Stop the batch under way, and start no other.
    public var stop: () -> Void
    /// After a batch broke something and could not be put back: put it back (the row's own Undo).
    public var undo: (Finding) -> Void
    /// A proposal ticked or unticked in the review.
    public var tick: (String, Bool) -> Void
    /// In the summary, for an item that needs a password: the row's own Run in Terminal.
    public var runInTerminal: (Finding) -> Void

    public init(open: @escaping () -> Void, close: @escaping () -> Void, run: @escaping () -> Void, stop: @escaping () -> Void,
                undo: @escaping (Finding) -> Void, tick: @escaping (String, Bool) -> Void = { _, _ in },
                runInTerminal: @escaping (Finding) -> Void = { _ in }) {
        self.open = open; self.close = close; self.run = run; self.stop = stop; self.undo = undo; self.tick = tick; self.runInTerminal = runInTerminal
    }

    public static var none: FixAllActions { FixAllActions(open: {}, close: {}, run: {}, stop: {}, undo: { _ in }) }
}

/// Fix all under the panel's header: the review, the run, or how it went, in one PanelCard.
public struct FixAllCard: View {
    public var panel: FixAllPanel
    public var actions: FixAllActions

    public init(panel: FixAllPanel, actions: FixAllActions) { self.panel = panel; self.actions = actions }

    public var body: some View {
        Group {
            if let batch = panel.batch {
                switch batch.phase {
                case .review: FixAllReview(batch: batch, waitingFor: panel.waitingFor, cancel: actions.close, run: actions.run, tick: actions.tick)
                case .running: FixAllProgress(batch: batch, run: panel.run, stop: actions.stop)
                case .done: FixAllSummary(batch: batch, undo: panel.undo, waitingFor: panel.waitingFor, actions: actions)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .panelCard()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Fix all")
    }
}

/// The one review: a line per batch (one command per tool and place) with its fixes beneath, the proposals that need
/// the person's OK (unticked), what it leaves alone with the row's own reason, and Cancel or Fix all. No dry runs here:
/// each batch has its own just before it runs, when an earlier one may have changed the picture.
struct FixAllReview: View {
    let batch: FixAllState
    let waitingFor: String?
    let cancel: () -> Void
    let run: () -> Void
    let tick: (String, Bool) -> Void
    @State private var allSkipped = false

    /// The lines of "Not included" shown before "and N more".
    static let skippedShown = 3

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Fix all").font(Typeface.title).foregroundStyle(.primary).accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(batch.batches.enumerated()), id: \.element.id) { i, b in FixAllBatchLine(number: i + 1, batch: b) }
            }
            if !batch.proposals.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Can do with your OK").font(Typeface.small.weight(.semibold)).foregroundStyle(.secondary)
                    ForEach(batch.proposals) { p in FixAllProposalLine(proposal: p) { tick(p.id, !p.ticked) } }
                }
            }
            if !batch.skipped.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Not included").font(Typeface.small.weight(.semibold)).foregroundStyle(.secondary)
                    let folds = batch.skipped.count > Self.skippedShown + 1           // never "and 1 more"
                    ForEach(folds && !allSkipped ? Array(batch.skipped.prefix(Self.skippedShown)) : batch.skipped) { FixAllSkipLine(skip: $0) }
                    if folds {
                        FixDisclosure(allSkipped ? "Fewer" : "And \(batch.skipped.count - Self.skippedShown) more", open: allSkipped) {
                            withAnimation(.smooth(duration: 0.2)) { allSkipped.toggle() }
                        }
                        .padding(.leading, FixAllBatchLine.numberWidth + 6)
                    }
                }
            }
            Text(batch.batches.count == 1 ? "Checked again just before it runs." : "One command per tool. Each is checked again just before it runs.")
                .font(Typeface.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Cancel", action: cancel)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .keyboardShortcut(.cancelAction)
                Button(action: run) { Text("Fix all").fontWeight(.semibold) }
                    .buttonStyle(.borderedProminent)
                    .buttonBorderShape(.capsule)
                    .disabled(waitingFor != nil || batch.batches.isEmpty)
                    .help("Runs each command above in the app, as you, without a shell")
            }
            .controlSize(.regular)
            if let w = waitingFor { Text(FixButton.waiting(w)).font(Typeface.caption).foregroundStyle(.secondary) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Review Fix all")
    }
}

/// One batch of the review: "2  Python 3.11  9 packages", then each of its fixes on a line of its own beneath
/// ("starlette  0.48.0 → 1.3.1"), the most urgent first. A command that fixes several findings at once (a formula that
/// brings several Python packages) names what it updates, then each finding. Long lists fold after five.
struct FixAllBatchLine: View {
    let number: Int
    let batch: FixAllState.Batch
    @State private var all = false

    /// The numbers' column, which the lines under it line up with.
    static let numberWidth: CGFloat = 14
    /// Fixes shown before "and N more".
    static let shown = 5

    private struct Member: Identifiable {
        var id: String
        var name: String
        var change: String
        var heading: Bool
    }

    /// Each fix beneath the batch: an item's own line, or the thing it updates and each finding under it.
    private var members: [Member] {
        batch.items.flatMap { item -> [Member] in
            if item.findings.count == 1 {
                return [Member(id: item.id, name: item.name, change: FixAll.change(item.findings[0], item.plan), heading: false)]
            }
            return [Member(id: "head-" + item.id, name: item.name, change: "", heading: true)]
                + zip(item.findings, item.offers).map { Member(id: $0.0.id, name: "  " + $0.0.title, change: FixAll.change($0.0, $0.1.plan), heading: false) }
        }
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(number)").font(Typeface.count(11, weight: .semibold)).foregroundStyle(.secondary)
                .frame(width: Self.numberWidth, alignment: .trailing)
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(batch.label).fontWeight(.semibold).foregroundStyle(.primary)
                    Spacer(minLength: 0)
                    if case .single = batch.kind {} else { Text(batch.count).foregroundStyle(.secondary).fixedSize() }
                }
                .help(batch.command)
                let list = members
                let folds = list.count > Self.shown + 1
                ForEach(folds && !all ? Array(list.prefix(Self.shown)) : list) { m in
                    Text(m.heading ? "\(m.name)" : "\(m.name)  \(Text(FixAllBatchLine.unbroken(m.change)).foregroundStyle(.secondary))")
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if folds {
                    FixDisclosure(all ? "Fewer" : "And \(list.count - Self.shown) more", open: all) {
                        withAnimation(.smooth(duration: 0.2)) { all.toggle() }
                    }
                }
            }
        }
        .font(Typeface.small)
    }

    /// "1.30.2 → 1.30.7" kept on one line.
    static func unbroken(_ s: String) -> String { s.replacingOccurrences(of: " ", with: "\u{00A0}") }
}

/// A proposal in the review: its tick (off until the person turns it on), what it does and what it costs, in one line,
/// and for an upgrade together who pip asks. Drawn with the review's own symbols, like the lines around it.
struct FixAllProposalLine: View {
    let proposal: FixAllState.Proposal
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: proposal.ticked ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 11)).foregroundStyle(proposal.ticked ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
                    .frame(width: FixAllBatchLine.numberWidth, alignment: .trailing)
                    .contentTransition(.symbolEffect(.replace))
                VStack(alignment: .leading, spacing: 1) {
                    Text(proposal.line).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                    if let asks = proposal.asks { Text(FixAllProposalLine.whole(asks)).font(Typeface.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                }
            }
            .font(Typeface.small)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(proposal.ticked ? [.isSelected] : [])
        .help(proposal.ticked ? "Leave it out" : "Run it with its Python's batch")
    }

    /// A package name never breaks at its hyphens: "prometheus-fastapi-instrumentator" stays on one line.
    static func whole(_ s: String) -> String { s.replacingOccurrences(of: "-", with: "\u{2011}") }
}

/// What the review leaves alone: the finding, and its row's reason.
struct FixAllSkipLine: View {
    let skip: FixAllState.Skip

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "minus.circle").font(.system(size: 10.5)).foregroundStyle(.secondary)
                .frame(width: FixAllBatchLine.numberWidth, alignment: .trailing)
                .accessibilityHidden(true)
            Text("\(Text(skip.finding.title).fontWeight(.semibold))  \(Text(skip.reason).foregroundStyle(.secondary))")
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(Typeface.small)
    }
}

/// The run: one line ("Batch 2 of 4 · Python 3.11: 9 packages"), a quiet line when a batch was put back and runs one at
/// a time, then the run's own card: its steps, its time, its live log, Stop (which ends the batch and starts no other).
struct FixAllProgress: View {
    let batch: FixAllState
    let run: FixRunState?
    let stop: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(batch.progressLine ?? "Fix all…").font(Typeface.body.weight(.semibold)).foregroundStyle(.primary)
                .lineLimit(1).truncationMode(.middle)
                .contentTransition(.numericText())
            if let why = batch.currentBatch?.isolated {
                FixNotice(symbol: "arrow.uturn.backward.circle", text: "Together \(why). Put back; now one at a time.")
            }
            if let run {
                FixRunCard(run: run, stop: stop)
            } else {
                FixSpinnerLabel("Checking again…")
            }
        }
        .accessibilityElement(children: .contain)
    }
}

/// How it went, in one line: "Fixed 6 · 1 failed · 2 need you"; a batch put back and run one at a time says so; each
/// item that needs the person is listed with its reason and its way on. After an undo that did not finish, what broke
/// and its Undo. Each row keeps its own outcome.
struct FixAllSummary: View {
    let batch: FixAllState
    let undo: PipUndo?
    let waitingFor: String?
    let actions: FixAllActions

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                FixNotice(symbol: symbol, text: headline, strong: true)
                Spacer(minLength: 8)
                Button("Close", action: actions.close)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
            }
            ForEach(Array(batch.isolatedBatches.enumerated()), id: \.offset) { _, b in
                FixNotice(symbol: "arrow.uturn.backward.circle", text: "\(b.label): together \(b.why). Put back, then one at a time.")
            }
            ForEach(batch.needYou + batch.failedItems, id: \.finding.id) { item in
                FixAllNeedLine(finding: item.finding, outcome: item.outcome, waitingFor: waitingFor) { actions.runInTerminal(item.finding) }
            }
            if let broke = batch.broke {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(batch.summary).font(Typeface.small).foregroundStyle(.secondary)
                        .padding(.leading, 20)
                    Spacer(minLength: 8)
                    if let undo {
                        Button { actions.undo(broke.batch.findings[0]) } label: { Text("Undo").fontWeight(.semibold) }
                            .buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                            .controlSize(.regular)
                            .disabled(waitingFor != nil)
                            .help("Puts back " + undo.restores.joined(separator: ", ") + ": " + undo.command)
                    }
                }
            }
        }
        .accessibilityElement(children: .contain)
    }

    /// The one line, or what broke. Each part stays whole on a line ("2 need you" never breaks).
    private var headline: String {
        switch batch.ending {
        case let .broke(_, what)?: return "Stopped: \(what) is broken, and putting it back did not finish."
        case .stopped?: return "Stopped · " + String.whole(batch.summary)
        default: return String.whole(batch.summary)
        }
    }

    private var symbol: String {
        let t = batch.tally
        switch batch.ending {
        case .broke?: return "exclamationmark.triangle.fill"
        case .stopped?: return "stop.circle"
        default: return t.failed + t.needYou + t.notRun == 0 ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
        }
    }
}

/// One item the summary says needs the person: its name, its one-line reason, and for a password the row's own Run in
/// Terminal (one at a time, by the person's click, after Fix all ended).
struct FixAllNeedLine: View {
    let finding: Finding
    let outcome: FixOutcome
    let waitingFor: String?
    let runInTerminal: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: outcome == .needsPassword ? "lock.fill" : FixAllState.needsYou(outcome) ? "info.circle" : "exclamationmark.circle")
                    .font(.system(size: 10.5)).foregroundStyle(.secondary)
                    .frame(width: 14)
                    .accessibilityHidden(true)
                Text("\(Text(finding.title).fontWeight(.semibold))  \(Text(reason).foregroundStyle(.secondary))")
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(Typeface.small)
            Spacer(minLength: 8)
            if outcome == .needsPassword {
                TerminalButton(waitingFor: waitingFor, action: runInTerminal).controlSize(.small)
            }
        }
    }

    private var reason: String {
        switch outcome {
        case .needsPassword: return "Needs your administrator password"
        case let .blocked(why): return why
        default: return outcome.text
        }
    }
}

extension String {
    /// "Updating starlette" as "updating starlette".
    var lowercasedFirst: String { prefix(1).lowercased() + dropFirst() }

    /// "Fixed 6 · 2 need you" with each part kept whole on a line: a line breaks only between parts.
    static func whole(_ line: String) -> String {
        line.components(separatedBy: " · ").map { $0.replacingOccurrences(of: " ", with: "\u{00A0}") }.joined(separator: " · ")
    }
}
