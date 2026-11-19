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
    /// The current step's run, as its row has it: the steps, the time, the live log.
    public var run: FixRunState?
    /// After a step broke something: what puts it back.
    public var undo: PipUndo?

    public init(count: Int = 0, waitingFor: String? = nil, checking: Bool = false, batch: FixAllState? = nil, run: FixRunState? = nil,
                undo: PipUndo? = nil) {
        self.count = count; self.waitingFor = waitingFor; self.checking = checking; self.batch = batch; self.run = run; self.undo = undo
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
    /// Stop the step under way, and start no other.
    public var stop: () -> Void
    /// After a step broke something: put it back (the row's own Undo).
    public var undo: (Finding) -> Void

    public init(open: @escaping () -> Void, close: @escaping () -> Void, run: @escaping () -> Void, stop: @escaping () -> Void,
                undo: @escaping (Finding) -> Void) {
        self.open = open; self.close = close; self.run = run; self.stop = stop; self.undo = undo
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
                case .review: FixAllReview(batch: batch, waitingFor: panel.waitingFor, cancel: actions.close, run: actions.run)
                case .running: FixAllProgress(batch: batch, run: panel.run, stop: actions.stop)
                case .done: FixAllSummary(batch: batch, undo: panel.undo, waitingFor: panel.waitingFor, undoAction: actions.undo, close: actions.close)
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

/// The one review: a line per step (what, from → to, where; a command that fixes several names each under it), what
/// it leaves alone with the row's own reason, and Cancel or Fix all. No dry runs here: each step has its own just
/// before it runs, when an earlier step may have changed the picture.
struct FixAllReview: View {
    let batch: FixAllState
    let waitingFor: String?
    let cancel: () -> Void
    let run: () -> Void
    @State private var allSkipped = false

    /// The lines of "Not included" shown before "and N more".
    static let skippedShown = 3

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Fix all").font(Typeface.title).foregroundStyle(.primary).accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(batch.steps.enumerated()), id: \.element.id) { i, step in FixAllStepLine(number: i + 1, step: step) }
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
                        .padding(.leading, FixAllStepLine.numberWidth + 6)
                    }
                }
            }
            Text("One at a time. Each is checked again just before it runs.")
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
                    .disabled(waitingFor != nil)
                    .help("Runs each step above in the app, as you, without a shell")
            }
            .controlSize(.regular)
            if let w = waitingFor { Text(FixButton.waiting(w)).font(Typeface.caption).foregroundStyle(.secondary) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Review Fix all")
    }
}

/// One step of the review: "4  nginx  1.30.2 → 1.30.7", and where at the end of the line ("Homebrew"). A command that
/// fixes several findings names the thing it updates, then each finding on a line of its own. A line too long wraps
/// between the name and the versions, never inside "1.30.2 → 1.30.7".
struct FixAllStepLine: View {
    let number: Int
    let step: FixAllState.Step

    /// The numbers' column, which "Not included" lines up with.
    static let numberWidth: CGFloat = 14

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(number)").font(Typeface.count(11, weight: .semibold)).foregroundStyle(.secondary)
                .frame(width: Self.numberWidth, alignment: .trailing)
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    if step.findings.count == 1 {
                        Text("\(Text(step.name).fontWeight(.semibold))  \(Self.unbroken(FixAll.change(step.findings[0], step.plan)))")
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text(step.name).fontWeight(.semibold)
                    }
                    Spacer(minLength: 0)
                    Text(step.place).foregroundStyle(.secondary).fixedSize()
                        .help(step.plan.place)
                }
                ForEach(Array(zip(step.findings, step.offers).enumerated()), id: \.offset) { _, member in
                    if step.findings.count > 1 {
                        Text("\(member.0.title)  \(Self.unbroken(FixAll.change(member.0, member.1.plan)))").fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .foregroundStyle(.primary)
        }
        .font(Typeface.small)
    }

    /// "1.30.2 → 1.30.7" kept on one line.
    static func unbroken(_ s: String) -> String { s.replacingOccurrences(of: " ", with: "\u{00A0}") }
}

/// What the review leaves alone: the finding, and its row's reason.
struct FixAllSkipLine: View {
    let skip: FixAllState.Skip

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "minus.circle").font(.system(size: 10.5)).foregroundStyle(.secondary)
                .frame(width: FixAllStepLine.numberWidth, alignment: .trailing)
                .accessibilityHidden(true)
            Text("\(Text(skip.finding.title).fontWeight(.semibold))  \(Text(skip.reason).foregroundStyle(.secondary))")
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(Typeface.small)
    }
}

/// The run: one line ("3 of 7 · Updating nginx…"), then the step's own run card: its steps, its time, its live log,
/// Stop (which ends the step and starts no other).
struct FixAllProgress: View {
    let batch: FixAllState
    let run: FixRunState?
    let stop: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(batch.progressLine ?? "Fix all…").font(Typeface.body.weight(.semibold)).foregroundStyle(.primary)
                .lineLimit(1).truncationMode(.middle)
                .contentTransition(.numericText())
            if let run {
                FixRunCard(run: run, stop: stop)
            } else {
                FixSpinnerLabel("Checking again…")
            }
        }
        .accessibilityElement(children: .contain)
    }
}

/// How it went, in one line: "Fixed 6 · 1 failed · 2 need you". After a step broke something, what broke and its Undo.
/// Each row keeps its own outcome.
struct FixAllSummary: View {
    let batch: FixAllState
    let undo: PipUndo?
    let waitingFor: String?
    let undoAction: (Finding) -> Void
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                FixNotice(symbol: symbol, text: headline, strong: true)
                Spacer(minLength: 8)
                Button("Close", action: close)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
            }
            if let broke = batch.broke {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(batch.summary).font(Typeface.small).foregroundStyle(.secondary)
                        .padding(.leading, 20)
                    Spacer(minLength: 8)
                    if let undo {
                        Button { undoAction(broke.step.findings[0]) } label: { Text("Undo").fontWeight(.semibold) }
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

    /// The one line, or what broke.
    private var headline: String {
        switch batch.ending {
        case let .broke(i, what)?: return "Stopped: \(batch.steps[i].doing.lowercasedFirst) broke \(what)."
        case .stopped?: return "Stopped · " + batch.summary
        default: return batch.summary
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

extension String {
    /// "Updating starlette" as "updating starlette".
    var lowercasedFirst: String { prefix(1).lowercased() + dropFirst() }
}
