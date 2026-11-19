import OSVAKit
import SwiftUI

/// One finding, as content on its group's container. Closed: name with verification mark and grade; installed →
/// fixed version; status; where it came from; how its last fix went. Open: why, what to run (and a button that runs it
/// in the app after a review, with its live progress and how it ended), and a link to the site.
public struct FindingRow: View {
    let finding: Finding
    let expanded: Bool
    let actions: PopoverActions
    let fix: FixRowState
    let toggle: () -> Void
    @State private var hover = false
    @State private var copied = false

    public init(finding: Finding, expanded: Bool, actions: PopoverActions, fix: FixRowState = FixRowState(), toggle: @escaping () -> Void) {
        self.finding = finding; self.expanded = expanded; self.actions = actions; self.fix = fix; self.toggle = toggle
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 6) {
                Text(finding.title).font(Typeface.title).foregroundStyle(.primary).lineLimit(1).truncationMode(.middle)
                VerificationMark(finding.verification, size: 16)
                if let g = finding.grade { GradeTile(g) }
                Spacer(minLength: 8)
                Button(action: toggle) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 11, weight: .semibold))
                        .rotationEffect(.degrees(expanded ? 180 : 0))
                        .frame(width: 20, height: 18)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(hover ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
                .help(expanded ? "Hide what to do" : "Show what to do")
                .accessibilityLabel(expanded ? "Hide what to do" : "Show what to do")
            }
            versionLine
            if !fix.isResolved { statusChips }
            Text(finding.originSummary).font(Typeface.small).foregroundStyle(.secondary)
                .lineLimit(expanded ? 3 : 1).truncationMode(.middle)
            if let progress = fix.progress, !(expanded && showsCard) { FixStatusLine(progress, run: fix.run).padding(.top, 2) }
            if fix.isResolved && finding.malicious {
                // removing it is not the end: what it could read may already be gone
                Text("Now rotate every secret it could read.").font(Typeface.small).foregroundStyle(Tokens.Malicious.text.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if expanded { details }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .rowHover($hover)
        .contentShape(Rectangle())
        .onTapGesture(perform: toggle)
        .accessibilityElement(children: .contain)
    }

    private var statusChips: some View {
        HStack(spacing: 8) {
            if finding.malicious {
                StatusChip(.malicious)
            } else {
                if finding.exploited { StatusChip(.exploited) }
                if let s = finding.severity { SeverityLabel(s) }
                if finding.flawCount > 1 {
                    Text("\(finding.flawCount) flaws").font(Typeface.count(11.5, weight: .medium)).foregroundStyle(.secondary)
                }
            }
        }
    }

    /// The version a fix reached, when the check found it fixed.
    private var fixedNow: String? {
        switch fix.progress {
        case let .finished(.fixed(now))?, let .finished(.fixedCheck(now, _))?: return now
        default: return nil
        }
    }

    /// Fixed, but beyond a patch of something others use: the row keeps a card with who to check, and Undo.
    private var checkAfterFix: Bool {
        if case .fixedCheck? = fix.outcome, fix.run?.undo != nil { return true }
        return false
    }

    /// Installed in `.secondary`, a `.tertiary` arrow, the fixed version in `.primary`; or the plain "no fixed
    /// release known". Malware has no fixed version: only what is installed. Once a fix is confirmed, the installed
    /// version rolls over to the new one and the rest goes.
    private var versionLine: some View {
        HStack(spacing: 0) {
            Text(fixedNow ?? finding.installedLabel)
                .foregroundStyle(fixedNow == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                .contentTransition(.numericText())
            if !finding.malicious && fixedNow == nil {
                if let fixed = finding.fixedVersion {
                    Text(" → ").foregroundStyle(.tertiary)
                    Text(fixed).foregroundStyle(.primary)
                } else if !finding.unresolved.isEmpty && finding.unresolved.allSatisfy({ !$0.affectsThisMac }) {
                    Text("  does not affect this Mac").font(Typeface.small).foregroundStyle(.secondary)
                } else {
                    Text("  no fixed release known").font(Typeface.small).foregroundStyle(.secondary)
                }
            }
        }
        .font(Typeface.version)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(fixedNow.map { "Now \($0)" } ?? finding.versionLine)
    }

    @ViewBuilder private var details: some View {
        VStack(alignment: .leading, spacing: 8) {
            ProvenanceView(finding.provenance)
            if !fix.isResolved { advice }
            if checkAfterFix, let outcome = fix.outcome {
                FixProblemCard(outcome: outcome, run: fix.run, waitingFor: fix.waitingFor, canRetry: false, retry: {},
                               undo: { actions.fix.undo(finding) }, runInTerminal: {}, copy: actions.copy)
            }
            SiteLink(finding.pageLabel, url: finding.pageURL, open: actions.open)
        }
        .padding(.top, 4)
        .transition(.opacity)
        .onAppear { actions.fix.assess(finding) }
    }

    /// Why, and what to do: everything a fixed row no longer needs.
    @ViewBuilder private var advice: some View {
        if let note = finding.note {
            Text(note).font(Typeface.small)
                .foregroundStyle(finding.malicious ? AnyShapeStyle(Tokens.Malicious.text.color) : AnyShapeStyle(.primary))
                .fixedSize(horizontal: false, vertical: true)
        }
        if let fixes = finding.fixesCount, let target = finding.fixedVersion, fixes > 0 {
            Text("\(target) fixes \(fixes == 1 ? "1 flaw" : "\(fixes) flaws") here.").font(Typeface.small).foregroundStyle(.primary)
        }
        ForEach(finding.unresolved, id: \.id) { u in
            // Information, not a failure: what this upgrade cannot fix here, and why. The flaw is named (by its
            // summary, else its id) so that two flaws with the same reason do not read as one listed twice.
            Label {
                VStack(alignment: .leading, spacing: 1) {
                    Text((u.severity.map { "\($0.label) · " } ?? "") + u.name).foregroundStyle(.secondary)
                    Text(u.explanation).foregroundStyle(.tertiary)
                }
                .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: u.affectsThisMac ? "info.circle" : "minus.circle").foregroundStyle(.secondary)
            }
            .font(Typeface.small)
            .help(u.id)
        }
        if finding.bigIssue != nil {
            Label {
                Text("On the site's “patch these first” list").foregroundStyle(.primary)
            } icon: {
                Image(systemName: "flag.fill").foregroundStyle(Tokens.critical.glyph.color)
            }
            .font(Typeface.small.weight(.medium))
        }
        if let command = finding.upgradeCommand ?? fix.run?.command {
            if case let .offered(offer)? = fix.availability, let preview = fix.preview, !fix.isBusy {
                FixConfirmation(offer: offer, preview: preview, waitingFor: fix.waitingFor,
                                cancel: { actions.fix.cancel(finding) }, run: { actions.fix.run(finding) })
            } else if let run = fix.run, fix.isBusy {
                FixRunCard(run: run) { actions.fix.stop(finding) }
            } else if let outcome = fix.outcome, outcome.isProblem, fix.run != nil {
                commandBlock(command)
                FixProblemCard(outcome: outcome, run: fix.run, waitingFor: fix.waitingFor, canRetry: canRetry(outcome),
                               retry: { actions.fix.retry(finding) }, undo: { actions.fix.undo(finding) },
                               runInTerminal: { actions.fix.runInTerminal(finding) }, copy: actions.copy)
            } else {
                commandBlock(command)
                fixControl
            }
        }
    }

    /// The open row shows the run (or how it ended) as a card, so the one-line status is left out.
    private var showsCard: Bool {
        if fix.run != nil && fix.isBusy { return true }
        if let o = fix.outcome, o.isProblem, fix.run != nil { return true }
        return checkAfterFix
    }

    /// Retry runs the same command again: for an ending that may go better a second time, while the button is offered.
    private func canRetry(_ outcome: FixOutcome) -> Bool {
        guard case .offered? = fix.availability else { return false }
        switch outcome {
        case .exitedWithError, .killed, .stopped, .timedOut, .couldNotStart, .couldNotCheck: return true
        default: return false
        }
    }

    /// Under the command: the button, or why there is none, or a moment while the app checks.
    @ViewBuilder private var fixControl: some View {
        if !fix.isBusy {
            switch fix.availability {
            case .checking?:
                FixSpinnerLabel("Checking…")
            case let .offered(offer)?:
                FixButton(title: offer.plan.actionTitle, waitingFor: fix.waitingFor) { actions.fix.begin(finding) }
            case let .withheld(why?)?:
                Label {
                    Text(why).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                }
                .font(Typeface.small)
            case .withheld(nil)?, nil:
                EmptyView()
            }
        }
    }

    private func commandBlock(_ command: String) -> some View {
        HStack(alignment: .top, spacing: 4) {
            CommandBlock(command)
            Button {
                actions.copy(command)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .contentTransition(.symbolEffect(.replace))
                    .font(.system(size: 13))
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(copied ? .primary : .secondary)
            .help(copied ? "Copied" : "Copy the command")
            .accessibilityLabel(copied ? "Copied" : "Copy the command")
        }
    }
}
