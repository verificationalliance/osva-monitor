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
            if !fix.isResolved && !finding.statusChips.isEmpty { statusChips }   // none: no empty line and its spacing
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

    /// The status line, `Finding.statusChips` in order: a chip that has no room on the line moves whole to the next.
    private var statusChips: some View {
        WrapAtSpaces(spacing: 8, lineSpacing: 4) {
            ForEach(finding.statusChips, id: \.self) { item in
                switch item {
                case let .chip(kind): StatusChip(kind)
                case let .severity(s): SeverityLabel(s).fixedSize()
                case let .flaws(n): Text("\(n) flaws").font(Typeface.count(11.5, weight: .medium)).foregroundStyle(.secondary).fixedSize()
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
                } else {
                    Text("  " + finding.withoutVersion).font(Typeface.small).foregroundStyle(.secondary)
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
        if finding.upgradeCommand ?? fix.run?.command != nil {
            let command = Self.copyable(finding, fix)
            if let offer = fix.reviewable, let preview = fix.preview, !fix.isBusy {
                FixConfirmation(offer: offer, preview: preview, waitingFor: fix.waitingFor,
                                cancel: { actions.fix.cancel(finding) }, run: { actions.fix.run(finding) })
            } else if let run = fix.run, fix.isBusy {
                FixRunCard(run: run) { actions.fix.stop(finding) }
            } else if let outcome = fix.outcome, outcome.isProblem, fix.run != nil {
                if let command { commandBlock(command) }
                FixProblemCard(outcome: outcome, run: fix.run, waitingFor: fix.waitingFor, canRetry: fix.offeredFix != nil || fix.offeredProposal != nil,
                               canCopy: command != nil, retry: { actions.fix.retry(finding) }, undo: { actions.fix.undo(finding) },
                               runInTerminal: { actions.fix.runInTerminal(finding) }, copy: actions.copy)
            } else {
                if let command { commandBlock(command) }
                fixControl
            }
        }
    }

    /// The command the row offers to copy, or none: not one the app refuses because running it would break something
    /// installed (a dependent's specifier, a runtime boundary, a project's own requirement: the row says why, and offers
    /// what is safe instead when there is something), nor one that cannot bring a fix now (Homebrew behind, the newest
    /// already installed). A command the app only does not run for you (pipx, MacPorts, Nix, conda, a user Ruby's gem, a
    /// lockfile), or one that needs a password, is there to copy.
    static func copyable(_ finding: Finding, _ fix: FixRowState) -> String? {
        if fix.hold == .blocked || fix.hold == .noFix { return nil }
        return finding.upgradeCommand ?? fix.run?.command
    }

    /// The open row shows the run (or how it ended) as a card, so the one-line status is left out.
    private var showsCard: Bool {
        if fix.run != nil && fix.isBusy { return true }
        if let o = fix.outcome, o.isProblem, fix.run != nil { return true }
        return checkAfterFix
    }

    /// Under the command: the button (FixRowState.offeredFix, which Fix all counts too: Retry, above, is the same
    /// decision), or why there is none, or a moment while the app checks.
    @ViewBuilder private var fixControl: some View {
        if let offer = fix.offeredFix {
            FixButton(title: offer.plan.actionTitle, waitingFor: fix.waitingFor) { actions.fix.begin(finding) }
        } else if !fix.isBusy {
            switch fix.availability {
            case .checking?:
                FixSpinnerLabel("Checking…")
            case .offered?:
                EmptyView()
            case let .withheld(why?)?:
                Label {
                    Text(why).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                }
                .font(Typeface.small)
                if let proposal = fix.offeredProposal { proposalControl(proposal) }
            case let .terminal(_, why)?:
                Label {
                    Text(why).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "lock.fill").foregroundStyle(.secondary)
                }
                .font(Typeface.small)
                TerminalButton(waitingFor: fix.waitingFor) { actions.fix.runInTerminal(finding) }
                    .controlSize(.regular)
            case .withheld(nil)?, nil:
                EmptyView()
            }
        }
    }

    /// What the app can do instead, with the person's OK: the proposal in one line, who pip asks for an upgrade
    /// together, and its button, which opens the same review as any fix.
    @ViewBuilder private func proposalControl(_ offer: FixOffer) -> some View {
        if let proposal = offer.proposal {
            VStack(alignment: .leading, spacing: 6) {
                Text(proposal.line(offer.plan)).font(Typeface.small.weight(.medium)).foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                if let asks = proposal.asks {
                    Text(FixAllProposalLine.whole(asks) + ".").font(Typeface.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                FixButton(title: proposal.buttonTitle(offer.plan), waitingFor: fix.waitingFor) { actions.fix.begin(finding) }
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

/// One item of a row's status line.
public enum StatusLineItem: Hashable, Sendable {
    case chip(StatusChip.Kind)
    case severity(Severity)
    case flaws(Int)
}

/// What a row says about a finding, beyond its fields.
extension Finding {
    /// The row's status line, in order: malicious alone; else the red chip of an exploited flaw the core checked, the
    /// severity, how many flaws, and the amber chip of a flaw it did not check, first on a likely or reported row (in
    /// the red chip's place), last on a checked row (after what was checked).
    public var statusChips: [StatusLineItem] {
        if malicious { return [.chip(.malicious)] }
        let leads = group.isNotChecked, amber = notCheckedChip.map(StatusLineItem.chip)
        var items: [StatusLineItem] = checkedExploited ? [.chip(.exploited)] : []
        if leads, let amber { items.append(amber) }
        if let severity { items.append(.severity(severity)) }
        if flawCount > 1 { items.append(.flaws(flawCount)) }
        if !leads, let amber { items.append(amber) }
        return items
    }

    /// The most urgent flaw of this finding the core did not check against published ranges, when it is exploited in
    /// the wild or critical: `notChecked`, or, for a likely or reported finding, its own exploited flag (a report saved
    /// before `notChecked` keeps its mark). Never its severity alone, which may come from a flaw whose published ranges
    /// the core checked and found the version outside. Nil for a malicious finding, which says only that.
    public var notCheckedMark: NotChecked? {
        guard !malicious else { return nil }
        let own = group.isNotChecked && exploited ? NotChecked(id: nil, exploited: true, critical: false) : nil
        return .worse(notChecked, own)
    }

    /// Exploited in the wild, in a flaw the core checked: the red "Exploited" chip and "Exploited flaw" say so, never
    /// of a likely or reported finding.
    public var checkedExploited: Bool { exploited && !malicious && !group.isNotChecked }

    /// The amber chip, when there is a mark. It names the flaw exploited, else critical, except that a likely or
    /// reported row whose own severity is critical already says so beside it ("Not checked").
    public var notCheckedChip: StatusChip.Kind? {
        notCheckedMark.map { .notChecked($0, namesCritical: !(group.isNotChecked && severity == .critical)) }
    }

    /// The version line without a version to upgrade to: what the core could not check has no checked fix to name, and
    /// a version the core found outside every published range, or whose every flaw is of another platform, has none to
    /// need.
    public var withoutVersion: String {
        if outsideItsRanges == true { return "outside its published ranges" }
        if onlyElsewhere == true { return "does not affect this Mac" }
        if !unresolved.isEmpty && unresolved.allSatisfy({ !$0.affectsThisMac }) { return "does not affect this Mac" }
        return group.isNotChecked ? "no checked fixed version" : "no fixed release known"
    }
}
