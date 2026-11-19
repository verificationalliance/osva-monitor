import OSVAKit
import SwiftUI

/// One finding, as content on its group's container. Closed: name with verification mark and grade; installed →
/// fixed version; status; where it came from; how its last fix went. Open: why, what to run (and a Fix button that
/// runs it in Terminal after a confirmation), and a link to the site.
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
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help(expanded ? "Hide what to do" : "Show what to do")
                .accessibilityLabel(expanded ? "Hide what to do" : "Show what to do")
            }
            versionLine
            if !fix.isResolved { statusChips }
            Text(finding.originSummary).font(Typeface.small).foregroundStyle(.secondary)
                .lineLimit(expanded ? 3 : 1).truncationMode(.middle)
            if let progress = fix.progress { FixStatusLine(progress).padding(.top, 2) }
            if fix.isResolved && finding.malicious {
                // removing it is not the end: what it could read may already be gone
                Text("Now rotate every secret it could read.").font(Typeface.small).foregroundStyle(Tokens.Malicious.text.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if expanded { details }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background { if hover { Rectangle().fill(.quaternary) } }
        .contentShape(Rectangle())
        .onTapGesture(perform: toggle)
        .onHover { hover = $0 }
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

    /// Installed in `.secondary`, a `.tertiary` arrow, the fixed version in `.primary`; or the plain "no fixed
    /// release known". Malware has no fixed version: only what is installed.
    private var versionLine: some View {
        HStack(spacing: 0) {
            Text(finding.installedLabel).foregroundStyle(.secondary)
            if !finding.malicious {
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
        .accessibilityLabel(finding.versionLine)
    }

    @ViewBuilder private var details: some View {
        VStack(alignment: .leading, spacing: 8) {
            ProvenanceView(finding.provenance)
            if !fix.isResolved { advice }
            Button { actions.open(finding.pageURL) } label: {
                Label(finding.pageLabel, systemImage: "arrow.up.right")
            }
            .buttonStyle(.link)
            .font(Typeface.small)
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
        if let command = finding.upgradeCommand {
            if case let .offered(offer)? = fix.availability, let preview = fix.preview, !fix.isBusy {
                FixConfirmation(offer: offer, preview: preview, cancel: { actions.fix.cancel(finding) }, run: { actions.fix.run(finding) })
            } else {
                commandBlock(command)
                fixControl
            }
        }
    }

    /// Under the command: the Fix button, or why there is none, or a moment while Homebrew is asked.
    @ViewBuilder private var fixControl: some View {
        if !fix.isBusy {
            switch fix.availability {
            case .checking?:
                HStack(spacing: 6) {
                    ProgressView().controlSize(.mini)
                    Text("Checking Homebrew…").font(Typeface.small).foregroundStyle(.secondary)
                }
            case let .offered(offer)?:
                FixButton(removal: offer.plan.action == .removal) { actions.fix.begin(finding) }
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
            .buttonStyle(.borderless)
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(copied ? .primary : .secondary)
            .help(copied ? "Copied" : "Copy the command")
            .accessibilityLabel(copied ? "Copied" : "Copy the command")
        }
    }
}
