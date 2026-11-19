import OSVAKit
import SwiftUI

// Running a finding's fix: the Fix button, the confirmation, and the line that says how the last run went. One
// component each, coloured only from Theme.swift, like everything in Components.swift.

/// What a finding's row shows about running its fix.
public struct FixRowState: Equatable, Sendable {
    public enum Availability: Equatable, Sendable {
        /// Reading Homebrew's data (the first time a `brew upgrade` row opens).
        case checking
        case offered(FixOffer)
        /// No button; why, when there is something to say.
        case withheld(String?)
    }

    public enum Preview: Equatable, Sendable {
        case loading
        case ready(FixPreview)
    }

    public enum Progress: Equatable, Sendable {
        /// The Terminal window is open; the app waits for its result file.
        case running
        /// The command ended; the app is checking the finding again.
        case rechecking
        case finished(FixOutcome)
    }

    public var availability: Availability?
    /// Set while the confirmation is open.
    public var preview: Preview?
    public var progress: Progress?

    public init(availability: Availability? = nil, preview: Preview? = nil, progress: Progress? = nil) {
        self.availability = availability; self.preview = preview; self.progress = progress
    }

    /// A run is under way: no button, no confirmation.
    public var isBusy: Bool { progress == .running || progress == .rechecking }

    /// The finding is fixed or removed: its row only says so.
    public var isResolved: Bool {
        if case let .finished(outcome)? = progress { return outcome.isResolved }
        return false
    }
}

/// What a row can ask the app to do about a fix.
public struct FixActions {
    /// The row opened: decide whether it gets a Fix button.
    public var assess: (Finding) -> Void
    /// Fix… was pressed: open the confirmation and ask the tool for a dry run.
    public var begin: (Finding) -> Void
    public var cancel: (Finding) -> Void
    /// Run in Terminal was pressed.
    public var run: (Finding) -> Void

    public init(assess: @escaping (Finding) -> Void, begin: @escaping (Finding) -> Void, cancel: @escaping (Finding) -> Void,
                run: @escaping (Finding) -> Void) {
        self.assess = assess; self.begin = begin; self.cancel = cancel; self.run = run
    }

    public static var none: FixActions { FixActions(assess: { _ in }, begin: { _ in }, cancel: { _ in }, run: { _ in }) }
}

/// "Fix…" (or "Remove…" for malware): a small bordered button under the command. The ellipsis says a confirmation
/// comes first; nothing runs from this button alone.
public struct FixButton: View {
    public var removal: Bool
    public var action: () -> Void
    public init(removal: Bool, action: @escaping () -> Void) { self.removal = removal; self.action = action }

    public var body: some View {
        Button(action: action) {
            Label(removal ? "Remove…" : "Fix…", systemImage: "terminal")
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .help(removal ? "Remove it in a Terminal window, after you confirm" : "Run this command in a Terminal window, after you confirm")
    }
}

/// The confirmation: the exact command, where it runs, what else the tool says will change, and what to watch for.
/// Nothing runs until Run in Terminal.
public struct FixConfirmation: View {
    public var offer: FixOffer
    public var preview: FixRowState.Preview
    public var cancel: () -> Void
    public var run: () -> Void

    public init(offer: FixOffer, preview: FixRowState.Preview, cancel: @escaping () -> Void, run: @escaping () -> Void) {
        self.offer = offer; self.preview = preview; self.cancel = cancel; self.run = run
    }

    private var plan: FixPlan { offer.plan }

    public var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(plan.action == .removal ? "Remove it in a Terminal window" : "Run it in a Terminal window")
                .font(Typeface.small.weight(.semibold)).foregroundStyle(.primary)
            CommandBlock(plan.command)
            VStack(alignment: .leading, spacing: 6) {
                fact("Where") { value(plan.place) }
                if plan.homebrew == nil || plan.inProjectFolder {          // Homebrew's place already names its brew
                    fact("Tool") {
                        if plan.inProjectFolder {
                            value("The \(plan.toolName) your shell finds first", caption: "On this Mac: " + Paths.abbreviatingHome(plan.toolPath))
                        } else {
                            value(Paths.abbreviatingHome(plan.toolPath))
                        }
                    }
                }
                if let line = offer.homebrew { fact("Homebrew") { value(line, caption: HomebrewAvailability.source) } }
                fact("Also") { alsoChanges }
            }
            if let m = plan.majorUpgrade { notice("exclamationmark.triangle", m) }
            if let l = plan.lockfileNote { notice("doc.text", l) }
            Text("It runs as you, in a window you can watch. If it asks for a password, you type it there.")
                .font(Typeface.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Cancel", action: cancel)
                    .buttonStyle(.bordered)
                    .keyboardShortcut(.cancelAction)
                Button(action: run) {
                    Label("Run in Terminal", systemImage: "terminal")
                }
                .buttonStyle(.borderedProminent)
                .help("Opens Terminal and runs the command above")
            }
            .controlSize(.small)
        }
        .padding(10)
        .background {
            let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
            shape.fill(.quinary).overlay(shape.strokeBorder(.quaternary, lineWidth: 1))
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Confirm the fix")
    }

    /// The width of the names column: "Homebrew", the longest, is 52 pt in 11.5 pt SF Pro.
    static let termWidth: CGFloat = 64

    /// One fact: its name in `.secondary` on the left, the value filling the rest of the line.
    private func fact<V: View>(_ name: String, @ViewBuilder _ value: () -> V) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(name).font(Typeface.small).foregroundStyle(.secondary).frame(width: Self.termWidth, alignment: .leading)
            value().frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func value(_ text: String, caption: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(text).font(Typeface.small).foregroundStyle(.primary)
            if let caption { Text(caption).font(Typeface.caption).foregroundStyle(.secondary) }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var alsoChanges: some View {
        switch preview {
        case .loading:
            HStack(spacing: 6) {
                ProgressView().controlSize(.mini)
                Text("Asking \(plan.toolName) for a dry run…").font(Typeface.small).foregroundStyle(.secondary)
            }
        case let .ready(p):
            VStack(alignment: .leading, spacing: 2) {
                if let why = p.unavailable {
                    Text(why).font(Typeface.small).foregroundStyle(.secondary)
                } else {
                    ForEach(Array(p.lines.prefix(FixPreview.maxLines).enumerated()), id: \.offset) { _, line in
                        // a section's heading ("Would upgrade 2 outdated packages:") is quieter than its items
                        Text(line).font(Typeface.small).foregroundStyle(line.hasSuffix(":") ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                    }
                    if p.lines.count > FixPreview.maxLines {
                        Text("and \(p.lines.count - FixPreview.maxLines) more").font(Typeface.small).foregroundStyle(.secondary)
                    }
                    if let source = p.source { Text(source).font(Typeface.caption).foregroundStyle(.secondary) }
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func notice(_ symbol: String, _ text: String) -> some View {
        Label {
            Text(text).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: symbol).foregroundStyle(.secondary)
        }
        .font(Typeface.small)
    }
}

/// How the last run of a row's fix went: running, checking again, or what the check found. Shown on the row open or
/// closed, under where the finding came from.
public struct FixStatusLine: View {
    public var progress: FixRowState.Progress
    public init(_ progress: FixRowState.Progress) { self.progress = progress }

    public var body: some View {
        Label {
            Text(text).foregroundStyle(quiet ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            icon
        }
        .font(Typeface.small.weight(.medium))
        .accessibilityElement(children: .combine)
    }

    private var text: String {
        switch progress {
        case .running: return "Running in Terminal…"
        case .rechecking: return "Checking again…"
        case let .finished(outcome): return outcome.text
        }
    }

    private var quiet: Bool { progress == .running || progress == .rechecking }

    @ViewBuilder private var icon: some View {
        switch progress {
        case .running: Image(systemName: "terminal").foregroundStyle(.secondary)
        case .rechecking: Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(.secondary)
        case let .finished(outcome) where outcome.isResolved:
            // the check is cut out of the disc, so it reads on light and dark glass alike
            Image(systemName: "checkmark.circle.fill").symbolRenderingMode(.monochrome).foregroundStyle(Tokens.clean.color)
        case .finished: Image(systemName: "exclamationmark.circle").foregroundStyle(.secondary)
        }
    }
}
