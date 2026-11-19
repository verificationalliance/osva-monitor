import OSVAKit
import SwiftUI

// Running a finding's fix inside the app: the button, the review, the run with its live log, and how it ended. One
// component each, coloured only from Theme.swift, like everything in Components.swift. Every state is one short
// sentence and its action; the rest (the exact arguments, the dry run, the whole log) is one click away.

/// One run inside the app, as its row shows it: which step, since when, and what the tool has printed.
public struct FixRunState: Equatable, Sendable {
    public enum Step: Int, CaseIterable, Sendable {
        /// The app checks the command again (and, for pip, what depends on the package).
        case preparing
        /// The tool runs.
        case running
        /// The command ended; the app checks the finding again.
        case checking
    }

    public var step: Step
    /// "Updating", "Removing", "Undoing": the running step's name.
    public var doing: String
    public var startedAt: Date
    /// When the command ended: the elapsed time stops there.
    public var endedAt: Date?
    public var log: FixLog
    /// Stop was pressed and the command has not ended yet.
    public var stopping: Bool
    /// The command shown, for Copy.
    public var command: String
    /// After a pip upgrade broke something: what puts it back.
    public var undo: PipUndo?

    public init(step: Step = .preparing, doing: String, startedAt: Date = Date(), endedAt: Date? = nil, log: FixLog = FixLog(),
                stopping: Bool = false, command: String, undo: PipUndo? = nil) {
        self.step = step; self.doing = doing; self.startedAt = startedAt; self.endedAt = endedAt; self.log = log
        self.stopping = stopping; self.command = command; self.undo = undo
    }
}

/// What a finding's row shows about running its fix.
public struct FixRowState: Equatable, Sendable {
    public enum Availability: Equatable, Sendable {
        /// Asking Homebrew, or reading what depends on a Python package (the first time the row opens).
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
        /// The command runs: in the app (`run` says how far), or in a Terminal window (`run` is nil).
        case running
        /// The command ended; the app is checking the finding again.
        case rechecking
        case finished(FixOutcome)
    }

    public var availability: Availability?
    /// Set while the review is open.
    public var preview: Preview?
    public var progress: Progress?
    /// The last run inside the app: its steps, time and log. Nil for a run in Terminal.
    public var run: FixRunState?
    /// Another fix is running (its finding's name): one runs at a time, so this row's button waits.
    public var waitingFor: String?

    public init(availability: Availability? = nil, preview: Preview? = nil, progress: Progress? = nil, run: FixRunState? = nil,
                waitingFor: String? = nil) {
        self.availability = availability; self.preview = preview; self.progress = progress; self.run = run; self.waitingFor = waitingFor
    }

    /// A run is under way: no button, no review.
    public var isBusy: Bool { progress == .running || progress == .rechecking }

    /// The finding is fixed or removed: its row only says so.
    public var isResolved: Bool {
        if case let .finished(outcome)? = progress { return outcome.isResolved }
        return false
    }

    /// How the last run ended, if it has.
    public var outcome: FixOutcome? {
        if case let .finished(o)? = progress { return o }
        return nil
    }

    /// The fix the row offers to run in the app now: its button (or its open review), or Retry after a run that may go
    /// better a second time. Nil while it runs, once it is fixed, and when the row offers only Terminal, Undo or
    /// nothing. The row draws its button from this, and Fix all counts and runs exactly these.
    public var offeredFix: FixOffer? {
        guard case let .offered(offer)? = availability, !isBusy, !isResolved else { return nil }
        guard let outcome, outcome.isProblem, run != nil else { return offer }
        return outcome.canRetry ? offer : nil
    }
}

/// What a row can ask the app to do about a fix.
public struct FixActions {
    /// The row opened: decide whether it gets a button.
    public var assess: (Finding) -> Void
    /// The button was pressed: open the review and ask the tool for a dry run.
    public var begin: (Finding) -> Void
    /// The review's Cancel.
    public var cancel: (Finding) -> Void
    /// The review's Update or Remove: run it in the app.
    public var run: (Finding) -> Void
    /// Stop the run.
    public var stop: (Finding) -> Void
    /// Run the same command again, after it did not finish.
    public var retry: (Finding) -> Void
    /// Put back what a pip upgrade changed.
    public var undo: (Finding) -> Void
    /// Only after the tool asked for an administrator password: run it in a Terminal window, where it can ask.
    public var runInTerminal: (Finding) -> Void

    public init(assess: @escaping (Finding) -> Void, begin: @escaping (Finding) -> Void, cancel: @escaping (Finding) -> Void,
                run: @escaping (Finding) -> Void, stop: @escaping (Finding) -> Void = { _ in }, retry: @escaping (Finding) -> Void = { _ in },
                undo: @escaping (Finding) -> Void = { _ in }, runInTerminal: @escaping (Finding) -> Void = { _ in }) {
        self.assess = assess; self.begin = begin; self.cancel = cancel; self.run = run
        self.stop = stop; self.retry = retry; self.undo = undo; self.runInTerminal = runInTerminal
    }

    public static var none: FixActions { FixActions(assess: { _ in }, begin: { _ in }, cancel: { _ in }, run: { _ in }) }
}

/// The fix's one prominent action, worded as what it does: "Update to 1.30.7", "Update OpenMTP", "Remove axios", and
/// the panel's "Fix all (5)". A capsule in the person's accent colour, like Scan Now; nothing runs from it alone (the
/// review comes first). When another fix is running, it waits and says so: beside it, or where its container puts the
/// line (`saysWhy: false`; the panel's header puts it under the button).
public struct FixButton: View {
    public var title: String
    public var waitingFor: String?
    /// Waiting for something other than a fix ("Checking what can be fixed…"): disabled, and the container says why.
    public var paused: Bool
    public var saysWhy: Bool
    public var action: () -> Void

    public init(title: String, waitingFor: String? = nil, paused: Bool = false, saysWhy: Bool = true, action: @escaping () -> Void) {
        self.title = title; self.waitingFor = waitingFor; self.paused = paused; self.saysWhy = saysWhy; self.action = action
    }

    /// Why a fix waits, everywhere it waits: "One fix at a time: nginx is running."
    public nonisolated static func waiting(_ busy: String) -> String { "One fix at a time: \(busy) is running." }

    public var body: some View {
        HStack(spacing: 10) {
            Button(action: action) { Text(title).fontWeight(.semibold) }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.regular)
                .disabled(waitingFor != nil || paused)
            if let w = waitingFor, saysWhy {
                Text(Self.waiting(w)).font(Typeface.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .help(waitingFor == nil ? "Shows what it will do; nothing runs until you confirm" : "Waits for the fix that is running")
    }
}

/// The review: what will happen in one sentence, what else changes, a warning if there is one, and the one action.
/// The exact arguments, where it runs and the tool's dry run are under Details.
public struct FixConfirmation: View {
    public var offer: FixOffer
    public var preview: FixRowState.Preview
    public var waitingFor: String?
    public var cancel: () -> Void
    public var run: () -> Void
    @State private var details = false

    public init(offer: FixOffer, preview: FixRowState.Preview, waitingFor: String? = nil, details: Bool = false,
                cancel: @escaping () -> Void, run: @escaping () -> Void) {
        self.offer = offer; self.preview = preview; self.waitingFor = waitingFor; self.cancel = cancel; self.run = run
        _details = State(initialValue: details)
    }

    private var plan: FixPlan { offer.plan }

    private var ready: FixPreview? { if case let .ready(p) = preview { return p } else { return nil } }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(plan.summary).font(Typeface.body.weight(.semibold)).foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            switch preview {
            case .loading:
                FixSpinnerLabel("Asking \(plan.toolName) what else changes…")
            case let .ready(p):
                if let blocked = p.blocked {
                    FixNotice(symbol: "exclamationmark.triangle.fill", text: blocked.prefix(1).uppercased() + blocked.dropFirst() + ".", strong: true)
                } else {
                    if let also = Self.also(p, plan: plan, companions: offer.companions) {
                        Text(also).font(Typeface.small).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    if let used = Self.usedBy(p.usedBy) {
                        Text(used).font(Typeface.small).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if let m = plan.majorUpgrade { FixNotice(symbol: "exclamationmark.triangle", text: m) }
            if details { FixDetails(offer: offer, preview: ready) }
            HStack(spacing: 8) {
                FixDisclosure(details ? "Hide details" : "Details", open: details) { withAnimation(.smooth(duration: 0.2)) { details.toggle() } }
                Spacer(minLength: 0)
                Button("Cancel", action: cancel)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .keyboardShortcut(.cancelAction)
                Button(action: run) { Text(plan.verb).fontWeight(.semibold) }
                    .buttonStyle(.borderedProminent)
                    .buttonBorderShape(.capsule)
                    .disabled(ready == nil || ready?.blocked != nil || waitingFor != nil)
                    .help("Runs the command above in the app, as you, without a shell")
            }
            .controlSize(.regular)
            if let w = waitingFor { Text(FixButton.waiting(w)).font(Typeface.caption).foregroundStyle(.secondary) }
        }
        .fixCard()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Review the fix")
    }

    /// "Used by whisperx, pyannote.audio.": who to check afterwards, when it changes more than a patch.
    static func usedBy(_ names: [String]) -> String? {
        guard !names.isEmpty else { return nil }
        return "Used by " + names.prefix(3).joined(separator: ", ") + (names.count > 3 ? " and \(names.count - 3) more." : ".")
    }

    /// "Also updates openssl@3.", "Also installs idna and 2 more.", "Also updates torchaudio, which moves with it.";
    /// nil when nothing else changes.
    static func also(_ p: FixPreview, plan: FixPlan, companions: [String] = []) -> String? {
        let others = p.others(than: plan.pip?.name ?? plan.homebrew?.name ?? plan.title)
        guard let first = others.first else { return nil }
        let moving = Set(companions.map(PythonNames.normal))
        if !moving.isEmpty, others.allSatisfy({ moving.contains(PythonNames.normal($0)) }) {
            return "Also updates \(others.joined(separator: " and ")), which " + (others.count == 1 ? "moves" : "move") + " with it."
        }
        let verb = plan.pip != nil ? "installs" : "updates"
        return "Also \(verb) \(first)" + (others.count > 1 ? " and \(others.count - 1) more." : ".")
    }
}

/// What exactly runs: every argument as it is passed (each in its own pill, so one argument can never pass for two),
/// where, and what the tool's dry run said.
struct FixDetails: View {
    let offer: FixOffer
    let preview: FixPreview?

    var body: some View {
        let plan = offer.plan
        VStack(alignment: .leading, spacing: 7) {
            fact("Runs") {
                WrapAtSpaces(spacing: 4, lineSpacing: 4) {
                    ForEach(Array((plan.invocation.argv + (preview?.pins ?? [])).enumerated()), id: \.offset) { i, arg in
                        Text(i == 0 ? Paths.abbreviatingHome(arg) : arg)
                            .font(Typeface.code).foregroundStyle(.primary)
                            .padding(.horizontal, 5).padding(.vertical, 1.5)
                            .well(cornerRadius: 4)
                            .fixedSize()
                    }
                }
            }
            fact("Where") { value(plan.place) }
            if let line = offer.homebrew { fact("Homebrew") { value(line) } }
            if let p = preview {
                fact("Dry run") {
                    VStack(alignment: .leading, spacing: 2) {
                        if let why = p.unavailable {
                            Text(why).foregroundStyle(.secondary)
                        } else {
                            ForEach(Array(p.lines.prefix(FixPreview.maxLines).enumerated()), id: \.offset) { _, line in
                                Text(line).foregroundStyle(line.hasSuffix(":") ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                            }
                            if p.lines.count > FixPreview.maxLines { Text("and \(p.lines.count - FixPreview.maxLines) more").foregroundStyle(.secondary) }
                        }
                    }
                    .font(Typeface.small)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text("No shell and no password: it runs as you, and stops after 15 minutes.")
                .font(Typeface.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .transition(.opacity)
    }

    /// The width of the names column: "Homebrew", the longest, is 52 pt in 11.5 pt SF Pro.
    static let termWidth: CGFloat = 60

    private func fact<V: View>(_ name: String, @ViewBuilder _ value: () -> V) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(name).font(Typeface.small).foregroundStyle(.secondary).frame(width: Self.termWidth, alignment: .leading)
            value().frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func value(_ text: String) -> some View {
        Text(text).font(Typeface.small).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
    }
}

/// The run: the three steps with the elapsed time, the tool's last lines (all of them on request, live, selectable),
/// and Stop.
public struct FixRunCard: View {
    public var run: FixRunState
    public var stop: () -> Void
    @State private var full: Bool

    public init(run: FixRunState, full: Bool = false, stop: @escaping () -> Void) {
        self.run = run; self.stop = stop; _full = State(initialValue: full)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                FixStepLine(step: run.step, doing: run.doing)
                Spacer(minLength: 4)
                FixElapsed(start: run.startedAt, end: run.endedAt)
            }
            FixLogView(log: run.log, full: $full, placeholder: run.step == .preparing ? "Checking the command again…" : "Waiting for output…")
            if run.step != .checking {
                Button(run.stopping ? "Stopping…" : "Stop", action: stop)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
                    .disabled(run.stopping)
                    .help("Stops the command and everything it started")
            }
        }
        .fixCard()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(run.doing), step \(run.step.rawValue + 1) of 3")
    }
}

/// Preparing · Updating · Checking again: done steps checked, the current one moving, the next ones quiet.
public struct FixStepLine: View {
    public var step: FixRunState.Step
    public var doing: String
    public init(step: FixRunState.Step, doing: String) { self.step = step; self.doing = doing }

    public var body: some View {
        HStack(spacing: 10) {
            ForEach(FixRunState.Step.allCases, id: \.self) { s in
                HStack(spacing: 4) {
                    icon(s).frame(width: 13)
                    Text(name(s))
                        .foregroundStyle(s == step ? AnyShapeStyle(.primary) : s.rawValue < step.rawValue ? AnyShapeStyle(.secondary) : AnyShapeStyle(.tertiary))
                        .fontWeight(s == step ? .semibold : .regular)
                }
            }
        }
        .font(Typeface.small)
        .lineLimit(1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(name(step))
    }

    private func name(_ s: FixRunState.Step) -> String {
        switch s { case .preparing: return "Preparing"; case .running: return doing; case .checking: return "Checking again" }
    }

    @ViewBuilder private func icon(_ s: FixRunState.Step) -> some View {
        if s.rawValue < step.rawValue {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.secondary).font(.system(size: 11))
        } else if s == step {
            FixSpinner()
        } else {
            Image(systemName: "circle").foregroundStyle(.tertiary).font(.system(size: 11))
        }
    }
}

/// The app's one spinner: an SF Symbol moving, which draws everywhere a symbol draws (an AppKit spinner does not
/// draw off-screen).
struct FixSpinner: View {
    var body: some View {
        Image(systemName: "progress.indicator")
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.primary)
            .symbolEffect(.variableColor.iterative, options: .repeat(.continuous))
            .accessibilityHidden(true)
    }
}

struct FixSpinnerLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        HStack(spacing: 6) {
            FixSpinner()
            Text(text).font(Typeface.small).foregroundStyle(.secondary)
        }
    }
}

/// "0:42", "12:03": from the start to now, or to the end once the command ended.
public struct FixElapsed: View {
    public var start: Date
    public var end: Date?
    public init(start: Date, end: Date?) { self.start = start; self.end = end }

    public var body: some View {
        TimelineView(.periodic(from: start, by: 1)) { context in
            Text(Self.format((end ?? context.date).timeIntervalSince(start)))
                .font(Typeface.count(11.5, weight: .medium)).foregroundStyle(.secondary)
                .contentTransition(.numericText())
        }
        .accessibilityLabel("Elapsed")
    }

    static func format(_ t: TimeInterval) -> String {
        let s = max(0, Int(t))
        return "\(s / 60):" + String(format: "%02d", s % 60)
    }
}

/// The tool's output in a well: its last lines, one each (cut at the edge), or all of it, wrapped, in a scroll view
/// that follows the end as it grows. Monospaced and selectable; what is in it was already made safe by TerminalText.
/// The corner button switches between the two.
public struct FixLogView: View {
    public var log: FixLog
    @Binding public var full: Bool
    public var placeholder: String
    /// Lines shown when not full.
    public static let lastLines = 4

    public init(log: FixLog, full: Binding<Bool>, placeholder: String = "No output.") {
        self.log = log; _full = full; self.placeholder = placeholder
    }

    public var body: some View {
        Group {
            if log.isEmpty {
                Text(placeholder).font(Typeface.small).foregroundStyle(.tertiary).frame(maxWidth: .infinity, alignment: .leading)
            } else if full {
                ScrollView(.vertical) {
                    Text(log.text).foregroundStyle(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                        .padding(.trailing, 18)
                }
                .defaultScrollAnchor(.bottom)
                .frame(height: 168)
            } else {
                VStack(alignment: .leading, spacing: 1.5) {
                    ForEach(Array(log.last(Self.lastLines).enumerated()), id: \.offset) { _, line in
                        Text(line).lineLimit(1).truncationMode(.tail)
                    }
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.trailing, 18)
                .textSelection(.enabled)
            }
        }
        .font(Typeface.log)
        .padding(.horizontal, 8).padding(.vertical, 6)
        .overlay(alignment: .topTrailing) {
            if !log.isEmpty {
                Button { withAnimation(.smooth(duration: 0.2)) { full.toggle() } } label: {
                    Image(systemName: full ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right")
                        .font(.system(size: 9.5, weight: .semibold)).foregroundStyle(.secondary)
                        .frame(width: 22, height: 20).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(full ? "Show the last lines" : "Show the whole log")
                .accessibilityLabel(full ? "Show the last lines" : "Show the whole log")
            }
        }
        .well()
        .transaction { $0.animation = nil }                    // a growing log does not animate, it updates
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Output")
    }
}

/// How a run in the app ended, when it needs saying more than a status line: the sentence, the last lines of output,
/// and the way on (Undo, Run in Terminal, Retry, Copy command).
public struct FixProblemCard: View {
    public var outcome: FixOutcome
    public var run: FixRunState?
    public var waitingFor: String?
    public var canRetry: Bool
    public var retry: () -> Void
    public var undo: () -> Void
    public var runInTerminal: () -> Void
    public var copy: (String) -> Void
    @State private var full = false
    @State private var copied = false

    public init(outcome: FixOutcome, run: FixRunState?, waitingFor: String? = nil, canRetry: Bool, retry: @escaping () -> Void,
                undo: @escaping () -> Void, runInTerminal: @escaping () -> Void, copy: @escaping (String) -> Void) {
        self.outcome = outcome; self.run = run; self.waitingFor = waitingFor; self.canRetry = canRetry
        self.retry = retry; self.undo = undo; self.runInTerminal = runInTerminal; self.copy = copy
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                FixNotice(symbol: symbol, text: sentence, strong: true)
                if let run, run.endedAt != nil {
                    Spacer(minLength: 4)
                    FixElapsed(start: run.startedAt, end: run.endedAt)
                }
            }
            if let run, !run.log.isEmpty, showsLog { FixLogView(log: run.log, full: $full) }
            HStack(spacing: 8) { actions }
                .controlSize(.regular)
            if let w = waitingFor { Text(FixButton.waiting(w)).font(Typeface.caption).foregroundStyle(.secondary) }
        }
        .fixCard()
        .accessibilityElement(children: .contain)
    }

    /// One sentence. The password case says why the app stops there.
    private var sentence: String {
        switch outcome {
        case .needsPassword: return "This step needs your administrator password, which the app never handles."
        case let .broke(what): return "Updated, but it broke \(what)."
        default: return outcome.text + "."
        }
    }

    private var symbol: String {
        switch outcome {
        case .needsPassword: return "lock.fill"
        case .fixedCheck: return "checkmark.circle.fill"
        case .broke, .undoFailed: return "exclamationmark.triangle.fill"
        default: return "exclamationmark.circle.fill"
        }
    }

    private var showsLog: Bool {
        switch outcome { case .blocked, .fixedCheck: return false; default: return true }
    }

    @ViewBuilder private var actions: some View {
        switch outcome {
        case .broke, .undoFailed:
            if let undo = run?.undo {
                Button(action: self.undo) { Text("Undo").fontWeight(.semibold) }
                    .buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                    .disabled(waitingFor != nil)
                    .help("Puts back " + undo.restores.joined(separator: ", ") + ": " + undo.command)
            }
        case .fixedCheck:
            if let undo = run?.undo {
                Button("Undo", action: self.undo)                      // there if the check finds something broken
                    .buttonStyle(.bordered).buttonBorderShape(.capsule)
                    .disabled(waitingFor != nil)
                    .help("Puts back " + undo.restores.joined(separator: ", ") + ": " + undo.command)
            }
        case .needsPassword:
            Button(action: runInTerminal) { Text("Run in Terminal").fontWeight(.semibold) }
                .buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                .disabled(waitingFor != nil)
                .help("Opens Terminal with this command; it asks for the password there")
            copyButton
        case .blocked:
            EmptyView()
        default:
            if canRetry {
                Button(action: retry) { Text("Retry").fontWeight(.semibold) }
                    .buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                    .disabled(waitingFor != nil)
            }
            copyButton
        }
    }

    @ViewBuilder private var copyButton: some View {
        if let command = run?.command {
            Button {
                copy(command)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Text(copied ? "Copied" : "Copy command")
            }
            .buttonStyle(.bordered).buttonBorderShape(.capsule)
            .help(command)
        }
    }
}

/// How the last run went, in one line: on a closed row, and as the whole story when it ended well. A run that is
/// fixed draws its check on.
public struct FixStatusLine: View {
    public var progress: FixRowState.Progress
    public var run: FixRunState?
    public init(_ progress: FixRowState.Progress, run: FixRunState? = nil) { self.progress = progress; self.run = run }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            icon.frame(width: 14)
            Text(text).foregroundStyle(quiet ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                .fixedSize(horizontal: false, vertical: true)
            if let run, progress == .running {
                FixElapsed(start: run.startedAt, end: run.endedAt)
            }
        }
        .font(Typeface.small.weight(.medium))
        .accessibilityElement(children: .combine)
    }

    private var text: String {
        switch progress {
        case .running:
            guard let run else { return "Running in Terminal…" }
            switch run.step {
            case .preparing: return "Preparing…"
            case .running: return run.doing + "…"
            case .checking: return "Checking again…"
            }
        case .rechecking: return "Checking again…"
        case let .finished(outcome): return outcome.text
        }
    }

    private var quiet: Bool { progress == .running || progress == .rechecking }

    @ViewBuilder private var icon: some View {
        switch progress {
        case .running where run == nil: Image(systemName: "terminal").foregroundStyle(.secondary)
        case .running, .rechecking: FixSpinner()
        case let .finished(outcome) where outcome.isResolved || outcome.isUndone:
            // the check is cut out of the disc, so it reads on light and dark glass alike
            Image(systemName: "checkmark.circle.fill").symbolRenderingMode(.monochrome).foregroundStyle(Tokens.clean.color)
                .transition(.symbolEffect(.drawOn))
        case let .finished(outcome) where outcome == .needsPassword: Image(systemName: "lock.fill").foregroundStyle(.secondary)
        case .finished: Image(systemName: "exclamationmark.circle").foregroundStyle(.secondary)
        }
    }
}

extension FixOutcome {
    var isUndone: Bool { if case .undone = self { return true } else { return false } }

    /// An ending that may go better a second time: Retry runs the same command again.
    var canRetry: Bool {
        switch self {
        case .exitedWithError, .killed, .stopped, .timedOut, .couldNotStart, .couldNotCheck: return true
        default: return false
        }
    }
}

/// A notice inside a fix card: a symbol and one sentence.
struct FixNotice: View {
    let symbol: String
    let text: String
    var strong = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 14)
            Text(text).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
        }
        .font(strong ? Typeface.body.weight(.semibold) : Typeface.small)
    }
}

/// "Details": a quiet text toggle with a chevron, drawn by SwiftUI so it reads on any glass.
struct FixDisclosure: View {
    let title: String
    let open: Bool
    let action: () -> Void
    init(_ title: String, open: Bool, action: @escaping () -> Void) { self.title = title; self.open = open; self.action = action }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Text(title)
                Image(systemName: "chevron.down").font(.system(size: 8.5, weight: .bold)).rotationEffect(.degrees(open ? 180 : 0))
            }
            .font(Typeface.small.weight(.medium))
            .foregroundStyle(.secondary)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

extension View {
    /// The fix's cards (review, run, problem): set into the row as a well.
    func fixCard() -> some View {
        padding(10).frame(maxWidth: .infinity, alignment: .leading).well(cornerRadius: 10)
    }
}
