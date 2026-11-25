import Foundation

/// How a fix ended, as its row says it: one short sentence.
public enum FixOutcome: Equatable, Sendable {
    /// Checked again: the version installed now has no finding, and nothing that depends on it broke.
    case fixed(now: String)
    /// The same, after more than a patch upgrade of something other packages use: pip's checks cannot tell whether
    /// they still work, so the row says which to check ("whisperx"), and Undo stays.
    case fixedCheck(now: String, users: String)
    /// Checked again: no longer installed (a removal, or an uninstall).
    case removed
    /// Checked again and still found; the reason the app knows.
    case stillAffected(String)
    /// Checked again and still found, but only as reported by the site or likely affected: not checked against
    /// published ranges, so neither fixed nor a failure ("now 4.17.21").
    case notChecked(String)
    /// In Terminal: the command ended with an error (its exit status), and the package is still found.
    case failed(Int32)
    /// The command ended without error, but the app could not check again.
    case couldNotCheck(String)
    /// Terminal did not open the script.
    case couldNotOpen(String)

    // In the app

    /// The command ended with an error (its exit status), and the package is still found.
    case exitedWithError(Int32)
    /// Something else killed the command (the signal).
    case killed(Int32)
    /// The person stopped it; what the check found ("still 1.30.2").
    case stopped(String?)
    /// It ran past the time limit and was stopped.
    case timedOut(minutes: Int)
    /// It needs an administrator password, which the app never asks for or handles: Terminal is offered.
    case needsPassword
    /// The tool could not be started.
    case couldNotStart(String)
    /// It ran, and something that depends on what it changed is broken now ("fastapi 0.120.0"): never "Fixed".
    case broke(String)
    /// Not run: something installed depends on the version there now ("fastapi 0.120.0 needs starlette < 0.49.0").
    case blocked(String)
    /// The undo put these back ("starlette 0.48.0").
    case undone(String)
    /// The undo did not finish.
    case undoFailed
    /// A partial fix ran: now at this version, with this many flaws left (what blocked the rest still blocks them).
    case partlyFixed(now: String, remain: Int)
    /// Run on its own after its batch broke something, it broke it again (what), and was put back at once.
    case putBack(String)

    public var text: String {
        switch self {
        case let .fixed(now): return "Fixed — now \(now)"
        case let .fixedCheck(now, users): return "Fixed — now \(now) · check \(users) still " + (users.contains(" and ") ? "work" : "works")
        case .removed: return "Removed"
        case let .stillAffected(why): return "Still affected: \(why)"
        case let .notChecked(what): return "Still reported by the site; not checked: \(what)"
        case .failed(129): return "The Terminal window was closed before the command finished"
        case .failed: return "The command failed — see the Terminal window"
        case let .couldNotCheck(why): return "The command ran, but the app could not check again: \(why)"
        case let .couldNotOpen(why): return "Could not open Terminal: \(why)"
        case let .exitedWithError(status): return "It did not finish (exit status \(status))"
        case let .killed(signal): return "It was stopped by signal \(signal)"
        case let .stopped(found): return "Stopped" + (found.map { " — \($0)" } ?? "")
        case let .timedOut(minutes): return "Stopped after \(minutes) minutes"
        case .needsPassword: return "This step needs your administrator password"
        case let .couldNotStart(why): return "Could not start it: \(why)"
        case let .broke(what): return "Updated, but it broke \(what)"
        case let .blocked(why): return "Not run: \(why)"
        case let .undone(what): return "Undone — \(what) again"
        case .undoFailed: return "The undo did not finish"
        case let .partlyFixed(now, remain): return "Partly fixed — now \(now) · " + (remain == 1 ? "1 flaw remains" : "\(remain) flaws remain")
        case let .putBack(what): return "Put back: it broke \(what)"
        }
    }

    /// Whether the finding is gone.
    public var isResolved: Bool {
        switch self { case .fixed, .fixedCheck, .removed: return true; default: return false }
    }

    /// Whether this is a problem to show with the log and a way on (Retry, Undo, Terminal).
    public var isProblem: Bool {
        switch self {
        case .fixed, .fixedCheck, .removed, .undone, .partlyFixed, .notChecked: return false
        default: return true
        }
    }

    /// The outcome of a Terminal run that ended with `status`, from the re-check. What is installed decides first: a
    /// package that is fixed (or gone) is said to be, even if the command also reported an error. `homebrew` is
    /// Homebrew's answer read again after the run, for a `brew upgrade`.
    public static func make(status: Int32, before: Finding, recheck: Scanner.Recheck, homebrew: HomebrewAvailability?) -> FixOutcome {
        switch recheck {
        case let .fixed(now): return .fixed(now: now)
        case .removed: return .removed
        case let .couldNotCheck(why): return status == 0 ? .couldNotCheck(why) : .failed(status)
        case let .stillAffected(after):
            return status == 0 ? .stillAffected(reason(before: before, after: after, homebrew: homebrew)) : .failed(status)
        case let .notChecked(after):
            return status == 0 ? .notChecked(found(before: before, after: after)) : .failed(status)
        }
    }

    /// The outcome of a run in the app. Anything it broke decides first: a run that broke what depends on it is never
    /// "Fixed", whatever the package's own check says. Then what is installed, then how the command ended.
    /// `check`: who uses what changed beyond a patch ("whisperx"): a fixed outcome says to check them.
    public static func make(ending: FixEnding, before: Finding, recheck: Scanner.Recheck, homebrew: HomebrewAvailability?,
                            broke: String? = nil, check: String? = nil) -> FixOutcome {
        if let broke { return .broke(broke) }
        switch recheck {
        case let .fixed(now): return check.map { .fixedCheck(now: now, users: $0) } ?? .fixed(now: now)
        case .removed: return .removed
        case let .couldNotCheck(why): return ending.succeeded ? .couldNotCheck(why) : unfinished(ending, found: nil)
        case let .stillAffected(after):
            if ending.succeeded { return .stillAffected(reason(before: before, after: after, homebrew: homebrew)) }
            return unfinished(ending, found: found(before: before, after: after))
        case let .notChecked(after):
            return ending.succeeded ? .notChecked(found(before: before, after: after)) : unfinished(ending, found: found(before: before, after: after))
        }
    }

    static func unfinished(_ ending: FixEnding, found: String?) -> FixOutcome {
        switch ending {
        case let .exited(status): return .exitedWithError(status)
        case .stopped: return .stopped(found)
        case let .timedOut(minutes): return .timedOut(minutes: minutes)
        case .needsPassword: return .needsPassword
        case let .signalled(signal): return .killed(signal)
        case let .couldNotStart(why): return .couldNotStart(why)
        }
    }

    /// What is installed now: "still 1.30.2", "now Electron 42.11.16".
    public static func found(before: Finding, after: Finding) -> String {
        after.installedVersion == before.installedVersion ? "still \(before.installedLabel)" : "now \(after.installedLabel)"
    }

    /// Why it is still found: Homebrew did not have the fix; the version did not change; or it changed, not far enough.
    static func reason(before: Finding, after: Finding, homebrew: HomebrewAvailability?) -> String {
        if after.installedVersion == before.installedVersion {
            if case let .unavailable(why)? = homebrew { return why }
            if before.malicious { return "still installed; the command did not remove it" }
            return "still \(before.installedLabel); the command did not change it"
        }
        if let fixed = after.fixedVersion { return "now \(after.installedLabel); the fix is \(fixed)" }
        return "now \(after.installedLabel); no fixed release is known for what remains"
    }
}
