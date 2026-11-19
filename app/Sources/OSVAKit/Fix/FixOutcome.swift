import Foundation

/// How a fix ended, as its row says it.
public enum FixOutcome: Equatable, Sendable {
    /// Checked again: the version installed now has no finding.
    case fixed(now: String)
    /// Checked again: no longer installed (a removal, or an uninstall).
    case removed
    /// Checked again and still found; the reason the app knows.
    case stillAffected(String)
    /// The command ended with an error (its exit status), and the package is still found.
    case failed(Int32)
    /// The command ended without error, but the app could not check again.
    case couldNotCheck(String)
    /// Terminal did not open the script.
    case couldNotOpen(String)

    public var text: String {
        switch self {
        case let .fixed(now): return "Fixed — now \(now)"
        case .removed: return "Removed"
        case let .stillAffected(why): return "Still affected: \(why)"
        case .failed(129): return "The Terminal window was closed before the command finished"
        case .failed: return "The command failed — see the Terminal window"
        case let .couldNotCheck(why): return "The command ran, but the app could not check again: \(why)"
        case let .couldNotOpen(why): return "Could not open Terminal: \(why)"
        }
    }

    /// Whether the finding is gone.
    public var isResolved: Bool {
        switch self { case .fixed, .removed: return true; default: return false }
    }

    /// The outcome of a run that ended with `status`, from the re-check. What is installed decides first: a package
    /// that is fixed (or gone) is said to be, even if the command also reported an error. `homebrew` is Homebrew's
    /// answer read again after the run, for a `brew upgrade`.
    public static func make(status: Int32, before: Finding, recheck: Scanner.Recheck, homebrew: HomebrewAvailability?) -> FixOutcome {
        switch recheck {
        case let .fixed(now): return .fixed(now: now)
        case .removed: return .removed
        case let .couldNotCheck(why): return status == 0 ? .couldNotCheck(why) : .failed(status)
        case let .stillAffected(after):
            return status == 0 ? .stillAffected(reason(before: before, after: after, homebrew: homebrew)) : .failed(status)
        }
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
