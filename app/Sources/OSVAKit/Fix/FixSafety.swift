import Foundation

/// What may go into a command the app offers to run.
///
/// Every name, version and path in a command is shell-quoted (`UpgradeCommand.quote`), and quoting alone keeps the
/// shell from reading any of them as code. These checks are a second, independent line, and they decide whether the
/// app offers to *run* a command at all:
///   - a version comes from the server, so it must look like a version and nothing else;
///   - a name comes from this Mac (a lockfile in a cloned repository is someone else's text), so it must look like a
///     package name: quoting keeps "-rf" one word, but the tool would still read it as an option;
///   - nothing in a command may hold a control character (a newline would at least make the displayed line lie).
/// Anything else gets no Fix button; the command can still be read and copied.
public enum FixSafety {
    private static let letters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    private static let digits = CharacterSet(charactersIn: "0123456789")
    private static let versionSeparators = CharacterSet(charactersIn: ".+-_~")
    private static let nameInner = CharacterSet(charactersIn: "._-/@+")

    /// A version from the server: 1 to 64 ASCII characters, runs of letters and digits joined by single `. + - _ ~`,
    /// starting and ending with a letter or digit, with at least one digit. "1.30.7", "10.6p2", "v0.33.0",
    /// "1.0.0-beta.1", "2.0.0+build.5", "2026-09-25". Not "-1", "1..2", "1.0;", "$(x)", "1 .0", "1.0\n".
    public static func isSafeVersion(_ v: String) -> Bool {
        let scalars = Array(v.unicodeScalars)
        guard (1...64).contains(scalars.count) else { return false }
        var afterSeparator = true                     // so a leading separator fails
        var hasDigit = false
        for s in scalars {
            if letters.contains(s) || digits.contains(s) {
                afterSeparator = false
                if digits.contains(s) { hasDigit = true }
            } else if versionSeparators.contains(s) {
                if afterSeparator { return false }
                afterSeparator = true
            } else {
                return false
            }
        }
        return !afterSeparator && hasDigit
    }

    /// A package, formula or cask name from this Mac: 1 to 214 ASCII characters (npm's limit), a letter, digit or
    /// "@" first (npm scopes), then letters, digits and `. _ - / @ +`. "lodash", "@types/node", "golang.org/x/net",
    /// "openssl@3", "libsigc++", "guzzlehttp/guzzle". Not "-rf", "--registry=x", "a b", "x;y", "$(x)", "a\nb".
    public static func isSafeName(_ n: String) -> Bool {
        let scalars = Array(n.unicodeScalars)
        guard (1...214).contains(scalars.count), let first = scalars.first,
              letters.contains(first) || digits.contains(first) || first == "@" else { return false }
        return scalars.allSatisfy { letters.contains($0) || digits.contains($0) || nameInner.contains($0) }
    }

    /// Text with no control characters (C0, DEL, C1, and the line and paragraph separators), at most 2,000 scalars.
    public static func isPrintable(_ s: String) -> Bool {
        s.unicodeScalars.count <= 2000 && !s.unicodeScalars.contains { c in
            c.value < 0x20 || (0x7F...0x9F).contains(c.value) || c.value == 0x2028 || c.value == 0x2029
        }
    }

    /// An absolute path with no control characters: where a tool or a project lives.
    public static func isSafePath(_ p: String) -> Bool { p.hasPrefix("/") && isPrintable(p) }
}
