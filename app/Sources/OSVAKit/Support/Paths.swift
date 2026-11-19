import Foundation

public enum Paths {
    /// ~/Library/Application Support/OSVA Monitor, unless `OSVA_SUPPORT_DIR` names another directory (tests, CLI).
    public static func supportDirectory(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        if let dir = environment["OSVA_SUPPORT_DIR"], !dir.isEmpty { return URL(fileURLWithPath: dir, isDirectory: true) }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("OSVA Monitor", isDirectory: true)
    }

    /// The path with every symbolic link resolved, as the kernel and FSEvents write it: "/var/x" is "/private/var/x".
    /// (NSString's and URL's resolvingSymlinksInPath drop a leading "/private" instead.)
    public static func realPath(_ path: String) -> String {
        guard let r = realpath(path, nil) else { return path }
        defer { free(r) }
        return String(cString: r)
    }

    /// `path` written under `root` as given, when the file system reported it under root's real path.
    public static func underGivenRoot(_ path: String, root: String) -> String {
        let real = realPath(root)
        guard real != root, path == real || path.hasPrefix(real + "/") else { return path }
        return root + path.dropFirst(real.count)
    }

    /// "/Users/ana/code/x" -> "~/code/x".
    public static func abbreviatingHome(_ path: String, home: String = NSHomeDirectory()) -> String {
        guard !home.isEmpty, path == home || path.hasPrefix(home + "/") else { return path }
        return "~" + path.dropFirst(home.count)
    }
}

/// Minimal wrapper over NSRegularExpression with JavaScript-like helpers, for the parsers ported from the site.
struct Regex: @unchecked Sendable {   // NSRegularExpression is immutable and thread-safe
    private let re: NSRegularExpression

    /// `multiline` makes ^ and $ match at line boundaries, like JavaScript's `m` flag.
    init(_ pattern: String, multiline: Bool = false) {
        // Patterns are literals in this module; a bad one is a programming error caught by the tests.
        re = try! NSRegularExpression(pattern: pattern, options: multiline ? [.anchorsMatchLines] : [])
    }

    func test(_ s: String) -> Bool {
        re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// Capture groups of the first match (index 0 is the whole match); nil if no match.
    func firstMatch(_ s: String) -> [String?]? {
        guard let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        return groups(m, in: s)
    }

    /// Capture groups of every match, like JavaScript's `matchAll` with the `g` flag.
    func allMatches(_ s: String) -> [[String?]] {
        re.matches(in: s, range: NSRange(s.startIndex..., in: s)).map { groups($0, in: s) }
    }

    /// Splits like JavaScript's `String.prototype.split(regex)` (without capture groups).
    func split(_ s: String) -> [String] {
        var parts: [String] = [], last = s.startIndex
        for m in re.matches(in: s, range: NSRange(s.startIndex..., in: s)) {
            guard let r = Range(m.range, in: s) else { continue }
            parts.append(String(s[last..<r.lowerBound])); last = r.upperBound
        }
        parts.append(String(s[last...]))
        return parts
    }

    func replacing(in s: String, with template: String) -> String {
        re.stringByReplacingMatches(in: s, range: NSRange(s.startIndex..., in: s), withTemplate: template)
    }

    private func groups(_ m: NSTextCheckingResult, in s: String) -> [String?] {
        (0..<m.numberOfRanges).map { i in Range(m.range(at: i), in: s).map { String(s[$0]) } }
    }
}
