import Foundation

/// The app's changelog, and the only one there is (the website has none): Resources/CHANGELOG.md, one entry per
/// version, newest first. The panel shows the newest entry once after an update (`WhatsNew`); Settings lists them all.
public struct Changelog: Sendable, Equatable {
    public struct Entry: Sendable, Equatable, Identifiable {
        /// "0.3.1".
        public var version: String
        /// Short, plain lines, one per bullet in the file.
        public var lines: [String]
        public var id: String { version }

        public init(version: String, lines: [String]) { self.version = version; self.lines = lines }
    }

    /// Newest first.
    public var entries: [Entry]

    public init(entries: [Entry] = []) { self.entries = entries }

    public func entry(for version: String) -> Entry? { entries.first { $0.version == version } }

    /// Every entry, newest first, whatever order they were given in: the list in Settings.
    public var newestFirst: [Entry] {
        entries.sorted { a, b in
            guard let x = Self.parts(a.version), let y = Self.parts(b.version) else { return false }
            return y.lexicographicallyPrecedes(x)
        }
    }

    /// "0.3.1" as [0, 3, 1]; nil for anything but major.minor.patch.
    static func parts(_ version: String) -> [Int]? {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty && $0.count <= 3 && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }) else {
            return nil
        }
        return parts.compactMap { Int($0) }
    }

    public enum Problem: Error, Equatable, CustomStringConvertible {
        case missing
        case noEntries
        case notAVersion(line: Int, String)
        case unexpected(line: Int, String)
        case noLines(String)
        case twice(String)
        case notNewestFirst(String, after: String)

        public var description: String {
            switch self {
            case .missing: return "CHANGELOG.md is not in the app's resources"
            case .noEntries: return "CHANGELOG.md has no `## major.minor.patch` entry"
            case let .notAVersion(line, text): return "line \(line): \"\(text)\" is not a `## major.minor.patch` heading"
            case let .unexpected(line, text): return "line \(line): \"\(text)\" is neither a `- ` line nor its indented continuation"
            case let .noLines(v): return "\(v) has no lines"
            case let .twice(v): return "\(v) has two entries"
            case let .notNewestFirst(v, after): return "\(v) comes after \(after); the newest goes first"
            }
        }
    }

    // MARK: Reading

    /// Reads CHANGELOG.md: whatever comes before the first `## ` heading is for whoever edits the file; then each
    /// `## major.minor.patch` and its `- ` lines. Anything else is refused rather than shown or dropped.
    public static func parse(_ text: String) throws -> Changelog {
        var entries: [Entry] = []
        var version: String?
        var body: [(number: Int, text: String)] = []
        func close() throws {
            guard let v = version else { return }
            let lines = try bullets(body)
            guard !lines.isEmpty else { throw Problem.noLines(v) }
            entries.append(Entry(version: v, lines: lines))
        }
        for (i, line) in text.components(separatedBy: "\n").enumerated() {
            if line.hasPrefix("#") && version != nil || line.hasPrefix("## ") {
                try close()
                let heading = line.hasPrefix("## ") ? String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces) : line
                guard parts(heading) != nil else { throw Problem.notAVersion(line: i + 1, line) }
                if entries.contains(where: { $0.version == heading }) { throw Problem.twice(heading) }
                if let last = entries.last, let a = parts(last.version), let b = parts(heading), !b.lexicographicallyPrecedes(a) {
                    throw Problem.notNewestFirst(heading, after: last.version)
                }
                version = heading
                body = []
            } else if version != nil {
                body.append((number: i + 1, text: line))
            }
        }
        try close()
        guard !entries.isEmpty else { throw Problem.noEntries }
        return Changelog(entries: entries)
    }

    /// The line with each “quoted name” kept on one line: its spaces become no-break spaces, so a wrapped line never
    /// breaks “Not checked against published ranges” after "Not". The file keeps plain spaces, as the release notes do.
    public static func quotesWhole(_ line: String) -> String {
        var quoted = false
        return String(line.map { c -> Character in
            if c == "“" { quoted = true } else if c == "”" { quoted = false }
            return quoted && c == " " ? "\u{00A0}" : c
        })
    }

    /// The `- ` lines of a Markdown list, each with its indented continuation lines joined on: an entry's lines, and
    /// what a release notes file holds.
    public static func bullets(_ text: String) throws -> [String] {
        try bullets(text.components(separatedBy: "\n").enumerated().map { (number: $0.offset + 1, text: $0.element) })
    }

    private static func bullets(_ lines: [(number: Int, text: String)]) throws -> [String] {
        var out: [String] = []
        for (number, raw) in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if raw.hasPrefix("- ") {
                out.append(String(line.dropFirst(2)).trimmingCharacters(in: .whitespaces))
            } else if raw.hasPrefix("  "), let last = out.popLast() {
                out.append(last + " " + line)
            } else {
                throw Problem.unexpected(line: number, raw)
            }
        }
        return out
    }

    // MARK: The bundled file

    /// The changelog the app carries; empty if it cannot be read (the panel then shows no card and Settings no list,
    /// and ChangelogTests fail).
    public static let bundled: Changelog = (try? load()) ?? Changelog()

    static func load() throws -> Changelog {
        guard let url = resourceURL else { throw Problem.missing }
        return try parse(String(contentsOf: url, encoding: .utf8))
    }

    /// SwiftPM's resource bundle for this target.
    static let bundleName = "OSVAMonitor_OSVAMonitorUI.bundle"

    /// Where CHANGELOG.md is: in this target's resource bundle, which is in the app's Contents/Resources (build-app.sh
    /// copies it there), beside a command-line tool (osva-render), or beside the test bundle. Looked for here rather
    /// than through SwiftPM's `Bundle.module`, which stops the app when it finds no bundle, and which some SwiftPM
    /// versions look for only next to the .app itself, where code signing does not allow one.
    static var resourceURL: URL? {
        let code = Bundle(for: BundleToken.self)
        let places = [Bundle.main.resourceURL, Bundle.main.bundleURL, code.resourceURL, code.bundleURL.deletingLastPathComponent()]
        for case let place? in places {
            let folder = place.appendingPathComponent(bundleName, isDirectory: true)
            let candidates = [Bundle(url: folder)?.url(forResource: "CHANGELOG", withExtension: "md"),
                              folder.appendingPathComponent("Contents/Resources/CHANGELOG.md"), folder.appendingPathComponent("CHANGELOG.md")]
            if let found = candidates.compactMap({ $0 }).first(where: { FileManager.default.fileExists(atPath: $0.path) }) { return found }
        }
        return nil
    }
}

private final class BundleToken {}

/// When the panel shows What's New: once after the app was updated, never on a first install.
///
/// The version whose notes the person last closed is kept in the user defaults (`lastSeenKey`). Versions before 0.3.1
/// kept none, so an update from one of them is told apart from a first install by what an earlier version left behind:
/// the version that made the last full scan (recorded since 0.2.1), or a saved scan or settings file (every version).
public enum WhatsNew {
    public static let lastSeenKey = "whatsNewLastSeenVersion"

    public enum Decision: Equatable, Sendable {
        /// Show this entry at the top of the panel until the person closes it.
        case show(Changelog.Entry)
        /// Nothing to show (a first install, or no entry for this version): remember the version, so that the next
        /// update is the one shown.
        case remember(String)
        case nothing
    }

    public static func decide(current: String, lastSeen: String?, ranBefore: Bool, changelog: Changelog) -> Decision {
        guard let now = Changelog.parts(current) else { return .nothing }              // a build with no version (swift run)
        if let lastSeen {
            // this version's notes were closed already, or a newer one's (the app went back a version)
            if let seen = Changelog.parts(lastSeen), !seen.lexicographicallyPrecedes(now) { return .nothing }
        } else if !ranBefore {
            return .remember(current)                                                   // a first install: nothing is new
        }
        guard let entry = changelog.entry(for: current) else { return .remember(current) }
        return .show(entry)
    }
}
