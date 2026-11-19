import Darwin
import Foundation

// What else in a Python environment depends on a package, read from the installed distributions' own metadata, so an
// upgrade that would break one of them is never run (and one that did is never called fixed).
//
// 0.2.0 upgraded starlette to 1.10.0 in a Homebrew Python where fastapi 0.120.0 needs starlette < 0.49: pip warned
// and exited 0, the re-check saw starlette fixed, and the row said "Fixed". Now:
//   - before: every installed distribution's Requires-Dist is checked against the version the fix installs (and, when
//     pip's dry run names them, every other version it would install); one that excludes it withholds the button;
//   - after: the environment's own `pip check` runs again, and any conflict it did not have before makes the outcome
//     "Updated, but it broke …", with an Undo that puts back the exact versions that changed.

/// One installed distribution, as its metadata folder says. A finding is a file: this is one folder, and the same
/// project can have others further down sys.path (shadowed) or beside it (stale records).
public struct PythonDistribution: Hashable, Sendable {
    public var name: String
    public var version: String
    /// Its Requires-Dist lines, as written.
    public var requires: [String]
    /// Its metadata folder (".../site-packages/starlette-0.48.0.dist-info"); "" when made in code.
    public var path: String
    /// It has a REQUESTED file: some pip command named it. Evidence, not the person's intent: pip marks every name
    /// on its command line, the app's own fixes and undos included.
    public var requested: Bool
    /// Installed editable (direct_url.json): a project someone works on.
    public var editable: Bool

    public init(name: String, version: String, requires: [String], path: String = "", requested: Bool = false, editable: Bool = false) {
        self.name = name; self.version = version; self.requires = requires; self.path = path; self.requested = requested; self.editable = editable
    }

    /// PEP 503's normal form: lowercase, runs of `-_.` as one "-".
    public var key: String { PythonNames.normal(name) }

    /// The folder on sys.path it is in.
    public var folder: String { (path as NSString).deletingLastPathComponent }

    /// The extras its requirements name (`extra == "dev"`).
    public var extras: Set<String> {
        Set(requires.compactMap { PythonRequirement($0)?.marker }.flatMap(PythonMarker.extrasNamed))
    }
}

public enum PythonNames {
    public static func normal(_ name: String) -> String { PackageNames.indexName(name, in: .pypi) }
}

/// One version specifier of a requirement: `< 0.49.0`, `~= 2.2`, `== 1.4.*`.
///
/// Versions are ordered by the verified core alone (`Core.compareVersions`); what is done here is only PEP 440's
/// reading of each operator in terms of that order: release numbers padded with zeros to the same length before a
/// comparison ("0.49" is "0.49.0"), `== X.*` as "from X.dev0, below the next X", `~= X.Y` as ">= X.Y, == X.*".
/// What the app cannot read (an epoch, a non-numeric prefix) gives no answer, which the callers treat as a conflict.
public struct PythonSpecifier: Hashable, Sendable {
    public enum Op: String, Sendable, CaseIterable {
        case arbitrary = "===", compatible = "~=", equal = "==", notEqual = "!=", lessEqual = "<=", greaterEqual = ">=", less = "<", greater = ">"
    }

    public var op: Op
    public var version: String

    public init(op: Op, version: String) { self.op = op; self.version = version }

    /// "<0.49.0", " >= 0.40 ".
    public init?(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard let op = Op.allCases.first(where: { t.hasPrefix($0.rawValue) }) else { return nil }   // longest operators first
        let v = t.dropFirst(op.rawValue.count).trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty, !v.contains(" ") else { return nil }
        self.op = op; self.version = v
    }

    /// "< 0.49.0".
    public var display: String { "\(op.rawValue) \(version)" }

    /// Whether `candidate` satisfies it; nil when the app cannot tell.
    public func admits(_ candidate: String) -> Bool? {
        let v = Self.plain(candidate), s = Self.plain(version)
        guard Self.readable(v) else { return nil }
        if op == .arbitrary { return candidate.trimmingCharacters(in: .whitespaces).lowercased() == version.lowercased() }
        if s.hasSuffix(".*") {
            guard op == .equal || op == .notEqual, let matches = Self.prefixMatch(v, String(s.dropLast(2))) else { return nil }
            return op == .equal ? matches : !matches
        }
        guard Self.readable(s) else { return nil }
        let c = Self.compare(v, s)
        switch op {
        case .equal: return c == 0
        case .notEqual: return c != 0
        case .less: return c < 0
        case .lessEqual: return c <= 0
        case .greater: return c > 0
        case .greaterEqual: return c >= 0
        case .compatible:
            let release = Self.release(s)
            guard release.count >= 2 else { return nil }
            guard let inSeries = Self.prefixMatch(v, release.dropLast().map(String.init).joined(separator: ".")) else { return nil }
            return c >= 0 && inSeries
        case .arbitrary: return nil
        }
    }

    /// Whether two versions are the same release, as PEP 440 orders them ("2.8" is "2.8.0"); false when either cannot be
    /// read.
    public static func same(_ a: String, _ b: String) -> Bool {
        let (x, y) = (plain(a), plain(b))
        return readable(x) && readable(y) && compare(x, y) == 0
    }

    /// Lowercase, without a leading "v", spaces or local version ("+…" is dropped: PEP 440 ignores it in specifiers).
    static func plain(_ v: String) -> String {
        var s = v.trimmingCharacters(in: .whitespaces).lowercased()
        if let plus = s.firstIndex(of: "+") { s = String(s[..<plus]) }
        if s.hasPrefix("v") { s.removeFirst() }
        return s
    }

    /// A version the app reads: starts with a digit, no epoch ("1!2.0"), only letters, digits and `. - _`.
    static func readable(_ v: String) -> Bool {
        guard let f = v.unicodeScalars.first, ("0"..."9").contains(f) else { return false }
        return v.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || ".-_".unicodeScalars.contains($0)) }
    }

    /// The leading release numbers: "1.2.3rc1" is [1, 2, 3].
    static func release(_ v: String) -> [Substring] {
        var parts: [Substring] = []
        for part in v.split(separator: ".", omittingEmptySubsequences: false) {
            let digits = part.prefix { $0.isASCII && $0.isNumber }
            guard !digits.isEmpty else { break }
            parts.append(digits)
            if digits.count != part.count { break }
        }
        return parts
    }

    /// Both versions with their release numbers padded with ".0" to the same length, compared by the core.
    static func compare(_ a: String, _ b: String) -> Int {
        let (ra, rb) = (release(a).count, release(b).count)
        func pad(_ v: String, _ have: Int, _ want: Int) -> String {
            guard want > have else { return v }
            let zeros = String(repeating: ".0", count: want - have)
            let releaseEnd = v.index(v.startIndex, offsetBy: release(v).map(\.count).reduce(0, +) + max(have - 1, 0))
            return v[..<releaseEnd] + zeros + v[releaseEnd...]
        }
        return Core.shared.compareVersions(pad(a, ra, rb), pad(b, rb, ra))
    }

    /// Whether `v` is in the series `prefix.*` ("1.4" takes 1.4, 1.4.0, 1.4.9, 1.4rc1, 1.4.post1; not 1.40 or 1.5):
    /// from prefix.dev0 (the first thing PEP 440 puts in it) to below the next prefix's .dev0.
    static func prefixMatch(_ v: String, _ prefix: String) -> Bool? {
        let numbers = prefix.split(separator: ".", omittingEmptySubsequences: false)
        guard !numbers.isEmpty, numbers.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              let last = Int(numbers.last!) else { return nil }
        let next = (numbers.dropLast().map(String.init) + [String(last + 1)]).joined(separator: ".")
        return compare(v, prefix + ".dev0") >= 0 && compare(v, next + ".dev0") < 0
    }
}

/// A Requires-Dist line: "starlette<0.49.0,>=0.40.0", "uvicorn[standard] (>=0.12.0) ; extra == 'all'",
/// "httpx @ https://…".
public struct PythonRequirement: Hashable, Sendable {
    public var name: String
    /// The extras it asks of the package ("standard" in `uvicorn[standard]`).
    public var extras: Set<String> = []
    public var specifiers: [PythonSpecifier]
    public var marker: String?
    /// A direct reference ("name @ url"): the app cannot tell which versions it takes.
    public var url: Bool
    /// Some part of it the app could not read: treated as excluding any change.
    public var unreadable: Bool

    public var key: String { PythonNames.normal(name) }

    public init?(_ line: String) {
        var body = Substring(line), marker: String?
        if let semi = line.firstIndex(of: ";") {
            body = line[..<semi]
            marker = line[line.index(after: semi)...].trimmingCharacters(in: .whitespaces)
        }
        let scalars = body.unicodeScalars
        let nameEnd = scalars.firstIndex { !(CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0)) } ?? scalars.endIndex
        let name = String(scalars[..<nameEnd]).trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return nil }
        var rest = String(scalars[nameEnd...]).trimmingCharacters(in: .whitespaces)
        var extras = Set<String>()
        if rest.hasPrefix("[") {                                                   // extras the dependent asks for
            guard let close = rest.firstIndex(of: "]") else { return nil }
            extras = Set(rest[rest.index(after: rest.startIndex)..<close].split(separator: ",")
                .map { PythonNames.normal($0.trimmingCharacters(in: .whitespaces)) }.filter { !$0.isEmpty })
            rest = String(rest[rest.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        }
        self.name = name; self.extras = extras; self.marker = marker; self.url = false; self.unreadable = false; self.specifiers = []
        if rest.hasPrefix("@") { url = true; return }
        if rest.hasPrefix("(") && rest.hasSuffix(")") { rest = String(rest.dropFirst().dropLast()) }
        for part in rest.split(separator: ",") where !part.trimmingCharacters(in: .whitespaces).isEmpty {
            if let s = PythonSpecifier(String(part)) { specifiers.append(s) } else { unreadable = true }
        }
    }

    /// The specifiers `version` fails (or the app cannot check), shown as what the dependent needs: "< 0.49.0".
    /// Empty when it takes `version`.
    public func refuses(_ version: String) -> [String] {
        if url { return ["from a direct URL"] }
        if unreadable { return ["a version the app cannot read"] }
        return specifiers.filter { $0.admits(version) != true }.map(\.display)
    }
}

/// PEP 508 environment markers, evaluated for this interpreter and platform, with the extras that are active for the
/// distribution whose requirement it is (`PythonSite.activeExtras`): a requirement behind an extra nobody asked for does
/// not count, one behind an active extra does. Nil when the app cannot read the marker; the callers then treat the
/// requirement as applying.
public enum PythonMarker {
    public static func evaluate(_ marker: String, environment env: [String: String], extras: Set<String> = []) -> Bool? {
        var p = Parser(tokens: tokenize(marker), env: env, extras: extras)
        guard let tokens = p.tokens, let value = p.or(), p.at == tokens.count else { return nil }
        return value
    }

    /// The extras a marker names (`extra == "dev"` is "dev").
    public static func extrasNamed(_ marker: String) -> [String] {
        guard let tokens = tokenize(marker) else { return [] }
        var out: [String] = []
        for (i, t) in tokens.enumerated() where t == .word("extra") {
            for j in [i + 2, i - 2] where j >= 0 && j < tokens.count {
                if case let .string(s) = tokens[j] { out.append(PythonNames.normal(s)) }
            }
        }
        return out
    }

    enum Token: Equatable { case word(String), string(String), op(String), open, close }

    static func tokenize(_ s: String) -> [Token]? {
        var out: [Token] = [], i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c.isWhitespace { i = s.index(after: i); continue }
            if c == "(" { out.append(.open); i = s.index(after: i); continue }
            if c == ")" { out.append(.close); i = s.index(after: i); continue }
            if c == "'" || c == "\"" {
                guard let end = s[s.index(after: i)...].firstIndex(of: c) else { return nil }
                out.append(.string(String(s[s.index(after: i)..<end]))); i = s.index(after: end); continue
            }
            if "<>=!~".contains(c) {
                var j = i
                while j < s.endIndex, "<>=!~".contains(s[j]) { j = s.index(after: j) }
                out.append(.op(String(s[i..<j]))); i = j; continue
            }
            var j = i
            while j < s.endIndex, s[j].isLetter || s[j].isNumber || s[j] == "_" || s[j] == "." { j = s.index(after: j) }
            guard j > i else { return nil }
            out.append(.word(String(s[i..<j]))); i = j
        }
        return out
    }

    struct Parser {
        var tokens: [Token]?
        var env: [String: String]
        var extras: Set<String>
        var at = 0
        init(tokens: [Token]?, env: [String: String], extras: Set<String>) { self.tokens = tokens; self.env = env; self.extras = extras }

        mutating func next() -> Token? { guard let t = tokens, at < t.count else { return nil }; defer { at += 1 }; return t[at] }
        func peek() -> Token? { guard let t = tokens, at < t.count else { return nil }; return t[at] }

        mutating func or() -> Bool? {
            guard var v = and() else { return nil }
            while peek() == .word("or") { at += 1; guard let r = and() else { return nil }; v = v || r }
            return v
        }

        mutating func and() -> Bool? {
            guard var v = atom() else { return nil }
            while peek() == .word("and") { at += 1; guard let r = atom() else { return nil }; v = v && r }
            return v
        }

        mutating func atom() -> Bool? {
            if peek() == .open {
                at += 1
                guard let v = or(), next() == .close else { return nil }
                return v
            }
            guard let (lhs, lhsName) = value() else { return nil }
            var op: String
            switch next() {
            case let .op(o)?: op = o
            case .word("in")?: op = "in"
            case .word("not")?: guard next() == .word("in") else { return nil }; op = "not in"
            default: return nil
            }
            guard let (rhs, rhsName) = value() else { return nil }
            let variable = lhsName ?? rhsName
            if variable == "extra" {
                let named = PythonNames.normal(lhsName == "extra" ? rhs : lhs)
                return op == "==" ? extras.contains(named) : op == "!=" ? !extras.contains(named) : nil
            }
            switch op {
            case "in": return rhs.contains(lhs)
            case "not in": return !rhs.contains(lhs)
            default:
                let versionLike = ["python_version", "python_full_version", "implementation_version", "platform_release"].contains(variable ?? "")
                if versionLike || op == "~=" {
                    // the variable's value against the literal, as a version specifier
                    let (v, spec) = lhsName != nil ? (lhs, rhs) : (rhs, lhs)
                    let flipped: String = lhsName != nil ? op : [">": "<", "<": ">", ">=": "<=", "<=": ">="][op] ?? op
                    return PythonSpecifier(flipped + spec)?.admits(v)
                }
                switch op {
                case "==", "===": return lhs == rhs
                case "!=": return lhs != rhs
                default: return nil
                }
            }
        }

        /// A literal, or a variable's value (and its name).
        mutating func value() -> (String, String?)? {
            switch next() {
            case let .string(s)?: return (s, nil)
            case let .word(w)?:
                if w == "extra" { return ("", "extra") }
                guard let v = env[w] else { return nil }
                return (v, w)
            default: return nil
            }
        }
    }
}

/// A requirement one installed distribution has that a change would break.
public struct DependencyConflict: Hashable, Sendable {
    public var dependent: String
    public var dependentVersion: String
    public var package: String
    /// What the dependent needs, as its specifiers say: "< 0.49.0", or ">= 2, < 3".
    public var needs: String
    /// It pins the package (`==`, `~=` on a patch series): they move together, in one command, or not at all.
    public var exact: Bool = false

    /// "fastapi 0.120.0 needs starlette < 0.49.0".
    public var line: String { "\(dependent) \(dependentVersion) needs \(package) \(needs)" }
}

/// The distributions of one Python, read from the folders on its sys.path, and the values its markers are read with.
public struct PythonSite: Equatable, Sendable {
    /// The live copy of each project: the first on sys.path, which is the one Python imports.
    public var distributions: [PythonDistribution]
    public var markers: [String: String]
    /// Every metadata folder found, live or not, in sys.path order.
    public var copies: [PythonDistribution]

    public init(distributions: [PythonDistribution], markers: [String: String], copies: [PythonDistribution]? = nil) {
        self.distributions = distributions; self.markers = markers; self.copies = copies ?? distributions
    }

    /// Read from these folders (sys.path order).
    public init(folders: [String], markers: [String: String]) {
        let all = Self.scan(folders: folders)
        var seen = Set<String>()
        self.init(distributions: all.filter { seen.insert($0.key).inserted }, markers: markers, copies: all)
    }

    /// The live copy of a project, if it is installed.
    public func live(_ name: String) -> PythonDistribution? { distributions.first { $0.key == PythonNames.normal(name) } }

    /// More than one metadata folder for the project in one folder: stale records of an earlier install, not a second
    /// copy. Their RECORDs list the same files, so `pip uninstall` of either deletes the live code. The folders.
    public func staleRecords(_ name: String) -> [String] {
        let key = PythonNames.normal(name)
        let byFolder = Dictionary(grouping: copies.filter { $0.key == key }, by: \.folder)
        return byFolder.filter { $0.value.count > 1 }.keys.sorted()
    }

    /// The extras in use, by project: those some installed distribution asks for (`uvicorn[standard]`), under the
    /// extras active for it in turn, and every extra of an editable project (a developer installs those with their
    /// `[dev]`, which leaves no trace). A requirement behind an active extra gates an upgrade like any other.
    public func activeExtras() -> [String: Set<String>] {
        var active: [String: Set<String>] = [:]
        for d in distributions where d.editable { active[d.key] = d.extras }
        var changed = true
        while changed {
            changed = false
            for d in distributions {
                for line in d.requires {
                    guard let r = PythonRequirement(line), !r.extras.isEmpty else { continue }
                    if let m = r.marker, PythonMarker.evaluate(m, environment: markers, extras: active[d.key] ?? []) == false { continue }
                    let before = active[r.key, default: []]
                    let after = before.union(r.extras)
                    if after != before { active[r.key] = after; changed = true }
                }
            }
        }
        return active
    }

    /// Each distribution's version, by normal name.
    public var versions: [String: String] { Dictionary(distributions.map { ($0.key, $0.version) }, uniquingKeysWith: { a, _ in a }) }

    /// The installed distributions that would no longer have what they require if the packages in `changes`
    /// (normal name → new version) were at those versions. Distributions in `changes` themselves are not asked:
    /// their new releases bring their own requirements, which pip resolves.
    public func conflicts(_ changes: [String: String]) -> [DependencyConflict] {
        var out: [DependencyConflict] = []
        let extras = activeExtras()
        for d in distributions where changes[d.key] == nil {
            for line in d.requires {
                guard let r = PythonRequirement(line), let new = changes[r.key] else { continue }
                if let m = r.marker, PythonMarker.evaluate(m, environment: markers, extras: extras[d.key] ?? []) == false { continue }
                let refused = r.refuses(new)
                if !refused.isEmpty {
                    let name = distributions.first { $0.key == r.key }?.name ?? r.name
                    out.append(DependencyConflict(dependent: d.name, dependentVersion: d.version, package: name, needs: refused.joined(separator: ", "),
                                                  exact: r.specifiers.contains { $0.op == .equal || $0.op == .arbitrary || ($0.op == .compatible && Self.patchLevel($0.version)) }))
                }
            }
        }
        return out.sorted { ($0.dependent.lowercased(), $0.package) < ($1.dependent.lowercased(), $1.package) }
    }

    /// `~= 2.2.1` (three release numbers or more) pins a patch series: a lockstep pin, like `==`.
    static func patchLevel(_ v: String) -> Bool { PythonSpecifier.release(PythonSpecifier.plain(v)).count >= 3 }

    // MARK: Reading

    /// Every distribution in these folders, the first of each name winning (sys.path order is import order):
    /// `*.dist-info/METADATA`, and the older `*.egg-info/PKG-INFO` with its `requires.txt`.
    public static func read(folders: [String]) -> [PythonDistribution] {
        var seen = Set<String>()
        return scan(folders: folders).filter { seen.insert($0.key).inserted }
    }

    /// Every metadata folder in these folders, in order, with where it is, whether pip marked it REQUESTED, and
    /// whether it is an editable install.
    public static func scan(folders: [String]) -> [PythonDistribution] {
        var out: [PythonDistribution] = []
        let fm = FileManager.default
        for folder in folders {
            for entry in ((try? fm.contentsOfDirectory(atPath: folder)) ?? []).sorted() {
                let dir = (folder as NSString).appendingPathComponent(entry)
                var d: PythonDistribution?
                if entry.hasSuffix(".dist-info") {
                    d = readText((dir as NSString).appendingPathComponent("METADATA")).flatMap(parseMetadata)
                    d?.requested = fm.fileExists(atPath: (dir as NSString).appendingPathComponent("REQUESTED"))
                    if let direct = readText((dir as NSString).appendingPathComponent("direct_url.json")).map({ Data($0.utf8) }),
                       let json = try? JSONSerialization.jsonObject(with: direct) as? [String: Any],
                       (json["dir_info"] as? [String: Any])?["editable"] as? Bool == true {
                        d?.editable = true
                    }
                } else if entry.hasSuffix(".egg-info") {
                    d = readText((dir as NSString).appendingPathComponent("PKG-INFO")).flatMap(parseMetadata)
                    if d != nil, let reqs = readText((dir as NSString).appendingPathComponent("requires.txt")) {
                        d!.requires += parseRequiresTxt(reqs)
                    }
                }
                if var d { d.path = dir; out.append(d) }
            }
        }
        return out
    }

    /// Removes the REQUESTED marks pip left on these projects' live copies, so the app's own command does not read
    /// later as the person having asked for them. Only a regular file named REQUESTED, of this user's, inside a
    /// `*.dist-info` folder the site was read from. The projects whose mark it removed.
    @discardableResult
    public func clearRequested(_ keys: Set<String>) -> [String] {
        var cleared: [String] = []
        for d in distributions where keys.contains(d.key) && d.requested && d.path.hasSuffix(".dist-info") {
            let file = (d.path as NSString).appendingPathComponent("REQUESTED")
            var st = stat()
            guard lstat(file, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid() else { continue }
            if unlink(file) == 0 { cleared.append(d.name) }
        }
        return cleared
    }

    /// At most the first 512 KB: the headers come first, the long description after them.
    static func readText(_ path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        guard let data = try? h.read(upToCount: 512 * 1024) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// The Name, Version and Requires-Dist headers of a METADATA or PKG-INFO file (RFC 822 style, up to the first
    /// blank line; continuation lines are joined).
    public static func parseMetadata(_ text: String) -> PythonDistribution? {
        var name: String?, version: String?, requires: [String] = []
        var headers: [(String, String)] = []
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            if raw.isEmpty { break }
            if let f = raw.first, f == " " || f == "\t", !headers.isEmpty {
                headers[headers.count - 1].1 += " " + raw.trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = raw.firstIndex(of: ":") else { continue }
            headers.append((String(raw[..<colon]), raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)))
        }
        for (key, value) in headers {
            switch key.lowercased() {
            case "name": name = value
            case "version": version = value
            case "requires-dist": requires.append(value)
            default: break
            }
        }
        guard let name, let version, !name.isEmpty, !version.isEmpty else { return nil }
        return PythonDistribution(name: name, version: version, requires: requires)
    }

    /// An egg-info `requires.txt`: requirements, then `[extra]`, `[extra:marker]` or `[:marker]` sections. Extras are
    /// left out (as `pip check` leaves them out); a `[:marker]` section's lines get its marker.
    static func parseRequiresTxt(_ text: String) -> [String] {
        var out: [String] = [], marker: String?, inExtra = false
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let section = line.dropFirst().dropLast()
                let parts = section.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
                inExtra = !(parts.first?.isEmpty ?? true)
                marker = parts.count == 2 ? String(parts[1]) : nil
                continue
            }
            if inExtra { continue }
            out.append(marker.map { "\(line); \($0)" } ?? line)
        }
        return out
    }

    /// Prints the interpreter's sys.path (its absolute entries) and the values of PEP 508's marker variables, as JSON.
    /// A fixed text: nothing from a finding or a report is ever put in it.
    static let script = """
    import json, os, platform, sys
    print(json.dumps({"path": [p for p in sys.path if p and os.path.isabs(p) and os.path.isdir(p)], "markers": {
        "python_version": ".".join(platform.python_version_tuple()[:2]), "python_full_version": platform.python_version(),
        "os_name": os.name, "sys_platform": sys.platform, "platform_machine": platform.machine(),
        "platform_system": platform.system(), "platform_release": platform.release(),
        "platform_python_implementation": platform.python_implementation(), "implementation_name": sys.implementation.name}}))
    """

    /// Reads one interpreter's distributions now. Nil, with why, if the interpreter does not answer.
    public static func read(python: String, tools: ToolEnvironment) async -> Result<PythonSite, PythonSiteError> {
        do {
            let r = try await tools.run(python, ["-c", script], timeout: 30)
            guard r.status == 0, let json = try? JSONSerialization.jsonObject(with: r.stdout) as? [String: Any],
                  let path = json["path"] as? [String] else {
                return .failure(PythonSiteError(message: r.errorText.isEmpty ? "python exited with \(r.status)" : String(r.errorText.prefix(160))))
            }
            let markers = (json["markers"] as? [String: String]) ?? [:]
            return .success(PythonSite(folders: path, markers: markers))
        } catch {
            return .failure(PythonSiteError(message: error.localizedDescription))
        }
    }
}

public struct PythonSiteError: Error, Equatable, Sendable { public var message: String }

/// `pip check`: what the environment itself says is broken.
public enum PipCheck {
    /// The problems it lists, one line each, as pip wrote them ("fastapi 0.120.0 has requirement starlette<0.49.0,>=0.40.0,
    /// but you have starlette 1.10.0."). "No broken requirements found." is none.
    public static func problems(_ output: String) -> Set<String> {
        Set(output.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("No broken requirements") && !$0.lowercased().hasPrefix("warning") })
    }

    /// The distribution a problem line is about: "fastapi 0.120.0".
    public static func subject(_ line: String) -> String {
        line.split(separator: " ").prefix(2).joined(separator: " ")
    }

    /// Runs `python -m pip check`. Nil if pip did not answer (pip exits 1 when it finds problems, which is an answer).
    public static func run(python: String, tools: ToolEnvironment) async -> Set<String>? {
        guard let r = try? await tools.run(python, ["-m", "pip", "check", "--disable-pip-version-check"], timeout: 120),
              r.status == 0 || r.status == 1 else { return nil }
        return problems(String(decoding: r.stdout, as: UTF8.self))
    }
}

/// Puts back what a pip run changed: the exact earlier version of every distribution whose version changed, with
/// `--no-deps`, so pip resolves nothing and changes nothing else.
public struct PipUndo: Hashable, Sendable {
    public var invocation: FixInvocation
    /// "starlette 0.48.0", one per distribution put back.
    public var restores: [String]

    /// The projects it puts back that were not marked REQUESTED before the fix: their marks are removed afterwards.
    public var unmarked: Set<String> = []

    public init(invocation: FixInvocation, restores: [String], unmarked: Set<String> = []) {
        self.invocation = invocation; self.restores = restores; self.unmarked = unmarked
    }

    /// The undo, or nil if nothing changed or a name or version is not one the app puts in a command (`FixSafety`).
    public static func make(python: String, user: Bool, before: PythonSite, after: PythonSite) -> PipUndo? {
        let now = after.versions
        let changed = before.distributions.filter { now[$0.key] != nil && now[$0.key] != $0.version }
            .sorted { $0.key < $1.key }
        guard !changed.isEmpty, changed.allSatisfy({ FixSafety.isSafeName($0.name) && FixSafety.isSafeVersion($0.version) }) else { return nil }
        let args = ["-m", "pip", "install", "--no-deps", "--disable-pip-version-check"] + (user ? ["--user"] : [])
            + changed.map { "\($0.name)==\($0.version)" }
        return PipUndo(invocation: FixInvocation(executable: python, arguments: args), restores: changed.map { "\($0.name) \($0.version)" },
                       unmarked: Set(changed.filter { !$0.requested }.map(\.key)))
    }

    /// The command, as a person would type it.
    public var command: String { invocation.argv.map(UpgradeCommand.quote).joined(separator: " ") }
}

/// The checks around a pip upgrade, before and after it runs.
public struct PipGuard: Sendable {
    let tools: ToolEnvironment
    public init(tools: ToolEnvironment) { self.tools = tools }

    /// What a check before the run found.
    public enum Verdict: Equatable, Sendable {
        /// Nothing installed excludes the new versions: the site as it is now.
        case clear(PythonSite)
        /// Only packages that pin it exactly (torchaudio's `torch==`, OpenTelemetry's sdk and api) stand in the way:
        /// they move with it, in one pinned command, which pip's dry run works out at the review.
        case companions([String], PythonSite)
        /// It may not run: the line to show ("fastapi 0.120.0 needs starlette < 0.49.0 — update fastapi first").
        case blocked(String, [DependencyConflict])
        /// The interpreter did not answer, so nothing was checked: not run ("could not read what depends on starlette").
        case unknown(String)
    }

    /// Whether `pip.name` may go to `pip.target` (and, when pip's dry run named them, the other packages to the
    /// versions in `also`) without leaving an installed package without what it requires.
    public func check(_ pip: FixPlan.Pip, also: [String: String] = [:]) async -> Verdict {
        switch await PythonSite.read(python: pip.python, tools: tools) {
        case let .failure(e):
            return .unknown("could not read what depends on \(pip.name) (\(e.message))")
        case let .success(site):
            return Self.verdict(site, pip: pip, also: also)
        }
    }

    /// In order: which file the finding is (rules of identity), then what depends on it (every installed dependent's
    /// specifier, extras in use included), then whether what stands in the way can move with it.
    public static func verdict(_ site: PythonSite, pip: FixPlan.Pip, also: [String: String] = [:]) -> Verdict {
        // A finding is a file: the copy Python loads, once, in one folder.
        if let folder = site.staleRecords(pip.name).first {
            return .blocked("\(pip.name) has two records in \(Paths.abbreviatingHome(folder)): stale metadata, not a second copy. "
                            + "Remove the old record by hand; pip would delete the live files", [])
        }
        guard let live = site.live(pip.name) else { return .blocked("\(pip.name) is not installed in this Python any more", []) }
        if !pip.installed.isEmpty, PythonSpecifier.readable(PythonSpecifier.plain(live.version)), PythonSpecifier.readable(PythonSpecifier.plain(pip.installed)),
           PythonSpecifier.compare(PythonSpecifier.plain(live.version), PythonSpecifier.plain(pip.installed)) != 0 {
            return .blocked("Python loads \(live.name) \(live.version) from \(Paths.abbreviatingHome(live.folder)), not this \(pip.installed)", [])
        }
        var changes = also
        changes[PythonNames.normal(pip.name)] = pip.target
        let conflicts = site.conflicts(changes)
        // they pin it exactly: they can move with it, in one pinned command (only before the dry run names their versions)
        let companions = also.isEmpty ? conflicts.filter(\.exact) : []
        let blocking = conflicts.filter { c in !companions.contains(c) }
        if let first = blocking.first {
            let dependents = Array(Set(blocking.map(\.dependent))).sorted()
            let line = dependents.count == 1
                ? "\(first.line) — \(route(first.dependent, site: site, package: pip.name))"
                : "\(first.line), and \(dependents.count - 1) more — update them first"
            return .blocked(line, blocking)
        }
        // rule 4.5: a release known to remove what others use, while something installed uses the package
        let moving = Set(changes.keys).union(companions.map { PythonNames.normal($0.dependent) })
        for (key, target) in changes.sorted(by: { $0.key < $1.key }) {
            guard let now = site.live(key), let boundary = RuntimeBoundaries.crossed(key, from: now.version, to: target, in: site) else { continue }
            if let user = users(of: [key], in: site, except: moving).first {
                return .blocked("\(now.name) \(boundary.version) \(boundary.change) — \(user.name) \(user.version) may rely on it", [])
            }
        }
        if !companions.isEmpty { return .companions(Array(Set(companions.map(\.dependent))).sorted(), site) }
        return .clear(site)
    }

    /// The installed distributions that depend on any of `packages` (markers and extras in use counted), other than
    /// those in `except`: who to check after an upgrade that changes more than a patch.
    public static func users(of packages: Set<String>, in site: PythonSite, except: Set<String> = []) -> [PythonDistribution] {
        let extras = site.activeExtras()
        return site.distributions.filter { d in
            !packages.contains(d.key) && !except.contains(d.key) && d.requires.contains { line in
                guard let r = PythonRequirement(line), packages.contains(r.key) else { return false }
                return r.marker.map { PythonMarker.evaluate($0, environment: site.markers, extras: extras[d.key] ?? []) != false } ?? true
            }
        }.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    /// Whether `from` to `to` changes more than the patch number (the first two release numbers differ).
    public static func beyondPatch(from: String, to: String) -> Bool {
        let a = PythonSpecifier.release(PythonSpecifier.plain(from)).prefix(2).compactMap { Int($0) }
        let b = PythonSpecifier.release(PythonSpecifier.plain(to)).prefix(2).compactMap { Int($0) }
        return a.count < 2 || b.count < 2 || a != b
    }

    /// "whisperx", "whisperx and pyannote.audio", "whisperx and 2 more": who to check, for one short line.
    public static func usersLine(_ names: [String]) -> String? {
        guard let first = names.first else { return nil }
        switch names.count {
        case 1: return first
        case 2: return "\(first) and \(names[1])"
        default: return "\(first) and \(names.count - 1) more"
        }
    }

    /// What to do about one package that stands in the way, as far as the installed metadata tells: nothing needs it
    /// (remove it), it is the person's own project (change its range there), or update it.
    static func route(_ blocker: String, site: PythonSite, package: String) -> String {
        guard let b = site.live(blocker) else { return "update \(blocker) first" }
        if b.editable { return "it is a project installed for development: raise its \(package) range there" }
        let extras = site.activeExtras()
        let needed = site.distributions.contains { d in
            d.key != b.key && d.requires.contains { line in
                guard let r = PythonRequirement(line), r.key == b.key else { return false }
                return r.marker.map { PythonMarker.evaluate($0, environment: site.markers, extras: extras[d.key] ?? []) != false } ?? true
            }
        }
        if !needed && !b.requested { return "nothing installed needs \(b.name): removing it would clear the way" }
        return "update \(b.name) first"
    }

    /// What `pip check` says, before or after a run.
    public func problems(_ pip: FixPlan.Pip) async -> Set<String>? { await PipCheck.run(python: pip.python, tools: tools) }

    /// What a check after the run found.
    public struct After: Equatable, Sendable {
        /// The packages a new `pip check` problem is about ("fastapi 0.120.0 and 1 more"); nil when there is none.
        public var broke: String?
        /// Puts back what changed, when something did.
        public var undo: PipUndo?
        /// Why the app could not check, if it could not.
        public var uncheckable: String?
        /// The REQUESTED marks pip left that were not there before, removed.
        public var unmarked: [String] = []
    }

    /// Compares the environment with how it was before the run: new `pip check` problems, and an undo of every
    /// version that changed. pip marked every name on the command line REQUESTED; the marks that were not there before
    /// are removed, so a later look does not take the app's command for the person's wish.
    public func after(_ pip: FixPlan.Pip, before: PythonSite, problemsBefore: Set<String>) async -> After {
        let site = await PythonSite.read(python: pip.python, tools: tools)
        let problems = await self.problems(pip)
        var out = After()
        if case let .success(now) = site {
            out.undo = PipUndo.make(python: pip.python, user: pip.user, before: before, after: now)
            out.unmarked = now.clearRequested(Self.marksToClear(before: before, after: now))
        }
        guard let problems else {
            out.uncheckable = "pip check did not answer, so the app cannot tell whether anything that depends on \(pip.name) broke"
            return out
        }
        out.broke = Self.brokenLine(problems.subtracting(problemsBefore))
        return out
    }

    /// The projects marked REQUESTED now that were not before (new, or changed and unmarked before).
    static func marksToClear(before: PythonSite, after: PythonSite) -> Set<String> {
        let was = Dictionary(before.distributions.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
        return Set(after.distributions.filter { d in d.requested && !(was[d.key]?.requested ?? false) }.map(\.key))
    }

    /// After an undo: the marks on what it put back, where the projects were not marked before the fix.
    public func afterUndo(_ undo: PipUndo) async -> [String] {
        guard case let .success(now) = await PythonSite.read(python: undo.invocation.executable, tools: tools) else { return [] }
        return now.clearRequested(undo.unmarked)
    }

    /// "fastapi 0.120.0", "fastapi 0.120.0 and 1 more", or nil for no new problems.
    public static func brokenLine(_ newProblems: Set<String>) -> String? {
        let subjects = Array(Set(newProblems.map(PipCheck.subject))).sorted()
        guard let first = subjects.first else { return nil }
        return subjects.count == 1 ? first : "\(first) and \(subjects.count - 1) more"
    }
}
