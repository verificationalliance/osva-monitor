import Darwin
import Foundation

/// The two folders a fix uses, inside the app's own Application Support folder and readable by this user only (0700):
///   fixes/        the one-use scripts Terminal opens;
///   fix-results/  where a script, when its command has ended, leaves how it ended for the app.
/// Never a shared, world-writable place such as /tmp, where another account could swap a script before it runs.
public struct FixDirectories: Sendable, Equatable {
    public var scripts: URL
    public var results: URL

    public init(support: URL) {
        scripts = support.appendingPathComponent("fixes", isDirectory: true)
        results = support.appendingPathComponent("fix-results", isDirectory: true)
    }

    public init(scripts: URL, results: URL) { self.scripts = scripts; self.results = results }

    /// Creates both folders with mode 0700, or checks that they are real folders (not links) of this user's, and makes
    /// them 0700 again.
    public func prepare() throws {
        for dir in [scripts, results] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var st = stat()
            guard lstat(dir.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == getuid() else {
                throw FixScriptError("\(dir.path) is not a folder of this user's")
            }
            guard chmod(dir.path, 0o700) == 0 else { throw FixScriptError("could not make \(dir.path) private") }
        }
    }
}

public struct FixScriptError: Error, Equatable, CustomStringConvertible {
    public var description: String
    public init(_ d: String) { description = d }
}

/// The script a Terminal window runs for one fix.
///
/// It is zsh, the shell macOS opens in Terminal and the one the shown commands are quoted for (`UpgradeCommand.quote`
/// also quotes zsh's leading "="). Every value the app puts in it goes through that same quoting; the command line is
/// the shown command itself, character for character. Started with `-f`, it reads none of the person's zsh startup
/// files: it runs in the environment of the Terminal window that opened it, as a pasted command would.
///
/// It prints the command, runs it, prints how it ended, writes `<run>.json` into the results folder (written to a
/// `.part` file and renamed, so the app never reads half a file), deletes itself, and waits for a key. Closing the
/// window or interrupting it still records an ending (129, 143, or the command's 130).
public enum FixScript {
    /// For tests only: set, the script does not wait for a key.
    public static let noWaitVariable = "OSVA_FIX_NO_WAIT"

    public static func contents(plan: FixPlan, run: UUID, script: URL, results: URL) -> String {
        let q = UpgradeCommand.quote
        let record = "{\"run\":\"\(run.uuidString)\",\"finding\":\(jsonString(plan.findingID)),\"status\":"
        let doing = plan.action == .removal ? "removing" : "upgrading"
        var lines = [
            "#!/bin/zsh -f",
            "# OSVA Monitor wrote this script for one fix; it deletes itself when done. It shows the command, runs it exactly as the",
            "# app showed it, records how it ended for the app, and waits for a key.",
            "umask 077",
            "osva_results=\(q(results.path))",
            "osva_run=\(run.uuidString)",
            "osva_recorded=",
            "osva_record() {",
            "  [[ -n $osva_recorded ]] && return",
            "  osva_recorded=1",
            "  print -r -- \(q(record))\"$1\"',\"finished\":\"'\"$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)\"'\"}' >| \"$osva_results/$osva_run.json.part\" &&",
            "    /bin/mv -f -- \"$osva_results/$osva_run.json.part\" \"$osva_results/$osva_run.json\"",
            "  /bin/rm -f -- \(q(script.path))",
            "}",
            "trap 'osva_record 129; exit 129' HUP",
            "trap 'osva_record 143; exit 143' TERM",
            "trap ':' INT",
        ]
        if let dir = plan.pathFirst { lines.append("export PATH=\(q(dir)):\"$PATH\"") }
        lines += [
            "print -r -- \(q("OSVA Monitor is \(doing) \(plan.title). It runs:"))",
            "print -r -- \(q("  " + plan.command))",
            "print",
            plan.command,
            "osva_status=$?",
            "print",
            "if (( osva_status == 0 )); then",
            "  print -r -- \(q("Done. OSVA Monitor is checking \(plan.title) again."))",
            "else",
            "  print -r -- \"The command failed (exit status $osva_status). \"\(q("OSVA Monitor is checking \(plan.title) again."))",
            "fi",
            "osva_record $osva_status",
            "if [[ -z ${\(noWaitVariable):-} ]]; then",
            "  print",
            "  print -n -r -- 'Press any key to close this window. '",
            "  read -s -k 1",
            "  print",
            "fi",
            "exit 0",
            "",
        ]
        return lines.joined(separator: "\n")
    }

    /// Writes a new script for `plan` into the scripts folder: created afresh (never over an existing file or through a
    /// link) with mode 0700, so only this user can read, change or run it.
    public static func write(_ plan: FixPlan, run: UUID, directories: FixDirectories) throws -> URL {
        try directories.prepare()
        let url = directories.scripts.appendingPathComponent("fix-\(run.uuidString).command")
        let data = Data(contents(plan: plan, run: run, script: url, results: directories.results).utf8)
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o700)
        guard fd >= 0 else { throw FixScriptError("could not create \(url.lastPathComponent): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        guard fchmod(fd, 0o700) == 0 else { throw FixScriptError("could not make the script private") }
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        guard written == data.count else { throw FixScriptError("could not write the script") }
        return url
    }

    /// A JSON string literal ("brew|nginx|1.30.2" with quotes, escaped).
    static func jsonString(_ s: String) -> String {
        let data = (try? JSONEncoder().encode(s)) ?? Data("\"\"".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    /// Removes scripts and result files older than `age` (a window never run, an app quit before a result came).
    public static func sweep(_ directories: FixDirectories, olderThan age: TimeInterval, now: Date = Date()) {
        let fm = FileManager.default
        for dir in [directories.scripts, directories.results] {
            for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] {
                let url = dir.appendingPathComponent(name)
                guard let modified = (try? fm.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date,
                      now.timeIntervalSince(modified) > age else { continue }
                try? fm.removeItem(at: url)
            }
        }
    }
}

/// How one fix ended, as its script recorded it.
public struct FixResult: Equatable, Sendable {
    public var run: UUID
    public var findingID: String
    public var status: Int32
}

/// Reads the result files in the results folder.
///
/// What a file there can make the app do is bounded, so a file written by anything else is harmless:
///   - only names made from runs the app itself started in this session are looked at (`<UUID>.json`, a random UUID
///     the app made when it wrote the script); every other file is never opened;
///   - the file must be a regular file, not a link, of this user's, and at most 4 KB;
///   - it must be JSON naming that same run and the finding that run was for, with a status from 0 to 255;
///   - each run is read once and then forgotten.
/// What it can then cause: that one finding, which the person asked to fix, is checked again (its source read again
/// and one question to the API about that package), and its row says "The command failed" when the status is not 0.
/// Nothing in the file is run, opened, used as a path or sent anywhere: the status only chooses what the row says.
public enum FixResults {
    public static let maxBytes = 4096

    private struct Wire: Decodable {
        var run: String
        var finding: String
        var status: Int
    }

    /// The results that have arrived for the pending runs (run -> the finding it was for). Their files are removed,
    /// and so is a file at a pending run's name that does not hold a valid result for it.
    public static func collect(in directory: URL, pending: [UUID: String]) -> [FixResult] {
        var out: [FixResult] = []
        for (run, finding) in pending.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            let url = directory.appendingPathComponent("\(run.uuidString).json")
            var st = stat()
            guard lstat(url.path, &st) == 0 else { continue }                      // not arrived yet
            if let r = read(url, run: run, findingID: finding) { out.append(r) }
            try? FileManager.default.removeItem(at: url)
        }
        return out
    }

    /// One result file, if it is a valid result of exactly this run and finding.
    static func read(_ url: URL, run: UUID, findingID: String) -> FixResult? {
        var st = stat()
        guard lstat(url.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid(), st.st_size <= maxBytes else { return nil }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var buffer = [UInt8](repeating: 0, count: maxBytes + 1)
        let n = Darwin.read(fd, &buffer, buffer.count)
        guard n > 0, n <= maxBytes,
              let wire = try? JSONDecoder().decode(Wire.self, from: Data(buffer.prefix(n))),
              wire.run == run.uuidString, wire.finding == findingID, (0...255).contains(wire.status) else { return nil }
        return FixResult(run: run, findingID: findingID, status: Int32(wire.status))
    }
}

/// Tells when something changes in the results folder (a kqueue on the folder: a file added or renamed into it).
public final class FixResultWatcher: @unchecked Sendable {   // `source` is touched only on `queue`
    private let directory: URL
    private let handler: @Sendable () -> Void
    private let queue = DispatchQueue(label: "org.verificationalliance.osva-monitor.fix-results")
    private var source: DispatchSourceFileSystemObject?

    public init(directory: URL, handler: @escaping @Sendable () -> Void) {
        self.directory = directory; self.handler = handler
    }

    deinit { stop() }

    /// Starts watching (again, if the folder was replaced). False if the folder cannot be opened.
    @discardableResult
    public func start() -> Bool {
        queue.sync {
            source?.cancel(); source = nil
            let fd = open(directory.path, O_EVTONLY | O_DIRECTORY | O_NOFOLLOW)
            guard fd >= 0 else { return false }
            let s = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete, .link], queue: queue)
            let handler = self.handler
            s.setEventHandler { handler() }
            s.setCancelHandler { close(fd) }
            s.resume()
            source = s
            return true
        }
    }

    public func stop() {
        queue.sync { source?.cancel(); source = nil }
    }
}
