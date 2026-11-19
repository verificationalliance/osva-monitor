import Foundation

public struct CommandResult: Sendable {
    public var status: Int32
    public var stdout: Data
    public var stderr: Data
    public init(status: Int32, stdout: Data, stderr: Data) { self.status = status; self.stdout = stdout; self.stderr = stderr }
    public var errorText: String { String(decoding: stderr.prefix(400), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
}

/// Runs a local tool (brew, npm, python3 -m pip, gem). The app uses `ProcessRunner`; tests replay recorded output.
public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult
}

public struct ProcessRunner: CommandRunner {
    public init() {}

    public func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
                process.environment = environment
                process.currentDirectoryURL = FileManager.default.temporaryDirectory
                let out = Pipe(), err = Pipe()
                process.standardOutput = out
                process.standardError = err
                process.standardInput = FileHandle.nullDevice
                do { try process.run() } catch { continuation.resume(throwing: error); return }

                // Read both pipes while the tool runs: brew prints megabytes, more than a pipe buffers.
                let errSink = DataSink()
                let errHandle = err.fileHandleForReading
                let group = DispatchGroup()
                group.enter()
                DispatchQueue.global(qos: .utility).async {
                    errSink.set(errHandle.readDataToEndOfFile()); group.leave()
                }
                let running = RunningProcess(process)
                let deadline = DispatchWorkItem { running.terminateIfRunning() }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
                let stdout = out.fileHandleForReading.readDataToEndOfFile()
                group.wait()
                process.waitUntilExit()
                deadline.cancel()
                continuation.resume(returning: CommandResult(status: process.terminationStatus, stdout: stdout, stderr: errSink.get()))
            }
        }
    }
}

private final class RunningProcess: @unchecked Sendable {   // only asks the process to stop; Process is thread-safe for that
    private let process: Process
    init(_ process: Process) { self.process = process }
    func terminateIfRunning() { if process.isRunning { process.terminate() } }
}

private final class DataSink: @unchecked Sendable {   // written once by one thread, read after DispatchGroup.wait
    private let lock = NSLock()
    private var data = Data()
    func set(_ d: Data) { lock.lock(); data = d; lock.unlock() }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}

/// Where the tools are, and the environment they run in.
///
/// An app started from Finder or at login does not get the shell's PATH, so tools are looked for where their
/// installers put them. They run with their update checks and telemetry off: listing what is installed must not
/// send anything anywhere.
public struct ToolEnvironment: Sendable {
    public var home: URL
    public var base: [String: String]
    public var runner: any CommandRunner
    /// Whether a path is an executable file (tests pretend tools exist).
    public var isExecutable: @Sendable (String) -> Bool

    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                base: [String: String] = ProcessInfo.processInfo.environment,
                runner: any CommandRunner = ProcessRunner(),
                isExecutable: @escaping @Sendable (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }) {
        self.home = home; self.base = base; self.runner = runner; self.isExecutable = isExecutable
    }

    /// The first of these paths that is an executable file. "~" means the home directory.
    public func firstExecutable(_ candidates: [String]) -> String? {
        candidates.lazy.map(expand).first(where: isExecutable)
    }

    /// The executables among these paths, each real file once (/usr/local/bin/npm may link to the same npm).
    public func distinctExecutables(_ candidates: [String]) -> [String] {
        var seen = Set<String>()
        return candidates.map(expand).filter { p in
            isExecutable(p) && seen.insert((p as NSString).resolvingSymlinksInPath).inserted
        }
    }

    public func expand(_ path: String) -> String {
        path.hasPrefix("~/") ? home.appendingPathComponent(String(path.dropFirst(2))).path : path
    }

    /// The environment for running `tool`: its own directory first on PATH (npm's `#!/usr/bin/env node` needs it).
    public func environment(for tool: String, extra: [String: String] = [:]) -> [String: String] {
        var env = base
        let dirs = [(tool as NSString).deletingLastPathComponent, "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        let existing = (base["PATH"] ?? "").split(separator: ":").map(String.init)
        var seen = Set<String>()
        env["PATH"] = (dirs + existing).filter { !$0.isEmpty && seen.insert($0).inserted }.joined(separator: ":")
        env["HOME"] = home.path
        env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        env["HOMEBREW_NO_ANALYTICS"] = "1"
        env["HOMEBREW_NO_ENV_HINTS"] = "1"
        env["HOMEBREW_NO_COLOR"] = "1"
        env["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
        env["NPM_CONFIG_FUND"] = "false"
        env["NPM_CONFIG_LOGS_MAX"] = "0"                  // no debug log files for a read-only listing
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        env["PIP_NO_INPUT"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["NO_COLOR"] = "1"
        for (k, v) in extra { env[k] = v }
        return env
    }

    public func run(_ tool: String, _ arguments: [String], extra: [String: String] = [:], timeout: TimeInterval = 120) async throws -> CommandResult {
        try await runner.run(tool, arguments, environment: environment(for: tool, extra: extra), timeout: timeout)
    }
}
