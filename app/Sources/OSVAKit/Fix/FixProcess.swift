import Darwin
import Foundation

/// How a fix's command ended.
public enum FixEnding: Equatable, Sendable {
    /// It exited by itself with this status.
    case exited(Int32)
    /// The person pressed Stop.
    case stopped
    /// It ran longer than the time limit and was stopped.
    case timedOut(minutes: Int)
    /// It asked for an administrator password (sudo, an installer): with no terminal and no askpass program it cannot
    /// get one, so it was let fail, or stopped. Nothing was typed anywhere.
    case needsPassword
    /// Something else killed it with this signal.
    case signalled(Int32)
    /// It could not be started (the tool is gone, the folder is gone).
    case couldNotStart(String)

    public var succeeded: Bool { self == .exited(0) }
}

/// Limits on one run.
public struct FixLimits: Equatable, Sendable {
    /// How long it may run before it is stopped.
    public var timeout: TimeInterval
    /// How long a stopped command has between SIGTERM and SIGKILL.
    public var grace: TimeInterval
    /// How much output is kept.
    public var logBytes: Int

    public init(timeout: TimeInterval = 15 * 60, grace: TimeInterval = 5, logBytes: Int = 64 * 1024) {
        self.timeout = timeout; self.grace = grace; self.logBytes = logBytes
    }
}

/// Starts fix commands. The app uses `FixProcessLauncher`; tests use stand-ins that print and end on cue.
public protocol FixLaunching: Sendable {
    /// Starts it at once. `update` gets the log as it grows (at most ten times a second, on any thread).
    func launch(_ invocation: FixInvocation, environment: [String: String], limits: FixLimits,
                update: @escaping @Sendable (FixLog) -> Void) -> any FixRunning
}

/// A started command.
public protocol FixRunning: AnyObject, Sendable {
    /// Asks it to stop: SIGTERM to its whole process group, SIGKILL after the grace period.
    func stop()
    /// Waits for the end, and returns it with the whole log.
    func ending() async -> (FixEnding, FixLog)
}

public struct FixProcessLauncher: FixLaunching {
    public init() {}
    public func launch(_ invocation: FixInvocation, environment: [String: String], limits: FixLimits,
                       update: @escaping @Sendable (FixLog) -> Void) -> any FixRunning {
        let p = FixProcess(invocation, environment: environment, limits: limits, update: update)
        p.start()
        return p
    }
}

/// Sudo's and installers' words for "this needs a password": seen in the output, the run ends as `.needsPassword`.
public enum FixPasswordPrompt {
    static let phrases = [
        "a terminal is required to read the password",        // sudo, no tty and no askpass
        "a password is required",                              // sudo -n, and sudo with no way to ask
        "no tty present and no askpass program specified",     // older sudo
        "no askpass program specified",
        "you must have a tty to run sudo",
        "sudo: unable to read password",
        "sudo: 1 incorrect password attempt",
        "must be run as root",                                 // installer(8)
    ]

    public static func asks(_ line: String) -> Bool {
        let l = line.lowercased()
        return phrases.contains { l.contains($0) } || l.trimmingCharacters(in: .whitespaces) == "password:"
    }
}

/// One fix command, run inside the app with no shell and no terminal.
///
/// It is started with posix_spawn, given the program's path and the argument list as they are (an argument is never
/// split, joined, expanded or read by anything but the program), and the environment as given, nothing inherited:
///   - in a session of its own (POSIX_SPAWN_SETSID), so it has no controlling terminal: sudo cannot open /dev/tty to
///     ask for a password, and Stop reaches every process it started (they share its process group);
///   - stdin is /dev/null; stdout and stderr go to one pipe, read as they come; no other file of the app's is open
///     in it (POSIX_SPAWN_CLOEXEC_DEFAULT); signals start at their defaults and unblocked;
///   - stopped (by Stop, the time limit, or a password prompt) with SIGTERM to the group, then SIGKILL after the grace
///     period;
///   - its output goes through `TerminalText`: decoded, stripped, bounded.
final class FixProcess: FixRunning, @unchecked Sendable {   // every mutable field is guarded by `lock`
    private let invocation: FixInvocation
    private let environment: [String: String]
    private let limits: FixLimits
    private let update: @Sendable (FixLog) -> Void

    private let lock = NSLock()
    private var pid: pid_t = 0
    private var text: TerminalText
    private var reason: FixEnding?               // why the app stopped it, if it did
    private var exited = false
    private var result: (FixEnding, FixLog)?
    private var waiters: [CheckedContinuation<(FixEnding, FixLog), Never>] = []
    private var published = Date.distantPast
    private var dirty = false

    init(_ invocation: FixInvocation, environment: [String: String], limits: FixLimits, update: @escaping @Sendable (FixLog) -> Void) {
        self.invocation = invocation; self.environment = environment; self.limits = limits; self.update = update
        text = TerminalText(limit: limits.logBytes)
    }

    func start() {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { finish(.couldNotStart(String(cString: strerror(errno)))); return }
        let (readEnd, writeEnd) = (fds[0], fds[1])

        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        posix_spawn_file_actions_init(&actions)
        posix_spawnattr_init(&attributes)
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, writeEnd, 1)
        posix_spawn_file_actions_adddup2(&actions, writeEnd, 2)
        posix_spawn_file_actions_addchdir(&actions, invocation.directory ?? "/")
        var all = sigset_t(), none = sigset_t()
        sigfillset(&all); sigemptyset(&none)
        posix_spawnattr_setsigdefault(&attributes, &all)
        posix_spawnattr_setsigmask(&attributes, &none)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))

        let argv = invocation.argv.map { strdup($0) } + [nil]
        let envp = environment.sorted { $0.key < $1.key }.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var child: pid_t = 0
        let status = posix_spawn(&child, invocation.executable, &actions, &attributes, argv, envp)
        close(writeEnd)
        guard status == 0 else {
            close(readEnd)
            finish(.couldNotStart(String(cString: strerror(status))))
            return
        }
        let spawned = child
        lock.withLock { pid = spawned }

        let reader = Thread { [self] in read(from: readEnd) }
        reader.stackSize = 1 << 20
        reader.start()
        Thread { [self] in waitForExit(spawned) }.start()
        DispatchQueue.global().asyncAfter(deadline: .now() + limits.timeout) { [weak self] in
            guard let self else { return }
            self.stop(because: .timedOut(minutes: Int((self.limits.timeout / 60).rounded())))
        }
    }

    func stop() { stop(because: .stopped) }

    private func stop(because why: FixEnding) {
        let target: pid_t? = lock.withLock {
            guard !exited, pid > 0 else { return nil }
            if reason == nil { reason = why }
            return pid
        }
        guard let target else { return }
        kill(-target, SIGTERM)
        DispatchQueue.global().asyncAfter(deadline: .now() + limits.grace) { [weak self] in
            guard let self, !self.lock.withLock({ self.exited }) else { return }
            kill(-target, SIGKILL)
        }
    }

    /// Reads the pipe until it closes, or until 2 s after the command exited (a process it left behind may keep the
    /// pipe open for ever; its output after that is not the command's).
    private func read(from fd: Int32) {
        defer { close(fd) }
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        var exitSeen: Date?
        while true {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&p, 1, 200)
            if ready > 0 {
                let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                if n > 0 {
                    take(buffer.prefix(n))
                    continue
                }
                if n == 0 || (errno != EINTR && errno != EAGAIN) { break }   // closed, or broken
            } else if ready < 0 && errno != EINTR {
                break
            }
            publishIfDue(force: false)
            if lock.withLock({ exited }) {
                if exitSeen == nil { exitSeen = Date() }
                if Date().timeIntervalSince(exitSeen!) > 2 { break }
            }
        }
        lock.withLock { text.finish(); dirty = true }
        readerDone()
    }

    private func take(_ bytes: ArraySlice<UInt8>) {
        let asksForPassword = lock.withLock {
            let lines = text.feed(bytes)
            dirty = true
            return (lines + [text.log.partial]).contains(where: FixPasswordPrompt.asks)
        }
        if asksForPassword {
            // sudo fails at once without a terminal; give the tool a moment to say so and end by itself
            let first = lock.withLock { () -> Bool in
                guard reason == nil else { return false }
                reason = .needsPassword
                return true
            }
            if first {
                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { [weak self] in self?.stop(because: .needsPassword) }
            }
        }
        publishIfDue(force: false)
    }

    private func publishIfDue(force: Bool) {
        let snapshot: FixLog? = lock.withLock {
            guard dirty, force || Date().timeIntervalSince(published) >= 0.1 else { return nil }
            dirty = false
            published = Date()
            return text.log
        }
        if let snapshot { update(snapshot) }
    }

    private var exitStatus: Int32?
    private var readerFinished = false

    private func waitForExit(_ child: pid_t) {
        // Seen ended but not yet reaped, so its pid (and with it the group's id) cannot be given to another process
        // while the rest of a stopped command's group is killed.
        var info = siginfo_t()
        while waitid(P_PID, id_t(child), &info, WEXITED | WNOWAIT) < 0 && errno == EINTR {}
        if lock.withLock({ reason }) != nil { kill(-child, SIGKILL) }
        var status: Int32 = 0
        while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        lock.withLock { exited = true; exitStatus = status }
        completeIfReady()
    }

    private func readerDone() {
        lock.withLock { readerFinished = true }
        completeIfReady()
    }

    private func completeIfReady() {
        let ending: FixEnding? = lock.withLock {
            guard exited, readerFinished, result == nil, let status = exitStatus else { return nil }
            if let reason { return reason }
            let low = status & 0x7F
            if low == 0 { return .exited((status >> 8) & 0xFF) }                  // WIFEXITED
            return .signalled(low)                                                   // WIFSIGNALED
        }
        if let ending { finish(ending) }
    }

    private func finish(_ ending: FixEnding) {
        let (log, waiting): (FixLog, [CheckedContinuation<(FixEnding, FixLog), Never>]) = lock.withLock {
            exited = true
            result = (ending, text.log)
            defer { waiters = [] }
            return (text.log, waiters)
        }
        update(log)
        waiting.forEach { $0.resume(returning: (ending, log)) }
    }

    func ending() async -> (FixEnding, FixLog) {
        await withCheckedContinuation { c in
            let done: (FixEnding, FixLog)? = lock.withLock {
                if let result { return result }
                waiters.append(c)
                return nil
            }
            if let done { c.resume(returning: done) }
        }
    }
}
