import Darwin
import Foundation
import Testing
@testable import OSVAKit

// Running a fix inside the app: what a tool prints made safe to show, the command's words read as an argument list,
// the process run with no shell and no terminal, stopped, timed out, and the password case; and the Python checks
// that keep an upgrade from breaking what depends on it.

// MARK: - What a tool prints

@Suite struct TerminalTextTests {
    func read(_ chunks: [[UInt8]], limit: Int = 64 * 1024) -> FixLog {
        var t = TerminalText(limit: limit)
        for c in chunks { t.feed(c) }
        t.finish()
        return t.log
    }
    func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    @Test func coloursCursorMovesTitlesAndLinksAreRemoved() {
        let raw = "\u{1B}[1;32m==>\u{1B}[0m \u{1B}[1mPouring\u{1B}[22m nginx\u{1B}[K\n"
            + "\u{1B}]0;window title\u{07}title gone\n"
            + "\u{1B}]8;;https://evil.example\u{1B}\\click\u{1B}]8;;\u{1B}\\ here\n"
            + "\u{1B}P1$r0m\u{1B}\\dcs gone\n"
            + "\u{1B}(Bcharset\u{1B}7saved\u{1B}8\n"
            + "\u{1B}[2J\u{1B}[Hcleared\n"
        #expect(read([bytes(raw)]).lines == ["==> Pouring nginx", "title gone", "click here", "dcs gone", "charsetsaved", "cleared"])
    }

    @Test func anEscapeSplitAcrossReadsIsStillRemoved() {
        let raw = bytes("\u{1B}[38;5;196mred\u{1B}[0m\n\u{1B}]0;ti")
        let rest = bytes("tle\u{07}after\n")
        for cut in 1..<raw.count {
            #expect(read([Array(raw[..<cut]), Array(raw[cut...]), rest]).lines == ["red", "after"], "cut at \(cut)")
        }
    }

    @Test func carriageReturnsBackspacesAndTabs() {
        #expect(read([bytes("Downloading  10%\rDownloading  55%\rDownloading 100%\ndone\r\n")]).lines == ["Downloading 100%", "done"])
        #expect(read([bytes("abc\u{8}d\n")]).lines == ["abd"])
        #expect(read([bytes("a\tb\n")]).lines == ["a       b"])
        #expect(read([bytes("bell\u{07}\u{0}\u{7F} ok\n")]).lines == ["bell ok"])
    }

    @Test func utf8SplitAcrossReadsAndInvalidBytes() {
        let raw = bytes("🍺  /opt/homebrew/Cellar/nginx: 27 files — ünïcode\n")
        for cut in 1..<8 { #expect(read([Array(raw[..<cut]), Array(raw[cut...])]).lines == ["🍺  /opt/homebrew/Cellar/nginx: 27 files — ünïcode"]) }
        #expect(read([[0x61, 0xFF, 0xFE, 0x62, 0x0A]]).lines == ["a\u{FFFD}\u{FFFD}b"])
        // a partial line never shows half a character
        var t = TerminalText()
        t.feed(Array(raw.prefix(2)))
        #expect(t.log.partial == "")
    }

    @Test func nothingCanReorderOrSplitALine() {
        // C1 controls (as UTF-8), line/paragraph separators, bidi overrides and isolates
        let raw = "safe\u{202E}txt.exe\u{2066}x\u{2069}\u{2028}y\u{85}z\u{9B}31m\n"
        #expect(read([bytes(raw)]).lines == ["safetxt.exexyz31m"])
    }

    @Test func memoryIsBounded() {
        let line = String(repeating: "x", count: 99) + "\n"
        let chunk = bytes(String(repeating: line, count: 1000))                     // 100 KB a read
        var t = TerminalText(limit: 64 * 1024)
        for _ in 0..<20 { t.feed(chunk) }                                           // 2 MB in all
        t.finish()
        let kept = t.log.lines.reduce(0) { $0 + $1.utf8.count + 1 }
        #expect(kept <= 64 * 1024 && kept > 60 * 1024)
        #expect(t.log.droppedLines + t.log.lines.count == 20_000)
        #expect(t.log.text.hasPrefix("(\(t.log.droppedLines) earlier lines not kept)\n"))
        // one endless line is cut, not kept whole
        let endless = read([[UInt8](repeating: 0x61, count: 3 * TerminalText.maxLine + 10)])
        #expect(endless.lines.map(\.count) == [TerminalText.maxLine, TerminalText.maxLine, TerminalText.maxLine, 10])
    }

    @Test func lastLinesSkipBlankOnes() {
        let log = FixLog(["one", "", "two", "   ", "three"], partial: "four")
        #expect(log.last(3) == ["two", "three", "four"])
    }
}

// MARK: - The command's words, as an argument list

@Suite struct ShellWordsTests {
    @Test func readsEveryFormTheAppWrites() {
        func words(_ s: String) -> [String]? { ShellWords.read(s, home: "/Users/ana")?.words }
        #expect(words("brew upgrade --cask visual-studio-code") == ["brew", "upgrade", "--cask", "visual-studio-code"])
        #expect(words("/usr/bin/python3 -m pip install --user --upgrade 'setuptools==78.1.1'")
            == ["/usr/bin/python3", "-m", "pip", "install", "--user", "--upgrade", "setuptools==78.1.1"])
        #expect(words("'/Users/ana/My Tools/npm' install -g 'lodash@4.17.21'") == ["/Users/ana/My Tools/npm", "install", "-g", "lodash@4.17.21"])
        #expect(words("npm install -g 'it'\\''s@1.0'") == ["npm", "install", "-g", "it's@1.0"])
        #expect(words("npm i '-rf'") == ["npm", "i", "-rf"])
        #expect(words("npm i '$(touch x)' '`id`' 'a;b' 'a b'") == ["npm", "i", "$(touch x)", "`id`", "a;b", "a b"])
        let line = ShellWords.read("cd ~/'My Project' && npm uninstall axios", home: "/Users/ana")
        #expect(line == ShellWords.Line(directory: "/Users/ana/My Project", words: ["npm", "uninstall", "axios"]))
        #expect(ShellWords.read("cd /p && yarn remove x", home: "/Users/ana")?.directory == "/p")
    }

    @Test("anything outside that form is not read", arguments: [
        "", " ", "npm  install", "npm install ", " npm", "npm install x; rm -rf ~", "npm install $(id)", "npm install `id`", "npm i x|y", "npm i x&",
        "npm i x > f", "npm i *", "npm i ~/x", "npm i =ls", "npm i \"x\"", "npm i 'unclosed", "npm i \\x", "npm i x\ny", "npm i x\ty",
        "cd relative && npm i", "cd /p; npm i", "cd /p && ", "cd /p &&npm i", "cd ~ && npm i", "npm i {a,b}", "npm i x#y", "npm i ?", "npm i [a]",
        "npm i x!", "npm i ${HOME}", "npm i a;b", "npm i x;", "npm i a(b)", "npm i a<b", "FOO=1 npm i",
    ])
    func rejected(_ line: String) {
        let read = ShellWords.read(line, home: "/Users/ana")
        // "FOO=1 npm i" reads, but as words whose first is not a tool: FixInvocation refuses it
        if line == "FOO=1 npm i" {
            #expect(FixInvocation.make(command: line, toolPath: "/opt/homebrew/bin/npm", folder: nil, home: "/Users/ana") == nil)
        } else {
            #expect(read == nil, "\(line.debugDescription) read as \(String(describing: read))")
        }
    }

    /// sh and zsh, given the same line, pass the same arguments as ShellWords reads: printf stands in for the tool.
    @Test func shAndZshReadTheSameWords() throws {
        let home = temporaryDirectory()
        let lines = [
            "brew upgrade --cask visual-studio-code", "npm install -g 'lodash@4.17.21'", "npm install -g 'it'\\''s@1.0'",
            "npm i '$(touch /tmp/osva-canary)' '`id`' 'a;b' 'a b' '*' '~root' '=ls' '-rf' 'x\\y' '!!'",
            "x -m pip install --upgrade 'six==2.0.0' 'a:b,c%d+e@f'",
            "cd ~/'My Project' && npm uninstall axios", "cd '/tmp/a b' && cargo update -p 'serde' --precise '1.0.200'",
        ]
        for line in lines {
            guard let read = ShellWords.read(line, home: home.path) else { Issue.record("not read: \(line)"); continue }
            // the tool and `cd` become printf, so the shell prints the words it would have passed
            var script = line
            script = script.replacingOccurrences(of: "cd ", with: "printf 'D%s\\0' ", options: .anchored)
            let toolStart = script.range(of: " && ").map { $0.upperBound } ?? script.startIndex
            let toolEnd = script[toolStart...].firstIndex(of: " ") ?? script.endIndex
            script.replaceSubrange(toolStart..<toolEnd, with: "printf '%s\\0'")
            for shell in [["/bin/zsh", "-f", "-c"], ["/bin/sh", "-c"]] {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: shell[0])
                p.arguments = Array(shell.dropFirst()) + [script]
                p.environment = ["HOME": home.path, "PATH": "/usr/bin:/bin"]
                let out = Pipe()
                p.standardOutput = out
                try p.run()
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                var got = String(decoding: data, as: UTF8.self).split(separator: "\0", omittingEmptySubsequences: false).dropLast().map(String.init)
                var dir: String?
                if got.first?.hasPrefix("D") == true { dir = String(got.removeFirst().dropFirst()) }
                #expect(dir == read.directory, "\(shell[0]): \(line)")
                #expect(got == Array(read.words.dropFirst()), "\(shell[0]): \(line)")
            }
        }
        #expect(!FileManager.default.fileExists(atPath: "/tmp/osva-canary"))
    }

    @Test func theInvocationIsTheToolTheyFoundAndTheFolderTheyRecorded() {
        let brew = "/opt/homebrew/bin/brew"
        #expect(FixInvocation.make(command: "brew upgrade nginx", toolPath: brew, folder: nil, home: "/Users/ana")
            == FixInvocation(executable: brew, arguments: ["upgrade", "nginx"]))
        #expect(FixInvocation.make(command: "npm upgrade nginx", toolPath: brew, folder: nil, home: "/Users/ana") == nil)        // another tool
        #expect(FixInvocation.make(command: "/usr/local/bin/brew upgrade x", toolPath: brew, folder: nil, home: "/Users/ana") == nil)
        #expect(FixInvocation.make(command: "brew upgrade x", toolPath: "brew", folder: nil, home: "/Users/ana") == nil)        // not a path
        let npm = "/opt/homebrew/bin/npm"
        #expect(FixInvocation.make(command: "cd ~/code/shop && npm uninstall axios", toolPath: npm, folder: "/Users/ana/code/shop", home: "/Users/ana")
            == FixInvocation(executable: npm, arguments: ["uninstall", "axios"], directory: "/Users/ana/code/shop"))
        #expect(FixInvocation.make(command: "cd ~/code/other && npm uninstall axios", toolPath: npm, folder: "/Users/ana/code/shop", home: "/Users/ana") == nil)
        #expect(FixInvocation.make(command: "npm uninstall axios", toolPath: npm, folder: "/Users/ana/code/shop", home: "/Users/ana") == nil)
    }

    @Test func everyRunnablePlanCarriesItsInvocation() throws {
        let cases: [(Finding, [String])] = [
            (fixable(.homebrewFormula(name: "nginx"), "nginx", nil), ["/opt/homebrew/bin/brew", "upgrade", "nginx"]),
            (fixable(.homebrewCask(token: "firefox"), "firefox", nil), ["/opt/homebrew/bin/brew", "upgrade", "--cask", "firefox"]),
            (fixable(.npmGlobal(npm: "/opt/homebrew/bin/npm"), "eslint", fixed: "9.1.0"), ["/opt/homebrew/bin/npm", "install", "-g", "eslint@9.1.0"]),
            (fixable(.cargoInstall, "ripgrep", .crates, fixed: "14.1.1"), ["/Users/ana/.cargo/bin/cargo", "install", "ripgrep@14.1.1"]),
            (fixable(.pip(python: Fixture.pythonOrg, user: true, formula: nil), "six", .pypi, fixed: "1.17.0"),
             [Fixture.pythonOrg.executable, "-m", "pip", "install", "--user", "--upgrade", "six==1.17.0"]),
            (fixable(.pip(python: Fixture.applePython, user: false, formula: nil), "evil", .pypi, malicious: true),
             ["/usr/bin/python3", "-m", "pip", "uninstall", "-y", "evil"]),
        ]
        for (f, argv) in cases {
            let p = try ok(plan(f))
            #expect(p.invocation.argv == argv && p.invocation.directory == nil, "\(p.command)")
        }
        let removal = try ok(plan(fixable(.folder(root: "/Users/ana/code", lockfile: "/Users/ana/code/shop/package-lock.json", direct: true), "axios",
                                          malicious: true)))
        #expect(removal.invocation == FixInvocation(executable: "/opt/homebrew/bin/npm", arguments: ["uninstall", "axios"], directory: "/Users/ana/code/shop"))
    }
}

// MARK: - The process

/// A stand-in tool in a temporary folder: a script (the kernel runs its #! line; the app runs no shell).
func tool(_ body: String, in dir: URL = temporaryDirectory(), name: String = "tool") -> URL {
    let url = dir.appendingPathComponent(name)
    try! Data(("#!/bin/sh\n" + body + "\n").utf8).write(to: url)
    chmod(url.path, 0o755)
    return url
}

func run(_ invocation: FixInvocation, environment: [String: String] = ["PATH": "/usr/bin:/bin"], limits: FixLimits = FixLimits(),
         stopAfter: TimeInterval? = nil, stopWhenExists ready: URL? = nil,
         updates: UpdateRecorder = UpdateRecorder()) async -> (FixEnding, FixLog) {
    let p = FixProcessLauncher().launch(invocation, environment: environment, limits: limits) { updates.add($0) }
    if let stopAfter {
        Task { try? await Task.sleep(for: .seconds(stopAfter)); p.stop() }
    }
    if let ready {
        // Stop once the tool says it is ready, not after a fixed time: a slow machine may not have got that far yet.
        Task { _ = await eventually(seconds: 20) { FileManager.default.fileExists(atPath: ready.path) }; p.stop() }
    }
    return await p.ending()
}

/// Polls `condition` every 20 ms until it holds or `seconds` pass; whether it held.
func eventually(seconds: Double, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(20))
    }
    return condition()
}

final class UpdateRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var logs: [FixLog] = []
    func add(_ l: FixLog) { lock.withLock { logs.append(l) } }
    var all: [FixLog] { lock.withLock { logs } }
}

@Suite(.serialized) struct FixProcessTests {
    @Test func eachArgumentArrivesAsItIsAndNothingInItRuns() async throws {
        let dir = temporaryDirectory()
        let canary = dir.appendingPathComponent("canary").path
        let argvFile = dir.appendingPathComponent("argv")
        let t = tool("for a in \"$@\"; do printf '%s\\0' \"$a\"; done > '\(argvFile.path)'", in: dir)
        let args = ["$(touch \(canary))", "`touch \(canary)`", "a; touch \(canary)", "a b", "x\ny", "'", "\"", "*", "~", "-rf", "", "${HOME}", "|", "&&"]
        let (ending, _) = await run(FixInvocation(executable: t.path, arguments: args))
        #expect(ending == .exited(0))
        let got = String(decoding: try Data(contentsOf: argvFile), as: UTF8.self).split(separator: "\0", omittingEmptySubsequences: false).dropLast().map(String.init)
        #expect(got == args)
        #expect(!FileManager.default.fileExists(atPath: canary))
    }

    @Test func itGetsExactlyTheEnvironmentGivenAndNoTerminal() async throws {
        let t = tool("""
        env | sort
        if tty -s; then echo "tty: yes"; else echo "tty: no"; fi
        if (exec 3</dev/tty) 2>/dev/null; then echo "/dev/tty: open"; else echo "/dev/tty: none"; fi
        read line && echo "stdin: $line" || echo "stdin: empty"
        pwd
        """)
        let env = FixEnvironment.make(tools: ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: ["PATH": "/usr/bin", "SUDO_ASKPASS": "/x/askpass",
                                                                                                          "HOMEBREW_NO_AUTO_UPDATE": "1", "SECRET": "kept"]),
                                      executable: "/opt/homebrew/bin/brew", toolName: "brew")
        #expect(env["SUDO_ASKPASS"] == nil && env["HOMEBREW_NO_AUTO_UPDATE"] == nil && env["CI"] == nil)
        #expect(env["GIT_TERMINAL_PROMPT"] == "0" && env["PIP_NO_INPUT"] == "1" && env["npm_config_yes"] == "false" && env["HOMEBREW_NO_ENV_HINTS"] == "1")
        #expect(env["PATH"]?.hasPrefix("/opt/homebrew/bin:") == true)
        #expect(FixEnvironment.make(tools: ToolEnvironment(base: [:]), executable: "/opt/homebrew/bin/npm", toolName: "npm")["CI"] == "1")
        #expect(FixEnvironment.make(tools: ToolEnvironment(base: [:]), executable: "/opt/homebrew/bin/yarn", toolName: "yarn")["CI"] == nil)

        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []), environment: ["PATH": "/usr/bin:/bin", "ONLY": "this"])
        #expect(ending == .exited(0))
        let lines = log.lines
        let shellOwn = ["PWD=", "SHLVL=", "_=", "OLDPWD="]                        // what sh itself sets
        #expect(lines.filter { l in l.contains("=") && !shellOwn.contains { l.hasPrefix($0) } }.sorted() == ["ONLY=this", "PATH=/usr/bin:/bin"])
        #expect(lines.contains("tty: no") && lines.contains("/dev/tty: none") && lines.contains("stdin: empty") && lines.last == "/")
    }

    @Test func itRunsInTheProjectFolder() async throws {
        let dir = temporaryDirectory()
        let t = tool("pwd -P")
        let (_, log) = await run(FixInvocation(executable: t.path, arguments: [], directory: dir.path))
        #expect(log.lines == [Paths.realPath(dir.path)])
    }

    @Test func outputStreamsAsItComesAndIsCleaned() async throws {
        let t = tool("printf '\\033[1;32m==>\\033[0m one\\n'; sleep 0.4; printf 'two\\n'; sleep 0.4; printf 'three\\n' >&2")
        let updates = UpdateRecorder()
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []), updates: updates)
        #expect(ending == .exited(0) && log.lines == ["==> one", "two", "three"])
        // the row saw it grow: "==> one" alone before the rest
        #expect(updates.all.contains { $0.lines == ["==> one"] })
        #expect(updates.all.last?.lines == log.lines)
    }

    @Test func anErrorExitIsItsStatus() async {
        let t = tool("echo nope; exit 3")
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []))
        #expect(ending == .exited(3) && log.lines == ["nope"])
    }

    @Test func aToolThatIsNotThereCannotStart() async {
        let (ending, _) = await run(FixInvocation(executable: "/nonexistent/brew", arguments: ["upgrade"]))
        guard case .couldNotStart = ending else { Issue.record("\(ending)"); return }
        let (ending2, _) = await run(FixInvocation(executable: "/bin/echo", arguments: [], directory: "/nonexistent-folder"))
        guard case .couldNotStart = ending2 else { Issue.record("\(ending2)"); return }
    }

    @Test func stopEndsItAndEverythingItStarted() async throws {
        let dir = temporaryDirectory()
        let pids = dir.appendingPathComponent("pids")
        let marker = dir.appendingPathComponent("child-got-term")
        let ready = dir.appendingPathComponent("child-ready")
        // a child that takes a moment to clean up on SIGTERM, after the command itself has already ended: Stop gives it
        // the grace period, not an instant SIGKILL. It says it is ready only once its trap is set, and Stop waits for
        // that, so a slow machine cannot race it.
        let cleaner = tool("trap 'sleep 0.3; echo term > \"\(marker.path)\"; exit 0' TERM; : > \"\(ready.path)\"; while :; do sleep 0.1; done",
                           in: dir, name: "child")
        let t = tool("sleep 300 & echo $! > '\(pids.path)'; '\(cleaner.path)' & echo started; sleep 300", in: dir)
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []), stopWhenExists: ready)
        let stopped = Date()
        #expect(ending == .stopped && log.lines.first == "started")            // sh may also say what it killed
        #expect(await eventually(seconds: 5) { FileManager.default.fileExists(atPath: marker.path) })
        let child = Int32(try String(contentsOf: pids, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines))!
        #expect(await eventually(seconds: 5) { kill(child, 0) != 0 })            // the background child is gone too
        // and none of it waited for the 5 s SIGKILL: every process here ends on SIGTERM
        let readyAt = try FileManager.default.attributesOfItem(atPath: ready.path)[.modificationDate] as! Date
        #expect(stopped.timeIntervalSince(readyAt) < 4)
    }

    @Test func aCommandThatIgnoresSIGTERMIsKilledAfterTheGracePeriod() async {
        let t = tool("trap '' TERM; echo ignoring; while :; do sleep 0.1; done")
        let updates = UpdateRecorder()
        let p = FixProcessLauncher().launch(FixInvocation(executable: t.path, arguments: []), environment: ["PATH": "/usr/bin:/bin"],
                                            limits: FixLimits(grace: 0.5)) { updates.add($0) }
        // stop once the trap is set (a loaded machine may take a while to get there)
        for _ in 0..<100 where !updates.all.contains(where: { $0.lines.contains("ignoring") }) { try? await Task.sleep(for: .milliseconds(50)) }
        let start = Date()
        p.stop()
        let (ending, _) = await p.ending()
        #expect(ending == .stopped)
        let took = Date().timeIntervalSince(start)
        #expect(took >= 0.45 && took < 4, "\(took)")
    }

    @Test func theTimeLimitStopsIt() async {
        let t = tool("echo working; sleep 300")
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []), limits: FixLimits(timeout: 0.5, grace: 0.5))
        #expect(ending == .timedOut(minutes: 0) && log.lines == ["working"])
        #expect(FixOutcome.make(ending: .timedOut(minutes: 15), before: fixable(.homebrewFormula(name: "nginx"), "nginx", nil),
                                recheck: .stillAffected(fixable(.homebrewFormula(name: "nginx"), "nginx", nil)), homebrew: nil).text
            == "Stopped after 15 minutes")
    }

    @Test("a password prompt ends the run as one", arguments: [
        "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper",
        "sudo: a password is required",
        "sudo: no tty present and no askpass program specified",
        "installer: Must be run as root to install this package.",
        "Password:",
    ])
    func passwordPrompts(_ said: String) async {
        let t = tool("echo '==> Running installer for x with sudo; the password may be necessary.'; echo '\(said)' >&2; exit 1")
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []))
        #expect(ending == .needsPassword && log.lines.last == said)
    }

    @Test func aToolThatWaitsAfterAskingIsStopped() async {
        let t = tool("echo 'sudo: a password is required' >&2; sleep 300")
        let start = Date()
        let (ending, _) = await run(FixInvocation(executable: t.path, arguments: []), limits: FixLimits(grace: 0.5))
        #expect(ending == .needsPassword && Date().timeIntervalSince(start) < 6)
        #expect(!FixPasswordPrompt.asks("Collecting password-strength==1.0") && !FixPasswordPrompt.asks("==> Upgrading 1password"))
    }

    @Test func aFloodOfOutputStaysBounded() async {
        let t = tool("i=0; while [ $i -lt 30000 ]; do echo \"line $i of a long flood of output that goes on\"; i=$((i+1)); done")
        let (ending, log) = await run(FixInvocation(executable: t.path, arguments: []), limits: FixLimits(logBytes: 16 * 1024))
        #expect(ending == .exited(0))
        #expect(log.lines.reduce(0) { $0 + $1.utf8.count + 1 } <= 16 * 1024 && log.droppedLines > 0)
        #expect(log.lines.last == "line 29999 of a long flood of output that goes on")
    }

    /// The runner and what feeds it never involve a shell.
    @Test func noShellAnywhereInTheRunner() throws {
        let fix = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/OSVAKit/Fix")
        for file in ["FixProcess.swift", "FixInvocation.swift", "FixLog.swift"] {
            let text = try String(contentsOf: fix.appendingPathComponent(file), encoding: .utf8)
            // the code without its comments (whole-line, and after code)
            let code = text.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
                .map { $0.replacing(/\s\/\/.*$/, with: "") }.joined(separator: "\n")
            for banned in ["/bin/sh", "/bin/zsh", "/bin/bash", "zsh", "bash", "\"-c\"", "system(", "popen(", "NSAppleScript", "osascript", "Process()", "sudo "] {
                #expect(!code.contains(banned), "\(file) contains \(banned)")
            }
        }
    }
}

// MARK: - What depends on a Python package

@Suite struct PythonDependentsTests {
    static let before = Fixture.url("python-site/before").path
    static let after = Fixture.url("python-site/after").path
    static let markers = ["python_version": "3.11", "python_full_version": "3.11.14", "sys_platform": "darwin", "os_name": "posix",
                          "platform_system": "Darwin", "platform_machine": "arm64", "implementation_name": "cpython"]
    static let pip = FixPlan.Pip(python: "/opt/homebrew/bin/python3.11", requirement: "starlette==1.3.1", user: false, name: "starlette", target: "1.3.1")

    func spec(_ s: String, _ v: String) -> Bool? { PythonSpecifier(s)!.admits(v) }

    @Test func specifiersAsPEP440ReadsThem() {
        #expect(spec("<0.49.0", "0.48.0") == true && spec("<0.49.0", "1.3.1") == false && spec("<0.49.0", "0.49.0") == false)
        #expect(spec("<0.49", "0.49.0") == false && spec("<=0.49", "0.49.0") == true && spec("==0.49", "0.49.0") == true)   // zero padding
        #expect(spec(">=0.40.0", "0.40") == true && spec(">0.40", "0.40.0") == false && spec(">0.40", "0.40.1") == true)
        #expect(spec("!=1.8.1", "1.8.1") == false && spec("!=1.8.1", "1.8.2") == true && spec("!=1.8", "1.8.0") == false)
        #expect(spec("~=2.2", "2.9.1") == true && spec("~=2.2", "3.0") == false && spec("~=2.2", "2.1") == false)
        #expect(spec("~=1.4.5", "1.4.9") == true && spec("~=1.4.5", "1.5.0") == false && spec("~=1", "1.0") == nil)
        #expect(spec("==1.4.*", "1.4.0") == true && spec("==1.4.*", "1.4") == true && spec("==1.4.*", "1.4.12.post1") == true)
        #expect(spec("==1.4.*", "1.40") == false && spec("==1.4.*", "1.5.0") == false && spec("==1.4.*", "1.3.9") == false)
        #expect(spec("!=1.4.*", "1.4.2") == false && spec("!=1.4.*", "1.5") == true)
        #expect(spec(">=1.0", "1.0rc1") == false && spec("<1.0", "1.0rc1") == true && spec(">=1.0", "1.0.post1") == true)
        #expect(spec("===1.0", "1.0") == true && spec("===1.0", "1.0.0") == false)
        #expect(spec("<2", "1!1.0") == nil && spec("<2", "latest") == nil)          // what the app cannot read gives no answer
        #expect(PythonSpecifier("<=  0.49 ")?.display == "<= 0.49" && PythonSpecifier("0.49") == nil && PythonSpecifier("<") == nil)
    }

    @Test func requirementsAndMarkers() {
        let r = PythonRequirement("uvicorn[standard] (>=0.12.0, <1) ; extra == 'standard'")!
        #expect(r.key == "uvicorn" && r.specifiers.map(\.display) == [">= 0.12.0", "< 1"] && r.marker == "extra == 'standard'")
        #expect(PythonRequirement("Typing_Extensions>=4")!.key == "typing-extensions")
        #expect(PythonRequirement("httpx @ https://example.com/httpx.whl")!.refuses("1.0") == ["from a direct URL"])
        #expect(PythonRequirement("x>=1,2")!.refuses("3") == ["a version the app cannot read"])
        #expect(PythonRequirement("starlette<0.49.0,>=0.40.0")!.refuses("1.3.1") == ["< 0.49.0"])
        func m(_ s: String) -> Bool? { PythonMarker.evaluate(s, environment: Self.markers) }
        #expect(m("python_version < \"3.13\"") == true && m("python_version >= '3.12'") == false && m("'3.12' > python_version") == true)
        #expect(m("sys_platform == \"win32\"") == false && m("sys_platform == 'darwin' and platform_machine == 'arm64'") == true)
        #expect(m("extra == \"full\"") == false && m("sys_platform == 'darwin' or extra == 'x'") == true)
        #expect(m("(os_name == 'nt' or os_name == 'posix') and python_full_version != '3.11.0'") == true)
        #expect(m("'arm' in platform_machine") == true && m("platform_machine not in 'x86_64 i386'") == true)
        #expect(m("unknown_variable == '1'") == nil && m("python_version <") == nil)
    }

    @Test func readsSitePackages() {
        let site = PythonSite.read(folders: [Self.before])
        #expect(Set(site.map(\.key)) == ["starlette", "fastapi", "prometheus-fastapi-instrumentator", "uvicorn", "anyio", "sse-starlette", "legacy-pkg"])
        let starlette = site.first { $0.key == "starlette" }!
        #expect(starlette.version == "0.48.0" && starlette.requires.count == 4)              // the description's lookalike is not read
        let legacy = site.first { $0.key == "legacy-pkg" }!
        #expect(legacy.requires == ["six", "starlette!=0.47.0; sys_platform == \"darwin\""])  // [test] is an extra, left out
        // the first folder on sys.path wins
        #expect(PythonSite.read(folders: [Self.after, Self.before]).first { $0.key == "starlette" }?.version == "1.10.0")
    }

    /// 0.2.0 broke this on a real Mac: starlette upgraded under fastapi 0.120.0, which needs < 0.49. Now no button.
    @Test func theStarletteUpgradeIsRefusedBeforeItRuns() {
        let site = PythonSite(distributions: PythonSite.read(folders: [Self.before]), markers: Self.markers)
        let conflicts = site.conflicts(["starlette": "1.3.1"])
        #expect(conflicts.map(\.line) == ["fastapi 0.120.0 needs starlette < 0.49.0",
                                          "prometheus-fastapi-instrumentator 7.1.0 needs starlette < 1.0.0"])
        guard case let .blocked(line, _) = PipGuard.verdict(site, pip: Self.pip) else { Issue.record("not blocked"); return }
        #expect(line == "fastapi 0.120.0 needs starlette < 0.49.0, and 1 more — update them first")
        // a version every dependent takes is clear; the extra-only and Windows-only requirements do not count
        let fine = PipGuard.verdict(site, pip: FixPlan.Pip(python: "/x", requirement: "starlette==0.48.2", user: false, name: "starlette", target: "0.48.2"))
        guard case .clear = fine else { Issue.record("\(fine)"); return }
        // the egg-info's darwin-only requirement counts on this Mac
        #expect(site.conflicts(["starlette": "0.47.0"]).map(\.dependent) == ["legacy-pkg"])
        // what pip's dry run would also install is checked the same way
        guard case let .blocked(also, _) = PipGuard.verdict(site, pip: FixPlan.Pip(python: "/x", requirement: "uvicorn==0.40.0", user: false,
                                                                                    name: "uvicorn", target: "0.40.0"), also: ["anyio": "5.0.0"]) else {
            Issue.record("anyio 5 not blocked"); return
        }
        #expect(also == "starlette 0.48.0 needs anyio < 5 — update starlette first")
    }

    /// And had it run: `pip check` after the run has problems it did not have before, so the outcome is never "Fixed".
    @Test func theStarletteBreakageIsCaughtAfterTheRun() throws {
        let before = PipCheck.problems(Fixture.text("python-site/pip-check-before.txt"))
        let after = PipCheck.problems(Fixture.text("python-site/pip-check-after.txt"))
        #expect(before.isEmpty && after.count == 2)
        let broke = PipGuard.brokenLine(after.subtracting(before))
        #expect(broke == "fastapi 0.120.0 and 1 more")
        #expect(PipGuard.brokenLine(after.subtracting(after)) == nil)              // a problem that was there before is not new
        let finding = fixable(.pip(python: PythonEnvironment(executable: Self.pip.python, version: "3.11.14", kind: .homebrew, externallyManaged: false,
                                                             userSite: nil, formula: "python@3.11"), user: false, formula: nil), "starlette", .pypi,
                              installed: "0.48.0", fixed: "1.3.1")
        let outcome = FixOutcome.make(ending: .exited(0), before: finding, recheck: .fixed(now: "1.10.0"), homebrew: nil, broke: broke)
        #expect(outcome == .broke("fastapi 0.120.0 and 1 more") && !outcome.isResolved && outcome.text == "Updated, but it broke fastapi 0.120.0 and 1 more")
        // Undo puts back exactly the version that changed, and nothing else
        let undo = try #require(PipUndo.make(python: Self.pip.python, user: false,
                                             before: PythonSite(distributions: PythonSite.read(folders: [Self.before]), markers: [:]),
                                             after: PythonSite(distributions: PythonSite.read(folders: [Self.after]), markers: [:])))
        #expect(undo.invocation.argv == ["/opt/homebrew/bin/python3.11", "-m", "pip", "install", "--no-deps", "--disable-pip-version-check", "starlette==0.48.0"])
        #expect(undo.restores == ["starlette 0.48.0"] && undo.command.hasSuffix("starlette==0.48.0"))
    }

    /// Rule A-R12: exact pins only. Never `>=`, which let pip take starlette 1.10 over 1.3.1.
    @Test func pipUpgradesPinTheExactVersion() throws {
        let p = try ok(plan(fixable(.pip(python: Fixture.pythonOrg, user: false, formula: nil), "setuptools", .pypi, installed: "58.0.4", fixed: "78.1.1")))
        #expect(p.command == "\(Fixture.pythonOrg.executable) -m pip install --upgrade setuptools==78.1.1")
        #expect(p.pip == FixPlan.Pip(python: Fixture.pythonOrg.executable, requirement: "setuptools==78.1.1", user: false, name: "setuptools",
                                     target: "78.1.1", installed: "58.0.4"))
        #expect(p.actionTitle == "Update to 78.1.1" && p.summary == "pip updates setuptools to 78.1.1.")
        #expect(!p.command.contains(">=") && !p.invocation.argv.contains { $0.contains(">=") })
        // the copyable command for a requirements file pins exactly too
        let r = UpgradeCommand.advice(UpgradeCommand.Inputs(origin: .folder(root: "/p", lockfile: "/p/requirements.txt", direct: true), name: "django",
                                                            ecosystem: .pypi, target: "5.2.17", malicious: false), home: home)
        #expect(r.command == "cd /p && python3 -m pip install django==5.2.17")
    }

    @Test func anAdvisorWithholdsTheButtonFromWhatDependsOnIt() async throws {
        // the interpreter answers with the fixture folder as its sys.path
        let script = #"{"path":["\#(Self.before)"],"markers":{"python_version":"3.11","sys_platform":"darwin"}}"#
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:],
                                    runner: SwitchableRunner(["\(Self.pip.python) -c \(PythonSite.script)": CommandResult(status: 0, stdout: Data(script.utf8), stderr: Data())]),
                                    isExecutable: { _ in true })
        let python = PythonEnvironment(executable: Self.pip.python, version: "3.11.14", kind: .homebrew, externallyManaged: false, userSite: nil, formula: "python@3.11")
        let f = fixable(.pip(python: python, user: false, formula: nil), "starlette", .pypi, installed: "0.48.0", fixed: "1.3.1")
        #expect(await FixAdvisor(tools: tools, home: home).assess(f) == .refused("fastapi 0.120.0 needs starlette < 0.49.0, and 1 more — update them first."))
        // an interpreter that does not answer: not offered either
        let silent = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: SwitchableRunner([:]), isExecutable: { _ in true })
        guard case let .withheld(why) = await FixAdvisor(tools: silent, home: home).assess(f) else { Issue.record("offered"); return }
        #expect(why.hasPrefix("Not offered: the app could not read what depends on starlette"))
    }
}

// MARK: - The research's rules for the fix engine

/// A site-packages folder written from (name, version, requires, requested, editable) tuples.
func site(_ dists: [(String, String, [String], Bool, Bool)], in dir: URL = temporaryDirectory()) -> URL {
    for (name, version, requires, requested, editable) in dists {
        let d = dir.appendingPathComponent("\(name.replacingOccurrences(of: "-", with: "_"))-\(version).dist-info")
        write("Metadata-Version: 2.1\nName: \(name)\nVersion: \(version)\n" + requires.map { "Requires-Dist: \($0)\n" }.joined(), to: d.appendingPathComponent("METADATA"))
        if requested { write("", to: d.appendingPathComponent("REQUESTED")) }
        if editable { write(#"{"url": "file:///Users/ana/code/blooper", "dir_info": {"editable": true}}"#, to: d.appendingPathComponent("direct_url.json")) }
    }
    return dir
}

@Suite struct FixEngineRuleTests {
    static let markers = PythonDependentsTests.markers
    func pip(_ name: String, _ target: String, installed: String = "") -> FixPlan.Pip {
        FixPlan.Pip(python: "/x/python", requirement: "\(name)==\(target)", user: false, name: name, target: target, installed: installed)
    }

    /// A-R1, B-R6, B-R14: every installed dependent's specifier gates, including requirements behind extras that are
    /// in use: asked for by another package (`uvicorn[standard]`), or of an editable project (its `[dev]`).
    @Test func extrasInUseGateToo() {
        let dir = site([("blooper-backend", "0.1.0", ["fastapi>=0.110", "anyio>=4.3.0; extra == \"dev\""], true, true),
                        ("fastapi", "0.120.0", ["uvicorn[standard]>=0.12.0"], true, false),
                        ("uvicorn", "0.38.0", ["python-dotenv>=0.13; extra == \"standard\"", "watchfiles>=0.13; extra == \"reload\""], false, false),
                        ("anyio", "4.11.0", [], false, false), ("python-dotenv", "1.0.1", [], false, false), ("watchfiles", "1.0.0", [], false, false)])
        let s = PythonSite(folders: [dir.path], markers: Self.markers)
        #expect(s.activeExtras()["uvicorn"] == ["standard"] && s.activeExtras()["blooper-backend"] == ["dev"])
        #expect(s.conflicts(["anyio": "4.0.0"]).map(\.line) == ["blooper-backend 0.1.0 needs anyio >= 4.3.0"])          // the [dev] edge
        #expect(s.conflicts(["python-dotenv": "0.12"]).map(\.line) == ["uvicorn 0.38.0 needs python-dotenv >= 0.13"])    // the [standard] edge
        #expect(s.conflicts(["watchfiles": "0.1"]).isEmpty)                                                              // [reload]: nobody asked
        guard case let .blocked(line, _) = PipGuard.verdict(s, pip: pip("anyio", "4.0.0")) else { Issue.record("not blocked"); return }
        #expect(line == "blooper-backend 0.1.0 needs anyio >= 4.3.0 — it is a project installed for development: raise its anyio range there")
    }

    /// A-R3, A-R11, B-R17: packages that pin it exactly move with it, in one pinned command, or not at all.
    @Test func lockstepFamiliesMoveTogether() async throws {
        let dir = site([("torch", "2.7.0", [], true, false), ("torchaudio", "2.7.0", ["torch==2.7.0"], true, false),
                        ("opentelemetry-sdk", "1.41.1", ["opentelemetry-api==1.41.1"], false, false), ("opentelemetry-api", "1.41.1", [], false, false),
                        ("exporter", "1.41.1", ["opentelemetry-sdk~=1.41.1"], true, false)])
        let s = PythonSite(folders: [dir.path], markers: Self.markers)
        #expect(PipGuard.verdict(s, pip: pip("torch", "2.8.0")) == .companions(["torchaudio"], s))
        guard case .clear = PipGuard.verdict(s, pip: pip("torch", "2.8.0"), also: ["torch": "2.8.0", "torchaudio": "2.8.0"]) else { Issue.record("not clear"); return }
        // a dry run that leaves a pinning package behind is blocked, not run
        guard case .blocked = PipGuard.verdict(s, pip: pip("opentelemetry-api", "1.45.2"), also: ["opentelemetry-api": "1.45.2"]) else { Issue.record("ran alone"); return }
        // the advisor: the dry run names the companions' versions, and they are pinned on the command line
        let py = Fixture.pythonOrg.executable
        let siteJSON = #"{"path":["\#(dir.path)"],"markers":{"python_version":"3.13","sys_platform":"darwin"}}"#
        func ok(_ text: String) -> CommandResult { CommandResult(status: 0, stdout: Data(text.utf8), stderr: Data()) }
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: SwitchableRunner([
            "\(py) -c \(PythonSite.script)": ok(siteJSON),
            "\(py) -m pip --version": ok("pip 24.0 from /x (python 3.13)\n"),
            "\(py) -m pip install --dry-run --only-binary=:all: --upgrade --disable-pip-version-check --no-input torch==2.8.0 torchaudio":
                ok("Would install torch-2.8.0 torchaudio-2.8.0\n"),
        ]), isExecutable: { _ in true })
        let f = fixable(.pip(python: Fixture.pythonOrg, user: false, formula: nil), "torch", .pypi, installed: "2.7.0", fixed: "2.8.0")
        let advisor = FixAdvisor(tools: tools, home: home)
        guard case let .offer(offer) = await advisor.assess(f) else { Issue.record("no offer"); return }
        #expect(offer.companions == ["torchaudio"])
        let preview = await advisor.preview(offer)
        #expect(preview.blocked == nil && preview.pins == ["torchaudio==2.8.0"])
        #expect(offer.plan.invocation.arguments + preview.pins == ["-m", "pip", "install", "--upgrade", "torch==2.8.0", "torchaudio==2.8.0"])
    }

    /// A-R4: nothing runs without pip's dry run.
    @Test func noDryRunNoRun() async throws {
        let dir = site([("six", "1.16.0", [], false, false)])
        let py = Fixture.pythonOrg.executable
        let tools = ToolEnvironment(home: URL(fileURLWithPath: home), base: [:], runner: SwitchableRunner([
            "\(py) -c \(PythonSite.script)": CommandResult(status: 0, stdout: Data(#"{"path":["\#(dir.path)"],"markers":{}}"#.utf8), stderr: Data()),
            "\(py) -m pip --version": CommandResult(status: 0, stdout: Data("pip 21.2.4 from /x (python 3.13)\n".utf8), stderr: Data()),
        ]), isExecutable: { _ in true })
        let f = fixable(.pip(python: Fixture.pythonOrg, user: false, formula: nil), "six", .pypi, installed: "1.16.0", fixed: "1.17.0")
        let preview = await FixAdvisor(tools: tools, home: home).preview(try ok(plan(f, tools: tools)))
        #expect(preview.blocked == "nothing runs without pip's dry run, which could not say what would change")
    }

    /// A-R6, B-R5: REQUESTED marks are evidence; the ones a fix's command left are removed afterwards.
    @Test func theMarksAFixLeftAreRemoved() {
        let before = site([("starlette", "0.48.0", [], false, false), ("fastapi", "0.120.0", [], true, false)])
        let after = site([("starlette", "1.3.1", [], true, false), ("fastapi", "0.120.0", [], true, false), ("anyio", "5.0.0", [], true, false)])
        let b = PythonSite(folders: [before.path], markers: [:]), a = PythonSite(folders: [after.path], markers: [:])
        #expect(PipGuard.marksToClear(before: b, after: a) == ["starlette", "anyio"])
        #expect(Set(a.clearRequested(PipGuard.marksToClear(before: b, after: a))) == ["starlette", "anyio"])
        let now = PythonSite.scan(folders: [after.path])
        #expect(now.filter(\.requested).map(\.key) == ["fastapi"])                    // what the person asked for stays
        // a link named REQUESTED is not followed
        let linked = site([("x", "1.0", [], false, false)])
        let file = linked.appendingPathComponent("x-1.0.dist-info/REQUESTED")
        let elsewhere = temporaryDirectory().appendingPathComponent("keep")
        write("keep", to: elsewhere)
        try? FileManager.default.createSymbolicLink(at: file, withDestinationURL: elsewhere)
        var s = PythonSite(folders: [linked.path], markers: [:])
        s.distributions[0].requested = true
        #expect(s.clearRequested(["x"]).isEmpty && FileManager.default.fileExists(atPath: elsewhere.path))
    }

    /// B-R1, B-R2, B-R3: a finding is a file. The live copy is the first on sys.path; two records of one project in
    /// one folder are stale metadata, never a reason to run `pip uninstall`.
    @Test func aFindingIsAFile() {
        let user = site([("six", "1.17.0", [], false, false)]), system = site([("six", "1.16.0", [], false, false)])
        let s = PythonSite(folders: [user.path, system.path], markers: [:])
        #expect(s.live("six")?.version == "1.17.0" && s.copies.count == 2)
        guard case let .blocked(line, _) = PipGuard.verdict(s, pip: pip("six", "1.17.0", installed: "1.16.0")) else { Issue.record("shadowed copy"); return }
        #expect(line.hasPrefix("Python loads six 1.17.0 from ") && line.hasSuffix(", not this 1.16.0"))
        let stale = site([("pip", "25.0.1", [], false, false), ("pip", "26.2.2", [], false, false)])
        let t = PythonSite(folders: [stale.path], markers: [:])
        #expect(t.staleRecords("pip") == [stale.path])
        guard case let .blocked(why, _) = PipGuard.verdict(t, pip: pip("pip", "26.3", installed: "25.0.1")) else { Issue.record("stale records"); return }
        #expect(why.contains("stale metadata") && why.contains("pip would delete the live files"))
    }

    /// C-Rule 4: never a no-op as the fix. A formula that is already Homebrew's newest, or disabled, gets no button.
    @Test func noNoOpUpgrades() {
        let formula = FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "python@3.14", cask: false, versionIsTheFix: true, label: "python@3.14")
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "python@3.14", stable: "3.14.10", installed: "3.14.10"), for: formula, fixedVersion: "3.14.10")
            == .unavailable("3.14.10 is already Homebrew's newest python@3.14: brew upgrade would change nothing."))
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "python@3.14", stable: "3.14.10", installed: "3.14.10"), for: formula, fixedVersion: "3.14.11")
            == .unavailable("Homebrew still ships 3.14.10; the fix is 3.14.11 upstream."))
        guard case .unavailable = HomebrewAvailability.decide(HomebrewInfo(name: "python@3.9", stable: "3.9.25", installed: "3.9.24", disabled: true),
                                                               for: formula, fixedVersion: "3.9.25") else { Issue.record("disabled offered"); return }
    }
}

// MARK: - Runtime boundaries pip cannot see (rule 4.5)

@Suite struct RuntimeBoundaryTests {
    static let markers = PythonDependentsTests.markers
    func pip(_ name: String, _ target: String, installed: String) -> FixPlan.Pip {
        FixPlan.Pip(python: "/x/python", requirement: "\(name)==\(target)", user: false, name: name, target: target, installed: installed)
    }

    /// The owner's Python 3.11: the server's plan for torch targets 2.13; torchaudio pins torch and would move with it;
    /// the dry run and `pip check` are clean; pyannote.audio 3.3.2 then fails on import (torchaudio 2.9 removed
    /// AudioMetaData). Not offered, and one line says why.
    static func torchSite(withPyannote: Bool = true) -> PythonSite {
        var dists: [(String, String, [String], Bool, Bool)] = [
            ("torch", "2.7.0", [], true, false), ("torchaudio", "2.7.0", ["torch==2.7.0"], true, false),
            ("whisperx", "3.3.4", ["torch>=2", "torchaudio>=2", "pyannote.audio==3.3.2"], true, false),
        ]
        if withPyannote { dists.append(("pyannote.audio", "3.3.2", ["torch>=2.0.0", "torchaudio>=2.2.0", "lightning>=2.0.1"], false, false)) }
        return PythonSite(folders: [site(dists).path], markers: markers)
    }

    @Test func torchTo2Point13WithPyannoteIsRefused() {
        let s = Self.torchSite()
        guard case let .blocked(line, _) = PipGuard.verdict(s, pip: pip("torch", "2.13.0", installed: "2.7.0")) else { Issue.record("offered"); return }
        #expect(line == "torch 2.9 goes with torchaudio 2.9, which removed AudioMetaData — pyannote.audio 3.3.2 may rely on it")
        // and at the review, with torchaudio 2.13 from the dry run: refused all the same
        guard case let .blocked(review, _) = PipGuard.verdict(s, pip: pip("torch", "2.13.0", installed: "2.7.0"),
                                                               also: ["torch": "2.13.0", "torchaudio": "2.13.0"]) else { Issue.record("offered at review"); return }
        #expect(review.hasPrefix("torch 2.9") || review.hasPrefix("torchaudio 2.9 removed AudioMetaData"))
        // below the boundary it is offered, with torchaudio moving along, and the review names who to check
        #expect(PipGuard.verdict(s, pip: pip("torch", "2.8.0", installed: "2.7.0")) == .companions(["torchaudio"], s))
        let moving: Set = ["torch", "torchaudio"]
        #expect(PipGuard.users(of: moving, in: s, except: moving).map(\.name) == ["pyannote.audio", "whisperx"])
        #expect(PipGuard.beyondPatch(from: "2.7.0", to: "2.8.0") && !PipGuard.beyondPatch(from: "2.7.0", to: "2.7.1"))
    }

    @Test func theTableAndItsEdges() {
        #expect(RuntimeBoundaries.crossed("torchaudio", from: "2.8.0", to: "2.9.0")?.change == "removed AudioMetaData")
        #expect(RuntimeBoundaries.crossed("torchaudio", from: "2.9.0", to: "2.10.0") == nil)              // already past it
        #expect(RuntimeBoundaries.crossed("Huggingface_Hub", from: "0.36.0", to: "1.0") != nil)             // normal names, padding
        #expect(RuntimeBoundaries.crossed("setuptools", from: "80.9.0", to: "82.0.0")?.change == "removed pkg_resources")
        #expect(RuntimeBoundaries.crossed("setuptools", from: "78.1.1", to: "81.0.0") == nil)
        for (p, a, b) in [("starlette", "0.48.0", "1.3.1"), ("numpy", "1.26.4", "2.2.6"), ("pydantic", "1.10.13", "2.11.0"), ("urllib3", "1.26.20", "2.8.0"),
                          ("protobuf", "3.20.3", "5.29.6"), ("pyOpenSSL", "25.1.0", "26.2.0"), ("lightning", "2.5.6", "2.6.0"),
                          ("pytorch-lightning", "2.5.6", "2.6.6"), ("torch", "2.8.0", "2.13.0")] {
            #expect(RuntimeBoundaries.crossed(p, from: a, to: b) != nil, "\(p) \(a) → \(b)")
        }
        // Pillow 13 only matters with an imageio below 2.38.2
        let old = PythonSite(folders: [site([("imageio", "2.37.0", ["pillow>=8.3.2"], false, false), ("pillow", "12.2.0", [], false, false)]).path], markers: [:])
        let new = PythonSite(folders: [site([("imageio", "2.38.2", ["pillow>=8.3.2"], false, false), ("pillow", "12.2.0", [], false, false)]).path], markers: [:])
        #expect(RuntimeBoundaries.crossed("pillow", from: "12.2.0", to: "13.0.0", in: old) != nil)
        #expect(RuntimeBoundaries.crossed("pillow", from: "12.2.0", to: "13.0.0", in: new) == nil)
        // a boundary crossed by a package nothing depends on is fine
        let alone = PythonSite(folders: [site([("numpy", "1.26.4", [], true, false)]).path], markers: [:])
        guard case .clear = PipGuard.verdict(alone, pip: pip("numpy", "2.2.6", installed: "1.26.4")) else { Issue.record("numpy alone refused"); return }
    }

    /// certifi: calendar versions, used by requests; no boundary. Offered, and honest about who to check.
    @Test func certifiStaysOffered() {
        let s = PythonSite(folders: [site([("certifi", "2024.8.30", [], false, false), ("requests", "2.32.5", ["certifi>=2017.4.17"], true, false)]).path],
                           markers: Self.markers)
        guard case .clear = PipGuard.verdict(s, pip: pip("certifi", "2025.11.12", installed: "2024.8.30")) else { Issue.record("certifi refused"); return }
        #expect(PipGuard.beyondPatch(from: "2024.8.30", to: "2025.11.12"))
        #expect(PipGuard.users(of: ["certifi"], in: s).map(\.name) == ["requests"])
        let f = fixable(.pip(python: Fixture.pythonOrg, user: false, formula: nil), "certifi", .pypi, installed: "2024.8.30", fixed: "2025.11.12")
        #expect(FixOutcome.make(ending: .exited(0), before: f, recheck: .fixed(now: "2025.11.12"), homebrew: nil, check: PipGuard.usersLine(["requests"])).text
            == "Fixed — now 2025.11.12 · check requests still works")
        #expect(FixOutcome.fixedCheck(now: "2.8.0", users: "whisperx and pyannote.audio").text == "Fixed — now 2.8.0 · check whisperx and pyannote.audio still work")
        #expect(FixOutcome.fixedCheck(now: "2.8.0", users: "whisperx").isResolved)
        // a patch bump says nothing more
        #expect(!PipGuard.beyondPatch(from: "2024.8.30", to: "2024.8.31"))
    }

    /// starlette is still refused before it runs: its dependents' specifiers say so first.
    @Test func starletteIsStillRefused() {
        let s = PythonSite(distributions: PythonSite.read(folders: [PythonDependentsTests.before]), markers: Self.markers)
        guard case let .blocked(line, _) = PipGuard.verdict(s, pip: pip("starlette", "1.3.1", installed: "0.48.0")) else { Issue.record("offered"); return }
        #expect(line == "fastapi 0.120.0 needs starlette < 0.49.0, and 1 more — update them first")
    }
}

// MARK: - How a run in the app ended

@Suite struct FixEndingTests {
    let before = fixable(.homebrewFormula(name: "nginx"), "nginx", nil, installed: "1.30.2", fixed: "1.30.7")

    @Test func whatIsInstalledDecidesThenHowItEnded() {
        func make(_ e: FixEnding, _ r: OSVAKit.Scanner.Recheck) -> FixOutcome { FixOutcome.make(ending: e, before: before, recheck: r, homebrew: nil) }
        #expect(make(.exited(0), .fixed(now: "1.30.7")) == .fixed(now: "1.30.7"))
        #expect(make(.needsPassword, .fixed(now: "1.30.7")) == .fixed(now: "1.30.7"))
        #expect(make(.exited(1), .stillAffected(before)) == .exitedWithError(1))
        #expect(make(.stopped, .stillAffected(before)).text == "Stopped — still 1.30.2")
        #expect(make(.needsPassword, .stillAffected(before)) == .needsPassword)
        #expect(make(.signalled(9), .couldNotCheck("offline")) == .killed(9))
        #expect(make(.couldNotStart("No such file or directory"), .stillAffected(before)).text == "Could not start it: No such file or directory")
        #expect(make(.exited(0), .stillAffected(before)) == .stillAffected("still 1.30.2; the command did not change it"))
        #expect(FixOutcome.blocked("fastapi 0.120.0 needs starlette < 0.49.0").isProblem && !FixOutcome.undone("starlette 0.48.0").isProblem)
    }
}
