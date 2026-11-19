import Foundation

/// What runs for a fix: one program, its arguments, and the folder it starts in. No shell is involved anywhere: the
/// program is started directly with this argument list (`FixProcess`), so nothing in an argument is ever read as code.
public struct FixInvocation: Hashable, Sendable {
    /// An absolute path: the tool the plan found on this Mac.
    public var executable: String
    /// argv[1…], each exactly one argument.
    public var arguments: [String]
    /// A project folder for a project's tool; nil runs in "/", where nothing the user can write is picked up as config
    /// (a `package.json`, a `.cargo/config.toml`, a module next to `python -m`).
    public var directory: String?

    public init(executable: String, arguments: [String], directory: String? = nil) {
        self.executable = executable; self.arguments = arguments; self.directory = directory
    }

    public var argv: [String] { [executable] + arguments }

    /// The words as a person would type them: quoted only where the shell needs it ("-g" stays as it is).
    public var display: String {
        argv.map { w in
            w.unicodeScalars.allSatisfy({ ShellWords.plain.contains($0) }) && !w.isEmpty && !w.hasPrefix("=") ? w : UpgradeCommand.quote(w)
        }.joined(separator: " ")
    }

    /// The invocation the shown command stands for, or nil if the command is not exactly one the app can run that way.
    ///
    /// The command's words are read by `ShellWords`, which accepts only the quoting `UpgradeCommand.quote` writes and
    /// reads it as sh and zsh do. Its first word must be the plan's tool, by its path or by its plain name (`brew`,
    /// `npm`), and the tool runs from the path the plan found; a `cd <folder> &&` before it must name exactly the
    /// project folder the finding recorded.
    public static func make(command: String, toolPath: String, folder: String?, home: String) -> FixInvocation? {
        guard toolPath.hasPrefix("/"), let line = ShellWords.read(command, home: home), let tool = line.words.first else { return nil }
        let toolName = (toolPath as NSString).lastPathComponent
        guard tool == toolPath || (!tool.contains("/") && tool == toolName) else { return nil }
        guard line.directory == folder else { return nil }
        return FixInvocation(executable: toolPath, arguments: Array(line.words.dropFirst()), directory: folder)
    }
}

/// The words of a command line, read exactly as sh and zsh read it, for the one form the app writes and nothing else:
///
///     [cd <word> && ]<word> <word> …
///
/// words separated by single spaces, each made of
///   - plain characters, `A-Z a-z 0-9 @ % + = : , . / _ -` (a word may not start with "=": zsh would expand it),
///   - single-quoted text, `'…'`, which may hold anything but a single quote,
///   - `\'`, a single quote,
/// and, for the folder after `cd` only, a leading `~/`, which is the home directory. In this form neither shell
/// expands, splits, globs or substitutes anything, so the words read here are the arguments the shell would pass.
/// Anything else (another operator, a `$`, a glob, a double quote, two spaces, a control character) gives nil.
public enum ShellWords {
    public struct Line: Equatable, Sendable {
        /// The folder of a leading `cd <folder> &&`, with `~/` expanded.
        public var directory: String?
        public var words: [String]
    }

    static let plain = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-".unicodeScalars)

    public static func read(_ line: String, home: String) -> Line? {
        var rest = Substring(line)
        var directory: String?
        if rest.hasPrefix("cd ") {
            rest = rest.dropFirst(3)
            var expandHome = false
            if rest.hasPrefix("~/") {
                guard !home.isEmpty, home.hasPrefix("/") else { return nil }
                expandHome = true
                rest = rest.dropFirst(2)
            }
            guard let (folder, after) = word(rest), after.hasPrefix(" && ") else { return nil }
            directory = expandHome ? (home.hasSuffix("/") ? home : home + "/") + folder : folder
            guard directory!.hasPrefix("/") else { return nil }
            rest = after.dropFirst(4)
        }
        var words: [String] = []
        while true {
            guard let (w, after) = word(rest) else { return nil }
            words.append(w)
            if after.isEmpty { break }
            guard after.hasPrefix(" "), !after.dropFirst().isEmpty else { return nil }
            rest = after.dropFirst()
        }
        return Line(directory: directory, words: words)
    }

    /// One word at the start of `s`, and what follows it (empty, or starting with a space).
    static func word(_ s: Substring) -> (String, Substring)? {
        var out = String.UnicodeScalarView()
        var scalars = s.unicodeScalars[...]
        guard let first = scalars.first, first != "=", first != " " else { return nil }      // no empty word, no "=word"
        while let c = scalars.first, c != " " {
            if c == "'" {
                scalars = scalars.dropFirst()
                guard let close = scalars.firstIndex(of: "'") else { return nil }
                out.append(contentsOf: scalars[..<close])
                scalars = scalars[scalars.index(after: close)...]
            } else if c == "\\" {
                scalars = scalars.dropFirst()
                guard scalars.first == "'" else { return nil }
                out.append("'")
                scalars = scalars.dropFirst()
            } else if plain.contains(c) {
                out.append(c)
                scalars = scalars.dropFirst()
            } else {
                return nil
            }
        }
        return (String(out), Substring(scalars))
    }
}

/// The environment a fix runs in: the tools' own (`ToolEnvironment.environment(for:)`: the tool's folder first on
/// PATH, then Homebrew's and the system's; colour, analytics and update notices off), adjusted for a real change made
/// with nobody at a keyboard:
///   - nothing can ask a question that would wait for ever: no askpass program for sudo, ssh or git, git told not to
///     prompt, pip told there is no input, npm told to answer no;
///   - Homebrew refreshes its data before it upgrades, as when the command is typed (the app's read-only listings
///     turn that off; an upgrade needs current data);
///   - output is plain and unbuffered (TERM=dumb, PYTHONUNBUFFERED), so the log shows it as it happens;
///   - CI=1 for npm, pip and cargo, which then print no spinners and ask nothing. Not for Homebrew, whose behaviour CI
///     changes, nor yarn or pnpm, which refuse to change a lockfile under CI.
public enum FixEnvironment {
    public static let removed = ["SUDO_ASKPASS", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "GIT_ASKPASS", "DISPLAY",
                                 "HOMEBREW_NO_AUTO_UPDATE", "NPM_CONFIG_LOGS_MAX"]
    public static let ciTools: Set<String> = ["npm", "pip", "cargo"]

    public static func make(tools: ToolEnvironment, executable: String, toolName: String) -> [String: String] {
        var env = tools.environment(for: executable)
        for key in removed { env.removeValue(forKey: key) }
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["PIP_NO_INPUT"] = "1"
        env["PIP_PROGRESS_BAR"] = "off"
        env["npm_config_yes"] = "false"
        env["HOMEBREW_NO_ENV_HINTS"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["TERM"] = "dumb"
        if ciTools.contains(toolName) { env["CI"] = "1" }
        return env
    }
}
