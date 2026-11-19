import Foundation

/// What else a fix will change, as the tool itself tells it without changing anything: `brew upgrade --dry-run` (the
/// dependencies and dependents that would upgrade too) and `pip install --dry-run` (pip 22.2 and later). Tools without
/// a dry run the app trusts are said to have none.
public struct FixPreview: Equatable, Sendable {
    /// "brew upgrade --dry-run", "pip install --dry-run".
    public var source: String?
    /// What the tool says would change, one line each ("Would upgrade 1 outdated package: nginx 1.30.2 → 1.30.7").
    public var lines: [String]
    /// Why there is no preview, when there is none.
    public var unavailable: String?
    /// pip's dry run: every package it would install, by normal name, and the version.
    public var installs: [String: String]
    /// Something installed depends on a version the dry run would replace: the line that says so. Nothing runs.
    public var blocked: String?
    /// For pip: every other package the dry run would install, pinned ("torchaudio==2.8.0"). They go on the command
    /// line after the fix's own pin, so the run installs exactly what the review showed.
    public var pins: [String] = []
    /// For an upgrade beyond a patch: the installed packages that use what changes ("whisperx", "pyannote.audio"),
    /// for the review's "Used by" line. pip's checks cannot tell whether they still work.
    public var usedBy: [String] = []
    /// For a set of pip changes (an upgrade together, a batch): what its dry run's report said each would be, the new
    /// versions' own requirements included, for the end-state check just before it runs.
    public var report: [PythonDistribution] = []
    /// The names pip asked PyPI about, when the dry run named more than the finding's own package.
    public var asks: [String] = []

    public init(source: String?, lines: [String], unavailable: String? = nil, installs: [String: String] = [:], blocked: String? = nil,
                pins: [String] = [], usedBy: [String] = []) {
        self.source = source; self.lines = lines; self.unavailable = unavailable; self.installs = installs; self.blocked = blocked; self.pins = pins
        self.usedBy = usedBy
    }

    /// The other packages it would change, by name: "openssl@3" for a `brew upgrade nginx` that also upgrades it.
    public func others(than name: String) -> [String] {
        if !installs.isEmpty {
            return installs.keys.filter { $0 != PythonNames.normal(name) }.sorted()
        }
        return lines.filter { $0.contains(" → ") }.compactMap { $0.split(separator: " ").first.map(String.init) }.filter { $0 != name }
    }

    public static func none(_ why: String) -> FixPreview { FixPreview(source: nil, lines: [], unavailable: why) }

    /// At most this many lines are shown; the rest are counted.
    public static let maxLines = 8
}

/// Runs the dry runs: each with the app's argv runner (no shell), its tool's update checks off, and a timeout.
public struct FixPreviewer: Sendable {
    let tools: ToolEnvironment
    public init(tools: ToolEnvironment) { self.tools = tools }

    public func preview(_ plan: FixPlan, companions: [String] = []) async -> FixPreview {
        if let brew = plan.homebrew, plan.action == .upgrade { return await homebrew(brew) }
        if let pip = plan.pip { return await self.pip(pip, companions: companions.filter(FixSafety.isSafeName)) }
        if plan.action == .removal, plan.toolName == "pip" {
            return .none("pip has no dry run for a removal: the log shows what it removes.")
        }
        return .none("\(plan.toolName) has no dry run the app uses: the log shows what changes.")
    }

    // MARK: Homebrew

    func homebrew(_ brew: FixPlan.Homebrew) async -> FixPreview {
        let args = ["upgrade"] + (brew.cask ? ["--cask"] : []) + ["--dry-run", brew.name]
        var last = ""
        for extra in HomebrewInfoReader.attempts {
            do {
                let r = try await tools.run(brew.brew, args, extra: extra, timeout: 60)
                let text = String(decoding: r.stdout + Data("\n".utf8) + r.stderr, as: UTF8.self)
                if r.status == 0 {
                    let lines = Self.parseBrewDryRun(text)
                    return FixPreview(source: "brew upgrade --dry-run", lines: lines.isEmpty ? ["Nothing else would change."] : lines)
                }
                last = r.errorText.isEmpty ? "brew exited with \(r.status)" : r.errorText
            } catch {
                last = error.localizedDescription
            }
        }
        return .none("brew's dry run did not answer (\(String(last.prefix(160)))).")
    }

    /// `brew upgrade --dry-run`: "==> Would upgrade 1 outdated package:" headings with their items under them, and
    /// warnings ("Warning: nginx 1.30.7 already installed"). A heading becomes a line ending in ":", each item a line
    /// of its own ("nginx 1.30.2 → 1.30.7"); anything else (download notices, hints) is left out.
    public static func parseBrewDryRun(_ text: String) -> [String] {
        var out: [String] = []
        var inSection = false
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("==> ") {
                let h = String(line.dropFirst(4)).trimmingCharacters(in: CharacterSet(charactersIn: ": "))
                inSection = h.hasPrefix("Would")
                if inSection { out.append(h + ":") }
            } else if line.hasPrefix("Warning: ") {
                inSection = false
                out.append(String(line.dropFirst("Warning: ".count)))
            } else if inSection, !line.isEmpty {
                // "nginx 1.30.2 -> 1.30.7", or a cask's column-aligned "slack   4.51.1 -> 4.52.0"
                out.append(line.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ").replacingOccurrences(of: " -> ", with: " → "))
            }
        }
        return out
    }

    // MARK: pip

    func pip(_ pip: FixPlan.Pip, companions: [String] = []) async -> FixPreview {
        let version: String
        do {
            let r = try await tools.run(pip.python, ["-m", "pip", "--version"], timeout: 30)
            guard r.status == 0, let v = Self.pipVersion(String(decoding: r.stdout, as: UTF8.self)) else {
                return .none("pip did not say its version, so the app did not ask it for a dry run.")
            }
            version = v
        } catch {
            return .none("pip did not answer (\(error.localizedDescription)).")
        }
        guard Core.shared.compareVersions(version, "22.2") >= 0 else {
            return .none("This pip (\(version)) has no dry run: pip 22.2 added it.")
        }
        // --only-binary: working out what a source release needs would run its build code, which a preview must not do.
        let args = ["-m", "pip", "install", "--dry-run", "--only-binary=:all:", "--upgrade", "--disable-pip-version-check", "--no-input"]
            + (pip.user ? ["--user"] : []) + [pip.requirement] + companions
        do {
            let r = try await tools.run(pip.python, args, timeout: 60)
            if r.status == 0 {
                let text = String(decoding: r.stdout, as: UTF8.self)
                let lines = Self.parsePipDryRun(text)
                return FixPreview(source: "pip install --dry-run (asks PyPI, installs nothing)", lines: lines.isEmpty ? ["Nothing else would change."] : lines,
                                  installs: Self.pipDryRunInstalls(text))
            }
            let err = r.errorText
            if err.contains("No matching distribution") || err.contains("only-binary") {
                return .none("pip could not work out what changes without building from source, which a preview does not do.")
            }
            let first = err.split(whereSeparator: \.isNewline).first.map(String.init) ?? "exit status \(r.status)"
            return .none("pip's dry run failed: \(String(first.prefix(160)))")
        } catch {
            return .none("pip's dry run did not answer (\(error.localizedDescription)).")
        }
    }

    /// "pip 24.0 from /…/site-packages/pip (python 3.12)" is "24.0".
    public static func pipVersion(_ text: String) -> String? {
        let words = text.split(separator: " ")
        guard words.count >= 2, words[0] == "pip" else { return nil }
        let v = String(words[1])
        return FixSafety.isSafeVersion(v) ? v : nil
    }

    /// "Would install urllib3-2.8.0 idna-3.10" is ["urllib3": "2.8.0", "idna": "3.10"] (normal names).
    public static func pipDryRunInstalls(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("Would install ") else { continue }
            for item in line.dropFirst("Would install ".count).split(separator: " ") {
                guard let dash = item.lastIndex(of: "-") else { continue }
                out[PythonNames.normal(String(item[..<dash]))] = String(item[item.index(after: dash)...])
            }
        }
        return out
    }

    /// "Would install urllib3-2.8.0 idna-3.10" is "Would install urllib3 2.8.0, idna 3.10".
    public static func parsePipDryRun(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("Would install ") else { return nil }
            let items = line.dropFirst("Would install ".count).split(separator: " ").map { item -> String in
                guard let dash = item.lastIndex(of: "-") else { return String(item) }
                return item[..<dash] + " " + item[item.index(after: dash)...]
            }
            return "Would install " + items.joined(separator: ", ")
        }
    }
}
