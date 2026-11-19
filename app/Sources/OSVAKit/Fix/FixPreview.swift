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

    public init(source: String?, lines: [String], unavailable: String? = nil) {
        self.source = source; self.lines = lines; self.unavailable = unavailable
    }

    public static func none(_ why: String) -> FixPreview { FixPreview(source: nil, lines: [], unavailable: why) }

    /// At most this many lines are shown; the rest are counted.
    public static let maxLines = 8
}

/// Runs the dry runs: each with the app's argv runner (no shell), its tool's update checks off, and a timeout.
public struct FixPreviewer: Sendable {
    let tools: ToolEnvironment
    public init(tools: ToolEnvironment) { self.tools = tools }

    public func preview(_ plan: FixPlan) async -> FixPreview {
        if let brew = plan.homebrew, plan.action == .upgrade { return await homebrew(brew) }
        if let pip = plan.pip { return await self.pip(pip) }
        if plan.action == .removal, plan.toolName == "pip" {
            return .none("pip lists what it removes and asks before it does, in the Terminal window.")
        }
        return .none("\(plan.toolName) has no dry run the app uses: the Terminal window shows what changes.")
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

    func pip(_ pip: FixPlan.Pip) async -> FixPreview {
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
            + (pip.user ? ["--user"] : []) + [pip.requirement]
        do {
            let r = try await tools.run(pip.python, args, timeout: 60)
            if r.status == 0 {
                let lines = Self.parsePipDryRun(String(decoding: r.stdout, as: UTF8.self))
                return FixPreview(source: "pip install --dry-run (asks PyPI, installs nothing)", lines: lines.isEmpty ? ["Nothing else would change."] : lines)
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
