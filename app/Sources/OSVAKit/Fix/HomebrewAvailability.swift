import Foundation

/// What Homebrew's data on this Mac says about one formula or cask, from `brew info --json=v2`.
public struct HomebrewInfo: Equatable, Sendable {
    public var name: String
    /// The version Homebrew would install now ("1.30.7"; a cask's "5.7.3,2320" is "5.7.3").
    public var stable: String?
    /// The version in use (the linked keg, else the newest installed; Homebrew's "_1" revision removed).
    public var installed: String?
    public var pinned: Bool
    public var disabled: Bool

    public init(name: String, stable: String?, installed: String?, pinned: Bool = false, disabled: Bool = false) {
        self.name = name; self.stable = stable; self.installed = installed; self.pinned = pinned; self.disabled = disabled
    }

    /// Reads `brew info --json=v2 --formula <name>` or `--cask <token>`. Nil if the answer does not describe it.
    public static func parse(_ data: Data, name: String, cask: Bool) -> HomebrewInfo? {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        if cask {
            guard let c = (root["casks"] as? [[String: Any]])?.first(where: { $0["token"] as? String == name }) else { return nil }
            func first(_ v: String?) -> String? { v.flatMap { $0.split(separator: ",", maxSplits: 1).first.map(String.init) } }
            return HomebrewInfo(name: name, stable: first(c["version"] as? String), installed: first(c["installed"] as? String),
                                disabled: c["disabled"] as? Bool ?? false)
        }
        guard let f = (root["formulae"] as? [[String: Any]])?.first(where: { $0["name"] as? String == name || $0["full_name"] as? String == name })
        else { return nil }
        let installed = (f["installed"] as? [[String: Any]] ?? []).compactMap { $0["version"] as? String }
        let linked = (f["linked_keg"] as? String).flatMap { installed.contains($0) ? $0 : nil }
        let inUse = linked ?? Core.shared.newestVersion(installed)
        return HomebrewInfo(name: name, stable: (f["versions"] as? [String: Any])?["stable"] as? String,
                            installed: inUse.map(HomebrewSource.upstreamVersion), pinned: f["pinned"] as? Bool ?? false,
                            disabled: f["disabled"] as? Bool ?? false)
    }
}

/// Whether Homebrew can bring the fix, decided before a `brew upgrade` is offered.
///
/// It reads Homebrew's data on this Mac, which can be out of date: `brew upgrade` refreshes it first (unless told not
/// to) and may then install something newer. Every line says where the answer comes from.
public enum HomebrewAvailability: Equatable, Sendable {
    /// Offer the Fix button; `line` says what Homebrew has (shown beside the word "Homebrew": "Has 1.30.7.").
    case available(line: String)
    /// No Fix button: Homebrew cannot bring the fix now, and why.
    case unavailable(String)
    /// `brew info` did not answer: the button is offered, and that is said.
    case unknown(String)

    public static let source = "From Homebrew's data on this Mac, which brew may refresh before it upgrades."

    /// The decision, from what `brew info` said. Versions are compared by the verified core.
    public static func decide(_ info: HomebrewInfo, for plan: FixPlan.Homebrew, fixedVersion: String?) -> HomebrewAvailability {
        let what = plan.cask ? "the \(info.name) cask" : info.name
        if info.disabled { return .unavailable("Homebrew has disabled \(what): brew will not install it.") }
        if info.pinned { return .unavailable("\(info.name) is pinned in Homebrew, so brew upgrade leaves it as it is. Unpin it first: brew unpin \(info.name).") }
        guard let stable = info.stable, !stable.isEmpty else { return .unknown("Homebrew's data on this Mac has no version of \(what).") }
        let core = Core.shared
        if plan.versionIsTheFix, let fixed = fixedVersion {
            if core.compareVersions(stable, fixed) < 0 {
                return .unavailable("Homebrew still ships \(stable); the fix is \(fixed) upstream.")
            }
            // never a no-op as the fix: brew upgrade of what is already Homebrew's newest changes nothing
            if let installed = info.installed, core.compareVersions(stable, installed) <= 0 {
                return .unavailable("\(installed) is already Homebrew's newest \(what): brew upgrade would change nothing.")
            }
            return .available(line: "Has \(stable).")
        }
        // A cask or formula that carries the vulnerable thing: Homebrew can only tell whether there is a newer one.
        if let installed = info.installed, core.compareVersions(stable, installed) <= 0 {
            return .unavailable("Homebrew has no newer \(plan.label) than \(installed), the one installed.")
        }
        let from = info.installed.map { "; \($0) is installed" } ?? ""
        return .available(line: "Has \(plan.label) \(stable)\(from). Whether that brings the fix shows when the app checks again.")
    }
}

/// Runs `brew info` for one formula or cask: local and read-only (no update, no analytics).
public struct HomebrewInfoReader: Sendable {
    let tools: ToolEnvironment
    public init(tools: ToolEnvironment) { self.tools = tools }

    public func read(_ plan: FixPlan.Homebrew) async -> Result<HomebrewInfo, HomebrewInfoError> {
        var last = ""
        for extra in HomebrewInfoReader.attempts {
            do {
                let r = try await tools.run(plan.brew, ["info", "--json=v2", plan.cask ? "--cask" : "--formula", plan.name], extra: extra, timeout: 60)
                if r.status == 0, let info = HomebrewInfo.parse(r.stdout, name: plan.name, cask: plan.cask) { return .success(info) }
                last = r.errorText.isEmpty ? "brew exited with \(r.status)" : r.errorText
            } catch {
                last = error.localizedDescription
            }
        }
        return .failure(HomebrewInfoError(message: String(last.prefix(200))))
    }

    /// As `HomebrewSource` reads it: the downloaded API data unless it is more than a week old, then the local taps
    /// (for an installation another user owns, or a Mac that is offline).
    static let attempts: [[String: String]] = [["HOMEBREW_API_AUTO_UPDATE_SECS": "604800"], ["HOMEBREW_NO_INSTALL_FROM_API": "1"]]

    /// The decision, or `.unknown` with the reason when brew did not answer.
    public func availability(_ plan: FixPlan.Homebrew, fixedVersion: String?) async -> HomebrewAvailability {
        switch await read(plan) {
        case let .success(info): return HomebrewAvailability.decide(info, for: plan, fixedVersion: fixedVersion)
        case let .failure(e): return .unknown("Could not read Homebrew's data (\(e.message)).")
        }
    }
}

public struct HomebrewInfoError: Error, Equatable, Sendable { public var message: String }
