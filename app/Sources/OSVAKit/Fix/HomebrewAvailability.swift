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
    /// A cask's install and uninstall steps, when its record lists them.
    public var artifacts: CaskArtifacts?

    public init(name: String, stable: String?, installed: String?, pinned: Bool = false, disabled: Bool = false, artifacts: CaskArtifacts? = nil) {
        self.name = name; self.stable = stable; self.installed = installed; self.pinned = pinned; self.disabled = disabled; self.artifacts = artifacts
    }

    /// Reads `brew info --json=v2 --formula <name>` or `--cask <token>`. Nil if the answer does not describe it.
    public static func parse(_ data: Data, name: String, cask: Bool) -> HomebrewInfo? {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        if cask {
            guard let c = (root["casks"] as? [[String: Any]])?.first(where: { $0["token"] as? String == name }) else { return nil }
            func first(_ v: String?) -> String? { v.flatMap { $0.split(separator: ",", maxSplits: 1).first.map(String.init) } }
            return HomebrewInfo(name: name, stable: first(c["version"] as? String), installed: first(c["installed"] as? String),
                                disabled: c["disabled"] as? Bool ?? false, artifacts: (c["artifacts"] as? [Any]).map(CaskArtifacts.init))
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

/// What a cask's record says it installs and removes: the apps it moves into place, and the steps that run as root
/// (brew runs them with sudo, which the app never answers). Read from `brew info --json=v2 --cask`'s `artifacts`.
public struct CaskArtifacts: Equatable, Sendable {
    /// The app bundles it installs ("OpenMTP.app").
    public var apps: [String] = []
    /// Steps that need an administrator's password whatever this Mac has: "an installer package", "a kernel extension".
    public var privileged: [String] = []
    /// launchd services its uninstall stops: root's only when installed system-wide (/Library/LaunchDaemons or
    /// /Library/LaunchAgents), which the reader looks at.
    public var services: [String] = []

    public init(apps: [String] = [], privileged: [String] = [], services: [String] = []) {
        self.apps = apps; self.privileged = privileged; self.services = services
    }

    /// From the `artifacts` list: `app`, `pkg` and `installer` entries, and `uninstall` and `zap` steps that run as root
    /// (`kext`, `pkgutil`, `launchctl` of a system service, `delete` outside the home folder, a `script` with sudo).
    public init(_ artifacts: [Any]) {
        func add(_ what: String) { if !privileged.contains(what) { privileged.append(what) } }
        func strings(_ v: Any?) -> [String] { (v as? String).map { [$0] } ?? (v as? [Any])?.compactMap { $0 as? String } ?? [] }
        for case let entry as [String: Any] in artifacts {
            for (kind, value) in entry {
                switch kind {
                case "app": apps += strings(value).filter { $0.hasSuffix(".app") && !$0.contains("/") }
                case "pkg": add("an installer package")
                case "installer": add("an installer")
                case "artifact":
                    // a folder moved into the machine's own (a JDK into /Library/Java/JavaVirtualMachines): brew uses sudo
                    let targets = (value as? [Any] ?? []).compactMap { ($0 as? [String: Any])?["target"] as? String }
                    if targets.contains(where: { $0.hasPrefix("/Library/") || $0.hasPrefix("/System/") }) { add("files outside your home folder") }
                case "uninstall", "zap":
                    for case let step as [String: Any] in (value as? [Any]) ?? [value] {
                        if step["kext"] != nil { add("a kernel extension") }
                        if step["pkgutil"] != nil { add("installer receipts") }
                        services += strings(step["launchctl"])
                        if strings(step["delete"]).contains(where: { !$0.hasPrefix("~/") }) { add("files outside your home folder") }
                        for key in ["script", "early_script"] {
                            if let script = step[key] as? [String: Any], script["sudo"] as? Bool == true { add("a script run as root") }
                        }
                    }
                default: break
                }
            }
        }
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
    /// The upgrade would change the app, but runs a step as root (an installer, a kernel extension, an app bundle this
    /// user cannot write): it needs an administrator's password, which the app never handles. Terminal only.
    case needsPassword(String)

    /// What a row says when a cask's upgrade needs a password.
    public static let passwordLine = "Needs your administrator password"

    public static let source = "From Homebrew's data on this Mac, which brew may refresh before it upgrades."

    /// The decision, from what `brew info` said. Versions are compared by the verified core.
    ///
    /// For a cask, the version installed is the app bundle's own (`bundleVersion`, its CFBundleShortVersionString), not
    /// the cask record's: an app that updates itself leaves the record behind (Dropbox 280.4 with a record of 236.4), and
    /// `brew upgrade` of an app already at Homebrew's newest changes nothing (research rules C-4, C-7, 5.2). `electron`:
    /// the Electron the app ships, for the line. `root`: why the upgrade needs an administrator's password, if it does.
    public static func decide(_ info: HomebrewInfo, for plan: FixPlan.Homebrew, fixedVersion: String?, bundleVersion: String? = nil,
                              electron: String? = nil, root: String? = nil) -> HomebrewAvailability {
        let what = plan.cask ? "the \(info.name) cask" : info.name
        if info.disabled { return .unavailable("Homebrew has disabled \(what): brew will not install it.") }
        if info.pinned { return .unavailable("\(info.name) is pinned in Homebrew, so brew upgrade leaves it as it is. Unpin it first: brew unpin \(info.name).") }
        guard let rawStable = info.stable, !rawStable.isEmpty else { return .unknown("Homebrew's data on this Mac has no version of \(what).") }
        let core = Core.shared
        // OpenJDK's formulae write Java's versions their own way (openjdk@8 is "1.8.0-512"); the finding has them as
        // Java names them (8u512): both are compared in Java's canonical form.
        let java = !plan.cask && JavaVersion.isHomebrewFormula(info.name)
        func comparable(_ v: String) -> String { java ? JavaVersion.canonical(v) ?? v : v }
        func said(_ v: String) -> String { java ? JavaVersion.shown(v) : v }
        let stable = comparable(rawStable), fixedVersion = fixedVersion.map(comparable)
        var info = info
        info.installed = info.installed.map(comparable)
        if plan.cask {
            if plan.versionIsTheFix, let fixed = fixedVersion, core.compareVersions(stable, fixed) < 0 {
                return .unavailable("Homebrew still ships \(stable); the fix is \(fixed) upstream.")
            }
            if let installed = bundleVersion ?? info.installed, core.compareVersions(stable, installed) <= 0 {
                return .unavailable(newestInstalled(electron: electron))
            }
            if let root { return .needsPassword("\(passwordLine): \(root).") }
            let from = (bundleVersion ?? info.installed).map { "; \($0) is installed" } ?? ""
            if plan.versionIsTheFix { return .available(line: "Has \(stable)\(from).") }
            return .available(line: "Has \(plan.label) \(stable)\(from). Whether that brings the fix shows when the app checks again.")
        }
        if plan.versionIsTheFix, let fixed = fixedVersion {
            if core.compareVersions(stable, fixed) < 0 {
                return .unavailable("Homebrew still ships \(said(stable)); the fix is \(said(fixed)) upstream.")
            }
            // never a no-op as the fix: brew upgrade of what is already Homebrew's newest changes nothing
            if let installed = info.installed, core.compareVersions(stable, installed) <= 0 {
                return .unavailable("\(said(installed)) is already Homebrew's newest \(what): brew upgrade would change nothing.")
            }
            return .available(line: "Has \(said(stable)).")
        }
        // A cask or formula that carries the vulnerable thing: Homebrew can only tell whether there is a newer one.
        if let installed = info.installed, core.compareVersions(stable, installed) <= 0 {
            return .unavailable("Homebrew has no newer \(plan.label) than \(said(installed)), the one installed.")
        }
        let from = info.installed.map { "; \(said($0)) is installed" } ?? ""
        return .available(line: "Has \(plan.label) \(said(stable))\(from). Whether that brings the fix shows when the app checks again.")
    }

    /// "Newest version installed; no fixed release yet. It still ships Electron 18.3.15."
    public static func newestInstalled(electron: String?) -> String {
        "Newest version installed; no fixed release yet." + (electron.map { " It still ships \($0)." } ?? "")
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

    /// The decision, or `.unknown` with the reason when brew did not answer. For a cask, the app bundle on disk is read
    /// too: its own version, whether this user can replace it, and which of its record's services run system-wide.
    public func availability(_ plan: FixPlan.Homebrew, fixedVersion: String?) async -> HomebrewAvailability {
        switch await read(plan) {
        case let .success(info):
            guard plan.cask else { return HomebrewAvailability.decide(info, for: plan, fixedVersion: fixedVersion) }
            let bundle = plan.bundle ?? info.artifacts?.apps.lazy.compactMap { app in
                [tools.system("/Applications/" + app), tools.expand("~/Applications/" + app)].first { FileManager.default.fileExists(atPath: $0) }
            }.first
            return HomebrewAvailability.decide(info, for: plan, fixedVersion: fixedVersion, bundleVersion: bundle.flatMap(Self.bundleVersion),
                                               electron: plan.electron, root: root(info.artifacts, bundle: bundle))
        case let .failure(e): return .unknown("Could not read Homebrew's data (\(e.message)).")
        }
    }

    /// An app bundle's CFBundleShortVersionString, as a version ("6.6.10 (69071)" is 6.6.10).
    public static func bundleVersion(_ bundle: String) -> String? {
        let plist = (bundle as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = FileManager.default.contents(atPath: plist), data.count <= 4 << 20,
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let short = info["CFBundleShortVersionString"] as? String else { return nil }
        return VersionText.leading(short)
    }

    /// Why a cask's upgrade needs root, if it does: its record's steps, a launchd service installed system-wide, or an
    /// app bundle this user cannot replace.
    func root(_ artifacts: CaskArtifacts?, bundle: String?) -> String? {
        // the step a person knows by name first: a cask whose uninstall forgets receipts also runs an installer package
        let steps = artifacts?.privileged ?? []
        if let first = steps.first(where: { $0.hasPrefix("an installer") }) ?? steps.first { return "its update runs \(first)" }
        let services = artifacts?.services ?? []
        if services.contains(where: { s in FixSafety.isSafeName(s) && ["/Library/LaunchDaemons/", "/Library/LaunchAgents/"].contains {
            FileManager.default.fileExists(atPath: tools.system($0 + s + ".plist")) } }) {
            return "its update stops a system service"
        }
        if let bundle, FileManager.default.fileExists(atPath: bundle), !FileManager.default.isWritableFile(atPath: bundle) {
            return "this user cannot replace the app"
        }
        return nil
    }
}

public struct HomebrewInfoError: Error, Equatable, Sendable { public var message: String }
