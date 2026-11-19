import Foundation

/// An editor or a browser whose extensions are read: where it keeps them, which store's reports apply to them, and how
/// one is removed.
public enum ExtensionHost: String, Codable, Sendable, CaseIterable {
    case vscode, vscodeInsiders, cursor, vscodium, windsurf
    case chrome, brave, edge, arc, vivaldi
    case firefox

    public var title: String {
        switch self {
        case .vscode: return "VS Code"
        case .vscodeInsiders: return "VS Code Insiders"
        case .cursor: return "Cursor"
        case .vscodium: return "VSCodium"
        case .windsurf: return "Windsurf"
        case .chrome: return "Chrome"
        case .brave: return "Brave"
        case .edge: return "Edge"
        case .arc: return "Arc"
        case .vivaldi: return "Vivaldi"
        case .firefox: return "Firefox"
        }
    }

    public var isEditor: Bool { cli != nil }

    /// The store whose reports (the index's `M` lines) apply: VS Code installs from the Visual Studio Marketplace, its
    /// forks from Open VSX, Chromium browsers from the Chrome Web Store, Firefox from addons.mozilla.org. An ID means
    /// one thing in one store only: the same "publisher.name" on Open VSX may belong to someone else.
    public var store: String {
        switch self {
        case .vscode, .vscodeInsiders: return "vscode"
        case .cursor, .vscodium, .windsurf: return "openvsx"
        case .chrome, .brave, .edge, .arc, .vivaldi: return "chrome"
        case .firefox: return "firefox"
        }
    }

    /// The editor's own command-line tool, which removes an extension (`code --uninstall-extension`).
    public var cli: String? {
        switch self {
        case .vscode: return "code"
        case .vscodeInsiders: return "code-insiders"
        case .cursor: return "cursor"
        case .vscodium: return "codium"
        case .windsurf: return "windsurf"
        default: return nil
        }
    }

    /// Where a browser's extensions are removed, typed into its address bar.
    public var extensionsPage: String? {
        switch self {
        case .chrome, .arc: return "chrome://extensions"
        case .brave: return "brave://extensions"
        case .edge: return "edge://extensions"
        case .vivaldi: return "vivaldi://extensions"
        case .firefox: return "about:addons"
        default: return nil
        }
    }

    /// Where its extensions are, under the home folder: an editor's extensions folder, a browser's profiles folder.
    public var folder: String {
        switch self {
        case .vscode: return ".vscode/extensions"
        case .vscodeInsiders: return ".vscode-insiders/extensions"
        case .cursor: return ".cursor/extensions"
        case .vscodium: return ".vscode-oss/extensions"
        case .windsurf: return ".windsurf/extensions"
        case .chrome: return "Library/Application Support/Google/Chrome"
        case .brave: return "Library/Application Support/BraveSoftware/Brave-Browser"
        case .edge: return "Library/Application Support/Microsoft Edge"
        case .arc: return "Library/Application Support/Arc/User Data"
        case .vivaldi: return "Library/Application Support/Vivaldi"
        case .firefox: return "Library/Application Support/Firefox/Profiles"
        }
    }

    /// The store, named for a sentence ("Flagged by the Chrome Web Store").
    public static func storeTitle(_ store: String) -> String {
        switch store {
        case "vscode": return "the Visual Studio Marketplace"
        case "openvsx": return "Open VSX"
        case "chrome": return "the Chrome Web Store"
        case "firefox": return "addons.mozilla.org"
        default: return store
        }
    }
}

extension Origin {
    /// One browser's extension in several profiles, for one line: "Chrome extension · Work, Personal". Nil otherwise.
    static func profilesSummary(_ origins: [Origin]) -> String? {
        guard origins.count > 1, case let .addOn(host, _, _, _, _) = origins[0], !host.isEditor else { return nil }
        var profiles: [String] = []
        for o in origins {
            guard case let .addOn(h, _, _, profile, _) = o, h == host else { return nil }
            let p = profile ?? "default profile"
            if !profiles.contains(p) { profiles.append(p) }
        }
        let shown = profiles.prefix(3).joined(separator: ", ")
        return "\(host.title) extension · " + shown + (profiles.count > 3 ? " and \(profiles.count - 3) more" : "")
    }
}

/// An editor or browser extension, as found on this Mac. Stays on this Mac: extension IDs are never sent.
public struct InstalledExtension: Hashable, Codable, Sendable {
    public var host: ExtensionHost
    /// "publisher.name" for an editor's, the 32-letter ID for a Chromium browser's, the add-on ID for Firefox's.
    public var id: String
    /// The name its store shows ("GitLens — Git supercharged"), else its ID.
    public var name: String
    public var version: String
    /// A browser profile: its name ("Work") when the browser keeps one, else its folder ("Profile 1").
    public var profile: String?
    /// The extension's folder (Firefox: the profile's).
    public var path: String

    public init(host: ExtensionHost, id: String, name: String, version: String, profile: String?, path: String) {
        self.host = host; self.id = id; self.name = name; self.version = version; self.profile = profile; self.path = path
    }

    public var origin: Origin { .addOn(host: host, id: id, name: name, profile: profile, path: path) }

    /// The key of the index's `M` lines: "<store>\u{1F}<id>", the ID lowercased (stores compare IDs without case).
    public var maliciousKey: String { ProductIndex.maliciousKey(store: host.store, id: id) }
}

/// An app bundle in /Applications or ~/Applications, as its Info.plist describes it. Stays on this Mac: bundle
/// identifiers and paths are never sent; only a product key the public index itself lists can be.
public struct InstalledApp: Hashable, Codable, Sendable {
    /// The name Finder shows: the bundle's file name without ".app".
    public var name: String
    public var path: String
    public var bundleID: String?
    /// CFBundleShortVersionString, as written ("6.6.10 (69071)").
    public var shortVersion: String?
    /// CFBundleVersion, as written ("6.6.10.69071").
    public var bundleVersion: String?
    /// The Homebrew cask that installed it, if one did.
    public var caskToken: String?

    public init(name: String, path: String, bundleID: String?, shortVersion: String?, bundleVersion: String?, caskToken: String?) {
        self.name = name; self.path = path; self.bundleID = bundleID; self.shortVersion = shortVersion
        self.bundleVersion = bundleVersion; self.caskToken = caskToken
    }

    public var origin: Origin { .application(name: name, bundlePath: path, caskToken: caskToken) }
}
