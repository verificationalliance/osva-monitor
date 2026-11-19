import Foundation
import Security

/// Which apps something else keeps up to date: web apps a Chromium browser installed, apps from the Mac App Store,
/// and Apple's own. Nothing here checks them either; they are told apart so "not checked" lists only the apps nobody
/// is known to look after.
///
/// What an app says about itself is not taken on trust: anyone can name a bundle "com.apple.something" or ship a
/// receipt file. An App Store app must carry the Mac App Store's signature, and an Apple app Apple's: the Security
/// framework checks the bundle's signature and who signed it, without hashing every page of the executable (Kindle's
/// is 256 MB, WhatsApp's 485 MB) or its resources. A doctored executable under a genuine signature would pass, and
/// then be listed as kept up to date by the App Store instead of as having no security record: neither list says an
/// app was checked.
enum AppKeepers {
    /// Chromium browsers' bundle identifiers, and what each is called.
    static let browsers: [(id: String, title: String)] = [
        ("com.google.Chrome", "Chrome"), ("com.microsoft.edgemac", "Edge"), ("com.brave.Browser", "Brave"),
        ("com.vivaldi.Vivaldi", "Vivaldi"), ("org.chromium.Chromium", "Chromium"),
    ]

    /// The Mac App Store's signature: Apple's chain, and the leaf only the App Store signs with.
    static let appStoreRequirement = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"
    /// Apple's own code.
    static let appleRequirement = "anchor apple"

    static func keeper(of bundle: URL, plist: [String: Any], bundleID: String?) -> (keeper: AppKeeper?, name: String?) {
        if let browser = webAppBrowser(plist: plist, bundleID: bundleID) {
            return (.browser(browser), webAppName(plist))
        }
        let receipt = BoundedFile.size(bundle.appendingPathComponent("Contents/_MASReceipt/receipt")) != nil
        if receipt, satisfies(bundle, appStoreRequirement) || satisfies(bundle, appleRequirement) { return (.appStore, nil) }
        if bundleID?.hasPrefix("com.apple.") == true, satisfies(bundle, appleRequirement) { return (.macOS, nil) }
        return (nil, nil)
    }

    /// The browser a web-app shim belongs to: Chromium writes CrAppModeShortcutID and the browser's identifier
    /// (CrBundleIdentifier) into the shim, and names it "<browser id>.app.<32-letter app id>".
    static func webAppBrowser(plist: [String: Any], bundleID: String?) -> String? {
        let browserID = (plist["CrBundleIdentifier"] as? String) ?? bundleID
        let isShim = plist["CrAppModeShortcutID"] is String
            || (bundleID.map { id in browsers.contains { id.hasPrefix($0.id + ".") } && appIDPattern.test(id) } ?? false)
        guard isShim else { return nil }
        return browsers.first { browserID?.hasPrefix($0.id) == true }?.title ?? "Chromium"
    }

    /// Its own name, never its file's ("Default beimhnaefocolcplfimocfiaiefpkgbf") nor its ID: the shortcut's name,
    /// the bundle's display name or name, whichever names it, else the site it opens.
    static func webAppName(_ plist: [String: Any]) -> String {
        for key in ["CrAppModeShortcutName", "CFBundleDisplayName", "CFBundleName"] {
            if let name = Documents.string(plist, key, max: 80), !appIDPattern.test(name) { return name }
        }
        if let url = (plist["CrAppModeShortcutURL"] as? String).flatMap(URL.init(string:)), let host = url.host, !host.isEmpty {
            return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
        }
        return "Unnamed web app"
    }

    /// A Chromium app ID: 32 letters a to p.
    private static let appIDPattern = Regex("[a-p]{32}")

    /// Whether the bundle's code signature is valid and its signer meets the requirement (pages and resources not
    /// hashed, as above).
    static func satisfies(_ bundle: URL, _ requirement: String) -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundle as CFURL, SecCSFlags(), &code) == errSecSuccess, let code else { return false }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &req) == errSecSuccess, let req else { return false }
        let flags = SecCSFlags(rawValue: kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources)
        return SecStaticCodeCheckValidity(code, flags, req) == errSecSuccess
    }
}
