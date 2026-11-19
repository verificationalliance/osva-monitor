import CryptoKit
import Foundation
import Testing
@testable import OSVARelease

/// The update settings the app is built with (app/Resources/Info.plist), and how scripts/build-app.sh signs Sparkle.
@Suite struct InfoPlistTests {
    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../..").standardized

    static var plist: [String: Any] {
        let data = try! Data(contentsOf: root.appendingPathComponent("app/Resources/Info.plist"))
        return try! PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
    }

    @Test func updatesComeFromTheSignedFeed() {
        let p = Self.plist
        #expect(p["SUFeedURL"] as? String == "https://verificationalliance.org/app/appcast.xml")
        #expect(p["SUFeedURL"] as? String == Appcast.feedURL)
        #expect(p["SURequireSignedFeed"] as? Bool == true)
        #expect(p["SUVerifyUpdateBeforeExtraction"] as? Bool == true)
    }

    /// The real key's public half, and a key CryptoKit accepts.
    @Test func theUpdateKey() throws {
        let key = try #require(Self.plist["SUPublicEDKey"] as? String)
        #expect(key == "9cEJw3YLnFNchYW7zNMy1geAw8SW2uvLC+5CT5FtAcw=")
        _ = try UpdateKey.publicKey(base64: key)
    }

    @Test func checksDailyWithoutAsking() {
        let p = Self.plist
        #expect(p["SUEnableAutomaticChecks"] as? Bool == true)
        #expect(p["SUScheduledCheckInterval"] as? Int == 86_400)
        #expect(p["SUEnableSystemProfiling"] as? Bool == false)
        #expect(p["SUAutomaticallyUpdate"] == nil)                     // installing stays the person's choice
        #expect(p["LSUIElement"] as? Bool == true)
    }

    /// Not sandboxed, so none of Sparkle's sandbox services; and a release build allows no plain-http loads.
    @Test func nothingForSandboxesOrTests() {
        let p = Self.plist
        for key in ["SUEnableInstallerLauncherService", "SUEnableDownloaderService", "SUEnableInstallerConnectionService",
                    "SUEnableInstallerStatusService", "NSAppTransportSecurity"] {
            #expect(p[key] == nil, "\(key)")
        }
    }

    /// Inside out (Sparkle's "Code Signing" for an app that is not sandboxed): the XPC services, Autoupdate,
    /// Updater.app, the framework, the app; never `--deep` when signing.
    @Test func buildScriptSignsInsideOut() throws {
        let script = try String(contentsOf: Self.root.appendingPathComponent("scripts/build-app.sh"), encoding: .utf8)
        let signing = script.split(separator: "\n").filter { $0.contains("codesign --force") }.map(String.init)
        let order = ["Installer.xpc", "Downloader.xpc", "/Autoupdate\"", "/Updater.app\"", "\"$fw\"", "\"$app\""]
        #expect(signing.count == order.count)
        for (line, piece) in zip(signing, order) { #expect(line.contains(piece), "\(line) should sign \(piece)") }
        #expect(signing.allSatisfy { !$0.contains("--deep") })
        #expect(signing[1].contains("--preserve-metadata=entitlements"))
        #expect(script.contains("cp \"$app_src/Resources/Info.plist\""))
        #expect(script.contains("sign_inside_out --options runtime --timestamp"))
    }
}
