// probe: runs Sparkle's real update cycle on an app bundle without any window, for scripts/test-update.sh.
//
//   probe <OSVA Monitor.app> <feed URL>
//   probe new-key <file>     a throwaway update key: writes its private half (0600), prints its public half
//
// It is Sparkle's own SPUUpdater with the app as its host: Sparkle reads the app's Info.plist (its update key,
// SURequireSignedFeed, SUVerifyUpdateBeforeExtraction), fetches and checks the feed, picks the update, downloads it,
// and its installer (Autoupdate, from the Sparkle.framework this probe links) checks the zip's signature against the
// app's key and replaces the app. Only the windows are replaced, by the answers a person would give: install.
// Each step is printed. The exit status is 0 when the app was updated, 1 when Sparkle refused or failed, 2 on timeout.
import AppKit
import CryptoKit
import Sparkle

func say(_ s: String) { FileHandle.standardOutput.write(Data("probe: \(s)\n".utf8)) }

@MainActor
final class Driver: NSObject, SPUUserDriver {
    func finish(_ code: Int32) -> Never { exit(code) }

    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks: false, sendSystemProfile: false))
    }
    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) { say("checking the feed") }
    func showUpdateFound(with item: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        say("found \(item.displayVersionString) (bundle version \(item.versionString)), feed signature \(item.signingValidationStatus == .succeeded ? "valid" : "status \(item.signingValidationStatus.rawValue)")")
        say("  zip \(item.fileURL?.absoluteString ?? "-"), \(item.contentLength) bytes, needs macOS \(item.minimumSystemVersion ?? "-")")
        if let notes = item.itemDescription { say("  notes (\(item.itemDescriptionFormat ?? "html")): \(notes)") }
        reply(.install)
    }
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {}
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: any Error) {}
    func showUpdateNotFoundWithError(_ error: any Error, acknowledgement: @escaping () -> Void) {
        say("no update: \(error.localizedDescription)")
        finish(1)
    }
    func showUpdaterError(_ error: any Error, acknowledgement: @escaping () -> Void) {
        let e = error as NSError
        say("refused: \(e.localizedDescription)")
        if let under = e.userInfo[NSUnderlyingErrorKey] as? NSError { say("  because: \(under.localizedDescription)") }
        finish(1)
    }
    func showDownloadInitiated(cancellation: @escaping () -> Void) { say("downloading") }
    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {}
    func showDownloadDidReceiveData(ofLength length: UInt64) {}
    func showDownloadDidStartExtractingUpdate() { say("downloaded; the installer verifies and unpacks it") }
    func showExtractionReceivedProgress(_ progress: Double) {}
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) {
        say("verified and unpacked; installing")
        reply(.install)
    }
    func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        say("installing")
    }
    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) {
        say("installed")
        finish(0)
    }
    func showUpdateInFocus() {}
    func dismissUpdateInstallation() {}
}

@MainActor
final class Delegate: NSObject, SPUUpdaterDelegate {
    let feed: String
    init(feed: String) { self.feed = feed }
    func feedURLString(for updater: SPUUpdater) -> String? { feed }
    func updaterShouldRelaunchApplication(_ updater: SPUUpdater) -> Bool { false }
}

let args = CommandLine.arguments
if args.count == 3, args[1] == "new-key" {
    let key = Curve25519.Signing.PrivateKey()
    guard FileManager.default.createFile(atPath: args[2], contents: Data(key.rawRepresentation.base64EncodedString().utf8),
                                         attributes: [.posixPermissions: 0o600]) else { exit(1) }
    print(key.publicKey.rawRepresentation.base64EncodedString())
    exit(0)
}
guard args.count == 3, let bundle = Bundle(path: args[1]) else {
    FileHandle.standardError.write(Data("usage: probe <app> <feed URL>\n".utf8))
    exit(2)
}
MainActor.assumeIsolated {
    let driver = Driver(), delegate = Delegate(feed: args[2])
    let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: delegate)
    do { try updater.start() } catch {
        say("Sparkle did not start: \(error.localizedDescription)")
        exit(1)
    }
    say("\(bundle.bundlePath) is \(bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") ?? "?"), trusts \(bundle.object(forInfoDictionaryKey: "SUPublicEDKey") ?? "?")")
    updater.checkForUpdates()
    DispatchQueue.main.asyncAfter(deadline: .now() + 120) { say("timed out"); exit(2) }
    withExtendedLifetime((driver, delegate, updater)) { RunLoop.main.run() }
}
