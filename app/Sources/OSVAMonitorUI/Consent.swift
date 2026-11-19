import Foundation
import OSVAKit

/// The first-launch card's three switches (ConsentView). After Start each lives where it always has: the daily update
/// check in Sparkle, notifications in the settings file, open at login in SMAppService; Settings shows all three.
public struct ConsentChoices: Equatable, Sendable {
    /// Sparkle's daily check for a new version of the app.
    public var checkForUpdates: Bool
    /// Notifications about malware and exploited flaws. On, macOS asks for permission once Start is pressed.
    public var notify: Bool
    public var openAtLogin: Bool

    public init(checkForUpdates: Bool, notify: Bool, openAtLogin: Bool) {
        self.checkForUpdates = checkForUpdates; self.notify = notify; self.openAtLogin = openAtLogin
    }

    /// A first install's: all on.
    public static let fresh = ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: true)
}

/// Asked once, before the app does anything: until the person presses Start, nothing reaches the network or reads
/// beyond the app's own files (AppModel.start is the one gate, and it starts the updater too). What they agreed to is
/// a version, kept in the user defaults; a card that says something new raises it, and asks again.
///
/// Versions before 0.5.0 never asked, so someone updating from one sees the card once too, its switches set as they
/// have them now.
public enum Consent {
    public static let version = 1
    public static let key = "consentVersion"

    public static func given(_ defaults: UserDefaults) -> Bool { defaults.integer(forKey: key) >= version }

    /// The card's switches: all on for a first install; for someone updating, what they have now.
    public static func prefill(ranBefore: Bool, settings: MonitorSettings, openAtLogin: Bool, checksForUpdates: Bool) -> ConsentChoices {
        guard ranBefore else { return .fresh }
        return ConsentChoices(checkForUpdates: checksForUpdates, notify: settings.notificationsEnabled, openAtLogin: openAtLogin)
    }
}
