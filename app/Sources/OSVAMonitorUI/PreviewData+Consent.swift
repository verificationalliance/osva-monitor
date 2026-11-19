import Foundation

extension PreviewData {
    /// The first-launch card's switches on a first install: all on.
    public static let consentFresh = ConsentChoices.fresh
    /// Someone updating from 0.4.0, which never asked: the daily check and notifications on as they were, open at
    /// login off as it was.
    public static let consentUpgrade = ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: false)
}
