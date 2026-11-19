import Foundation
import OSVAKit
import ServiceManagement
import UserNotifications

/// Whether this process is the bundled, signed app. Notifications and the login item work only there:
/// UNUserNotificationCenter stops a process that is not an app bundle, and macOS ties both to the app's signature.
public enum AppBundle {
    public static var isInstalledApp: Bool {
        let bundle = Bundle.main
        guard bundle.bundleURL.pathExtension == "app", bundle.bundleIdentifier != nil else { return false }
        return FileManager.default.fileExists(atPath: bundle.bundleURL.appendingPathComponent("Contents/_CodeSignature").path)
    }
}

/// Posts notifications for new findings that deserve one.
public protocol Notifier: Sendable {
    var isAvailable: Bool { get }
    func requestPermission() async
    func post(_ findings: [Finding]) async
}

public struct SystemNotifier: Notifier {
    public init() {}

    public var isAvailable: Bool { AppBundle.isInstalledApp }

    public func requestPermission() async {
        guard isAvailable else { return }
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }

    public func post(_ findings: [Finding]) async {
        guard isAvailable, !findings.isEmpty else { return }
        let content = UNMutableNotificationContent()
        let (title, body) = Self.text(for: findings)
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: "findings-\(UUID().uuidString)", content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }

    /// One notification for any number of new findings, worst first.
    public static func text(for findings: [Finding]) -> (title: String, body: String) {
        let worst = findings.sorted { $0.group < $1.group }
        let first = worst[0]
        let what = first.malicious ? (first.isExtension ? "Malicious extension" : "Malicious package") : first.exploited ? "Exploited flaw" : "On the “patch these first” list"
        let title = findings.count == 1 ? "\(what): \(first.title)" : "\(findings.count) new findings, starting with \(first.title)"
        var body = "\(first.versionLine) · \(first.originSummary)"
        if findings.count > 1 { body += "\nAlso: " + worst.dropFirst().prefix(3).map(\.title).joined(separator: ", ") + (findings.count > 4 ? " …" : "") }
        return (title, body)
    }
}

/// Open at login, through SMAppService (only for the installed app).
public enum LoginItem {
    public static var isAvailable: Bool { AppBundle.isInstalledApp }

    public static var isEnabled: Bool {
        isAvailable && SMAppService.mainApp.status == .enabled
    }

    /// Returns the state after trying; an error (the person declined in System Settings) leaves it as it was.
    @discardableResult
    public static func set(_ enabled: Bool) -> Bool {
        guard isAvailable else { return false }
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {}
        return isEnabled
    }
}
