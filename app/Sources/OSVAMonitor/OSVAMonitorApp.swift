import AppKit
import OSVAKit
import OSVAMonitorUI
import SwiftUI

/// OSVA Monitor: a shield in the menu bar that watches what is installed on this Mac and shows what the Open Source
/// Verification Alliance knows about it.
@main
struct OSVAMonitorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            PopoverScene(model: delegate.model, updater: delegate.updater)
        } label: {
            MenuBarLabel(delegate.model.popoverContent.menuBarState)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsScene(model: delegate.model, updater: delegate.updater)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    let updater = Updater()

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let capture = CaptureMode(arguments: CommandLine.arguments) {
            let model = self.model, updater = self.updater
            CaptureMode.panelContent = { AnyView(PopoverScene(model: model, updater: updater)) }
            capture.run(model: model)                     // draws its own windows to PNG, then quits
        } else {
            model.start()
            updater.start()
        }
    }
}

struct PopoverScene: View {
    let model: AppModel
    let updater: Updater
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        PopoverView(content: model.popoverContent, actions: PopoverActions(
            scanNow: { model.scanNow() },
            openSettings: {
                NSApp.activate(ignoringOtherApps: true)        // a menu-bar app is not frontmost by itself
                openSettings()
            },
            quit: { NSApp.terminate(nil) },
            open: { NSWorkspace.shared.open($0) },
            copy: { command in
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
            },
            checkForUpdates: { updater.checkForUpdates() }),
            updates: updater.state,
            expanded: model.initiallyExpanded)
        .onAppear { CaptureMode.openSettings = openSettings }
    }
}

struct SettingsScene: View {
    let model: AppModel
    let updater: Updater

    var body: some View {
        SettingsView(
            state: SettingsState(folders: model.settings.watchedFolders, intervalHours: model.settings.scanIntervalHours,
                                 notifications: model.settings.notificationsEnabled, notificationsAvailable: model.notifier.isAvailable,
                                 launchAtLogin: model.launchAtLogin, launchAtLoginAvailable: LoginItem.isAvailable, lastReport: model.report,
                                 updates: updater.state),
            actions: SettingsActions(addFolder: { model.chooseFolder() }, removeFolder: { model.removeFolder($0) },
                                     setInterval: { model.setInterval(hours: $0) }, setNotifications: { model.setNotifications($0) },
                                     setLaunchAtLogin: { model.setLaunchAtLogin($0) },
                                     checkForUpdates: { updater.checkForUpdates() },
                                     setChecksForUpdatesAutomatically: { updater.setChecksAutomatically($0) }))
    }
}
