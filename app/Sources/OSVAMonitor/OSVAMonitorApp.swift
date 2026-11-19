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
            MenuBarLabel(delegate.model.menuBarState)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsScene(model: delegate.model, updater: delegate.updater)
        }

        // A long list of names opened from the panel ("Apps with no security record"), with its search field.
        Window("List", id: NameListView.windowID) {
            if let list = delegate.model.shownList {
                NameListView(list: list, scanned: delegate.model.report?.finishedAt ?? Date())
                    .id(list.id)                                  // a new list starts with an empty search
                    .navigationTitle(list.title)
            }
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let updater: Updater
    let model: AppModel

    override init() {
        let updater = Updater()
        self.updater = updater
        model = AppModel(updater: updater)               // the model starts it, once the person pressed Start
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let capture = CaptureMode(arguments: CommandLine.arguments) {
            let model = self.model, updater = self.updater
            CaptureMode.panelContent = { AnyView(PopoverScene(model: model, updater: updater)) }
            capture.run(model: model)                     // draws its own windows to PNG, then quits
        } else {
            model.start()
        }
    }
}

/// Until the person agreed, the panel and Settings show the first-launch card, and nothing else (Consent).
struct ConsentScene: View {
    let model: AppModel
    let choices: ConsentChoices

    var body: some View {
        ConsentView(choices: Binding(get: { model.consent ?? choices }, set: { model.setConsent($0) }),
                    start: { model.agree() }, quit: { NSApp.terminate(nil) })
    }
}

struct PopoverScene: View {
    let model: AppModel
    let updater: Updater
    @Environment(\.openSettings) private var openSettings
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let choices = model.consent {
            ConsentScene(model: model, choices: choices)
        } else {
            popover
        }
    }

    private var popover: some View {
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
            fix: FixActions(assess: { model.assessFix($0) }, begin: { model.beginFix($0) }, cancel: { model.cancelFix($0) },
                            run: { model.runFix($0) }, stop: { model.stopFix($0) }, retry: { model.retryFix($0) },
                            undo: { model.undoFix($0) }, runInTerminal: { model.runFixInTerminal($0) }),
            checkForUpdates: { updater.checkForUpdates() },
            openList: { list in
                model.shownList = list
                NSApp.activate(ignoringOtherApps: true)        // a menu-bar app is not frontmost by itself
                openWindow(id: NameListView.windowID)
            },
            closeWhatsNew: { model.closeWhatsNew() },
            fixAll: FixAllActions(open: { model.openFixAll() }, close: { model.closeFixAll() }, run: { model.runFixAll() },
                                  stop: { model.stopFixAll() }, undo: { model.undoFix($0) })),
            fixes: model.rowFixes,
            updates: updater.state,
            whatsNew: model.whatsNew,
            fixAll: model.fixAllPanel,
            expanded: model.initiallyExpanded)
        .onAppear { CaptureMode.openSettings = openSettings }
    }
}

struct SettingsScene: View {
    let model: AppModel
    let updater: Updater

    var body: some View {
        if let choices = model.consent {
            ConsentScene(model: model, choices: choices)
        } else {
            settings
        }
    }

    private var settings: some View {
        SettingsView(
            state: SettingsState(folders: model.settings.watchedFolders, intervalHours: model.settings.scanIntervalHours,
                                 notifications: model.settings.notificationsEnabled, notificationsAvailable: model.notifier.isAvailable,
                                 launchAtLogin: model.launchAtLogin, launchAtLoginAvailable: LoginItem.isAvailable, lastReport: model.report,
                                 updates: updater.state, changelog: model.changelog),
            actions: SettingsActions(addFolder: { model.chooseFolder() }, removeFolder: { model.removeFolder($0) },
                                     setInterval: { model.setInterval(hours: $0) }, setNotifications: { model.setNotifications($0) },
                                     setLaunchAtLogin: { model.setLaunchAtLogin($0) },
                                     checkForUpdates: { updater.checkForUpdates() },
                                     setChecksForUpdatesAutomatically: { updater.setChecksAutomatically($0) }))
    }
}
