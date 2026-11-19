import AppKit
import Foundation
import SwiftUI

/// The app's own updates, as the views show them. The updater itself (Sparkle) lives in the app target and writes
/// this; the views, the renders and the tests never link Sparkle.
public struct UpdateState: Sendable, Equatable {
    /// Whether there is an updater at all: only in the installed app, not under `swift run`, osva-render or tests.
    public var isAvailable: Bool
    /// False while a check or an update is already under way.
    public var canCheck: Bool
    /// Check once a day (Sparkle's automatic checks); on unless the person turned it off.
    public var checksAutomatically: Bool
    /// This app's version ("0.1.0").
    public var version: String
    public var lastChecked: Date?
    /// A newer version a scheduled check found and that waits for the person: shown in the popover rather than in a
    /// window that would open behind whatever they are doing.
    public var waitingVersion: String?

    public init(isAvailable: Bool, canCheck: Bool, checksAutomatically: Bool, version: String, lastChecked: Date? = nil,
                waitingVersion: String? = nil) {
        self.isAvailable = isAvailable; self.canCheck = canCheck; self.checksAutomatically = checksAutomatically
        self.version = version; self.lastChecked = lastChecked; self.waitingVersion = waitingVersion
    }

    public static let none = UpdateState(isAvailable: false, canCheck: false, checksAutomatically: false,
                                         version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")

    /// "Last checked today at 09:12", or nil before the first check.
    public func lastCheckedLine(now: Date = Date()) -> String? {
        guard let d = lastChecked else { return nil }
        let day = Calendar.current.isDate(d, inSameDayAs: now) ? "today"
            : Calendar.current.isDate(d, inSameDayAs: now.addingTimeInterval(-86_400)) ? "yesterday"
            : d.formatted(date: .abbreviated, time: .omitted)
        return "Last checked \(day) at \(d.formatted(date: .omitted, time: .shortened))"
    }
}

/// The popover's line for a waiting update: one quiet row above the controls, the whole of it a button.
struct UpdateWaitingRow: View {
    let version: String
    let install: () -> Void

    var body: some View {
        Button(action: install) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: "arrow.down.circle.fill").symbolRenderingMode(.palette).foregroundStyle(.white, .tint)
                Text("OSVA Monitor \(version) is available").foregroundStyle(.primary)
                Spacer(minLength: 8)
                Text("Install…").fontWeight(.semibold).foregroundStyle(.primary)   // accent text on grey glass does not read
            }
            .font(Typeface.small)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Surface.card.color, in: ConcentricRectangle(corners: .concentric(minimum: 12), isUniform: true))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Shows what is new in \(version) and installs it")
    }
}

/// The settings gear's menu in the popover: Settings, and checking for a new version of the app. An AppKit menu,
/// opened on click under the gear, so the gear itself stays SwiftUI's own drawing (osva-render draws it).
@MainActor
enum AppMenu {
    /// `anchor` is the gear's frame in its window's content, top-left origin (SwiftUI's global space).
    static func show(below anchor: CGRect, updates: UpdateState, openSettings: @escaping () -> Void, checkForUpdates: @escaping () -> Void) {
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.addItem(ClosureMenuItem("Settings…", key: ",", action: openSettings))
        let check = ClosureMenuItem("Check for Updates…", key: "", action: checkForUpdates)
        check.isEnabled = updates.isAvailable && updates.canCheck
        menu.addItem(check)
        if let window = NSApp.keyWindow, let content = window.contentView {
            let point = NSPoint(x: anchor.minX, y: content.isFlipped ? anchor.maxY + 4 : content.bounds.height - anchor.maxY - 4)
            menu.popUp(positioning: nil, at: point, in: content)
        } else {
            menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
        }
    }

    private final class ClosureMenuItem: NSMenuItem {
        private let run: () -> Void
        init(_ title: String, key: String, action: @escaping () -> Void) {
            run = action
            super.init(title: title, action: #selector(fire), keyEquivalent: key)
            target = self
        }
        required init(coder: NSCoder) { fatalError("not from a nib") }
        @objc private func fire() { run() }
    }
}
