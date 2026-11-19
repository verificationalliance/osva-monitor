import AppKit
import OSVAKit
import OSVAMonitorUI
import SwiftUI

/// `OSVA Monitor --capture <dir> [--fixtures]`: opens the app's real windows (the menu-bar panel, a clean-state panel,
/// the Settings window), captures each, composited by the window server with its Liquid Glass, in light and dark
/// appearance, writes `<view>-<appearance>.png` into <dir>, and quits.
///
/// With --fixtures it shows the render fixtures instead of the last scan; --only <id>[,<id>…] keeps just those findings,
/// opened (for a close-up of one fix plan). Either way it does not scan, send anything,
/// ask for notification permission, or write anything but the PNGs. It captures only its own windows, which macOS
/// allows without Screen Recording permission.
@MainActor
struct CaptureMode {
    let directory: URL
    let fixtures: Bool
    /// How long to wait for someone to click the shield before falling back to the replica (`--wait <seconds>`).
    let waitSeconds: Int
    /// Finding ids to keep, opened (`--only`); empty keeps them all with the malicious one opened.
    let only: [String]

    /// The popover's openSettings action, registered when the popover appears.
    static var openSettings: OpenSettingsAction?

    init?(arguments: [String]) {
        guard let i = arguments.firstIndex(of: "--capture"), i + 1 < arguments.count else { return nil }
        directory = URL(fileURLWithPath: (arguments[i + 1] as NSString).expandingTildeInPath, isDirectory: true)
        fixtures = arguments.contains("--fixtures")
        if let w = arguments.firstIndex(of: "--wait"), w + 1 < arguments.count, let n = Int(arguments[w + 1]) {
            waitSeconds = max(0, min(n, 3600))
        } else {
            waitSeconds = 90
        }
        if let o = arguments.firstIndex(of: "--only"), o + 1 < arguments.count {
            only = arguments[o + 1].split(separator: ",").map(String.init)
        } else {
            only = []
        }
    }

    func run(model: AppModel) {
        var full = fixtures ? PreviewData.report() : model.report
        if !only.isEmpty { full = full.map { r in var c = r; c.findings = r.findings.filter { only.contains($0.id) }; return c } }
        let clean = fixtures ? PreviewData.report(findings: []) : model.report.map { r in var c = r; c.findings = []; return c }
        let fixtureSettings = fixtures ? MonitorSettings(watchedFolders: PreviewData.settings().folders) : model.settings
        model.showFixtures(full, settings: fixtureSettings)
        model.initiallyExpanded = only.isEmpty ? ["pkg|npm|axios|1.14.1"] : Set(only)
        Task { @MainActor in
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let appearances: [(String, NSAppearance.Name)] = [("light", .aqua), ("dark", .darkAqua)]

                // The panel, open once and kept open while the appearance changes (it closes when focus moves).
                NSApp.appearance = NSAppearance(named: .aqua)
                var (panel, isReplica) = try await openPanel()
                let prefix = isReplica ? "replica-" : ""
                for (name, appearance) in appearances {
                    NSApp.appearance = NSAppearance(named: appearance)
                    model.showFixtures(full, settings: fixtureSettings)
                    try await settle()
                    if isReplica { try await Self.fitReplica() } else { panel = try await reopenIfClosed(panel) }
                    try capture(panel, "\(prefix)popover-\(name)")
                    if let bar = statusBarWindow(), bar.windowNumber > 0 { try? capture(bar, "menubar-\(name)") }
                    model.showFixtures(clean, settings: fixtureSettings)
                    try await settle()
                    if isReplica { try await Self.fitReplica() } else { panel = try await reopenIfClosed(panel) }
                    try capture(panel, "\(prefix)popover-clean-\(name)")
                }
                panel.orderOut(nil)

                for (name, appearance) in appearances {
                    NSApp.appearance = NSAppearance(named: appearance)
                    model.showFixtures(full, settings: fixtureSettings)
                    NSApp.activate(ignoringOtherApps: true)
                    Self.openSettings?()
                    try await settle(seconds: 1.5)
                    // the one visible window that is neither the status item nor the panel
                    if let settings = NSApp.windows.first(where: { $0.isVisible && $0 !== panel && !isStatusBar($0) }) {
                        settings.makeKeyAndOrderFront(nil)
                        try await settle(seconds: 0.5)
                        try capture(settings, "settings-\(name)")
                        settings.close()
                    } else {
                        FileHandle.standardError.write(Data("capture: the Settings window did not open\n".utf8))
                    }
                    try await settle(seconds: 0.5)
                }
            } catch {
                FileHandle.standardError.write(Data("capture failed: \(error)\n".utf8))
            }
            NSApp.terminate(nil)
        }
    }

    /// Opens the real MenuBarExtra panel: first by clicking the app's own status item, then by waiting up to 90 s for
    /// the person at the Mac to click it. Only if neither works, the NSGlassEffectView replica (`isReplica`).
    private func openPanel() async throws -> (NSWindow, isReplica: Bool) {
        if let open = panelWindow() { return (open, false) }
        guard let statusWindow = statusBarWindow(), let button = statusWindow.contentView.flatMap(findButton) else {
            throw CaptureError("no status item")
        }
        // A real click, delivered to the app's own status item: SwiftUI's MenuBarExtra opens its panel on the mouse
        // event, not on the button's action, so performClick alone does nothing. Events sent to our own window need
        // no permission.
        let point = button.convert(NSPoint(x: button.bounds.midX, y: button.bounds.midY), to: nil)
        func click(_ type: NSEvent.EventType) -> NSEvent? {
            NSEvent.mouseEvent(with: type, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                               windowNumber: statusWindow.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)
        }
        if let up = click(.leftMouseUp) { NSApp.postEvent(up, atStart: false) }   // queued first: the button's tracking loop reads it
        if let down = click(.leftMouseDown) { statusWindow.sendEvent(down) }
        for _ in 0..<20 {
            try await Task.sleep(for: .milliseconds(100))
            if let w = panelWindow() { return (w, false) }
        }
        if let action = button.action { NSApp.sendAction(action, to: button.target, from: button) }
        for _ in 0..<20 {
            try await Task.sleep(for: .milliseconds(100))
            if let w = panelWindow() { return (w, false) }
        }
        FileHandle.standardError.write(Data("click the OSVA shield in the menu bar\n".utf8))
        for _ in 0..<(waitSeconds * 10) {
            try await Task.sleep(for: .milliseconds(100))
            if let w = panelWindow() {
                try await settle(seconds: 0.5)
                return (w, false)
            }
        }
        if let replica = try await Self.glassPanel(under: statusWindow) { return (replica, true) }
        throw CaptureError("the menu-bar panel did not open, and there is no replica content")
    }

    /// The real panel closes as soon as focus moves (a click anywhere else, or a second click on the shield). Rather than
    /// fail, ask for another click and wait for it to open again.
    private func reopenIfClosed(_ current: NSWindow) async throws -> NSWindow {
        if current.isVisible { return current }
        FileHandle.standardError.write(Data("the panel closed: click the OSVA shield again\n".utf8))
        for _ in 0..<(waitSeconds * 10) {
            try await Task.sleep(for: .milliseconds(100))
            if let w = panelWindow() {
                try await settle()
                return w
            }
        }
        throw CaptureError("the menu-bar panel closed and was not opened again")
    }

    /// The panel's own content in a borderless window whose content view is macOS 26's NSGlassEffectView, under the
    /// status item. Not the real panel: the replica can add or omit glass the MenuBarExtra window does not have, so
    /// its captures are named replica-*. Made key, so its controls draw active.
    static var panelContent: (() -> AnyView)?
    private static var replicaWindow: ReplicaPanel?
    private static var replicaHost: NSHostingView<AnyView>?

    private final class ReplicaPanel: NSPanel {
        override var canBecomeKey: Bool { true }
        override var canBecomeMain: Bool { true }
    }

    static func glassPanel(under status: NSWindow) async throws -> NSWindow? {
        guard let content = panelContent?() else { return nil }
        let hosting = NSHostingView(rootView: content)
        let panel = ReplicaPanel(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300), styleMask: [.borderless, .nonactivatingPanel, .fullSizeContentView],
                                 backing: .buffered, defer: false)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .popUpMenu
        let glass = NSGlassEffectView()
        glass.cornerRadius = 18
        glass.contentView = hosting
        panel.contentView = glass
        replicaWindow = panel
        replicaHost = hosting
        // a non-activating panel becomes key without activating the app (macOS may refuse activation to a background app)
        panel.orderFrontRegardless()
        panel.makeKey()
        try await fitReplica(under: status)
        FileHandle.standardError.write(Data("capture: the real panel did not open; using NSGlassEffectView with the same content\n".utf8))
        return panel
    }

    /// Sizes the replica to its content's natural size (the list measures itself first, so this settles twice),
    /// hanging from the status item, and never taller than the screen.
    static func fitReplica(under status: NSWindow? = nil) async throws {
        guard let panel = replicaWindow, let hosting = replicaHost else { return }
        let anchor = status.map { NSPoint(x: $0.frame.midX, y: $0.frame.minY - 6) } ?? NSPoint(x: panel.frame.midX, y: panel.frame.maxY)
        for _ in 0..<3 {
            hosting.layoutSubtreeIfNeeded()
            let size = hosting.fittingSize
            let maxHeight = (panel.screen ?? NSScreen.main)?.visibleFrame.height ?? 900
            let height = min(size.height, maxHeight - 12)
            panel.setFrame(NSRect(x: anchor.x - size.width / 2, y: anchor.y - height, width: size.width, height: height), display: true)
            try await Task.sleep(for: .milliseconds(300))
        }
        panel.makeKeyAndOrderFront(nil)
    }

    private func isStatusBar(_ w: NSWindow) -> Bool { NSStringFromClass(type(of: w)).contains("StatusBar") }

    private func statusBarWindow() -> NSWindow? { NSApp.windows.first(where: isStatusBar) }

    /// SwiftUI's MenuBarExtra window (its class names it), or else the visible panel-like window that is not Settings.
    private func panelWindow() -> NSWindow? {
        let visible = NSApp.windows.filter { $0.isVisible && !isStatusBar($0) }
        return visible.first { NSStringFromClass(type(of: $0)).contains("MenuBarExtra") }
            ?? visible.first { $0 is NSPanel && $0.frame.width > 200 && $0 !== Self.replicaWindow }
    }

    private func findButton(_ view: NSView) -> NSStatusBarButton? {
        if let b = view as? NSStatusBarButton { return b }
        for v in view.subviews { if let b = findButton(v) { return b } }
        return nil
    }

    /// Waits for layout, animations and the glass to settle.
    private func settle(seconds: Double = 1.2) async throws {
        try await Task.sleep(for: .seconds(seconds))
    }

    private func capture(_ window: NSWindow, _ name: String) throws {
        guard let image = WindowCapture.image(of: window) else {
            throw CaptureError("could not capture \(name): window \(window.windowNumber) visible=\(window.isVisible) onActiveSpace=\(window.isOnActiveSpace) frame=\(window.frame) occlusion=\(window.occlusionState.rawValue) appActive=\(NSApp.isActive)")
        }
        let rep = NSBitmapImageRep(cgImage: image)
        let file = directory.appendingPathComponent(name + ".png")
        try rep.representation(using: .png, properties: [:])!.write(to: file)
        print("\(file.path)  \(image.width)×\(image.height) px")
    }

    struct CaptureError: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }
}

/// CGWindowListCreateImage, which the SDK marks unavailable in favour of ScreenCaptureKit, but which still returns an
/// app's own windows as the window server composited them (glass included) without Screen Recording permission.
enum WindowCapture {
    private typealias CreateImage = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?

    private static let createImage: CreateImage? = {
        guard let handle = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW),
              let symbol = dlsym(handle, "CGWindowListCreateImage") else { return nil }
        return unsafeBitCast(symbol, to: CreateImage.self)
    }()

    @MainActor
    static func image(of window: NSWindow) -> CGImage? {
        let includingWindow: UInt32 = 1 << 3          // kCGWindowListOptionIncludingWindow
        let ignoreFraming: UInt32 = 1 << 0            // kCGWindowImageBoundsIgnoreFraming
        guard let id = UInt32(exactly: window.windowNumber), id > 0 else { return nil }   // not on screen (yet)
        return createImage?(.null, includingWindow, id, ignoreFraming)?.takeRetainedValue()
    }
}
