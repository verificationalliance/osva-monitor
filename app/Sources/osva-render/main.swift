// osva-render: draws the popover and the settings window off-screen to PNG, from fixture data (or a real report), in
// light and dark appearance, so the UI can be checked without opening a window on anyone's screen.
//
//   osva-render [--out DIR] [--report last-scan.json] [--scale 2] [--only <prefix>] [--grey]
//
// --grey also draws each view over mid-grey (the panel's glass over a bright wallpaper, as on the owner's Mac, where
// white text measured 3:1 against it), in both appearances: <view>-<mode>-grey.png.
//
// What can be drawn off-screen, as of macOS 26:
//   - ImageRenderer draws SwiftUI's own content, but not scroll-view content or AppKit controls (buttons, toggles,
//     progress bars come out as placeholders or not at all). Used for the popover, its list drawn unscrolled.
//   - NSHostingView.cacheDisplay draws AppKit controls but none of SwiftUI's own drawing. Used for Settings, which
//     is a native form.
// Neither draws the panel's Liquid Glass, which the window server composites. The panel's glass is stood in for by the
// window background colour. For the real thing, run the app itself with --capture (see CaptureMode.swift).
import AppKit
import OSVAKit
import OSVAMonitorUI
import SwiftUI

enum Method { case imageRenderer, hostingView }

@MainActor
func capture<V: View>(_ view: V, appearance: NSAppearance, method: Method, scale: CGFloat, width: CGFloat? = nil,
                      backdrop: Color? = nil) throws -> NSBitmapImageRep {
    let dark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
    let root = view
        .background(backdrop ?? Color(nsColor: .windowBackgroundColor))
        .environment(\.colorScheme, dark ? .dark : .light)
    var result: Result<NSBitmapImageRep, Error> = .failure(CocoaError(.fileWriteUnknown))
    appearance.performAsCurrentDrawingAppearance {
        result = Result { try draw(root, appearance: appearance, method: method, scale: scale, width: width) }
    }
    return try result.get()
}

@MainActor
private func draw<V: View>(_ root: V, appearance: NSAppearance, method: Method, scale: CGFloat, width: CGFloat?) throws -> NSBitmapImageRep {
    switch method {
    case .imageRenderer:
        let r = ImageRenderer(content: root.frame(width: width))
        r.scale = scale
        guard let cg = r.cgImage else { throw CocoaError(.fileWriteUnknown) }
        let rep = NSBitmapImageRep(cgImage: cg)
        rep.size = NSSize(width: CGFloat(cg.width) / scale, height: CGFloat(cg.height) / scale)
        return rep
    case .hostingView:
        let host = NSHostingView(rootView: root)
        host.appearance = appearance
        var size = host.fittingSize
        for _ in 0..<3 {
            host.frame = NSRect(x: 0, y: 0, width: width ?? size.width, height: size.height)
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.15))
            size = host.fittingSize
        }
        host.frame = NSRect(x: 0, y: 0, width: width ?? size.width, height: size.height)
        host.layoutSubtreeIfNeeded()
        let w = Int((host.bounds.width * scale).rounded()), h = Int((host.bounds.height * scale).rounded())
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8, samplesPerPixel: 4,
                                         hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else {
            throw CocoaError(.fileWriteUnknown)
        }
        rep.size = host.bounds.size
        host.cacheDisplay(in: host.bounds, to: rep)
        return rep
    }
}

@MainActor
func write(_ rep: NSBitmapImageRep, _ name: String, into dir: URL) throws {
    let file = dir.appendingPathComponent(name + ".png")
    try rep.representation(using: .png, properties: [:])!.write(to: file)
    print("\(file.path)  \(Int(rep.size.width))×\(Int(rep.size.height)) pt")
}

/// Every status component, side by side, for close inspection.
struct ComponentSheet: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 14) {
                ForEach([16.0, 22.0, 48.0], id: \.self) { s in VerificationMark(.whole, size: s); VerificationMark(.parts, size: s) }
            }
            HStack(spacing: 6) { ForEach(["A", "B", "C", "D", "F", "U"], id: \.self) { GradeTile($0) } }
            HStack(spacing: 12) { ForEach(Severity.allCases.reversed(), id: \.self) { SeverityLabel($0) } }
            HStack(spacing: 10) { StatusChip(.exploited); StatusChip(.malicious) }
            HStack(spacing: 5) {
                StatusChip(.count(.malicious, 1)); StatusChip(.count(.exploited, 2))
                StatusChip(.count(.severity(.critical), 3)); StatusChip(.count(.severity(.high), 4))
            }
            HStack(spacing: 18) {
                MenuBarLabel(.notScanned); MenuBarLabel(.clean); MenuBarLabel(.action(3)); MenuBarLabel(.malicious(12))
            }
            .font(.system(size: 13))
            CommandBlock("cd ~/osva-monitor/run/demo-projects/api && python3 -m pip install 'Django>=5.2.17'").frame(width: 300)
        }
        .padding(18)
    }
}

/// Rows with the pointer over the middle one (findings, Not checked), and the site link: hover may only raise contrast.
struct HoverSheet: View {
    var body: some View {
        let ids = [PreviewData.FixID.nginx, PreviewData.FixID.openssh, PreviewData.FixID.cpython]
        let rows = PreviewData.findings.filter { ids.contains($0.id) }
        VStack(alignment: .leading, spacing: 14) {
            GroupContainer(.criticalHigh, count: rows.count) {
                ForEach(Array(rows.enumerated()), id: \.offset) { i, f in
                    if i > 0 { Divider().padding(.leading, 12) }
                    FindingRow(finding: f, expanded: false, actions: .none) {}.environment(\.showsHover, i == 1)
                }
            }
            GroupContainer(.notChecked, count: 8) {
                ListDisclosureRow("Homebrew packages with no graded project", items: ["abseil 20260817.0", "ack 3.10.0"])
                Divider().padding(.leading, 12)
                ListDisclosureRow("Apps that do not bundle Electron", items: ["Firefox", "Xcode"]).environment(\.showsHover, true)
            }
            SiteLink("Open on verificationalliance.org", url: URL(string: "https://verificationalliance.org/")!) { _ in }
        }
        .padding(14)
        .frame(width: PopoverView.width)
    }
}

/// A run's three steps, and the review with its details open, one under another.
struct FixStepSheet: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(PreviewData.runSteps().enumerated()), id: \.offset) { _, run in FixRunCard(run: run) {} }
            if case let .offered(offer)? = PreviewData.fixConfirmations[PreviewData.FixID.nginx]?.availability,
               let preview = PreviewData.fixConfirmations[PreviewData.FixID.nginx]?.preview {
                FixConfirmation(offer: offer, preview: preview, details: true, cancel: {}, run: {})
            }
        }
        .padding(14)
        .frame(width: 348 + 28)
    }
}

@MainActor
func main() throws {
    var out = URL(fileURLWithPath: "shots", isDirectory: true), reportPath: String?, scale: CGFloat = 2, grey = false, onlyPrefix: String?
    var args = CommandLine.arguments.dropFirst()
    while let a = args.popFirst() {
        switch a {
        case "--out": out = URL(fileURLWithPath: args.popFirst() ?? "shots", isDirectory: true)
        case "--report": reportPath = args.popFirst()
        case "--scale": scale = CGFloat(Double(args.popFirst() ?? "2") ?? 2)
        case "--grey": grey = true
        case "--only": onlyPrefix = args.popFirst()
        default:
            FileHandle.standardError.write(Data("usage: osva-render [--out DIR] [--report last-scan.json] [--scale 2] [--only <prefix>] [--grey]\n".utf8))
            exit(2)
        }
    }
    try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    // ImageRenderer draws some symbol renderings blank until AppKit has drawn once in this process.
    _ = NSApplication.shared
    _ = try capture(Text("warm-up"), appearance: NSAppearance(named: .aqua)!, method: .hostingView, scale: 1)

    let now = PreviewData.now
    let full = PreviewData.report()
    let open: Set<String> = ["pkg|npm|axios|1.14.1", "brew|nginx|1.30.2"]
    func popover(_ report: ScanReport?, scanning: Bool = false, progress: String = "", expanded: Set<String> = [],
                 fixes: [String: FixRowState] = [:], resolved: [Finding] = []) -> some View {
        PopoverView(content: PopoverContent(report: report, isScanning: scanning, progress: progress, now: now, resolved: resolved), actions: .none,
                    fixes: fixes, expanded: expanded, scrolls: false)
    }
    var views: [(String, AnyView, Method)] = [
        ("popover", AnyView(popover(full, expanded: open)), .imageRenderer),
        ("popover-scanning", AnyView(popover(full, scanning: true, progress: "Checking 27 package versions…")), .imageRenderer),
        ("popover-first-scan", AnyView(popover(nil, scanning: true, progress: "Looking at what is installed…")), .imageRenderer),
        ("popover-not-scanned", AnyView(popover(nil)), .imageRenderer),
        ("popover-clean", AnyView(popover(PreviewData.report(findings: PreviewData.findings.filter { $0.group == .other }))), .imageRenderer),
        ("popover-high-only", AnyView(popover(PreviewData.report(findings: PreviewData.findings.filter { $0.severity == .high && !$0.exploited }))),
         .imageRenderer),
        ("popover-offline", AnyView(popover(PreviewData.report(findings: [], problems: ["Could not refresh the public index; using the copy from 2 days ago."]))), .imageRenderer),
        ("settings", AnyView(SettingsView(state: PreviewData.settings(), actions: .none, showSent: true)), .hostingView),
        ("settings-empty", AnyView(SettingsView(state: SettingsState(folders: [], intervalHours: 24, notifications: false, notificationsAvailable: false,
                                                                     launchAtLogin: false, launchAtLoginAvailable: false, lastReport: nil), actions: .none)), .hostingView),
        ("components", AnyView(ComponentSheet()), .imageRenderer),
        ("fix-steps", AnyView(FixStepSheet()), .imageRenderer),
        ("fix-hover", AnyView(HoverSheet()), .imageRenderer),
    ]
    // Each state of the in-app fix, on the findings it applies to (PreviewData.fixScene).
    for name in PreviewData.fixSceneNames {
        let scene = PreviewData.fixScene(name)!
        views.append(("fix-\(name)", AnyView(popover(scene.report(), expanded: scene.open, fixes: scene.fixes, resolved: scene.resolvedFindings)),
                      .imageRenderer))
    }
    if let reportPath {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let real = try decoder.decode(ScanReport.self, from: Data(contentsOf: URL(fileURLWithPath: reportPath)))
        views.append(("popover-real", AnyView(PopoverView(content: PopoverContent(report: real, isScanning: false, now: real.finishedAt.addingTimeInterval(120)),
                                                          actions: .none, scrolls: false)), .imageRenderer))
    }
    // Increase Contrast cannot be drawn here: AppKit returns plain Aqua for the high-contrast appearance names unless
    // the setting is on, so those variants are checked by ToneTests and on the real panel.
    for (mode, name) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
        let appearance = NSAppearance(named: name)!
        for (view, content, method) in views where onlyPrefix.map(view.hasPrefix) ?? true {
            let width = view.hasPrefix("popover") || (view.hasPrefix("fix-") && view != "fix-steps" && view != "fix-hover") ? PopoverView.width : nil
            try write(capture(content, appearance: appearance, method: method, scale: scale, width: width), "\(view)-\(mode)", into: out)
            if grey, method == .imageRenderer {
                try write(capture(content, appearance: appearance, method: method, scale: scale, width: width, backdrop: Color(white: 0.54)),
                          "\(view)-\(mode)-grey", into: out)
            }
        }
    }
}

try MainActor.assumeIsolated { try main() }
