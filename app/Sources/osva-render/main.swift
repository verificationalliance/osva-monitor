// osva-render: draws the popover and the settings window off-screen to PNG, from fixture data (or a real report), in
// light and dark appearance (the panel also over a mid-grey backdrop), so the UI can be checked without opening a
// window on anyone's screen.
//
//   osva-render [--out DIR] [--report last-scan.json] [--scale 2] [--only PREFIX,…] [--apps]
//
// --apps also draws the app lists from this Mac's own /Applications and ~/Applications (read here, sent nowhere), for
// a look at real names and icons; keep those PNGs out of the repository.
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

enum Method { case imageRenderer, hostingView, window }

@MainActor
func capture<V: View>(_ view: V, appearance: NSAppearance, method: Method, scale: CGFloat, width: CGFloat? = nil,
                      backdrop: NSColor? = nil) throws -> NSBitmapImageRep {
    let dark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
    let root = view
        .background(Color(nsColor: backdrop ?? .windowBackgroundColor))
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
    case .hostingView, .window:
        let host = NSHostingView(rootView: root)
        host.appearance = appearance
        // A List is an NSTableView, which makes its rows only once it is in a window: the sheets get one, never shown.
        var window: NSWindow?
        if method == .window {
            let w = NSWindow(contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.borderless], backing: .buffered, defer: false)
            w.appearance = appearance
            w.contentView = host
            window = w
        }
        defer { window?.contentView = nil }
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
    guard let png = rep.representation(using: .png, properties: [:]) else {   // a real report's whole popover can be too tall
        FileHandle.standardError.write(Data("osva-render: \(name) is too large to encode (\(rep.pixelsWide)×\(rep.pixelsHigh) px), skipped\n".utf8))
        return
    }
    try png.write(to: file)
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

@MainActor
func main() throws {
    var out = URL(fileURLWithPath: "shots", isDirectory: true), reportPath: String?, scale: CGFloat = 2, prefixes: [String] = [], thisMacsApps = false
    var args = CommandLine.arguments.dropFirst()
    while let a = args.popFirst() {
        switch a {
        case "--out": out = URL(fileURLWithPath: args.popFirst() ?? "shots", isDirectory: true)
        case "--report": reportPath = args.popFirst()
        case "--scale": scale = CGFloat(Double(args.popFirst() ?? "2") ?? 2)
        case "--apps": thisMacsApps = true
        case "--only": prefixes = (args.popFirst() ?? "").split(separator: ",").map(String.init)
        default:
            FileHandle.standardError.write(Data("usage: osva-render [--out DIR] [--report last-scan.json] [--scale 2] [--only PREFIX,…] [--apps]\n".utf8))
            exit(2)
        }
    }
    try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    // App icons: this tool runs where macOS's icon service may not answer (an SSH session gets only placeholders), so
    // it reads each app's own .icns, at most 8 MB, from the bundle on this Mac. The app itself asks NSWorkspace.
    AppIcons.source = { path in
        let resources = URL(fileURLWithPath: path).appendingPathComponent("Contents/Resources")
        let info = NSDictionary(contentsOfFile: path + "/Contents/Info.plist")
        if var file = info?["CFBundleIconFile"] as? String, !file.contains("/") {
            if !file.hasSuffix(".icns") { file += ".icns" }
            let url = resources.appendingPathComponent(file)
            if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size <= 8 << 20, let image = NSImage(contentsOf: url) { return image }
        }
        return NSWorkspace.shared.icon(for: .applicationBundle)
    }
    // ImageRenderer draws some symbol renderings blank until AppKit has drawn once in this process.
    _ = NSApplication.shared
    _ = try capture(Text("warm-up"), appearance: NSAppearance(named: .aqua)!, method: .hostingView, scale: 1)

    let now = PreviewData.now
    let full = PreviewData.report()
    var waiting = PreviewData.updates
    waiting.version = "0.1.0"; waiting.waitingVersion = "0.1.1"
    /// The sheets behind "What leaves your Mac", one per list, and one narrowed by a search.
    func sheets(_ report: ScanReport, prefix: String) -> [(String, AnyView, Method)] {
        SentSummary.lists(report.sent).filter(\.canOpen).map { list in
            ("\(prefix)-\(list.kind.rawValue)", AnyView(SentListView(list: list, scanned: report.finishedAt)), Method.window)
        } + SentSummary.lists(report.sent).filter { $0.kind == .withheld && $0.canOpen }.map { list in
            ("\(prefix)-withheld-search", AnyView(SentListView(list: list, scanned: report.finishedAt, query: "lib")), Method.window)
        }
    }
    let open: Set<String> = ["pkg|npm|axios|1.14.1", "brew|nginx|1.30.2"]
    func popover(_ report: ScanReport?, scanning: Bool = false, progress: String = "", expanded: Set<String> = [],
                 fixes: [String: FixRowState] = [:], resolved: [Finding] = [], coverageOpen: Set<String> = []) -> some View {
        PopoverView(content: PopoverContent(report: report, isScanning: scanning, progress: progress, now: now, resolved: resolved), actions: .none,
                    fixes: fixes, expanded: expanded, scrolls: false, coverageOpen: coverageOpen)
    }
    /// The windows the panel opens for long lists: every app no check covers, narrowed by a search, and the App Store's.
    func coverageLists() -> [(String, AnyView, Method)] {
        let c = PreviewData.appCoverage, scanned = PreviewData.coverageReport().finishedAt
        let noRecord = CoverageLists.list(c.notChecked[1], in: .notChecked), appStore = CoverageLists.list(c.updatedElsewhere[0], in: .updatedElsewhere)
        return [("list-no-record", AnyView(NameListView(list: noRecord, scanned: scanned)), .window),
                ("list-no-record-search", AnyView(NameListView(list: noRecord, scanned: scanned, query: "micro")), .window),
                ("list-app-store", AnyView(NameListView(list: appStore, scanned: scanned)), .window)]
    }
    // The fix button, its confirmation, and how runs ended, each on the findings it applies to.
    typealias F = PreviewData.FixID
    func only(_ ids: [String]) -> ScanReport { PreviewData.report(findings: PreviewData.findings.filter { ids.contains($0.id) }) }
    let offerIDs = [F.axios, F.nginx, F.cpython], confirmIDs = [F.nginx, F.setuptools, F.hacl]
    let resultIDs = [F.axios, F.openssh, F.openmtp, F.nginx, F.nokogiri, F.vscode]
    let resolved = PreviewData.findings.filter { PreviewData.fixResolved.contains($0.id) }
    let afterRuns = PreviewData.report(findings: PreviewData.findings.filter { resultIDs.contains($0.id) && !PreviewData.fixResolved.contains($0.id) })
    var views: [(String, AnyView, Method)] = [
        ("popover", AnyView(popover(full, expanded: open)), .imageRenderer),
        ("popover-scanning", AnyView(popover(full, scanning: true, progress: "Checking 27 package versions…")), .imageRenderer),
        ("popover-first-scan", AnyView(popover(nil, scanning: true, progress: "Looking at what is installed…")), .imageRenderer),
        ("popover-not-scanned", AnyView(popover(nil)), .imageRenderer),
        ("popover-clean", AnyView(popover(PreviewData.report(findings: PreviewData.findings.filter { $0.group == .other }))), .imageRenderer),
        ("popover-high-only", AnyView(popover(PreviewData.report(findings: PreviewData.findings.filter { $0.severity == .high && !$0.exploited }))),
         .imageRenderer),
        ("popover-offline", AnyView(popover(PreviewData.report(findings: [], problems: ["Could not refresh the public index; using the copy from 2 days ago."]))), .imageRenderer),
        ("settings", AnyView(SettingsView(state: PreviewData.settings(), actions: .none)), .hostingView),
        ("settings-whole", AnyView(SettingsView(state: PreviewData.settings(), actions: .none, height: 1080)), .hostingView),
        ("popover-update-waiting", AnyView(PopoverView(content: PopoverContent(report: PreviewData.report(findings: []), isScanning: false, now: now),
                                                       actions: .none, updates: waiting, scrolls: false)), .imageRenderer),
        ("settings-empty", AnyView(SettingsView(state: SettingsState(folders: [], intervalHours: 24, notifications: false, notificationsAvailable: false,
                                                                     launchAtLogin: false, launchAtLoginAvailable: false, lastReport: nil), actions: .none)), .hostingView),
        ("components", AnyView(ComponentSheet()), .imageRenderer),
        ("fix-offer", AnyView(popover(only(offerIDs), expanded: Set(offerIDs), fixes: PreviewData.fixOffers)), .imageRenderer),
        ("fix-confirm", AnyView(popover(only(confirmIDs), expanded: Set(confirmIDs), fixes: PreviewData.fixConfirmations)), .imageRenderer),
        ("fix-results", AnyView(popover(afterRuns, expanded: [F.nginx, F.openmtp], fixes: PreviewData.fixResults, resolved: resolved)), .imageRenderer),
        // apps, the libraries they bundle, and extensions
        ("popover-bundles", AnyView(popover(PreviewData.bundlesReport(), expanded: PreviewData.bundlesOpen)), .imageRenderer),
        ("popover-bundles-closed", AnyView(popover(PreviewData.bundlesReport())), .imageRenderer),
        ("settings-bundles", AnyView(SettingsView(state: PreviewData.settings(report: PreviewData.bundlesReport()), actions: .none)), .hostingView),
        // what could not be vouched for: one name per line, long lists in a window of their own
        ("popover-coverage", AnyView(popover(PreviewData.coverageReport(), coverageOpen: ["Bundled libraries with no readable version", "updatedElsewhere",
                                                                                  AppCoverage.webApps("Edge")])), .imageRenderer),
    ] + sheets(full, prefix: "sent") + sheets(PreviewData.bundlesReport(), prefix: "sent-bundles") + coverageLists()
    if let reportPath {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let real = try decoder.decode(ScanReport.self, from: Data(contentsOf: URL(fileURLWithPath: reportPath)))
        views.append(("popover-real", AnyView(PopoverView(content: PopoverContent(report: real, isScanning: false, now: real.finishedAt.addingTimeInterval(120)),
                                                          actions: .none, scrolls: false)), .imageRenderer))
        views.append(("settings-real", AnyView(SettingsView(state: PreviewData.settings(report: real), actions: .none, height: 1080)), .hostingView))
        views += sheets(real, prefix: "sent-real")
    }
    if thisMacsApps {
        let roots = ElectronSource.defaultRoots(home: FileManager.default.homeDirectoryForCurrentUser)
        let split = AppCoverage.buckets(ElectronSource(roots: roots).collect().otherApps, apps: AppSource(roots: roots).collect().apps)
        var coverage = PreviewData.appCoverage
        coverage.notChecked = coverage.notChecked.flatMap { $0.source == AppCoverage.noRecord ? [split.notChecked].compactMap { $0 } : [$0] }
        coverage.updatedElsewhere = split.updatedElsewhere
        let mac = PreviewData.report(findings: PreviewData.findings.filter { $0.group == .other }, coverage: coverage)
        views.append(("popover-coverage-mac", AnyView(popover(mac, coverageOpen: ["updatedElsewhere"])), .imageRenderer))
        for (name, bucket, part) in [("no-record", split.notChecked, CoverageLists.Part.notChecked)] + split.updatedElsewhere.map({ ("kept-" + $0.source.prefix(24).lowercased().replacingOccurrences(of: " ", with: "-"), Optional($0), CoverageLists.Part.updatedElsewhere) }) {
            if let bucket { views.append(("list-mac-\(name)", AnyView(NameListView(list: CoverageLists.list(bucket, in: part), scanned: mac.finishedAt)), .window)) }
        }
    }
    // Increase Contrast cannot be drawn here: AppKit returns plain Aqua for the high-contrast appearance names unless
    // the setting is on, so those variants are checked by ToneTests and on the real panel.
    // The panel's views also over a mid-grey backdrop, in both appearances: glass over a grey desktop, where contrast
    // is hardest. Windows are opaque, so they are drawn on their own background only.
    let grey = NSColor(white: 0.5, alpha: 1)
    for (mode, name, backdrop) in [("light", NSAppearance.Name.aqua, nil), ("dark", .darkAqua, nil), ("grey-light", .aqua, grey), ("grey-dark", .darkAqua, grey)] {
        let appearance = NSAppearance(named: name)!
        for (view, content, method) in views where prefixes.isEmpty || prefixes.contains(where: view.hasPrefix) {
            let panel = view.hasPrefix("popover") || view.hasPrefix("fix-")
            guard backdrop == nil || panel else { continue }
            try write(capture(content, appearance: appearance, method: method, scale: scale, width: panel ? PopoverView.width : nil, backdrop: backdrop),
                      "\(view)-\(mode)", into: out)
        }
    }
}

try MainActor.assumeIsolated { try main() }
