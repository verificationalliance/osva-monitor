import OSVAKit
import SwiftUI

/// What the settings window shows.
public struct SettingsState: Sendable {
    public var folders: [String]
    public var intervalHours: Int
    public var notifications: Bool
    public var notificationsAvailable: Bool
    public var launchAtLogin: Bool
    public var launchAtLoginAvailable: Bool
    public var lastReport: ScanReport?

    public init(folders: [String], intervalHours: Int, notifications: Bool, notificationsAvailable: Bool,
                launchAtLogin: Bool, launchAtLoginAvailable: Bool, lastReport: ScanReport?) {
        self.folders = folders; self.intervalHours = intervalHours; self.notifications = notifications
        self.notificationsAvailable = notificationsAvailable; self.launchAtLogin = launchAtLogin
        self.launchAtLoginAvailable = launchAtLoginAvailable; self.lastReport = lastReport
    }
}

public struct SettingsActions {
    public var addFolder: () -> Void
    public var removeFolder: (String) -> Void
    public var setInterval: (Int) -> Void
    public var setNotifications: (Bool) -> Void
    public var setLaunchAtLogin: (Bool) -> Void

    public init(addFolder: @escaping () -> Void, removeFolder: @escaping (String) -> Void, setInterval: @escaping (Int) -> Void,
                setNotifications: @escaping (Bool) -> Void, setLaunchAtLogin: @escaping (Bool) -> Void) {
        self.addFolder = addFolder; self.removeFolder = removeFolder; self.setInterval = setInterval
        self.setNotifications = setNotifications; self.setLaunchAtLogin = setLaunchAtLogin
    }

    public static var none: SettingsActions {
        SettingsActions(addFolder: {}, removeFolder: { _ in }, setInterval: { _ in }, setNotifications: { _ in }, setLaunchAtLogin: { _ in })
    }
}

/// The settings window, a native grouped form: watched folders, scanning, notifications, open at login, and exactly
/// what left the Mac in the last scan.
public struct SettingsView: View {
    public static let size = CGSize(width: 540, height: 720)

    public var state: SettingsState
    public var actions: SettingsActions
    @State private var showSent: Bool

    public init(state: SettingsState, actions: SettingsActions, showSent: Bool = false) {
        self.state = state; self.actions = actions
        _showSent = State(initialValue: showSent)
    }

    public var body: some View {
        Form {
            Section {
                if state.folders.isEmpty {
                    Text("No folders yet.").foregroundStyle(.secondary)
                }
                ForEach(state.folders, id: \.self) { path in
                    HStack(spacing: 10) {
                        Image(systemName: "folder.fill").symbolRenderingMode(.hierarchical).foregroundStyle(.secondary)
                        Text(Paths.abbreviatingHome(path)).font(.system(size: 12.5, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button { actions.removeFolder(path) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .symbolRenderingMode(.hierarchical)
                            .foregroundStyle(.secondary)
                            .help("Stop watching \(Paths.abbreviatingHome(path))")
                            .accessibilityLabel("Stop watching \(Paths.abbreviatingHome(path))")
                    }
                }
                HStack {
                    Spacer()
                    Button { actions.addFolder() } label: { Label("Add Folder…", systemImage: "plus") }
                }
            } header: {
                Text("Project Folders")
            } footer: {
                Text("Lockfiles in these folders (package-lock.json, yarn.lock, Cargo.lock, go.sum, Gemfile.lock and others) are read on this Mac, up to six folders deep, skipping node_modules, .git and build output. A changed lockfile is checked within seconds.")
                    .settingsFooter()
            }

            Section {
                Picker(selection: Binding(get: { state.intervalHours }, set: { actions.setInterval($0) })) {
                    ForEach(MonitorSettings.intervalChoices, id: \.self) { h in Text(h == 24 ? "Every day" : h == 1 ? "Every hour" : "Every \(h) hours").tag(h) }
                } label: {
                    Label("Scan", systemImage: "clock.arrow.circlepath").symbolRenderingMode(.hierarchical)
                }
                Toggle(isOn: Binding(get: { state.notifications }, set: { actions.setNotifications($0) })) {
                    Label {
                        Text("Notifications")
                        Text("Malicious packages and extensions, flaws exploited in the wild, and anything on the site's “patch these first” list.")
                    } icon: { Image(systemName: "bell.badge").symbolRenderingMode(.hierarchical) }
                }
                .disabled(!state.notificationsAvailable)
                Toggle(isOn: Binding(get: { state.launchAtLogin }, set: { actions.setLaunchAtLogin($0) })) {
                    Label("Open at Login", systemImage: "power").symbolRenderingMode(.hierarchical)
                }
                .disabled(!state.launchAtLoginAvailable)
            } header: {
                Text("Scanning")
            } footer: {
                Text(state.notificationsAvailable && state.launchAtLoginAvailable
                     ? "The public index is downloaded again once a day."
                     : "The public index is downloaded again once a day. Notifications and opening at login work in the installed app, OSVA Monitor.app.")
                    .settingsFooter()
            }

            Section {
                Text("OSVA Monitor downloads the site's public index (packages with an advisory or a malicious report, graded projects, apps, bundled libraries, malicious extensions) and decides on this Mac which installed things are in it. Only those are named to verificationalliance.org: packages by name and exact version (saying macOS, and a Python package's Python), projects and products by the index's own names. Extensions are checked on this Mac only. No file paths, bundle identifiers, extension IDs or list of what else is installed are sent.")
                    .font(Typeface.body).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let report = state.lastReport {
                    let counts = SentSummary.counts(report.sent)
                    LabeledContent("Package versions checked") { count(counts.batch) }
                    LabeledContent("Projects matched from Homebrew") { count(counts.projects) }
                    LabeledContent("Apps and bundled libraries checked") { count(counts.products) }
                    LabeledContent("Answered from this Mac's cache") { count(report.sent.answeredFromCache) }
                    LabeledContent("Not in the public index, never sent") { count(report.sent.withheldCount) }
                    if !report.sent.requests.isEmpty {
                        DisclosureGroup(isExpanded: $showSent) {
                            sentList(report.sent)
                        } label: {
                            Text("Everything sent in the last scan")
                        }
                    }
                }
            } header: {
                Text("What Leaves Your Mac")
            } footer: {
                if let report = state.lastReport {
                    Text("Last scan \(report.finishedAt.formatted(date: .abbreviated, time: .shortened)).").settingsFooter()
                } else {
                    Text("Nothing has been sent yet.").settingsFooter()
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: Self.size.width, height: Self.size.height)
    }

    private func count(_ n: Int) -> some View {
        Text("\(n)").font(Typeface.count(13, weight: .medium)).foregroundStyle(n == 0 ? .secondary : .primary)
    }

    private func sentList(_ sent: SentRecord) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(SentSummary.groups(sent).enumerated()), id: \.offset) { _, group in
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.title).font(Typeface.chip).foregroundStyle(.secondary)
                    ForEach(group.items, id: \.self) { Text($0).font(Typeface.code).textSelection(.enabled) }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }
}

private extension Text {
    func settingsFooter() -> some View {
        font(Typeface.small).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

/// The words and numbers for "What leaves your Mac".
public enum SentSummary {
    public struct Counts: Equatable, Sendable { public var batch: Int; public var projects: Int; public var products: Int = 0 }

    public static func counts(_ sent: SentRecord) -> Counts {
        func count(_ endpoint: String) -> Int { sent.requests.filter { $0.endpoint == endpoint }.reduce(0) { $0 + $1.items.count } }
        return Counts(batch: count("POST api/v1/check/batch"), projects: count("GET api/v1/project"), products: count("GET api/v1/product"))
    }

    public struct Group { public var title: String; public var items: [String] }

    public static func groups(_ sent: SentRecord) -> [Group] {
        sent.requests.map { r in
            let title: String
            switch r.endpoint {
            case "POST api/v1/check/batch": title = "POST /api/v1/check/batch · \(r.items.count)"
            case "GET api/v1/project": title = "GET /api/v1/project · \(r.items.count)"
            case "GET api/v1/product": title = "GET /api/v1/product · \(r.items.count)"
            default: title = r.endpoint
            }
            return Group(title: title, items: r.items)
        }
    }
}
