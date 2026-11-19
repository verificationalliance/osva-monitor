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
    public var updates: UpdateState
    /// Every version and what it brought, for What's New.
    public var changelog: Changelog

    public init(folders: [String], intervalHours: Int, notifications: Bool, notificationsAvailable: Bool,
                launchAtLogin: Bool, launchAtLoginAvailable: Bool, lastReport: ScanReport?, updates: UpdateState = .none,
                changelog: Changelog = Changelog()) {
        self.folders = folders; self.intervalHours = intervalHours; self.notifications = notifications
        self.notificationsAvailable = notificationsAvailable; self.launchAtLogin = launchAtLogin
        self.launchAtLoginAvailable = launchAtLoginAvailable; self.lastReport = lastReport; self.updates = updates
        self.changelog = changelog
    }
}

public struct SettingsActions {
    public var addFolder: () -> Void
    public var removeFolder: (String) -> Void
    public var setInterval: (Int) -> Void
    public var setNotifications: (Bool) -> Void
    public var setLaunchAtLogin: (Bool) -> Void
    public var checkForUpdates: () -> Void
    public var setChecksForUpdatesAutomatically: (Bool) -> Void

    public init(addFolder: @escaping () -> Void, removeFolder: @escaping (String) -> Void, setInterval: @escaping (Int) -> Void,
                setNotifications: @escaping (Bool) -> Void, setLaunchAtLogin: @escaping (Bool) -> Void,
                checkForUpdates: @escaping () -> Void = {}, setChecksForUpdatesAutomatically: @escaping (Bool) -> Void = { _ in }) {
        self.addFolder = addFolder; self.removeFolder = removeFolder; self.setInterval = setInterval
        self.setNotifications = setNotifications; self.setLaunchAtLogin = setLaunchAtLogin
        self.checkForUpdates = checkForUpdates; self.setChecksForUpdatesAutomatically = setChecksForUpdatesAutomatically
    }

    public static var none: SettingsActions {
        SettingsActions(addFolder: {}, removeFolder: { _ in }, setInterval: { _ in }, setNotifications: { _ in }, setLaunchAtLogin: { _ in })
    }
}

/// The settings window, a native grouped form: watched folders, scanning, notifications, open at login, exactly
/// what left the Mac in the last scan (each number opens its list), updates, and what each version brought.
public struct SettingsView: View {
    public static let size = CGSize(width: 540, height: 720)

    public var state: SettingsState
    public var actions: SettingsActions
    /// The window's height; osva-render draws it taller to show every section at once.
    public var height: CGFloat
    /// Versions opened under What's New from the start (for renders).
    let whatsNewOpen: Set<String>
    @State private var openList: SentList.Kind?

    public init(state: SettingsState, actions: SettingsActions, height: CGFloat = SettingsView.size.height, whatsNewOpen: Set<String> = []) {
        self.state = state; self.actions = actions; self.height = height; self.whatsNewOpen = whatsNewOpen
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
                    ForEach(SentSummary.lists(report.sent)) { list in
                        SentListRow(list: list) { openList = list.kind }
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

            if state.updates.isAvailable {
                updatesSection
            }

            if !state.changelog.entries.isEmpty {
                WhatsNewSection(changelog: state.changelog, open: whatsNewOpen)
            }
        }
        .formStyle(.grouped)
        .frame(width: Self.size.width, height: height)
        .sheet(item: $openList) { kind in
            if let report = state.lastReport, let list = SentSummary.lists(report.sent).first(where: { $0.kind == kind }) {
                SentListView(list: list, scanned: report.finishedAt)
            }
        }
    }

    /// The app's own updates: its version and a check now, and the daily check, on unless turned off.
    private var updatesSection: some View {
        Section {
            LabeledContent {
                Button("Check for Updates…", action: actions.checkForUpdates).disabled(!state.updates.canCheck)
            } label: {
                Label {
                    Text("OSVA Monitor \(state.updates.version)")
                    if let line = state.updates.lastCheckedLine() { Text(line) }
                } icon: { Image(systemName: "arrow.down.circle").symbolRenderingMode(.hierarchical) }
            }
            Toggle(isOn: Binding(get: { state.updates.checksAutomatically }, set: { actions.setChecksForUpdatesAutomatically($0) })) {
                Label {
                    Text("Check Automatically")
                    Text("Once a day. You choose whether to install what it finds.")
                } icon: { Image(systemName: "arrow.trianglehead.2.clockwise.rotate.90").symbolRenderingMode(.hierarchical) }
            }
        } header: {
            Text("Updates")
        } footer: {
            Text("New versions come from the project's GitHub releases. One is installed only if it is signed with the OSVA Monitor update key, which this app carries. The check downloads verificationalliance.org/app/appcast.xml and tells it nothing about this Mac but the app's version.")
                .settingsFooter()
        }
    }
}

/// One number under "What leaves your Mac". With anything to show, the whole row opens its list; without, the
/// chevron's place stays empty so the numbers still line up.
struct SentListRow: View {
    let list: SentList
    let open: () -> Void

    var body: some View {
        if list.canOpen {
            Button(action: open) { row.contentShape(Rectangle()) }
                .buttonStyle(.plain)
                .help("Show the \(list.count.formatted()) \(list.noun)")
                .accessibilityHint("Shows the list")
        } else {
            row
        }
    }

    private var row: some View {
        HStack(spacing: 6) {
            Text(list.title).foregroundStyle(.primary)
            Spacer(minLength: 8)
            Text(list.count.formatted()).font(Typeface.count(13, weight: .medium)).foregroundStyle(list.count == 0 ? .secondary : .primary)
            Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(.tertiary)
                .opacity(list.canOpen ? 1 : 0)
                .accessibilityHidden(true)
        }
        .accessibilityElement(children: .combine)
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

    /// The numbers, each with the list behind it, in the order Settings shows them. Apps and bundled libraries have a
    /// number of their own once a scan has asked about any.
    public static func lists(_ sent: SentRecord) -> [SentList] {
        func items(_ endpoint: String) -> [String] { sent.requests.filter { $0.endpoint == endpoint }.flatMap(\.items) }
        let checked = items("POST api/v1/check/batch")
        let projects = items("GET api/v1/project").map(projectSlug)
        let products = items("GET api/v1/product").map(productKey)
        let cachedPackages = sent.cached.filter { !$0.hasPrefix("project ") && !$0.hasPrefix("product ") }
        let cachedProjects = sent.cached.filter { $0.hasPrefix("project ") }.map(projectSlug)
        let cachedProducts = sent.cached.filter { $0.hasPrefix("product ") }.map(productKey)
        return [
            SentList(kind: .checked, count: checked.count, sections: [.init(title: nil, items: checked)]),
            SentList(kind: .projects, count: projects.count, sections: [.init(title: nil, items: projects)]),
        ] + (products.isEmpty && cachedProducts.isEmpty ? [] : [SentList(kind: .products, count: products.count, sections: [.init(title: nil, items: products)])]) + [
            SentList(kind: .cached, count: sent.answeredFromCache,
                     sections: [.init(title: "Package versions", items: cachedPackages), .init(title: "Projects", items: cachedProjects),
                                .init(title: "Apps and bundled libraries", items: cachedProducts)]),
            SentList(kind: .withheld, count: sent.withheldCount, sections: sent.withheld.map { .init(title: $0.source, items: $0.items) }),
        ]
    }

    /// "project openssl" (as recorded) is the slug "openssl".
    static func projectSlug(_ item: String) -> String { item.hasPrefix("project ") ? String(item.dropFirst("project ".count)) : item }
    /// "product zoom" (as recorded) is the key "zoom".
    static func productKey(_ item: String) -> String { item.hasPrefix("product ") ? String(item.dropFirst("product ".count)) : item }
}

/// One of the lists behind "What leaves your Mac": what one number counts, by name.
public struct SentList: Identifiable, Sendable, Equatable {
    public enum Kind: String, CaseIterable, Identifiable, Sendable {
        case checked, projects, products, cached, withheld
        public var id: String { rawValue }
    }

    public struct Section: Sendable, Equatable {
        public var title: String?
        public var items: [String]
    }

    public var kind: Kind
    /// The number in the row: exact, even when the saved list was cut short.
    public var count: Int
    /// The names, empty sections left out.
    public var sections: [Section]
    public var id: Kind { kind }

    public init(kind: Kind, count: Int, sections: [Section]) {
        self.kind = kind; self.count = count; self.sections = sections.filter { !$0.items.isEmpty }
    }

    /// How many names the list holds (at most SentRecord.listLimit; none for a report from before lists were kept).
    public var shown: Int { sections.reduce(0) { $0 + $1.items.count } }
    /// A row opens only when there is something to show: a count of 0 is not a disclosure.
    public var canOpen: Bool { count > 0 && shown > 0 }

    public var title: String {
        switch kind {
        case .checked: return "Package versions checked"
        case .projects: return "Projects matched from Homebrew"
        case .products: return "Apps and bundled libraries checked"
        case .cached: return "Answered from this Mac's cache"
        case .withheld: return "Not in the public index, never sent"
        }
    }

    /// What the items are, for "Show the 245 …".
    public var noun: String {
        switch kind {
        case .checked: return count == 1 ? "package version sent" : "package versions sent"
        case .projects: return count == 1 ? "project asked about" : "projects asked about"
        case .products: return count == 1 ? "app or library asked about" : "apps and libraries asked about"
        case .cached: return count == 1 ? "answer from the cache" : "answers from the cache"
        case .withheld: return count == 1 ? "name that stayed on this Mac" : "names that stayed on this Mac"
        }
    }

    /// The sentence under the sheet's title.
    public var explanation: String {
        switch kind {
        case .checked:
            return "Sent to verificationalliance.org in the last scan, exactly as written here: ecosystem, name and version. A Python package also names its Python, and a package installed on this Mac says macOS."
        case .projects:
            return "Asked about by name in the last scan: the projects the site grades that your Homebrew formulae and casks belong to. Formula and cask names are not sent."
        case .products:
            return "Asked about by name in the last scan: the apps and bundled libraries the public index lists, by the index's own name for each. Bundle identifiers, app file names and paths are not sent."
        case .cached:
            return "Checked in an earlier scan and answered this time from this Mac's cache, so not sent again."
        case .withheld:
            return "Installed on this Mac but not in the public index, by where each was found. Their names were not sent anywhere; this list is only on this Mac."
        }
    }
}
