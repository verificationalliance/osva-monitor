import AppKit
import OSVAKit
import SwiftUI

/// The names behind a number: the package versions a scan sent, the names that stayed on this Mac, the apps nothing
/// checks. Every such list is this one component, so they all read alike: one name per line, an app's own icon beside
/// it, and a search field once there are more than about twenty names, too many to scan by eye.
public struct NameList: Identifiable, Sendable, Equatable {
    public enum Style: Sendable, Equatable {
        /// Names with versions, as a registry writes them and as they were sent: monospaced.
        case code
        /// Apps and what they bundle: the app's own typography, each with its app's icon.
        case names
    }

    public struct Section: Sendable, Equatable {
        public var title: String?
        public var items: [String]
        /// Each item's app bundle, in order, for its icon.
        public var paths: [String]?
        public init(title: String?, items: [String], paths: [String]? = nil) {
            self.title = title; self.items = items; self.paths = paths.flatMap { $0.count == items.count ? $0 : nil }
        }
    }

    /// More names than this get a search field (and, in the panel, a window of their own).
    public static let searchThreshold = 20

    public var title: String
    /// The sentence under the title: what the names are, and what was or was not done with them.
    public var explanation: String
    /// The number in the row: exact, even when the saved list was cut short.
    public var count: Int
    /// Empty sections left out.
    public var sections: [Section]
    public var style: Style
    /// What one name is and what many are ("app", "apps"), for the footer.
    public var one: String
    public var many: String
    public var id: String { title }

    public init(title: String, explanation: String, count: Int, sections: [Section], style: Style, one: String = "name", many: String = "names") {
        self.title = title; self.explanation = explanation; self.count = count; self.sections = sections.filter { !$0.items.isEmpty }
        self.style = style; self.one = one; self.many = many
    }

    /// How many names the list holds.
    public var shown: Int { sections.reduce(0) { $0 + $1.items.count } }
    public var searchable: Bool { shown > Self.searchThreshold }
}

/// A list of names in its own sheet or window: the title and what the names are, a search field when there are more
/// than about twenty, the names one per line in a list that draws only the rows on screen (a scan can withhold
/// thousands), and how many there are.
public struct NameListView: View {
    public static let size = CGSize(width: 500, height: 560)
    /// The window the panel opens a long list in.
    public static let windowID = "name-list"

    let list: NameList
    let scanned: Date
    @State private var query: String
    @Environment(\.dismiss) private var dismiss

    public init(list: NameList, scanned: Date, query: String = "") {
        self.list = list; self.scanned = scanned
        _query = State(initialValue: query)
    }

    struct Row: Identifiable { let id: Int; let text: String; let path: String? }
    struct Part: Identifiable { let id: Int; let title: String?; let rows: [Row] }

    /// The sections with their rows, numbered once, filtered by the query (case and diacritics ignored).
    nonisolated static func sections(_ list: NameList, matching query: String) -> [Part] {
        let q = query.trimmingCharacters(in: .whitespaces)
        var next = 0
        return list.sections.enumerated().compactMap { i, s in
            let rows = s.items.enumerated().compactMap { j, item -> Row? in
                defer { next += 1 }
                return q.isEmpty || item.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil
                    ? Row(id: next, text: item, path: s.paths?[j]) : nil
            }
            return rows.isEmpty ? nil : Part(id: i, title: s.title, rows: rows)
        }
    }

    public var body: some View {
        let sections = Self.sections(list, matching: query)
        let matching = sections.reduce(0) { $0 + $1.rows.count }
        let searching = !query.trimmingCharacters(in: .whitespaces).isEmpty
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(list.title).font(.headline)
                Text(list.explanation).font(Typeface.small).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 12)

            if list.searchable {
                SearchField(text: $query, prompt: "Search \(list.shown.formatted()) \(list.many)")
                    .padding(.horizontal, 20).padding(.bottom, 10)
            }

            List {
                ForEach(sections) { section in
                    if let title = section.title {
                        SwiftUI.Section {
                            rows(section)
                        } header: {
                            Text("\(title) · \((searching ? section.rows.count : list.sections[section.id].items.count).formatted())")
                        }
                    } else {
                        rows(section)
                    }
                }
            }
            .listStyle(.bordered(alternatesRowBackgrounds: true))
            .overlay {
                if sections.isEmpty { ContentUnavailableView.search(text: query) }
            }
            .padding(.horizontal, 20)

            HStack(alignment: .firstTextBaseline) {
                Text(Self.footer(list, scanned: scanned, query: query, matching: matching)).font(Typeface.small).foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20).padding(.vertical, 14)
        }
        .frame(width: Self.size.width, height: Self.size.height)
        .onExitCommand { dismiss() }
    }

    private func rows(_ section: Part) -> some View {
        ForEach(section.rows) { row in
            NameRow(row.text, path: row.path, style: list.style, font: list.style == .code ? Typeface.listCode : Typeface.body)
                .textSelection(.enabled)
        }
    }

    /// "141 apps · last scan 19 Nov 2026 at 02:06", "12 of 141", or, when the saved list was cut, how much it holds.
    nonisolated static func footer(_ list: NameList, scanned: Date, query: String, matching: Int) -> String {
        if !query.trimmingCharacters(in: .whitespaces).isEmpty { return "\(matching.formatted()) of \(list.shown.formatted())" }
        let when = "last scan \(scanned.formatted(date: .abbreviated, time: .shortened))"
        if list.shown < list.count { return "The first \(list.shown.formatted()) of \(list.count.formatted()) · \(when)" }
        return "\(list.shown.formatted()) \(list.shown == 1 ? list.one : list.many) · \(when)"
    }
}

/// One name on its own line: in a list window and in the panel alike. An app's name has its icon beside it.
struct NameRow: View {
    let text: String
    let path: String?
    let style: NameList.Style
    let font: Font

    init(_ text: String, path: String?, style: NameList.Style, font: Font) {
        self.text = text; self.path = path; self.style = style; self.font = font
    }

    var body: some View {
        HStack(spacing: 7) {
            if style == .names { AppIcon(path: path ?? "") }        // the generic app icon when its bundle is not known
            Text(text).font(font).lineLimit(1).truncationMode(.middle)
        }
        .help(text)
    }
}

/// An app's own icon, small, as Finder draws it. An app no longer there gets the generic app icon.
struct AppIcon: View {
    let path: String
    var body: some View {
        Image(nsImage: AppIcons.icon(path)).resizable().interpolation(.high).frame(width: 16, height: 16).accessibilityHidden(true)
    }
}

/// Icons by path, kept once read (a list redraws rows as it scrolls).
@MainActor public enum AppIcons {
    private static let cache = NSCache<NSString, NSImage>()

    /// Where an icon comes from. In the app: NSWorkspace, which has macOS's icon service, outside this process, read
    /// and draw the app's icon, so no third-party image file is decoded here. osva-render runs where there is no icon
    /// service (an SSH session gets only placeholders) and sets its own.
    public static var source: (String) -> NSImage = { path in
        FileManager.default.fileExists(atPath: path) ? NSWorkspace.shared.icon(forFile: path) : NSWorkspace.shared.icon(for: .applicationBundle)
    }

    static func icon(_ path: String) -> NSImage {
        if let hit = cache.object(forKey: path as NSString) { return hit }
        let image = source(path)
        image.size = NSSize(width: 16, height: 16)
        cache.setObject(image, forKey: path as NSString)
        return image
    }
}
