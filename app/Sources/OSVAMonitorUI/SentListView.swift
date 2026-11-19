import AppKit
import SwiftUI

/// The sheet behind one number in "What leaves your Mac": every name it counts, in a list that draws only the rows on
/// screen (a scan can withhold thousands), with a search field that narrows it as you type.
public struct SentListView: View {
    public static let size = CGSize(width: 500, height: 560)

    let list: SentList
    let scanned: Date
    @State private var query: String
    @Environment(\.dismiss) private var dismiss

    public init(list: SentList, scanned: Date, query: String = "") {
        self.list = list; self.scanned = scanned
        _query = State(initialValue: query)
    }

    struct Row: Identifiable { let id: Int; let text: String }
    struct Part: Identifiable { let id: Int; let title: String?; let rows: [Row] }

    /// The sections with their rows, numbered once, filtered by the query (case and diacritics ignored).
    nonisolated static func sections(_ list: SentList, matching query: String) -> [Part] {
        let q = query.trimmingCharacters(in: .whitespaces)
        var next = 0
        return list.sections.enumerated().compactMap { i, s in
            let rows = s.items.compactMap { item -> Row? in
                defer { next += 1 }
                return q.isEmpty || item.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil ? Row(id: next, text: item) : nil
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

            SearchField(text: $query, prompt: "Search \(list.shown.formatted()) names")
                .padding(.horizontal, 20).padding(.bottom, 10)

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
            Text(row.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                .lineLimit(1).truncationMode(.middle).help(row.text)
        }
    }

    /// "760 names · last scan 19 Nov 2026 at 02:06", "12 of 760", or, when the saved list was cut, how much it holds.
    nonisolated static func footer(_ list: SentList, scanned: Date, query: String, matching: Int) -> String {
        if !query.trimmingCharacters(in: .whitespaces).isEmpty { return "\(matching.formatted()) of \(list.shown.formatted())" }
        let when = "last scan \(scanned.formatted(date: .abbreviated, time: .shortened))"
        if list.shown < list.count { return "The first \(list.shown.formatted()) of \(list.count.formatted()) · \(when)" }
        return "\(list.shown.formatted()) \(list.shown == 1 ? "name" : "names") · \(when)"
    }
}

/// AppKit's search field: the native look, its clear button, and the focus it takes when the sheet opens.
struct SearchField: NSViewRepresentable {
    @Binding var text: String
    var prompt: String

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = prompt
        field.sendsSearchStringImmediately = true
        field.delegate = context.coordinator
        DispatchQueue.main.async { field.window?.makeFirstResponder(field) }
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
        field.placeholderString = prompt
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func controlTextDidChange(_ note: Notification) {
            if let field = note.object as? NSSearchField { text.wrappedValue = field.stringValue }
        }
    }
}
