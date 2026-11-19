import AppKit
import SwiftUI

/// The sheet behind one number in "What leaves your Mac": every name it counts, in the one list component the app
/// has for names (NameListView).
public struct SentListView: View {
    public static let size = NameListView.size

    let list: SentList
    let scanned: Date
    let query: String

    public init(list: SentList, scanned: Date, query: String = "") {
        self.list = list; self.scanned = scanned; self.query = query
    }

    typealias Row = NameListView.Row
    typealias Part = NameListView.Part

    nonisolated static func sections(_ list: SentList, matching query: String) -> [Part] {
        NameListView.sections(list.nameList, matching: query)
    }

    public var body: some View { NameListView(list: list.nameList, scanned: scanned, query: query) }

    nonisolated static func footer(_ list: SentList, scanned: Date, query: String, matching: Int) -> String {
        NameListView.footer(list.nameList, scanned: scanned, query: query, matching: matching)
    }
}

extension SentList {
    /// As a list of names: monospaced, exactly as sent.
    public var nameList: NameList {
        NameList(title: title, explanation: explanation, count: count, sections: sections.map { .init(title: $0.title, items: $0.items) }, style: .code)
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
