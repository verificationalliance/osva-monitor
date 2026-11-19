import AppKit
import OSVAKit
import SwiftUI

/// Where a finding's copies are on this Mac and why each is there (`Finding.provenance`, read from local files): per
/// copy, a "Where" line with the path and Show in Finder, and a one-line "Why"; what needs it, and with which versions,
/// on demand. Text is `.primary` on the glass, its terms `.secondary`; the only control is a small bordered button,
/// untinted, so nothing here is coloured text on grey.
public struct ProvenanceView: View {
    let copies: [Provenance]
    @State private var open: Set<Int> = []
    @Environment(\.revealInFinder) private var reveal
    @Environment(\.provenanceDetailsOpen) private var detailsOpen

    /// Copies shown; the rest are counted.
    static let shownCopies = 3
    /// The terms' column: "Where", the wider, is 31 pt in 11.5 pt SF Pro.
    static let termWidth: CGFloat = 40

    public init(_ copies: [Provenance]?) {
        self.copies = (copies ?? []).filter { $0.path != nil || $0.why != nil }
    }

    /// A copy's details are open when toggled, or (for renders) when the environment opens them all.
    private func isOpen(_ index: Int) -> Bool { open.contains(index) != detailsOpen }

    public var body: some View {
        if !copies.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array(copies.prefix(Self.shownCopies).enumerated()), id: \.offset) { i, copy in
                    copyView(copy, index: i)
                }
                if copies.count > Self.shownCopies {
                    FactRow("") {
                        Text("and \(copies.count - Self.shownCopies) more \(copies.count - Self.shownCopies == 1 ? "place" : "places")")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .font(Typeface.small)
        }
    }

    @ViewBuilder private func copyView(_ copy: Provenance, index: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if let path = copy.path {
                FactRow("Where") {
                    Text(Self.breakable(Paths.abbreviatingHome(path)))
                        .foregroundStyle(.primary)
                        .help(path)
                        .accessibilityLabel(Paths.abbreviatingHome(path))
                }
            }
            if let why = copy.why {
                FactRow("Why") { Text(Self.breakable(why)).foregroundStyle(.primary).accessibilityLabel(why) }
            }
            if let advice = copy.advice {
                // a recommendation, set a little apart from the facts above it
                FactRow("") { Text(advice).fontWeight(.medium).foregroundStyle(.primary) }
            }
            if copy.path != nil || copy.hasMore {
                FactRow("") {
                    HStack(spacing: 12) {
                        if let path = copy.path {
                            Button { reveal(path) } label: { Label("Show in Finder", systemImage: "folder") }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .help("Select it in a Finder window")
                        }
                        if copy.hasMore { detailsToggle(index) }
                    }
                }
                .padding(.top, 2)
            }
            if isOpen(index) {
                FactRow("") { details(copy) }
                    .transition(.opacity)
            }
        }
        .accessibilityElement(children: .contain)
    }

    /// "Details" with a chevron, drawn by SwiftUI (so it renders off-screen too), `.secondary` like the row's own.
    private func detailsToggle(_ index: Int) -> some View {
        let isOpen = isOpen(index)
        return HStack(spacing: 4) {
            Text("Details")
            Image(systemName: "chevron.down")
                .font(.system(size: 9, weight: .semibold))
                .rotationEffect(.degrees(isOpen ? 180 : 0))
        }
        .foregroundStyle(.secondary)
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onTapGesture { withAnimation(.smooth(duration: 0.25)) { if isOpen { open.remove(index) } else { open.insert(index) } } }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(isOpen ? "Hide details" : "Show details")
        .accessibilityAddTraits(.isButton)
    }

    /// What needs it and the versions each accepts in `.primary`, only the word "needs" quieter (`.secondary` alone
    /// is too faint on mid-grey glass), then the rest.
    private func details(_ copy: Provenance) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(copy.dependents.prefix(12).enumerated()), id: \.offset) { _, d in
                Text(Self.dependentLine(d)).foregroundStyle(.secondary)
            }
            if copy.dependents.count > 12 {
                Text("and \(copy.dependents.count - 12) more").foregroundStyle(.secondary)
            }
            ForEach(Array(copy.details.enumerated()), id: \.offset) { _, line in
                Text(Self.breakable(line)).foregroundStyle(.primary)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    static func dependentLine(_ d: Provenance.Dependent) -> AttributedString {
        var who = AttributedString(d.name + (d.version.map { " \($0)" } ?? ""))
        who.foregroundColor = .primary
        func plain(_ s: String) -> AttributedString { var a = AttributedString(s); a.foregroundColor = .primary; return a }
        switch d.specifier {
        case nil: return who + AttributedString(" needs it")
        case ""?: return who + AttributedString(" needs ") + plain("any version")
        case let s?: return who + AttributedString(" needs ") + plain(s)
        }
    }

    /// A path that wraps after a "/" and never inside a name: a zero-width space after each separator, a word joiner
    /// after each hyphen ("site-packages" stays whole).
    static func breakable(_ s: String) -> String {
        s.replacingOccurrences(of: "-", with: "-\u{2060}").replacingOccurrences(of: "/", with: "/\u{200B}")
    }
}

/// One fact: its term in `.secondary` on the left, its value filling the rest of the line.
struct FactRow<Value: View>: View {
    let term: String
    let value: Value

    init(_ term: String, @ViewBuilder value: () -> Value) { self.term = term; self.value = value() }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(term).foregroundStyle(.secondary).frame(width: ProvenanceView.termWidth, alignment: .leading)
                .accessibilityHidden(term.isEmpty)
            value.frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Shows a path in Finder. The app's is NSWorkspace, on this Mac alone; previews and tests put their own in the
/// environment.
public struct RevealInFinder: Sendable {
    let action: @MainActor @Sendable (String) -> Void
    public init(_ action: @escaping @MainActor @Sendable (String) -> Void) { self.action = action }
    @MainActor public func callAsFunction(_ path: String) { action(path) }

    /// Selects it in a Finder window; a path that is gone since the scan shows the nearest folder still there.
    public static let finder = RevealInFinder { path in
        var p = path, steps = 0
        while !FileManager.default.fileExists(atPath: p), p != "/", !p.isEmpty, steps < 64 {
            p = (p as NSString).deletingLastPathComponent; steps += 1
        }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p.isEmpty ? "/" : p)])
    }
}

extension EnvironmentValues {
    @Entry public var revealInFinder: RevealInFinder = .finder
    /// Opens every copy's details (off-screen renders of that state).
    @Entry public var provenanceDetailsOpen: Bool = false
}
