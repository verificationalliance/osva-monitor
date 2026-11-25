import SwiftUI

/// What is new in this version, at the top of the panel the first time it opens after an update: the changelog's
/// lines for it, and Close. A PanelCard, like the groups under it. Closed, it is not shown again for this version;
/// Settings lists every version.
public struct WhatsNewCard: View {
    public var entry: Changelog.Entry
    public var close: () -> Void

    public init(entry: Changelog.Entry, close: @escaping () -> Void) { self.entry = entry; self.close = close }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "sparkles").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text("What’s new in \(entry.version)").font(Typeface.title).foregroundStyle(.primary)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 8)
                Button("Close", action: close)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
                    .help("Hides this until the next update. Settings lists every version.")
            }
            ChangelogLines(entry.lines)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .panelCard()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("What’s new in \(entry.version)")
    }
}

/// A version's lines, one per bullet, wrapping under their own first word: in the What's New card, and under each
/// version in Settings.
public struct ChangelogLines: View {
    public var lines: [String]
    public var font: Font

    public init(_ lines: [String], font: Font = Typeface.small) { self.lines = lines; self.font = font }

    public var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("•").foregroundStyle(.secondary).accessibilityHidden(true)
                    Text(Changelog.quotesWhole(line)).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .font(font)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Settings > What's New: every version in the changelog, newest first, each opening to its lines.
struct WhatsNewSection: View {
    let changelog: Changelog
    @State private var open: Set<String>

    init(changelog: Changelog, open: Set<String> = []) {
        self.changelog = changelog
        _open = State(initialValue: open)
    }

    /// The versions as the section lists them.
    var rows: [Changelog.Entry] { changelog.newestFirst }

    var body: some View {
        Section {
            ForEach(rows) { entry in
                DisclosureGroup(isExpanded: Binding(get: { open.contains(entry.version) },
                                                    set: { if $0 { open.insert(entry.version) } else { open.remove(entry.version) } })) {
                    ChangelogLines(entry.lines, font: Typeface.body).padding(.vertical, 2)
                } label: {
                    Text(entry.version).monospacedDigit()
                }
            }
        } header: {
            Text("What’s New")
        }
    }
}
