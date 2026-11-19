import OSVAKit
import SwiftUI

// The shared pieces. Each kind of thing has exactly one component here, coloured only from Theme.swift's tokens, so
// restyling can never leave a copy behind.

/// Severity as the site's `.sev`: an 8 pt square in the severity's fill, with a 1 pt ring in light mode so the pale
/// fills keep an edge on light glass.
public struct SeverityMark: View {
    public var severity: Severity
    public init(_ severity: Severity) { self.severity = severity }

    public var body: some View {
        let t = Tokens.severity(severity)
        RoundedRectangle(cornerRadius: 2, style: .continuous)
            .fill(t.fill.color)
            .overlay(RoundedRectangle(cornerRadius: 2, style: .continuous).strokeBorder(t.ring.color, lineWidth: 1))
            .frame(width: 8, height: 8)
            .accessibilityHidden(true)
    }
}

/// A severity in a row: the mark, then its word in `.secondary` (coloured small text would lose contrast and vibrancy).
public struct SeverityLabel: View {
    public var severity: Severity
    public init(_ severity: Severity) { self.severity = severity }
    public var body: some View {
        HStack(spacing: 5) {
            SeverityMark(severity)
            Text(severity.label).font(Typeface.small).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The small status labels. `.exploited` is the site's `.chip-kev` and the only solid red in the panel; `.malicious`
/// is the clay word with its octagon; `.count` is a hero summary chip, a faint capsule of the status colour with a
/// mark and a `.primary` label.
public struct StatusChip: View {
    public enum Kind: Sendable, Hashable {
        case exploited
        case malicious
        case count(PopoverContent.Tally, Int)
    }

    public var kind: Kind
    public init(_ kind: Kind) { self.kind = kind }

    public var body: some View {
        switch kind {
        case .exploited:
            Label("Exploited", systemImage: "flame.fill")
                .labelStyle(TightLabel())
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6).padding(.vertical, 2.5)
                .background(Capsule().fill(Tokens.Exploited.chip.color))
                .overlay(Capsule().strokeBorder(Tokens.Exploited.chipRing.color, lineWidth: 1))
                .help("Exploited in the wild (CISA KEV)")
        case .malicious:
            Label("Malicious", systemImage: "xmark.octagon.fill")
                .labelStyle(TightLabel())
                .font(Typeface.small.weight(.semibold))
                .foregroundStyle(Tokens.Malicious.text.color)
        case let .count(tally, n):
            HStack(spacing: 4) {
                mark(tally)
                Text("\(n)").font(Typeface.count(11, weight: .semibold))
                Text(tally.word(n)).font(Typeface.chip)
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 5.5).padding(.vertical, 2.5)
            .background(Capsule().fill(tint(tally).opacity(light: 0.15, dark: 0.25).color))
            .accessibilityElement(children: .combine)
        }
    }

    @ViewBuilder private func mark(_ tally: PopoverContent.Tally) -> some View {
        switch tally {
        case .malicious: RoundedRectangle(cornerRadius: 2, style: .continuous).fill(Tokens.Malicious.glyph.color).frame(width: 8, height: 8)
        case .exploited: RoundedRectangle(cornerRadius: 2, style: .continuous).fill(Tokens.Exploited.glyph.color).frame(width: 8, height: 8)
        case let .severity(s): SeverityMark(s)
        }
    }

    private func tint(_ tally: PopoverContent.Tally) -> Tone {
        switch tally {
        case .malicious: return Tokens.Malicious.glyph
        case .exploited: return Tokens.Exploited.glyph
        case let .severity(s): return Tokens.severity(s).fill
        }
    }
}

/// A trust grade, A to F, or U for not enough evidence: 16 pt tile, 4.5 pt corners, SF Rounded heavy letter. The site's
/// fills in both modes, with a ring on dark; U is hollow.
public struct GradeTile: View {
    public var grade: String
    public init(_ grade: String) { self.grade = grade }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: 4.5, style: .continuous)
        Group {
            if let t = Tokens.grades[grade] {
                Text(grade).foregroundStyle(.white)
                    .frame(width: 16, height: 16)
                    .background(shape.fill(Tokens.gradeFill(t)))
                    .overlay(shape.strokeBorder(Tokens.gradeRing(t), lineWidth: 1))
            } else {
                Text(grade).foregroundStyle(Tokens.UngradedTile.letter)
                    .frame(width: 16, height: 16)
                    .background(shape.fill(Tokens.UngradedTile.fill))
                    .overlay(shape.strokeBorder(Tokens.UngradedTile.ring, lineWidth: 1))
            }
        }
        .font(.system(size: 10, weight: .heavy, design: .rounded))
        .help(grade == "U" ? "Not enough evidence for a trust grade" : "Trust grade \(grade) on verificationalliance.org")
        .accessibilityLabel(grade == "U" ? "No trust grade: not enough evidence" : "Trust grade \(grade)")
    }
}

/// The site's verification mark (`vmark` in site/formalinformer/app.js), from the same 20 × 20 geometry: a filled disc
/// with a check for "verified as a whole", a ring with a dashed check for "verified parts". Drawn at 16 pt or larger,
/// as on the site, so the dashes stay long. In dark mode the disc is light blue with a navy check.
public struct VerificationMark: View {
    public var mark: Verification
    public var size: CGFloat

    public init(_ mark: Verification, size: CGFloat = 16) { self.mark = mark; self.size = size }

    public var body: some View {
        if mark != .none {
            let disc = Tokens.Verification.wholeDisc.color, ring = Tokens.Verification.wholeRing.color
            let check = Tokens.Verification.wholeCheck.color, stroke = Tokens.Verification.partsStroke.color
            let interior = Tokens.Verification.partsInterior.color
            Canvas { ctx, canvas in
                let s = canvas.width / 20
                func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * s, y: y * s) }
                let circle = Path(ellipseIn: CGRect(x: 1.4 * s, y: 1.4 * s, width: 17.2 * s, height: 17.2 * s))
                var tick = Path()
                if mark == .whole {
                    tick.move(to: p(5.8, 10.4)); tick.addLine(to: p(8.7, 13.3)); tick.addLine(to: p(14.3, 7.3))
                    ctx.fill(circle, with: .color(disc))
                    ctx.stroke(circle, with: .color(ring), lineWidth: 1 * s)
                    ctx.stroke(tick, with: .color(check), style: StrokeStyle(lineWidth: 2.3 * s, lineCap: .round, lineJoin: .round))
                } else {
                    tick.move(to: p(4.3, 10.2)); tick.addLine(to: p(8.3, 14.2)); tick.addLine(to: p(15.8, 6.0))
                    ctx.fill(circle, with: .color(interior))
                    ctx.stroke(circle, with: .color(stroke), lineWidth: 1.2 * s)
                    ctx.stroke(tick, with: .color(stroke),
                               style: StrokeStyle(lineWidth: 2.1 * s, lineCap: .butt, lineJoin: .miter, dash: [3.6 * s, 1.6 * s], dashPhase: 1 * s))
                }
            }
            .frame(width: size, height: size)
            .help(mark == .whole ? "Verified as a whole" : "Parts verified")
            .accessibilityLabel(mark.explanation)
        }
    }
}

extension Finding.Group {
    /// The title-case heading ("Critical and high").
    public var heading: String { title }
}

/// A group: a title-case heading (glyph, name, count), then its rows in one PanelCard, separated by dividers. The
/// malicious group is the one container with a clay wash and hairline.
public struct GroupContainer<Content: View>: View {
    public enum Heading: Equatable, Sendable {
        case findings(Finding.Group)
        /// What the app cannot classify: never counted as clean.
        case notChecked
    }

    public var heading: Heading
    public var count: Int
    let content: Content

    public init(_ group: Finding.Group, count: Int, @ViewBuilder content: () -> Content) {
        self.heading = .findings(group); self.count = count; self.content = content()
    }

    public init(_ heading: Heading, count: Int, @ViewBuilder content: () -> Content) {
        self.heading = heading; self.count = count; self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                glyph.font(.system(size: 12, weight: .semibold))
                Text(title).font(Typeface.groupTitle).foregroundStyle(.primary)
                if let n = Self.countText(count) { Text(n).font(Typeface.count(12, weight: .medium)).foregroundStyle(.secondary) }
            }
            .padding(.leading, 4)
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isHeader)
            VStack(spacing: 0) { content }
                .panelCard(heading == .findings(.malicious) ? .malicious : .plain)
        }
    }

    private var title: String {
        switch heading { case let .findings(g): return g.heading; case .notChecked: return "Not checked" }
    }

    /// The number beside the heading: what still needs action. None when every row it shows was fixed or removed and
    /// stays only until the next scan ("Malicious 0" above a removed row reads as a contradiction).
    static func countText(_ count: Int) -> String? { count > 0 ? count.formatted() : nil }

    @ViewBuilder private var glyph: some View {
        switch heading {
        case .findings(.malicious):
            Image(systemName: "xmark.octagon.fill").symbolRenderingMode(.palette).foregroundStyle(.white, Tokens.Malicious.glyph.color)
        case .findings(.exploited):
            Image(systemName: "flame.fill").symbolRenderingMode(.hierarchical).foregroundStyle(Tokens.Exploited.glyph.color)
        case .findings(.criticalHigh):
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.white, Tokens.critical.glyph.color)
        case .findings(.other):
            Image(systemName: "info.circle").symbolRenderingMode(.monochrome).foregroundStyle(.secondary)
        case .notChecked:
            Image(systemName: "questionmark.circle").symbolRenderingMode(.monochrome).foregroundStyle(.secondary)
        }
    }
}

/// A row with a list of names behind its number ("Apps with no security record · 141"). A short list opens in
/// place, one name per line; one long enough to need a search field opens in its own window (NameListView), as the
/// lists in Settings do. Either way the names are NameRows, an app's with its icon.
public struct ListDisclosureRow: View {
    public var list: NameList
    var openList: (NameList) -> Void
    @State private var open: Bool

    public init(_ list: NameList, open: Bool = false, openList: @escaping (NameList) -> Void = { _ in }) {
        self.list = list; self.openList = openList; _open = State(initialValue: open)
    }

    /// A list this long opens in a window with a search field rather than in the panel.
    public var opensWindow: Bool { list.searchable }

    public var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Text(list.title).font(Typeface.small).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Text(list.shown.formatted()).font(Typeface.count(11.5, weight: .medium)).foregroundStyle(.secondary)
                Image(systemName: opensWindow ? "chevron.right" : "chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(open && !opensWindow ? 180 : 0))
                    .frame(width: 10)
                    .accessibilityHidden(true)
            }
            if open && !opensWindow {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(Array(list.sections.flatMap { s in s.items.enumerated().map { (s.items[$0.offset], s.paths?[$0.offset]) } }.enumerated()),
                            id: \.offset) { _, item in
                        NameRow(item.0, path: item.1, style: list.style, font: list.style == .code ? Typeface.code : Typeface.small)
                            .foregroundStyle(.primary)            // what the row was opened to read, as in the list window
                    }
                }
                .textSelection(.enabled)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .rowHover()
        .contentShape(Rectangle())
        .onTapGesture {
            if opensWindow { openList(list) } else { withAnimation(.smooth(duration: 0.25)) { open.toggle() } }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(opensWindow ? "Opens the list in a window" : open ? "Hides the list" : "Shows the list")
    }
}

/// What could not be vouched for, as lists of names: titled by where they come from, with what that means.
public enum CoverageLists {
    public enum Part: Sendable { case notChecked, updatedElsewhere, notInIndex }

    public static func list(_ bucket: Coverage.Bucket, in part: Part) -> NameList {
        // A list of apps, or of what apps bundle, reads as names with icons; packages as they are written, monospaced.
        let ofApps = part == .updatedElsewhere || bucket.source == AppCoverage.noRecord
        let apps = ofApps || bucket.paths != nil
        return NameList(title: bucket.source, explanation: explanation(bucket.source, in: part), count: bucket.items.count,
                        sections: [.init(title: nil, items: bucket.items, paths: bucket.paths)], style: apps ? .names : .code,
                        one: ofApps ? "app" : "name", many: ofApps ? "apps" : "names")
    }

    /// Who keeps them up to date, in a few words: "App Store and web apps — not checked here".
    public static func keepersCaption(_ buckets: [Coverage.Bucket]) -> String {
        let titles = buckets.map(\.source)
        let keepers = [titles.contains(AppCoverage.appStore) ? "App Store" : nil, titles.contains(AppCoverage.macOS) ? "macOS" : nil,
                       titles.contains { $0.hasSuffix(" web apps") } ? "web apps" : nil].compactMap { $0 }
        let named = keepers.count <= 1 ? keepers.joined() : keepers.dropLast().joined(separator: ", ") + " and " + keepers.last!
        return (named.isEmpty ? "Updated elsewhere" : named) + " — not checked here"
    }

    /// What a list's names are, and what was or was not done with them.
    public static func explanation(_ source: String, in part: Part) -> String {
        switch source {
        case AppCoverage.noRecord:
            return "Apps the site has no security record of, so nothing checks their own code. Libraries they bundle that the site knows are checked, and appear with the findings."
        case AppCoverage.appStore:
            return "Apps from the Mac App Store, which updates them when automatic updates are on in its settings. The site has no security record of them, so they are not checked here."
        case AppCoverage.macOS:
            return "Apple's apps that come with macOS and are updated with it, in Software Update. They are not checked here."
        case "Homebrew packages with no graded project":
            return "Formulae and casks that belong to no project the site grades, so nothing here checks them."
        case "Packages the site cannot check":
            return "Packages from registries the site does not check, or with versions no registry would have."
        case "Apps with no readable version":
            return "Apps the site has a record of whose Info.plist gives no version to check."
        case "Bundled libraries with no readable version":
            return "Libraries the site knows, found inside these apps, whose version could not be read from their files."
        case "Bundled libraries with no product record":
            return "Libraries found inside these apps that the site has no record of yet."
        case "Bundled libraries numbered unlike their advisories":
            return "These libraries carry their own version numbers, which their advisories do not use, so the two cannot be compared."
        default:
            if source.hasSuffix(" web apps") {
                let browser = String(source.dropLast(" web apps".count))
                return "Websites \(browser) installed as apps. Each is \(browser) showing the site, so it is updated with \(browser); they are not checked here."
            }
            switch part {
            case .notInIndex: return "Installed, and not in the public index: nothing has ever been reported about them. That is no known problem, not proof of safety."
            case .updatedElsewhere: return "Kept up to date by something else; not checked here."
            case .notChecked: return "Nothing here checks these."
            }
        }
    }
}

/// An upgrade command in a `Surface.well`, in monospaced `.primary`. It wraps only at spaces, never inside a
/// word or a path; a single word wider than the block scrolls sideways instead.
public struct CommandBlock: View {
    public var command: String
    public init(_ command: String) { self.command = command }

    public var body: some View {
        let words = command.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        ViewThatFits(in: .horizontal) {
            WrapAtSpaces(spacing: 6.6, lineSpacing: 2) {
                ForEach(Array(words.enumerated()), id: \.offset) { _, w in Text(w).fixedSize() }
            }
            ScrollView(.horizontal) { Text(command).fixedSize() }.scrollIndicators(.never)
        }
        .font(Typeface.code)
        .foregroundStyle(.primary)
        .padding(.horizontal, 8).padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .well()
        .help(command)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(command)
    }
}

/// Lays words out left to right and starts a new line only between them. Its ideal width (asked with no width
/// offered, as `ViewThatFits` does) is its widest word: the narrowest it can wrap to. So it "fits" exactly when no
/// single word is wider than the space, and otherwise `ViewThatFits` picks the scrolling form.
struct WrapAtSpaces: Layout {
    var spacing: CGFloat
    var lineSpacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let widest = subviews.map { $0.sizeThatFits(.unspecified).width }.max() ?? 0
        let lines = arrange(subviews, width: proposal.width ?? widest)
        let width = lines.map(\.width).max() ?? 0
        let height = lines.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(lines.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for line in arrange(subviews, width: bounds.width) {
            var x = bounds.minX
            for i in line.items {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += line.height + lineSpacing
        }
    }

    private struct Line { var items: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(_ subviews: Subviews, width: CGFloat) -> [Line] {
        var lines: [Line] = [], line = Line()
        for (i, v) in subviews.enumerated() {
            let size = v.sizeThatFits(.unspecified)
            let needed = line.items.isEmpty ? size.width : line.width + spacing + size.width
            if !line.items.isEmpty && needed > width {
                lines.append(line); line = Line()
            }
            line.width = line.items.isEmpty ? size.width : line.width + spacing + size.width
            line.height = max(line.height, size.height)
            line.items.append(i)
        }
        if !line.items.isEmpty { lines.append(line) }
        return lines
    }
}

/// The one hover of the panel's rows (findings, Not checked, the not-in-index lists): the row takes a little more of
/// `Surface.hover`, which raises its text's contrast in either appearance and never lowers it. `hovering` lets the row
/// brighten its own chevron too.
struct RowHover: ViewModifier {
    var hovering: Binding<Bool>?
    @State private var hover = false
    @Environment(\.showsHover) private var showsHover

    func body(content: Content) -> some View {
        content
            .background { if hover || showsHover { Rectangle().fill(Surface.hover.color) } }
            .onHover { h in hover = h; hovering?.wrappedValue = h }
    }
}

extension EnvironmentValues {
    /// Draws rows as if the pointer were over them (osva-render's hover sheet: off-screen there is no pointer).
    @Entry public var showsHover = false
}

/// The panel's one container: `Surface.card` with a hairline edge, in corners concentric with the panel's own. The
/// groups of findings, the quiet coverage lists and a waiting update each sit in one, so restyling it reaches all of
/// them. The malicious group's is the one with a clay wash and hairline.
struct PanelCard: ViewModifier {
    enum Kind: Sendable { case plain, malicious }
    var kind: Kind

    static var shape: ConcentricRectangle { ConcentricRectangle(corners: .concentric(minimum: 12), isUniform: true) }

    func body(content: Content) -> some View {
        let (wash, edge) = kind == .malicious ? (Tokens.Malicious.wash, Tokens.Malicious.hairline) : (Surface.card, Surface.edge)
        // a 2 pt stroke, half of it clipped away by the card's own shape: a 1 pt hairline inside the edge
        content
            .background { Self.shape.fill(wash.color).overlay(Self.shape.stroke(edge.color, lineWidth: 2)) }
            .clipShape(Self.shape)
    }
}

extension View {
    func rowHover(_ hovering: Binding<Bool>? = nil) -> some View { modifier(RowHover(hovering: hovering)) }

    /// A container on the panel (PanelCard).
    func panelCard(_ kind: PanelCard.Kind = .plain) -> some View { modifier(PanelCard(kind: kind)) }

    /// A well set into its surface (a command, a log, a fix's card): `Surface.well` with a hairline, so it keeps its
    /// edge where the well and what is around it are both near white.
    func well(cornerRadius: CGFloat = 7) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return background { shape.fill(Surface.well.color).overlay(shape.strokeBorder(Surface.edge.color, lineWidth: 1)) }
    }
}

/// A link out of the app, readable on any glass: `.primary` text and a small accent-coloured arrow on a
/// `Surface.control` capsule with a hairline edge. Never system-blue text straight on the glass, which measured 1.7:1
/// on the owner's grey glass.
public struct SiteLink: View {
    public var title: String
    public var url: URL
    public var open: (URL) -> Void
    @State private var hover = false

    public init(_ title: String, url: URL, open: @escaping (URL) -> Void) { self.title = title; self.url = url; self.open = open }

    public var body: some View {
        Button { open(url) } label: {
            HStack(spacing: 5) {
                Text(title).foregroundStyle(.primary)
                Image(systemName: "arrow.up.right").font(.system(size: 9, weight: .bold)).foregroundStyle(Color.accentColor)
            }
            .font(Typeface.small.weight(.medium))
            .padding(.horizontal, 10).padding(.vertical, 4.5)
            .background {
                Capsule().fill(Surface.control.color)
                if hover { Capsule().fill(Surface.hover.color) }
            }
            .overlay(Capsule().strokeBorder(Surface.edge.color, lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help(url.absoluteString)
        .accessibilityAddTraits(.isLink)
    }
}

struct TightLabel: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 3) { configuration.icon.imageScale(.small); configuration.title }
    }
}

/// The menu-bar icon: a template SF Symbol (the system colours it for light, dark and selected menu bars) whose shape
/// carries the state, with the number of findings that need action in SF Pro monospaced digits.
public struct MenuBarLabel: View {
    public enum State: Equatable, Sendable {
        case notScanned
        case clean
        case action(Int)
        case malicious(Int)
    }

    public var state: State
    public init(_ state: State) { self.state = state }

    public var body: some View {
        HStack(spacing: 3) {
            Image(systemName: symbol)
            if let n = count { Text("\(n)").monospacedDigit() }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibility)
    }

    public var symbol: String {
        switch state {
        case .notScanned: return "shield"
        case .clean: return "checkmark.shield"
        case .action: return "exclamationmark.shield.fill"
        case .malicious: return "xmark.shield.fill"
        }
    }

    private var count: Int? {
        switch state { case let .action(n), let .malicious(n): return n; default: return nil }
    }

    private var accessibility: String {
        switch state {
        case .notScanned: return "OSVA Monitor: not scanned yet"
        case .clean: return "OSVA Monitor: nothing needs action"
        case let .action(n): return "OSVA Monitor: \(n) findings need action"
        case let .malicious(n): return "OSVA Monitor: malicious package found; \(n) findings need action"
        }
    }
}
