import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// "What leaves your Mac": each number and the list it opens.
@Suite struct SentListTests {
    @Test func fourNumbersEachWithItsList() {
        let lists = SentSummary.lists(PreviewData.sent)
        #expect(lists.map(\.kind) == [.checked, .projects, .cached, .withheld])
        #expect(lists.map(\.title) == ["Package versions checked", "Projects matched from Homebrew", "Answered from this Mac's cache",
                                       "Not in the public index, never sent"])
        #expect(lists.map(\.count) == [9, 4, 18, 69])
        #expect(lists.allSatisfy { $0.count == $0.shown && $0.canOpen })
    }

    /// The package versions exactly as sent; the projects by slug; the cache's answers in two parts; the rest by source.
    @Test func whatEachListHolds() {
        let lists = SentSummary.lists(PreviewData.sent)
        #expect(lists[0].sections.flatMap(\.items) == PreviewData.sent.requests[0].items)
        #expect(lists[0].sections.first?.items.contains("PyPI setuptools 58.0.4 · Python 3.9.6 · macOS") == true)
        #expect(lists[1].sections.flatMap(\.items) == ["cpython", "nginx", "openssh", "openssl"])
        #expect(lists[2].sections.map(\.title) == ["Package versions", "Projects"])
        #expect(lists[2].sections[1].items == ["curl", "git", "libxml2", "sqlite"])
        #expect(lists[3].sections.map(\.title) == ["Homebrew", "pip", "RubyGems", "Folders"])
    }

    /// The owner's scan: nothing sent, everything answered from the cache. A zero opens nothing, and a number from a
    /// report saved before the lists were kept opens nothing either (there are no names to show).
    @Test func zeroAndOldReportsOpenNothing() {
        let lists = SentSummary.lists(SentRecord(withheldCount: 760, answeredFromCache: 245))
        #expect(lists.map(\.count) == [0, 0, 245, 760])
        #expect(lists.map(\.canOpen) == [false, false, false, false])
        #expect(lists[0].sections.isEmpty)
    }

    @Test func searchNarrowsAndKeepsRowsApart() {
        let list = SentSummary.lists(PreviewData.sent)[3]
        let all = SentListView.sections(list, matching: "")
        #expect(all.reduce(0) { $0 + $1.rows.count } == 69)
        #expect(Set(all.flatMap(\.rows).map(\.id)).count == 69)                        // one identity per row
        let lib = SentListView.sections(list, matching: " LIB ")
        #expect(lib.map(\.title) == ["Homebrew", "pip"])
        #expect(lib.flatMap(\.rows).map(\.text) == ["glib 2.86.2", "libevent 2.1.12", "libuv 1.52.0", "macholib 1.15.2"])
        #expect(SentListView.sections(list, matching: "ünïcode-nothing").isEmpty)
        #expect(SentListView.sections(list, matching: "cfpropertylist").flatMap(\.rows).map(\.text) == ["CFPropertyList 2.3.6"])
        let ids = lib.flatMap(\.rows).map(\.id)
        #expect(ids == all.flatMap(\.rows).filter { lib.flatMap(\.rows).map(\.text).contains($0.text) }.map(\.id))   // same row, same id
    }

    /// Ten thousand names (the most a list keeps) narrow fast enough to follow typing.
    @Test func searchingTheLargestListIsQuick() {
        let names = (0..<SentRecord.listLimit).map { "package-\($0) \($0 % 7).\($0 % 13).0" }
        let list = SentList(kind: .withheld, count: names.count, sections: [.init(title: "Folders", items: names)])
        let clock = ContinuousClock()
        let took = clock.measure {
            for q in ["p", "pa", "pac", "package-9", "package-99", "package-999"] { _ = SentListView.sections(list, matching: q) }
        }
        #expect(SentListView.sections(list, matching: "package-4321").flatMap(\.rows).map(\.text) == ["package-4321 2.5.0"])
        #expect(took < .milliseconds(500), "six searches took \(took)")
    }

    @Test func footerSaysHowMany() {
        let date = PreviewData.now
        let list = SentSummary.lists(PreviewData.sent)[3]
        #expect(SentListView.footer(list, scanned: date, query: "", matching: 69).hasPrefix("69 names · last scan "))
        #expect(SentListView.footer(list, scanned: date, query: "lib", matching: 4) == "4 of 69")
        let cut = SentList(kind: .withheld, count: 12_345, sections: [.init(title: "Folders", items: ["a 1", "b 2"])])
        #expect(SentListView.footer(cut, scanned: date, query: "", matching: 2).hasPrefix("The first 2 of \(12_345.formatted()) · last scan "))
    }
}
