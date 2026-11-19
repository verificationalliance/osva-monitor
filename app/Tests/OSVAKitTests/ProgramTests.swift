import Foundation
import Testing
@testable import OSVAKit

/// The program fixtures (Fixtures/binaries, made by make-binaries.sh on a Mac): real executables with their machine
/// code zeroed.
enum Binaries {
    static func bytes(_ name: String) -> [UInt8] { Array(Fixture.data("binaries/\(name)")) }
    static let goInline = bytes("go-inline")
    static let goPointers = bytes("go-pointers")
    static let rust = bytes("rust-auditable")

    /// A universal file holding `slices` (cpu type, bytes), each at a 16 KB boundary.
    static func universal(_ slices: [(UInt32, [UInt8])]) -> [UInt8] {
        func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }
        var header = be32(0xCAFE_BABE) + be32(UInt32(slices.count))
        var body: [UInt8] = [], offset = 16384
        for (cpu, bytes) in slices {
            header += be32(cpu) + be32(0) + be32(UInt32(offset)) + be32(UInt32(bytes.count)) + be32(14)
            body += [UInt8](repeating: 0, count: offset - 16384 - body.count) + bytes
            offset = 16384 + ((body.count + 16383) / 16384) * 16384
        }
        return header + [UInt8](repeating: 0, count: 16384 - header.count) + body
    }

    /// The Rust fixture with its `.dep-v0` section renamed: a Rust program without a crate list.
    static var rustWithoutCrateList: [UInt8] {
        var b = rust
        let name = Array(".dep-v0".utf8)
        for i in 0..<min(b.count - name.count, 64 * 1024) where Array(b[i..<(i + name.count)]) == name {
            b[i + 5] = UInt8(ascii: "x")
        }
        return b
    }
}

@Suite struct MachOTests {
    @Test func readsSegmentsAndSections() throws {
        let m = try #require(MachOFile.parse(Binaries.goInline))
        #expect(m.filetype == MachOFile.mhExecute && m.cputype == MachOFile.cpuARM64)
        #expect(m.segments.map(\.name).prefix(2) == ["__PAGEZERO", "__TEXT"])
        #expect(m.section(named: "__go_buildinfo")?.segment == "__DATA")
        #expect(MachOFile.parse(Binaries.rust)?.section(named: ".dep-v0", segment: "__DATA") != nil)
    }

    @Test func universalFilesPreferThisMacsSlice() throws {
        let fat = Binaries.universal([(MachOFile.cpuX86_64, Binaries.goPointers), (MachOFile.cpuARM64, Binaries.goInline)])
        #expect(MachOFile.looksLikeMachO(fat))
        let arm = try #require(MachOFile.parse(fat, preferring: MachOFile.cpuARM64))
        #expect(GoBuildInfo.read(arm)?.goVersion == "go1.27.4")
        let intel = try #require(MachOFile.parse(fat, preferring: MachOFile.cpuX86_64))
        #expect(GoBuildInfo.read(intel)?.goVersion == "go1.17.13")          // the x86_64 slice (here: the 1.17 binary)
        // a slice that points past the end of the file is skipped, not read
        var broken = fat
        broken[16] = 0xF0                                                   // first slice's offset: far past the end
        let fallback = try #require(MachOFile.parse(broken, preferring: MachOFile.cpuX86_64))
        #expect(GoBuildInfo.read(fallback)?.goVersion == "go1.27.4")
    }

    @Test func notMachO() {
        #expect(MachOFile.parse(Array("#!/bin/sh\necho hi\n".utf8)) == nil)
        #expect(MachOFile.parse([]) == nil)
        #expect(!MachOFile.looksLikeMachO([0xCF, 0xFA]))
        // a Java class file starts like a universal binary; its "architectures" are nonsense and are refused
        #expect(MachOFile.parse([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34] + [UInt8](repeating: 0x41, count: 4096)) == nil)
    }

    @Test func hostileHeadersAreRefused() {
        var b = Binaries.goInline
        b[20] = 0xFF; b[21] = 0xFF; b[22] = 0xFF; b[23] = 0x7F           // sizeofcmds: 2 GB
        #expect(MachOFile.parse(b) == nil)
        var n = Binaries.goInline
        n[16] = 0xFF; n[17] = 0xFF; n[18] = 0xFF; n[19] = 0xFF           // ncmds: 4 billion
        #expect(MachOFile.parse(n) == nil)
        // a segment claiming more sections than its command holds keeps no sections from it
        var s = Binaries.goInline
        let firstSegment = 32
        s[firstSegment + 64] = 0xFF; s[firstSegment + 65] = 0xFF
        #expect(MachOFile.parse(s) != nil)
    }
}

@Suite struct GoBuildInfoTests {
    @Test func inlineFormat() throws {
        let macho = try #require(MachOFile.parse(Binaries.goInline))
        let info = try #require(GoBuildInfo.read(macho))
        #expect(info.goVersion == "go1.27.4" && info.stdlibVersion == "1.27.4")
        #expect(info.path == "example.com/osva/gofixture")
        #expect(info.main == .init(path: "example.com/osva/gofixture", version: "(devel)"))
        #expect(info.deps == [
            .init(path: "example.com/osva/local", version: "v0.0.0", replacement: .directory("./local")),
            .init(path: "golang.org/x/net", version: "v0.23.0"),
            .init(path: "golang.org/x/text", version: "v0.14.0", replacement: .module(path: "golang.org/x/text", version: "v0.3.7")),
        ])
    }

    @Test func pointerFormatBeforeGo118() throws {
        let macho = try #require(MachOFile.parse(Binaries.goPointers))
        let info = try #require(GoBuildInfo.read(macho))
        #expect(info.goVersion == "go1.17.13" && info.stdlibVersion == "1.17.13")
        #expect(info.deps == [.init(path: "golang.org/x/net", version: "v0.0.0-20210226172049-e18ecbb05110")])
    }

    @Test func whatIsChecked() throws {
        let macho = try #require(MachOFile.parse(Binaries.goInline))
        let info = try #require(GoBuildInfo.read(macho))
        let program = BuiltProgram(language: .go, path: "/x/gofixture", name: "gofixture", version: nil, place: .other, formula: nil,
                                   package: info.path, module: info.main?.path, toolchain: info.stdlibVersion)
        // the replacement is what was compiled; a local directory is no registry's; a (devel) main module has no version
        #expect(ProgramSource.packages(of: info, program: program).map { "\($0.name) \($0.version)" }
                == ["golang.org/x/net v0.23.0", "golang.org/x/text v0.3.7", "stdlib 1.27.4"])
    }

    @Test func modinfoLines() {
        let info = GoBuildInfo.parseModinfo("""
            path\tgithub.com/cli/cli/v2/cmd/gh
            mod\tgithub.com/cli/cli/v2\tv2.62.0\th1:abc=
            =>\tgithub.com/fork/cli/v2\tv2.62.1\th1:def=
            dep\tgolang.org/x/net\tv0.23.0
            dep\t\tv1
            dep\tonly-a-path
            =>\t../orphan
            garbage line
            build\t-trimpath=true
            """)
        #expect(info.path == "github.com/cli/cli/v2/cmd/gh")
        #expect(info.main?.effective?.path == "github.com/fork/cli/v2" && info.main?.effective?.version == "v2.62.1")
        #expect(info.deps.map(\.path) == ["golang.org/x/net"])
        #expect(info.deps[0].replacement == nil)                    // "=> ../orphan" followed a line it could not belong to
    }

    @Test("Go versions as OSV writes the standard library's", arguments: [
        ("go1.22.3", "1.22.3"), ("go1.22", "1.22.0"), ("go1.21rc2", "1.21.0-rc.2"), ("go1.18beta1", "1.18.0-beta.1"),
        ("go1.22.3 X:boringcrypto", "1.22.3"),
    ])
    func semver(_ go: String, _ expected: String) { #expect(GoBuildInfo.semver(go) == expected) }

    @Test func developmentToolchainsHaveNoVersion() {
        #expect(GoBuildInfo.semver("devel go1.24-abcdef Tue") == nil)
        #expect(GoBuildInfo.semver("go1") == nil && GoBuildInfo.semver("") == nil && GoBuildInfo.semver("go1.22.3-custom") == nil)
    }

    /// Truncated, flipped and random files: never a crash, and nothing read that is not there.
    @Test func damagedFilesDoNotCrash() {
        for fixture in [Binaries.goInline, Binaries.goPointers] {
            let magic = fixture.firstIndex(of: GoBuildInfo.magic, alignedTo: 16)!
            var lengths = Array(stride(from: 0, to: fixture.count, by: 8191)) + Array(0..<64) + Array((magic - 8)..<(magic + 80))
            lengths += [fixture.count - 1, fixture.count]
            for n in lengths {
                let cut = Array(fixture.prefix(n))
                if let m = MachOFile.parse(cut), let info = GoBuildInfo.read(m) { #expect(!info.goVersion.isEmpty) }
            }
            var rng = SeededRandom(seed: 7)
            for _ in 0..<200 {
                var b = fixture
                for _ in 0..<8 {
                    // flip bytes in the header and load commands, and in the build info blob
                    let at = rng.next() % 2 == 0 ? Int(rng.next() % 4096) : magic + Int(rng.next() % 1024)
                    b[at] = UInt8(truncatingIfNeeded: rng.next())
                }
                if let m = MachOFile.parse(b) { _ = GoBuildInfo.read(m); _ = RustAudit.read(m); _ = RustAudit.looksLikeRust(m) }
            }
        }
        var rng = SeededRandom(seed: 11)
        for _ in 0..<200 {
            var b = [UInt8](repeating: 0, count: Int(rng.next() % 8192))
            for i in b.indices { b[i] = UInt8(truncatingIfNeeded: rng.next()) }
            if Bool.random(using: &rng) && b.count >= 4 { b[0] = 0xCF; b[1] = 0xFA; b[2] = 0xED; b[3] = 0xFE }
            if let m = MachOFile.parse(b) { _ = GoBuildInfo.read(m); _ = RustAudit.read(m) }
        }
    }

    @Test func hostileLengthsAreRefused() throws {
        // inline format: a version string claiming 2^63 bytes
        var b = Binaries.goInline
        let magic = b.firstIndex(of: GoBuildInfo.magic, alignedTo: 16)!
        for i in 0..<9 { b[magic + 32 + i] = 0xFF }
        b[magic + 41] = 0x7F
        let damaged = try #require(MachOFile.parse(b))
        #expect(GoBuildInfo.read(damaged) == nil)
        // pointer format: a modinfo string header claiming 4 GB
        var p = Binaries.goPointers
        let m = try #require(MachOFile.parse(p))
        let pmagic = p.firstIndex(of: GoBuildInfo.magic, alignedTo: 16)!
        let modHeader = ByteReader(bytes: Array(p[(pmagic + 24)..<(pmagic + 32)]), bigEndian: false).u64(0)!
        let seg = m.segments.first { modHeader >= $0.vmaddr && modHeader - $0.vmaddr < $0.filesize }!
        let at = Int(seg.fileoff + modHeader - seg.vmaddr) + 8
        for i in 0..<8 { p[at + i] = i == 4 ? 1 : 0 }
        let pm = try #require(MachOFile.parse(p))
        let info = GoBuildInfo.read(pm)
        #expect(info?.goVersion == "go1.17.13" && info?.deps == [])          // the version still reads; the modules do not
    }
}

@Suite struct RustAuditTests {
    @Test func readsTheCrateList() throws {
        let macho = try #require(MachOFile.parse(Binaries.rust))
        let crates = try #require(RustAudit.read(macho))
        #expect(crates == [RustAudit.Crate(name: "libc", version: "0.2.191", source: "crates.io"),
                           RustAudit.Crate(name: "rustfixture", version: "0.1.0", source: "local", root: true),
                           RustAudit.Crate(name: "time", version: "0.1.43", source: "crates.io")])
    }

    @Test func checksCratesIOCratesThatRun() {
        let crates = [RustAudit.Crate(name: "ripgrep", version: "14.1.0", source: "crates.io", root: true),
                      RustAudit.Crate(name: "memchr", version: "2.7.1", source: "crates.io"),
                      RustAudit.Crate(name: "cc", version: "1.0.0", source: "crates.io", buildOnly: true),
                      RustAudit.Crate(name: "internal", version: "0.1.0", source: "git"),
                      RustAudit.Crate(name: "mirror", version: "1.0.0", source: "registry")]
        func names(_ place: BuiltProgram.Place) -> [String] {
            let p = BuiltProgram(language: .rust, path: "/x/rg", name: "rg", version: "14.1.0", place: place, formula: nil, package: "ripgrep",
                                 module: "ripgrep", toolchain: nil)
            return ProgramSource.packages(of: crates, program: p).map(\.name)
        }
        #expect(names(.other) == ["ripgrep", "memchr"])
        #expect(names(.cargoInstall) == ["memchr"])                 // the cargo source checks a cargo-installed crate itself
    }

    @Test func inflation() throws {
        let json = Array(#"{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"}]}"#.utf8)
        let compressed = Array(try (Data(json) as NSData).compressed(using: .zlib))      // raw deflate
        let sum = RustAudit.adler32(json)
        let zlib: [UInt8] = [0x78, 0x9C] + compressed + [UInt8(sum >> 24), UInt8(sum >> 16 & 0xFF), UInt8(sum >> 8 & 0xFF), UInt8(sum & 0xFF)]
        #expect(RustAudit.adler32(Array("Wikipedia".utf8)) == 0x11E6_0398)                 // the checksum's textbook example
        #expect(RustAudit.inflate(zlib: zlib, cap: 1024) == json)
        #expect(RustAudit.inflate(zlib: Array(zlib.dropLast()) + [0], cap: 1024) == nil)  // the wrong checksum
        #expect(RustAudit.inflate(zlib: zlib, cap: json.count - 1) == nil)              // larger than the cap: refused
        #expect(RustAudit.inflate(zlib: compressed, cap: 1024) == nil)                  // no zlib header
        #expect(RustAudit.inflate(zlib: [0x78, 0x9C, 1, 2, 3, 4, 5, 6, 7], cap: 1024) == nil)
        // a bomb: 64 MB of zeros does not get past a 16 MB cap
        let zeros = Array(try (Data(count: 64 << 20) as NSData).compressed(using: .zlib))
        #expect(RustAudit.inflate(zlib: [0x78, 0x9C] + zeros + [0, 0, 0, 1], cap: 16 << 20) == nil)
        #expect(RustAudit.parse(Array(#"{"packages":[{"name":1},{"name":"x"},{"name":"y","version":"2","kind":"build"}]}"#.utf8))
                == [RustAudit.Crate(name: "y", version: "2", source: "", buildOnly: true)])
        #expect(RustAudit.parse(Array("[]".utf8)) == nil)
    }

    @Test func plainlyRust() throws {
        let plain = try #require(MachOFile.parse(Binaries.rustWithoutCrateList))
        let go = try #require(MachOFile.parse(Binaries.goInline))
        #expect(RustAudit.looksLikeRust(plain) && RustAudit.read(plain) == nil)
        #expect(!RustAudit.looksLikeRust(go))
    }

    @Test func damagedFilesDoNotCrash() throws {
        let section = try #require(MachOFile.parse(Binaries.rust)?.section(named: ".dep-v0"))
        for n in Array(stride(from: 0, to: Binaries.rust.count, by: 997)) + Array(Int(section.offset)..<Int(section.offset + section.size + 2)) {
            if let m = MachOFile.parse(Array(Binaries.rust.prefix(n))) { _ = RustAudit.read(m); _ = RustAudit.looksLikeRust(m) }
        }
        var rng = SeededRandom(seed: 3)
        for _ in 0..<300 {
            var b = Binaries.rust
            b[Int(section.offset) + Int(rng.next() % section.size)] = UInt8(truncatingIfNeeded: rng.next())
            if let m = MachOFile.parse(b) { _ = RustAudit.read(m) }
        }
    }
}

@Suite struct ProgramSourceTests {
    let fm = FileManager.default

    func put(_ bytes: [UInt8], _ url: URL) {
        try! fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! Data(bytes).write(to: url)
    }

    func link(_ url: URL, to destination: String) {
        try! fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! fm.createSymbolicLink(atPath: url.path, withDestinationPath: destination)
    }

    @Test func findsProgramsWhereTheyAreInstalled() throws {
        let root = temporaryDirectory()
        let bin = root.appendingPathComponent("bin"), cellar = root.appendingPathComponent("Cellar")
        let gobin = root.appendingPathComponent("gobin")
        put(Binaries.goInline, cellar.appendingPathComponent("gh/2.62.0_1/bin/gh"))
        link(bin.appendingPathComponent("gh"), to: "../Cellar/gh/2.62.0_1/bin/gh")              // one link: followed
        put(Binaries.goPointers, gobin.appendingPathComponent("tool"))
        put(Binaries.rust, root.appendingPathComponent("store/rustfixture"))
        link(bin.appendingPathComponent("rustfixture"), to: root.appendingPathComponent("store/rustfixture").path)
        link(bin.appendingPathComponent("twice"), to: "rustfixture")                           // a link to a link: not followed
        put(Binaries.rustWithoutCrateList, bin.appendingPathComponent("plainrust"))
        put(Binaries.goInline, root.appendingPathComponent("Docker.app/Contents/Resources/bin/docker"))
        link(bin.appendingPathComponent("docker"), to: root.appendingPathComponent("Docker.app/Contents/Resources/bin/docker").path)
        put(Array("#!/bin/sh\nexit 0\n".utf8) + [UInt8](repeating: 0x20, count: 2048), bin.appendingPathComponent("script"))
        put(Binaries.goInline, bin.appendingPathComponent("not-executable"))
        try fm.createDirectory(at: bin.appendingPathComponent("a-folder"), withIntermediateDirectories: true)
        #expect(mkfifo(bin.appendingPathComponent("fifo").path, 0o644) == 0)                   // must not hang the scan

        let tools = ToolEnvironment(home: root, base: ["GOBIN": gobin.path], runner: RecordedRunner(outputs: [:]),
                                    isExecutable: { !$0.hasSuffix("not-executable") })
        let r = ProgramSource(environment: tools, directories: [bin.path, gobin.path], cellars: [cellar.path],
                              caskForApp: ["Docker.app": "docker-desktop"]).collect()
        let programs = Dictionary(r.programs.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        #expect(r.programs.map(\.name).sorted() == ["docker", "gh", "rustfixture", "tool"])        // each file once
        let gh = try #require(programs["gh"])
        #expect(gh.place == .homebrew && gh.formula == "gh" && gh.version == "2.62.0" && gh.path == bin.path + "/gh")
        #expect(gh.toolchain == "1.27.4")
        let tool = try #require(programs["tool"])
        #expect(tool.place == .goInstall && tool.package == "example.com/osva/gofixture117" && tool.toolchain == "1.17.13")
        #expect(programs["rustfixture"]?.place == .other && programs["rustfixture"]?.version == "0.1.0")
        #expect(programs["docker"]?.place == .app && programs["docker"]?.app == "Docker" && programs["docker"]?.cask == "docker-desktop")
        #expect(r.unchecked.map(\.item) == ["plainrust (\(Paths.abbreviatingHome((bin.path as NSString).standardizingPath)))"])
        #expect(r.filesRead == 6)                         // gh once (bin and Cellar are one file); not the link to a link
        let ghPackages = r.packages.filter { if case let .program(p) = $0.origin { return p.name == "gh" }; return false }
        #expect(ghPackages.map { "\($0.ecosystem) \($0.name) \($0.version)" } == ["Go golang.org/x/net v0.23.0", "Go golang.org/x/text v0.3.7", "Go stdlib 1.27.4"])
        #expect(r.packages.filter { $0.ecosystem == .crates }.map(\.name) == ["libc", "time"])
        #expect(r.reports.map(\.kind) == [.go, .rust])
        #expect(r.reports[0].detail == "3 programs, 3 module versions" && r.reports[0].seconds != nil)
        #expect(r.reports[1].detail == "1 program, 2 crates, 1 without a crate list")
    }

    @Test func limits() {
        let root = temporaryDirectory()
        put(Binaries.goInline, root.appendingPathComponent("a"))
        put(Binaries.goInline + [0], root.appendingPathComponent("b"))
        let tools = ToolEnvironment(home: root, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in true })
        var small = ProgramSource.Limits(); small.maxFileSize = 4096
        #expect(ProgramSource(environment: tools, directories: [root.path], cellars: [], limits: small).collect().programs.isEmpty)
        var one = ProgramSource.Limits(); one.maxFiles = 1
        let capped = ProgramSource(environment: tools, directories: [root.path], cellars: [], limits: one).collect()
        #expect(capped.programs.count == 1 && capped.reports[0].error == "stopped after 1 file")
        var none = ProgramSource.Limits(); none.timeBudget = 0
        let late = ProgramSource(environment: tools, directories: [root.path], cellars: [], limits: none).collect()
        #expect(late.reports[0].error == "stopped after 0 files (0 s limit)" && late.programs.isEmpty)
    }

    @Test func nothingIsReadWhereNothingIsExecutable() {
        let root = temporaryDirectory()
        put(Binaries.goInline, root.appendingPathComponent("gh"))
        let tools = ToolEnvironment(home: root, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        let r = ProgramSource(environment: tools, directories: [root.path], cellars: []).collect()
        #expect(r.programs.isEmpty && r.filesRead == 0 && r.reports[0].detail == "no Go programs found")
    }

    @Test func defaultFoldersSkipTheSystemsOwn() {
        let tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: ["PATH": "/usr/bin:/bin:/opt/x/bin:relative:/System/Cryptexes/App/usr/bin:/usr/local/bin",
                                                                                     "GOPATH": "/w/go", "CARGO_HOME": "/w/cargo"],
                                    runner: RecordedRunner(outputs: [:]))
        let dirs = ProgramSource.defaultDirectories(environment: tools)
        #expect(dirs == ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin", "/w/go/bin", "/Users/ana/go/bin",
                         "/w/cargo/bin", "/Users/ana/.local/bin", "/Users/ana/bin", "/opt/x/bin"])
    }
}

/// A small deterministic generator for the damaged-file tests.
struct SeededRandom: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed &* 0x9E37_79B9_7F4A_7C15 | 1 }
    mutating func next() -> UInt64 {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17
        return state
    }
}

/// `OSVA_MEASURE=1 swift test --filter measureThisMac`: the program pass over this Mac's own folders, timed.
@Suite struct ProgramMeasurement {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OSVA_MEASURE"] == "1"))
    func measureThisMac() {
        let source = ProgramSource(environment: ToolEnvironment())
        let folders = source.directories.count + source.cellarDirectories().count
        for run in 1...3 {
            let r = source.collect()
            print("run \(run): \(String(format: "%.3f", r.reports[0].seconds ?? 0)) s, \(folders) folders, \(r.filesRead) files read, "
                  + "\(r.programs.count) programs (\(r.programs.filter { $0.language == .go }.count) Go), \(r.packages.count) packages, "
                  + "\(r.unchecked.count) Rust without a crate list")
        }
    }
}
