import Foundation

/// Go and Rust programs: executables on the PATH, in Go's and cargo's bin folders and in Homebrew's Cellar, read for
/// the packages they were built with (Go's build info, cargo-auditable's crate list). Files are only read, never run:
/// regular files only, a symbolic link followed once, a size cap, and caps on how many files and how long.
public struct ProgramSource: Sendable {
    public struct Limits: Sendable {
        /// Files examined at most (after following links and dropping the ones already seen).
        public var maxFiles = 20_000
        /// Smaller files are not executables worth reading; larger ones are skipped.
        public var minFileSize: UInt64 = 1024
        public var maxFileSize: UInt64 = 1 << 30
        /// The whole pass stops after this long and says so.
        public var timeBudget: TimeInterval = 30
        public init() {}
    }

    public struct Result: Sendable {
        public var packages: [InstalledPackage]
        public var programs: [BuiltProgram]
        public var unchecked: [UncheckedItem]
        /// One report for Go programs and one for Rust programs (the same pass found both).
        public var reports: [SourceReport]
        /// Executable files examined.
        public var filesRead: Int
    }

    let environment: ToolEnvironment
    let directories: [String]
    let cellars: [String]
    let limits: Limits
    /// App bundle file name ("Docker.app") -> the Homebrew cask that installed it.
    let caskForApp: [String: String]

    /// `directories` and `cellars` default to this Mac's (`defaultDirectories`, Homebrew's two Cellars).
    public init(environment: ToolEnvironment, directories: [String]? = nil, cellars: [String]? = nil, limits: Limits = Limits(),
                caskForApp: [String: String] = [:]) {
        self.environment = environment
        self.caskForApp = caskForApp
        self.directories = directories ?? Self.defaultDirectories(environment: environment)
        self.cellars = cellars ?? ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
        self.limits = limits
    }

    /// Folders the system owns: Apple's programs, never Go or Rust, and many of them.
    static let systemFolders = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec"]
    static let systemPrefixes = ["/System/", "/Library/Apple/", "/Applications/Xcode", "/Library/Developer/", "/usr/libexec/", "/private/var/"]

    /// Go's bin folders: $GOBIN, each $GOPATH entry's bin, ~/go/bin.
    static func goBins(_ environment: ToolEnvironment) -> [String] {
        let env = environment.base
        var out: [String] = []
        if let gobin = env["GOBIN"], gobin.hasPrefix("/") { out.append(gobin) }
        for p in (env["GOPATH"] ?? "").split(separator: ":") where p.hasPrefix("/") { out.append(String(p) + "/bin") }
        out.append(environment.home.appendingPathComponent("go/bin").path)
        return out
    }

    /// cargo's bin folder: $CARGO_HOME/bin, else ~/.cargo/bin.
    static func cargoBins(_ environment: ToolEnvironment) -> [String] {
        if let home = environment.base["CARGO_HOME"], home.hasPrefix("/") { return [home + "/bin"] }
        return [environment.home.appendingPathComponent(".cargo/bin").path]
    }

    /// Homebrew's and /usr/local's bin and sbin, Go's and cargo's bin folders, ~/.local/bin, ~/bin, then the rest of
    /// PATH except the system's own folders. (An app started from Finder has a short PATH: the fixed ones matter.)
    public static func defaultDirectories(environment: ToolEnvironment) -> [String] {
        let home = environment.home
        var dirs = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin"]
        dirs += goBins(environment) + cargoBins(environment)
        dirs += [home.appendingPathComponent(".local/bin").path, home.appendingPathComponent("bin").path]
        for p in (environment.base["PATH"] ?? "").split(separator: ":").map(String.init) where p.hasPrefix("/") {
            let clean = (p as NSString).standardizingPath
            if systemFolders.contains(clean) || systemPrefixes.contains(where: { clean.hasPrefix($0) }) { continue }
            dirs.append(clean)
        }
        var seen = Set<String>()
        return dirs.filter { seen.insert(($0 as NSString).standardizingPath).inserted }
    }

    /// Each formula version's bin, sbin and libexec/bin in the Cellars: keg-only formulae are not linked onto PATH.
    func cellarDirectories() -> [String] {
        let fm = FileManager.default
        var out: [String] = []
        for cellar in cellars {
            for formula in ((try? fm.contentsOfDirectory(atPath: cellar)) ?? []).sorted() where !formula.hasPrefix(".") {
                let f = cellar + "/" + formula
                for version in ((try? fm.contentsOfDirectory(atPath: f)) ?? []).sorted() where !version.hasPrefix(".") {
                    out += ["bin", "sbin", "libexec/bin"].map { "\(f)/\(version)/\($0)" }
                }
            }
        }
        return out
    }

    /// A file to read: where it was found, the regular file it is, and that file's identity.
    struct Candidate: Sendable {
        var path: String, target: String, name: String, folder: String
        var identity: ReadOnlyFile.FileIdentity
    }

    /// What one file turned out to be.
    enum Outcome: Sendable {
        case nothing
        case program(BuiltProgram, [InstalledPackage])
        case plainRust(UncheckedItem)
    }

    /// The facts each file is judged against, the same for all of them.
    struct Context: Sendable {
        var realCellars: [String], goBins: Set<String>, cargoBins: Set<String>, caskForApp: [String: String]
    }

    public func collect() -> Result {
        let clock = ContinuousClock(), started = clock.now
        let deadline = started.advanced(by: .milliseconds(Int(limits.timeBudget * 1000)))
        let context = Context(realCellars: cellars.map { Paths.realPath($0) + "/" },
                              goBins: Set(Self.goBins(environment).map { ($0 as NSString).standardizingPath }),
                              cargoBins: Set(Self.cargoBins(environment).map { ($0 as NSString).standardizingPath }), caskForApp: caskForApp)
        var stopped: String?

        // 1. The files: listed, links followed once, each file once, nothing opened yet.
        var candidates: [Candidate] = [], seen = Set<ReadOnlyFile.FileIdentity>(), seenDirs = Set<String>()
        scan: for dir in directories + cellarDirectories() {
            guard seenDirs.insert(Paths.realPath(dir)).inserted, let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            let folder = (dir as NSString).standardizingPath
            for name in names.sorted() {
                let path = dir + "/" + name
                guard let (target, identity) = Self.regularFile(path, limits: limits), environment.isExecutable(path),
                      seen.insert(identity).inserted else { continue }
                if candidates.count == limits.maxFiles { stopped = "stopped after \(GlobalPackageSources.count(limits.maxFiles, "file"))"; break scan }
                candidates.append(Candidate(path: path, target: target, name: name, folder: folder, identity: identity))
            }
        }

        // 2. Each file read on its own, side by side: only its headers and the sections asked for.
        let files = candidates, outcomes = Outcomes(count: files.count)
        DispatchQueue.concurrentPerform(iterations: files.count) { i in
            guard clock.now <= deadline else { outcomes.timedOut(); return }
            outcomes.set(i, Self.examine(files[i], context))
        }
        if outcomes.didTimeOut {
            stopped = "stopped after \(GlobalPackageSources.count(outcomes.examined, "file")) (\(Int(limits.timeBudget)) s limit)"
        }

        // 3. In the order they were found.
        var packages: [InstalledPackage] = [], programs: [BuiltProgram] = [], unchecked: [UncheckedItem] = []
        for outcome in outcomes.all {
            switch outcome {
            case let .program(p, own): programs.append(p); packages += own
            case let .plainRust(item): unchecked.append(item)
            case .nothing: break
            }
        }
        let seconds = (clock.now - started).seconds
        let go = programs.filter { $0.language == .go }, rust = programs.filter { $0.language == .rust }
        let goPackages = packages.filter { $0.origin.kind == .go }, rustPackages = packages.filter { $0.origin.kind == .rust }
        let modules = Set(goPackages.filter { $0.name != "stdlib" }.map { "\($0.name)@\($0.version)" }).count
        let goDetail = go.isEmpty ? "no Go programs found"
            : "\(GlobalPackageSources.count(go.count, "program")), \(GlobalPackageSources.count(modules, "module version"))"
        var rustDetail = rust.isEmpty ? "no Rust programs with a crate list"
            : "\(GlobalPackageSources.count(rust.count, "program")), \(GlobalPackageSources.count(rustPackages.count, "crate"))"
        if !unchecked.isEmpty { rustDetail += ", \(unchecked.count) without a crate list" }
        return Result(packages: packages, programs: programs, unchecked: unchecked, reports: [
            SourceReport(kind: .go, available: true, count: goPackages.count, detail: goDetail, error: stopped, seconds: seconds),
            SourceReport(kind: .rust, available: true, count: rustPackages.count, detail: rustDetail, error: stopped, seconds: seconds),
        ], filesRead: outcomes.examined)
    }

    /// Reads one file: a Go program's build info, a Rust program's crate list, or whether it is plainly Rust.
    static func examine(_ c: Candidate, _ context: Context) -> Outcome {
        // The file opened is the file listed (not one swapped in since), and is never run.
        guard let file = ReadOnlyFile(path: c.target), file.identity == c.identity,
              MachO.looksLikeMachO(file.read(at: 0, count: 4)), let macho = MachO.parse(file), macho.filetype == MachO.mhExecute else { return .nothing }

        // Which Homebrew formula's Cellar holds it, and at which version.
        let resolved = Paths.realPath(c.target)
        var formula: String?, kegVersion: String?
        if let cellar = context.realCellars.first(where: { resolved.hasPrefix($0) }) {
            let parts = resolved.dropFirst(cellar.count).split(separator: "/")
            if parts.count >= 3 { formula = String(parts[0]); kegVersion = HomebrewSource.upstreamVersion(String(parts[1])) }
        }
        // An app bundle's program linked onto PATH (/usr/local/bin/docker -> Docker.app/Contents/Resources/bin/docker).
        let bundle = resolved.range(of: #"/[^/]+\.app/"#, options: .regularExpression).map { String(resolved[$0].dropFirst().dropLast()) }
        let app = bundle.map { String($0.dropLast(4)) }, cask = bundle.flatMap { context.caskForApp[$0] }
        func place(_ installer: BuiltProgram.Place, bins: Set<String>) -> BuiltProgram.Place {
            formula != nil ? .homebrew : app != nil ? .app : bins.contains(c.folder) ? installer : .other
        }

        if GoBuildInfo.isGo(macho), let info = GoBuildInfo.read(macho) {
            let mainVersion = info.main.flatMap { $0.version.isEmpty || $0.version == "(devel)" ? nil : withoutV($0.version) }
            let program = BuiltProgram(language: .go, path: c.path, name: c.name, version: kegVersion ?? mainVersion,
                                       place: place(.goInstall, bins: context.goBins), formula: formula,
                                       package: info.path.flatMap { $0.isEmpty || $0 == "command-line-arguments" ? nil : $0 },
                                       module: info.main?.path, toolchain: info.stdlibVersion, app: app, cask: cask)
            return .program(program, packages(of: info, program: program))
        }
        if let crates = RustAudit.read(macho) {
            let root = crates.first(where: \.root)
            let program = BuiltProgram(language: .rust, path: c.path, name: c.name, version: kegVersion ?? root?.version,
                                       place: place(.cargoInstall, bins: context.cargoBins), formula: formula,
                                       package: root.flatMap { $0.onCratesIO ? $0.name : nil }, module: root?.name, toolchain: nil,
                                       app: app, cask: cask)
            return .program(program, packages(of: crates, program: program))
        }
        if RustAudit.looksLikeRust(macho) {
            return .plainRust(UncheckedItem(kind: .rust, bucket: "Rust programs without a crate list",
                                            item: kegVersion.map { "\(c.name) \($0)" } ?? "\(c.name) (\(Paths.abbreviatingHome(c.folder)))",
                                            formula: formula))
        }
        return .nothing
    }

    /// The outcomes of the files read side by side, each written once by the thread that read it.
    final class Outcomes: @unchecked Sendable {        // every access holds the lock
        private let lock = NSLock()
        private var items: [Outcome?]
        private var stopped = false
        init(count: Int) { items = Array(repeating: nil, count: count) }
        func set(_ i: Int, _ o: Outcome) { lock.withLock { items[i] = o } }
        func timedOut() { lock.withLock { stopped = true } }
        var didTimeOut: Bool { lock.withLock { stopped } }
        var examined: Int { lock.withLock { items.filter { $0 != nil }.count } }
        var all: [Outcome] { lock.withLock { items.compactMap { $0 } } }
    }

    /// The regular file at `path`, following a symbolic link once, and its identity; nil for anything else, or a size
    /// outside the limits.
    static func regularFile(_ path: String, limits: Limits) -> (path: String, identity: ReadOnlyFile.FileIdentity)? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        var target = path
        if (st.st_mode & S_IFMT) == S_IFLNK {
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let n = readlink(path, &buffer, Int(PATH_MAX))
            guard n > 0 else { return nil }
            let link = String(decoding: buffer.prefix(n).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            target = link.hasPrefix("/") ? link : ((path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(link)
            guard lstat(target, &st) == 0 else { return nil }
        }
        guard (st.st_mode & S_IFMT) == S_IFREG, st.st_size >= 0 else { return nil }
        let size = UInt64(st.st_size)
        guard size >= limits.minFileSize && size <= limits.maxFileSize else { return nil }
        return (target, ReadOnlyFile.FileIdentity(device: UInt64(UInt32(bitPattern: st.st_dev)), inode: UInt64(st.st_ino)))
    }

    /// Go: every module compiled in (a replacement's module where there is one; a local directory has none), the main
    /// module when it has a released version, and the standard library at the toolchain's version.
    static func packages(of info: GoBuildInfo, program: BuiltProgram) -> [InstalledPackage] {
        var out: [InstalledPackage] = []
        var modules = info.deps
        if let main = info.main, main.version != "(devel)", !main.version.isEmpty { modules.insert(main, at: 0) }
        for m in modules {
            guard let e = m.effective, e.version != "(devel)", PackageNames.isPlausibleVersion(e.version) else { continue }
            out.append(InstalledPackage(ecosystem: .go, name: e.path, version: e.version, origin: .program(program)))
        }
        if let stdlib = info.stdlibVersion {
            out.append(InstalledPackage(ecosystem: .go, name: "stdlib", version: stdlib, origin: .program(program)))
        }
        return out
    }

    /// Rust: the crates.io crates that run (build-time ones do not). A `cargo install`ed program's own crate is
    /// checked by the cargo source already.
    static func packages(of crates: [RustAudit.Crate], program: BuiltProgram) -> [InstalledPackage] {
        crates.filter { $0.onCratesIO && !$0.buildOnly && !($0.root && program.place == .cargoInstall) }
            .map { InstalledPackage(ecosystem: .crates, name: $0.name, version: $0.version, origin: .program(program)) }
    }

    static func withoutV(_ version: String) -> String { version.hasPrefix("v") ? String(version.dropFirst()) : version }
}
