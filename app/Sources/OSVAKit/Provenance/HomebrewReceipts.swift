import Foundation

/// Homebrew's own records of why each formula and cask is here, read from its folders (asking `brew uses` would take
/// seconds per formula): each keg's INSTALL_RECEIPT.json (installed on request or as a dependency, when, and what it
/// depends on) and each cask's Caskroom metadata. Bounded by `maxKegs` and `maxReceiptBytes`; a missing or garbled
/// receipt is skipped and makes the picture `complete == false`.
public struct HomebrewReceipts: Sendable {
    public struct Keg: Hashable, Sendable {
        public var name: String
        /// Its Cellar folder ("/opt/homebrew/Cellar/brotli/1.2.1").
        public var path: String
        public var onRequest: Bool?
        public var installed: Date?
        /// What it depends on itself (declared in its formula), by name.
        public var dependencies: [String]
    }

    public static let maxKegs = 3000
    public static let maxReceiptBytes = 4 * 1024 * 1024

    /// "/opt/homebrew".
    public let prefix: String
    public let kegs: [String: Keg]
    public let complete: Bool
    private let dependents: [String: [String]]
    private let roots: [String]

    public init(prefix: String) {
        self.prefix = prefix
        let cellar = prefix + "/Cellar"
        let roots = LocalFiles.roots([cellar, prefix + "/Caskroom"])
        self.roots = roots
        var kegs: [String: Keg] = [:], complete = true
        let names = LocalFiles.list(cellar, limit: Self.maxKegs + 1).filter { !$0.hasPrefix(".") }
        if names.count > Self.maxKegs { complete = false }
        // Each receipt is read on its own, side by side. A formula folder with no version left in it (one Homebrew
        // emptied) is not installed.
        let wanted = Array(names.prefix(Self.maxKegs))
        var found = [(installed: Bool, keg: Keg?)](repeating: (false, nil), count: wanted.count)
        found.withUnsafeMutableBufferPointer { out in
            let buffer = out
            DispatchQueue.concurrentPerform(iterations: wanted.count) { i in
                let dir = cellar + "/" + wanted[i]
                guard LocalFiles.isDirectory(dir), LocalFiles.list(dir, limit: 200).contains(where: { !$0.hasPrefix(".") }) else { return }
                buffer[i] = (true, Self.keg(wanted[i], prefix: prefix, roots: roots))
            }
        }
        for (name, f) in zip(wanted, found) where f.installed {
            if let keg = f.keg { kegs[name] = keg } else { complete = false }
        }
        self.kegs = kegs
        self.complete = complete
        var dependents: [String: [String]] = [:]
        for keg in kegs.values.sorted(by: { $0.name < $1.name }) {
            for d in keg.dependencies where d != keg.name { dependents[d, default: []].append(keg.name) }
        }
        self.dependents = dependents
    }

    /// The keg in use: the one `opt/<name>` links to, else the newest folder in the Cellar.
    static func keg(_ name: String, prefix: String, roots: [String]) -> Keg? {
        let cellar = prefix + "/Cellar/" + name
        var path: String?
        let opt = Paths.realPath(prefix + "/opt/" + name)
        if opt.hasPrefix(Paths.realPath(cellar) + "/"), LocalFiles.isDirectory(opt) { path = opt }
        if path == nil {
            let versions = LocalFiles.list(cellar, limit: 200).filter { !$0.hasPrefix(".") && LocalFiles.isDirectory(cellar + "/" + $0) }
            path = versions.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.last.map { cellar + "/" + $0 }
        }
        guard let path, let data = LocalFiles.read(path + "/INSTALL_RECEIPT.json", limit: maxReceiptBytes, within: roots),
              let receipt = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        let runtime = (receipt["runtime_dependencies"] as? [Any] ?? []).compactMap { $0 as? [String: Any] }
        // Newer receipts mark the dependencies the formula declares itself; older ones list every runtime dependency.
        let declared = runtime.contains { $0["declared_directly"] != nil } ? runtime.filter { $0["declared_directly"] as? Bool == true } : runtime
        let deps = declared.compactMap { ($0["full_name"] as? String).map { ($0 as NSString).lastPathComponent } }
        let onRequest = (receipt["installed_on_request"] as? Bool) ?? (receipt["installed_as_dependency"] as? Bool).map { !$0 }
        let time = (receipt["time"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue) }
        return Keg(name: name, path: path, onRequest: onRequest, installed: ProvenanceText.plausible(time), dependencies: deps)
    }

    /// The installed formulae that declare `name` as a dependency.
    public func dependents(of name: String) -> [String] { dependents[name] ?? [] }

    /// The shortest chain of dependents from `name` up to a formula installed on request (else to one nothing needs).
    public func chainToTop(of name: String, maxDepth: Int = 8) -> (chain: [String], top: ProvenanceText.Top)? {
        var parent: [String: String] = [:], visited: Set<String> = [name], frontier = [name], fallback: String?
        func path(to k: String) -> [String] {
            var out: [String] = [], x = k
            while x != name, out.count <= maxDepth + 1 { out.append(x); x = parent[x] ?? name }
            return out.reversed()
        }
        for _ in 0..<maxDepth where !frontier.isEmpty {
            var next: [String] = []
            for k in frontier { for d in dependents(of: k) where visited.insert(d).inserted { parent[d] = k; next.append(d) } }
            if let r = next.first(where: { kegs[$0]?.onRequest == true }) { return (path(to: r), .requested) }
            if fallback == nil { fallback = next.first { dependents(of: $0).isEmpty } }
            frontier = next
        }
        if let f = fallback { return (path(to: f), .unknown) }
        return dependents(of: name).first.map { ([$0], .unknown) }
    }

    // MARK: Casks

    public struct Cask: Hashable, Sendable {
        public var token: String
        /// Its Caskroom folder for the installed version.
        public var path: String
        /// The app it put in place, when it has one and it is there.
        public var app: String?
        public var installed: Date?
    }

    /// A cask's Caskroom record: `Caskroom/<token>/.metadata/<version>/<timestamp>/Casks/<token>.json` names its app and
    /// was written when it was installed.
    public static func cask(_ token: String, version: String? = nil, prefix: String) -> Cask? {
        let roots = LocalFiles.roots([prefix + "/Caskroom"])
        let room = prefix + "/Caskroom/" + token
        let versions = LocalFiles.list(room, limit: 200).filter { !$0.hasPrefix(".") }
        guard !versions.isEmpty else { return nil }
        let installedVersion = versions.first { v in version.map { v == $0 || v.hasPrefix($0 + ",") } ?? false }
            ?? versions.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.last!
        let meta = room + "/.metadata/" + installedVersion
        let stamps = LocalFiles.list(meta, limit: 200).filter { !$0.hasPrefix(".") }.sorted()
        var installed: Date?, app: String?
        if let stamp = stamps.last {
            installed = ProvenanceText.plausible(LocalFiles.modified(meta + "/" + stamp))
            if let data = LocalFiles.read(meta + "/" + stamp + "/Casks/" + token + ".json", limit: 1024 * 1024, within: roots),
               let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                let appdir = Self.appDirectory(prefix: prefix, token: token, roots: roots)
                for artifact in j["artifacts"] as? [Any] ?? [] {
                    for a in (artifact as? [String: Any])?["app"] as? [Any] ?? [] {
                        let file = (a as? String) ?? ((a as? [String: Any])?["target"] as? String)
                        guard let file, !file.contains("..") else { continue }
                        let candidate = file.hasPrefix("/") ? file : appdir + "/" + (file as NSString).lastPathComponent
                        if app == nil, LocalFiles.exists(candidate) { app = candidate }
                    }
                }
            }
        }
        return Cask(token: token, path: room + "/" + installedVersion, app: app, installed: installed)
    }

    /// Where the cask put apps: its config.json's appdir, else /Applications.
    static func appDirectory(prefix: String, token: String, roots: [String]) -> String {
        guard let data = LocalFiles.read(prefix + "/Caskroom/" + token + "/.metadata/config.json", limit: 64 * 1024, within: roots),
              let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let dir = (j["default"] as? [String: Any])?["appdir"] as? String, dir.hasPrefix("/") else { return "/Applications" }
        return dir
    }

    /// The Homebrew prefix a path is under ("/opt/homebrew", "/usr/local"), if any.
    public static func prefix(of path: String) -> String? {
        if path.hasPrefix("/opt/homebrew/") { return "/opt/homebrew" }
        if path.hasPrefix("/usr/local/") { return "/usr/local" }
        return nil
    }
}
