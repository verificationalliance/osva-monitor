import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// Fix all, as the app runs it: one review, then one command per tool and place, batch after batch, through the
/// single-fix loop's steps. The tools are stand-ins in a temporary home: an npm that keeps each package's version in a
/// file (and can bring another package along, fail one item, or ask for a password), and a Python 3.11 that the pip
/// source finds (under the home as the machine's root), whose pip installs into a folder of METADATA files, answers
/// dry runs with a report, and can drag in a package that breaks another. FakeLauncher (FixLoopTests) holds a command
/// until the test ends it.
@MainActor @Suite(.serialized) struct FixAllTests {
    /// One package on a stand-in's list: vulnerable at `installed`, fixed in `fixed`.
    struct Package {
        var name: String, installed: String, fixed: String
        var group: Finding.Group = .criticalHigh, severity: Severity = .high, exploited = false, malicious = false
    }

    /// The site: an index that lists every package, and a batch answer that has each package vulnerable at its
    /// installed version and nothing to report about any other version.
    final class Site: HTTPTransport, @unchecked Sendable {
        let vulnerable: [(ecosystem: String, name: String, version: String, fixed: String)]
        init(_ vulnerable: [(String, String, String, String)]) { self.vulnerable = vulnerable.map { ($0.0, $0.1, $0.2, $0.3) } }
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let body: Data
            switch request.url!.path {
            case "/data/app-index.tsv":
                body = Data(("#osva-app-index\t1\t2026-11-19T03:00:00Z\t1\t0\n" + vulnerable.map { "K\t\($0.ecosystem)\t\($0.name)\n" }.joined()).utf8)
            case "/api/v1/check/batch":
                let asked = ((try? JSONSerialization.jsonObject(with: request.httpBody ?? Data())) as? [String: Any])?["packages"] as? [[String: Any]] ?? []
                let packages = vulnerable.filter { v in asked.contains { $0["name"] as? String == v.name && $0["version"] as? String == v.version } }.map { v in
                    #"{"ecosystem":"\#(v.ecosystem)","name":"\#(v.name)","version":"\#(v.version)","malicious":false,"distinct_flaws":1,"worst_severity":"HIGH","advisories":["GHSA-x"],"flaws":[{"id":"GHSA-x","severity":"HIGH","fixed_in":["\#(v.fixed)"],"ranges":[{"fixed":"\#(v.fixed)"}]}],"plan":{"target":"\#(v.fixed)","fixes":["GHSA-x"],"remaining":[]}}"#
                }
                body = Data(#"{"checked":1,"packages":[\#(packages.joined(separator: ","))]}"#.utf8)
            default: body = Data("{}".utf8)
            }
            return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
        }
    }

    /// Opens nothing: counts how often it was asked.
    final class CountingTerminal: TerminalOpener, @unchecked Sendable {
        let lock = NSLock()
        var opened = 0
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) { lock.withLock { opened += 1 }; completion("not here") }
    }

    struct Home {
        var model: AppModel
        var findings: [Finding]
        var npm: URL
        var python: URL?
        func finding(_ name: String) -> Finding { findings.first { $0.title == name }! }
        func id(_ name: String) -> String { finding(name).id }
        /// What a command would have done, for a FakeLauncher run: the package at this version now.
        func installed(_ name: String, _ version: String) throws {
            try Data(version.utf8).write(to: npm.deletingLastPathComponent().appendingPathComponent("v-\(name)"))
        }
        /// The npm commands that really ran, in order: "lodash@4.17.21 chalk@4.1.2", "uninstall evil".
        var npmInstalls: [String] {
            ((try? String(contentsOf: npm.deletingLastPathComponent().appendingPathComponent("installs"), encoding: .utf8)) ?? "")
                .split(separator: "\n").map(String.init)
        }
        /// The pip installs that really ran (dry runs too), each its arguments.
        var pipRuns: [[String]] {
            guard let python else { return [] }
            let text = (try? String(contentsOf: python.deletingLastPathComponent().appendingPathComponent("installs"), encoding: .utf8)) ?? ""
            return text.split(separator: "\n").map { $0.split(separator: "\0").map(String.init) }
        }
        /// The ones that changed something (not dry runs).
        var pipChanges: [[String]] { pipRuns.filter { !$0.contains("--dry-run") } }
        /// Each package's version in the Python's site now.
        var site: [String: String] {
            guard let python else { return [:] }
            return PythonSite.scan(folders: [python.deletingLastPathComponent().appendingPathComponent("site").path])
                .reduce(into: [:]) { $0[$1.key] = $1.version }
        }
        /// A file in the Python's folder: `drags-<name>` (what its real install also brings), `meta/<name>-<version>`
        /// (its requirements).
        func pipFile(_ name: String, _ text: String) throws {
            let url = python!.deletingLastPathComponent().appendingPathComponent(name)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(text.utf8).write(to: url)
        }
    }

    static let npmScript = """
    #!/bin/sh
    here="$(dirname "$0")"
    case "$1" in
      install)
        if [ "$(cat "$here/mode")" = "password" ] && [ -n "$CI" ]; then
          echo "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper" >&2
          exit 1
        fi
        shift 2; status=0
        echo "$*" >> "$here/installs"
        for spec in "$@"; do
          name="${spec%@*}"
          if [ -f "$here/fail-$name" ]; then echo "npm ERR! $name: ECONNRESET" >&2; status=1; continue; fi
          echo "${spec##*@}" > "$here/v-$name"
          if [ -f "$here/also-$name" ]; then other="$(cat "$here/also-$name")"; echo "${other##*@}" > "$here/v-${other%@*}"; fi
        done
        echo "changed $# packages"; exit $status ;;
      uninstall)
        echo "uninstall $3" >> "$here/installs"; rm -f "$here/v-$3"
        if [ -f "$here/also-$3" ]; then other="$(cat "$here/also-$3")"; echo "${other##*@}" > "$here/v-${other%@*}"; fi
        echo "removed 1 package" ;;
      ls)
        printf '{"dependencies":{'; sep=""
        for f in "$here"/v-*; do [ -f "$f" ] || continue; n="${f##*/v-}"; printf '%s"%s":{"version":"%s"}' "$sep" "$n" "$(cat "$f")"; sep=","; done
        printf '}}' ;;
    esac

    """

    /// A Python 3.11 the pip source finds: it describes itself, lists its site, reads its sys.path, and its pip installs
    /// into `site/` (a package's requirements from `meta/<name>-<version>`), dry-runs with a report or a "Would install"
    /// line, drags in what `drags-<name>` names on a real install (and breaks httpx then), and puts versions back with
    /// `--no-deps`. Its report resolves `name>=v` or a bare name to the version `resolve-<name>` names, when there is one.
    static let pythonScript = #"""
    #!/bin/sh
    here="$(cd "$(dirname "$0")" && pwd)"
    site="$here/site"
    put() {
      name="$1"; version="$2"
      rm -rf "$site/$name"-*.dist-info
      d="$site/$name-$version.dist-info"; mkdir -p "$d"
      { printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$name" "$version"
        if [ -f "$here/meta/$name-$version" ]; then sed 's/^/Requires-Dist: /' "$here/meta/$name-$version"; fi; } > "$d/METADATA"
    }
    if [ "$1" = "--put" ]; then put "$2" "$3"; exit 0; fi
    if [ "$1" = "-c" ]; then
      case "$2" in
        *base_prefix*) printf '{"version":"3.11.14","executable":"%s/python3.11","prefix":"%s/venv","base_prefix":"/base","stdlib":"/nonexistent","usersite":null}\n' "$here" "$here" ;;
        *) printf '{"path":["%s"],"markers":{"python_version":"3.11","sys_platform":"darwin"}}\n' "$site" ;;
      esac
      exit 0
    fi
    [ "$1" = "-m" ] && [ "$2" = "pip" ] || exit 2
    shift 2
    case "$1" in
      --version) echo "pip 24.0 from $here (python 3.11)" ;;
      list)
        printf '['; sep=""
        for d in "$site"/*.dist-info; do b="$(basename "$d" .dist-info)"; printf '%s{"name":"%s","version":"%s","location":"%s","installer":"pip"}' "$sep" "${b%-*}" "${b##*-}" "$site"; sep=","; done
        printf ']\n' ;;
      check) if [ -f "$here/broken" ]; then echo "httpx 0.27.0 has requirement anyio<5, but you have anyio 5.0.0."; exit 1; fi
             echo "No broken requirements found." ;;
      install)
        for a in "$@"; do printf '%s\0' "$a"; done >> "$here/installs"; echo >> "$here/installs"
        case " $* " in
          *" --report "*)
            printf '{"version":"1","install":['; sep=""
            for a in "$@"; do
              case "$a" in
                *==*) n="${a%%==*}"; v="${a#*==}" ;;
                -*) continue ;;
                *) n="${a%%>=*}"; [ -f "$here/resolve-$n" ] || continue; v="$(cat "$here/resolve-$n")" ;;
              esac
              r=""
              if [ -f "$here/meta/$n-$v" ]; then r="$(sed 's/.*/"&"/' "$here/meta/$n-$v" | paste -sd, -)"; fi
              printf '%s{"requested":true,"metadata":{"name":"%s","version":"%s","requires_dist":[%s]}}' "$sep" "$n" "$v" "$r"; sep=","
            done
            printf ']}\n' ;;
          *" --dry-run "*)
            out=""; for a in "$@"; do case "$a" in *==*) out="$out ${a%%==*}-${a#*==}" ;; esac; done
            echo "Would install$out" ;;
          *" --no-deps "*)
            for a in "$@"; do case "$a" in *==*) put "${a%%==*}" "${a#*==}" ;; esac; done
            rm -f "$here/broken"; echo "Successfully installed (put back)" ;;
          *)
            for a in "$@"; do case "$a" in *==*)
              n="${a%%==*}"; put "$n" "${a#*==}"
              if [ -f "$here/drags-$n" ]; then put $(cat "$here/drags-$n"); touch "$here/broken"; fi ;;
            esac; done
            echo "Successfully installed" ;;
        esac ;;
      *) exit 2 ;;
    esac

    """#

    /// A temporary home with the stand-in npm in ~/.volta/bin and these packages at their installed versions, and a
    /// last scan that found each of them. `pip`: packages in the stand-in Python 3.11 (with httpx 0.27.0, which needs
    /// anyio below 5, and anyio 4.0.0). `refused` adds a finding whose npm is not on this Mac. `twin`: a second finding
    /// with the first package's command (as several of a formula's packages share its upgrade).
    func setUp(_ packages: [Package], pip: [Package] = [], refused: Bool = false, twin: Bool = false, mode: String = "ok",
               terminal: any TerminalOpener = CountingTerminal(), alsoVulnerable: [(String, String, String, String)] = []) throws -> Home {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("osva-fixall-\(UUID().uuidString)", isDirectory: true)
        let bin = home.appendingPathComponent(".volta/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try Data(mode.utf8).write(to: bin.appendingPathComponent("mode"))
        let npm = bin.appendingPathComponent("npm")
        try Data(Self.npmScript.utf8).write(to: npm)
        chmod(npm.path, 0o755)
        for p in packages { try Data(p.installed.utf8).write(to: bin.appendingPathComponent("v-\(p.name)")) }

        var findings: [Finding] = [], inventory: [InstalledPackage] = []
        func add(_ origin: Origin, _ ecosystem: Ecosystem, _ p: Package, id: String? = nil) {
            let upgrade = p.malicious ? nil : PreviewData.fix(p.fixed, above: p.installed)
            let inputs = UpgradeCommand.Inputs(origin: origin, name: p.name, ecosystem: ecosystem, target: upgrade, malicious: p.malicious)
            findings.append(Finding(id: id ?? "pkg|\(ecosystem.rawValue)|\(p.name)|\(p.installed)", group: p.malicious ? .malicious : p.group,
                                    subject: .package(ecosystem: ecosystem, name: p.name), title: p.name, installedVersion: p.installed,
                                    upgrade: upgrade, severity: p.malicious ? nil : p.severity, advisoryIDs: ["GHSA-x"],
                                    flawCount: 1, exploited: p.exploited, malicious: p.malicious, note: nil, bigIssue: nil, origins: [origin],
                                    pageURL: SiteURL.packagePage(ecosystem, p.name, version: p.installed), advice: UpgradeCommand.advice(inputs),
                                    verification: .none, grade: nil, commandInputs: inputs))
            inventory.append(InstalledPackage(ecosystem: ecosystem, name: p.name, version: p.installed, origin: origin))
        }
        for p in packages { add(.npmGlobal(npm: npm.path), .npm, p) }
        if refused { add(.npmGlobal(npm: home.appendingPathComponent("gone/npm").path), .npm, Package(name: "left-pad", installed: "1.0.0", fixed: "1.3.0")) }
        if twin, let p = packages.first {
            add(.npmGlobal(npm: npm.path), .npm, p, id: "pkg|npm|\(p.name)|\(p.installed)|twin")
            inventory.removeLast()
        }

        var python: URL?
        if !pip.isEmpty {
            let pbin = home.appendingPathComponent("opt/homebrew/bin", isDirectory: true)
            try FileManager.default.createDirectory(at: pbin.appendingPathComponent("site"), withIntermediateDirectories: true)
            let py = pbin.appendingPathComponent("python3.11")
            try Data(Self.pythonScript.utf8).write(to: py)
            chmod(py.path, 0o755)
            func put(_ name: String, _ version: String) throws {
                let p = Process(); p.executableURL = py; p.arguments = ["--put", name, version]; try p.run(); p.waitUntilExit()
            }
            try FileManager.default.createDirectory(at: pbin.appendingPathComponent("meta"), withIntermediateDirectories: true)
            try Data("anyio<5\n".utf8).write(to: pbin.appendingPathComponent("meta/httpx-0.27.0"))
            try put("httpx", "0.27.0"); try put("anyio", "4.0.0")
            let env = PythonEnvironment(executable: py.path, version: "3.11.14", kind: .virtualEnv, externallyManaged: false, userSite: nil, formula: nil)
            for p in pip {
                try put(p.name, p.installed)
                add(.pip(python: env, user: false, formula: nil), .pypi, p, id: "pkg|PyPI|\(p.name)|\(p.installed)|py3.11.14")
            }
            python = py
        }

        var tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(),
                                    isExecutable: { $0.hasPrefix(home.path) && FileManager.default.isExecutableFile(atPath: $0) })
        tools.systemRoot = home.path                                // the pip source finds the stand-in Python, and only it
        let storage = Storage(directory: home.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: inventory),
                                findings: FindingOrder.sorted(findings), sent: SentRecord(), indexGeneratedAt: nil, problems: []))
        let site = Site(packages.map { ("npm", $0.name, $0.installed, $0.fixed) } + pip.map { ("PyPI", $0.name, $0.installed, $0.fixed) } + alsoVulnerable)
        let model = AppModel(storage: storage, notifier: FixLoopTests.Quiet(), tools: tools, transport: site, defaults: FixLoopTests.defaults())
        model.terminal = terminal
        return Home(model: model, findings: findings, npm: npm, python: python)
    }

    func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0..<600 where !condition() { try await Task.sleep(for: .milliseconds(50)) }
    }

    /// Every row decided (pip's are read in the background).
    func assessed(_ h: Home) async throws {
        h.model.assessAllFixes()
        try await waitUntil { !h.model.fixAllPanel.checking }
    }

    func done(_ h: Home) -> Bool { h.model.fixAll?.phase == .done }

    /// lodash high, chalk critical, debug moderate, minimist exploited: four npm findings of four ranks.
    static let four = [Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21"),
                       Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2", severity: .critical),
                       Package(name: "debug", installed: "2.6.8", fixed: "2.6.9", group: .other, severity: .moderate),
                       Package(name: "minimist", installed: "1.2.5", fixed: "1.2.6", group: .exploited, exploited: true)]

    static let evil = Package(name: "evil", installed: "1.0.0", fixed: "", malicious: true)

    // MARK: The count and the review

    /// N is exactly the rows that offer a fix: a refused row is not counted, a row that needs a password is not (it
    /// offers Terminal), a row whose run failed is (it offers Retry).
    @Test func theCountIsExactlyTheRowsThatOfferAFix() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21"),
                           Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2")], refused: true)
        try await assessed(h)
        let rowsThatOffer = { h.model.report!.findings.filter { h.model.rowFixes[$0.id]?.offeredFix != nil }.map(\.id) }
        #expect(h.model.fixAllPanel.count == 2 && Set(rowsThatOffer()) == [h.id("lodash"), h.id("chalk")])
        #expect(h.model.fixes[h.id("left-pad")]?.availability == .withheld("npm was not found on this Mac, so the app cannot run this for you."))
        h.model.openFixAll()
        #expect(Set(h.model.fixAll?.batches.flatMap(\.findings).map(\.id) ?? []) == [h.id("lodash"), h.id("chalk")])
        #expect(h.model.fixAll?.skipped == [FixAllState.Skip(finding: h.finding("left-pad"),
                                                              reason: "npm was not found on this Mac, so the app cannot run this for you.")])
        h.model.closeFixAll()

        // lodash fails once (Retry: still counted), then needs a password (Terminal only: not counted)
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        h.model.beginFix(h.finding("lodash"))
        try await waitUntil { h.model.fixes[h.id("lodash")]?.preview != .loading }
        h.model.runFix(h.finding("lodash"))
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].end(.exited(1))
        try await waitUntil { h.model.fixes[h.id("lodash")]?.outcome == .exitedWithError(1) && h.model.activeFix == nil }
        try await waitUntil { h.model.fixes[h.id("lodash")]?.availability != .checking }
        #expect(h.model.fixAllPanel.count == 2 && rowsThatOffer().count == 2)
        h.model.retryFix(h.finding("lodash"))
        try await waitUntil { launcher.runs.count == 2 }
        launcher.runs[1].end(.needsPassword)
        try await waitUntil { h.model.fixes[h.id("lodash")]?.outcome == .needsPassword && h.model.activeFix == nil }
        #expect(h.model.fixAllPanel.count == 1 && rowsThatOffer() == [h.id("chalk")])
        h.model.openFixAll()
        #expect(h.model.fixAll?.batches.flatMap(\.findings).map(\.id) == [h.id("chalk")])
        #expect(h.model.fixAll?.skipped.first { $0.id == h.id("lodash") }?.reason == "Needs your administrator password")
    }

    /// The review says what it leaves alone in each row's own words, lists the proposals apart (unticked), and every
    /// finding that needs action is in exactly one place.
    @Test func theReviewSaysWhatItLeavesAloneAndWhy() {
        let review = PreviewData.fixAllReview
        let reasons = Dictionary(uniqueKeysWithValues: review.skipped.map { ($0.id, $0.reason) })
        typealias F = PreviewData.FixID
        #expect(reasons[F.nokogiri] == "Part of macOS: only a macOS update changes Apple's Ruby and its gems.")
        #expect(reasons[F.setuptools]?.hasPrefix("Part of Apple's developer tools") == true)
        #expect(reasons[F.cpython] == "Homebrew still ships 3.12.17; the fix is 3.14.11 upstream.")
        #expect(reasons["pkg|PyPI|urllib3|1.26.5"] == "Nothing the app can run here: see its row")
        #expect(reasons[F.hacl]?.hasPrefix("Not run for you: it changes the project's dependencies") == true)   // lower, but it says why
        #expect(reasons["pkg|crates.io|time|0.1.43"] == nil && reasons["pkg|PyPI|pygments|2.14.0|py3.15.2"] == nil)   // lower, nothing to say
        #expect(reasons[PreviewData.FixAllID.dropbox] == "Newest version installed; no fixed release yet. It still ships Electron 37.10.3.")
        #expect(reasons[PreviewData.FixAllID.zoom] == "Needs your administrator password: its update runs an installer package.")
        // starlette and torch are proposals, not left alone, and not ticked
        #expect(review.proposals.map(\.id) == [F.starlette, PreviewData.FixAllID.torch311] && review.proposals.allSatisfy { !$0.ticked })
        #expect(review.proposals.map(\.line) == ["starlette with fastapi and the instrumentator (fixes the exploited flaw)",
                                                 "torch to 2.8.0 (6 of 14; whisperx needs below 2.9)"])
        #expect(review.proposals[0].asks == "pip asks PyPI about starlette, fastapi, prometheus-fastapi-instrumentator")
        let planned = Set(review.batches.flatMap(\.findings).map(\.id)), proposed = Set(review.proposals.map(\.id))
        for f in PreviewData.fixAllFindings where f.group.needsAction {
            let places = [planned.contains(f.id), proposed.contains(f.id), reasons[f.id] != nil].filter { $0 }.count
            #expect(places == 1, "\(f.id) is in \(places) places")
        }
    }

    /// One command per tool and place, in the batches' order (the removal, Homebrew's formulae, casks, each Python, the
    /// rest), the most urgent first within each; a command that fixes several findings is one item that names them.
    @Test func oneCommandPerToolAndPlace() {
        let review = PreviewData.fixAllReview
        #expect(review.batches.map(\.line) == ["storefront: Remove axios", "Homebrew: 3 formulae", "Homebrew casks: 2 apps", "Python 3.11: 9 packages",
                                               "Python 3.13: 1 package"])
        let brew = review.batches[1]
        #expect(brew.items.map(\.name) == ["OpenSSH", "nginx", "jupyterlab"] && brew.items[2].findings.map(\.id) == [PreviewData.FixAllID.tornado, PreviewData.FixAllID.jinja2])
        #expect(brew.command == "/opt/homebrew/bin/brew upgrade openssh nginx jupyterlab")
        #expect(review.batches[2].command == "/opt/homebrew/bin/brew upgrade --cask openmtp visual-studio-code")
        #expect(review.batches[3].items.first?.name == "pillow")                                  // the critical one first
        #expect(review.batches[3].command.hasPrefix("/opt/homebrew/bin/python3.11 -m pip install --disable-pip-version-check --no-input pillow==10.3.0 "))
        // a ticked proposal joins its Python's batch
        let ticked = FixAll.review(PreviewData.fixAllReport(), fixes: PreviewData.fixAllRows, ticked: [PreviewData.FixAllID.torch311])
        #expect(ticked.batches[3].line == "Python 3.11: 10 packages" && ticked.batches[3].items.contains { $0.id == PreviewData.FixAllID.torch311 })
        #expect(ticked.proposals.first { $0.id == PreviewData.FixAllID.torch311 }?.ticked == true)
    }

    /// Batches go removals first, then by tool; within one, worst first: malicious, exploited, critical, high, the rest.
    @Test func batchesGoInOrderWorstFirstWithin() {
        let tools = ToolEnvironment(base: [:], isExecutable: { _ in true })
        func f(_ name: String, _ group: Finding.Group, _ severity: Severity?, exploited: Bool = false, malicious: Bool = false,
               origin: Origin = .npmGlobal(npm: "/opt/homebrew/bin/npm"), eco: Ecosystem = .npm) -> Finding {
            let upgrade = malicious ? nil : PreviewData.fix("9.9.9", above: "1.0.0")
            let inputs = UpgradeCommand.Inputs(origin: origin, name: name, ecosystem: eco, target: upgrade, malicious: malicious)
            return Finding(id: "pkg|npm|\(name)|1.0.0", group: group, subject: .package(ecosystem: eco, name: name), title: name, installedVersion: "1.0.0",
                           upgrade: upgrade, severity: severity, advisoryIDs: [], flawCount: 1, exploited: exploited,
                           malicious: malicious, note: nil, bigIssue: nil, origins: [inputs.origin], pageURL: SiteURL.packagePage(eco, name, version: "1.0.0"),
                           advice: UpgradeCommand.advice(inputs), verification: .none, grade: nil, commandInputs: inputs)
        }
        let py = PythonEnvironment(executable: "/opt/homebrew/bin/python3.12", version: "3.12.4", kind: .homebrew, externallyManaged: false,
                                   userSite: nil, formula: "python@3.12")
        // in an order that is none of the right ones
        let findings = [f("low", .other, .low), f("high-a", .criticalHigh, .high), f("evil", .malicious, nil, malicious: true),
                        f("none", .other, nil), f("moderate", .other, .moderate), f("critical", .criticalHigh, .critical),
                        f("kev", .exploited, .moderate, exploited: true), f("high-b", .criticalHigh, .high),
                        f("requests", .criticalHigh, .high, origin: .pip(python: py, user: false, formula: nil), eco: .pypi),
                        f("ffmpeg", .criticalHigh, .high, origin: .homebrewFormula(name: "ffmpeg"), eco: .npm)]
        var rows: [String: FixRowState] = [:]
        for x in findings {
            guard case let .success(plan) = FixPlan.make(for: x, tools: tools) else { Issue.record("no plan for \(x.title)"); return }
            rows[x.id] = FixRowState(availability: .offered(FixOffer(plan: plan)))
        }
        let review = FixAll.review(findings, fixes: rows)
        #expect(review.batches.map(\.label) == ["global npm", "Homebrew", "Python 3.12", "global npm"])
        #expect(review.batches[0].items.map(\.name) == ["evil"] && review.batches[0].plan.action == .removal)
        #expect(review.batches[3].items.map(\.name) == ["kev", "critical", "high-a", "high-b", "low", "none", "moderate"])
        #expect(review.batches[3].command == "/opt/homebrew/bin/npm install -g kev@9.9.9 critical@9.9.9 high-a@9.9.9 high-b@9.9.9 low@9.9.9 none@9.9.9 moderate@9.9.9")
        #expect(FixAll.offered(findings, fixes: rows).count == findings.count)
    }

    @Test func theSummaryCounts() {
        func batch(_ outcomes: [FixOutcome], status: FixAllState.Batch.Status = .done) -> FixAllState.Batch {
            let fs = outcomes.indices.map { i in PreviewData.fixFindings[i] }
            var b = FixAllState.Batch(kind: .npm(npm: "/n"), label: "npm", items: fs.map { FixAllState.Item(findings: [$0], offers: [PreviewData.offer(PreviewData.FixID.nginx)]) },
                                      status: status)
            b.outcomes = Dictionary(uniqueKeysWithValues: zip(fs.map(\.id), outcomes))
            return b
        }
        var s = FixAllState(phase: .done, batches: [batch([.fixed(now: "1"), .removed, .fixedCheck(now: "2", users: "x")]),
                                                    batch([.fixed(now: "1"), .partlyFixed(now: "2.8.0", remain: 8), .fixed(now: "1")]),
                                                    batch([.exitedWithError(1), .needsPassword, .blocked("why")])], skipped: [])
        #expect(s.summary == "Fixed 5 · 1 partly fixed · 1 failed · 2 need you")
        #expect(s.needYou.map(\.outcome) == [.needsPassword, .blocked("why")])
        s.batches.append(batch([.stopped("still 1.0")]))
        s.batches.append(batch([.fixed(now: "1"), .fixed(now: "1")], status: .notRun))
        #expect(s.summary == "Fixed 5 · 1 partly fixed · 1 failed · 2 need you · 3 not run")
        #expect(FixAllState(phase: .done, batches: [batch([.needsPassword])], skipped: []).summary == "1 needs you")
        #expect(FixAllState(phase: .done, batches: [batch([.putBack("httpx 0.27.0"), .couldNotCheck("x")])], skipped: []).summary == "1 failed · 1 needs you")
        // ran, and the version now is only reported by the site: neither fixed nor failed
        let reported = FixAllState(phase: .done, batches: [batch([.fixed(now: "1"), .notChecked("now 4.17.21")])], skipped: [])
        #expect(reported.summary == "Fixed 1 · 1 still reported, not checked" && reported.failedItems.isEmpty)
    }

    // MARK: The run

    /// One batch at a time, in the review's order, each one command: the removal first, then the npm batch with its
    /// four packages, worst first. The next starts only once the last has ended and been checked again.
    @Test func batchesRunOneAtATimeEachOneCommand() async throws {
        let h = try setUp(Self.four + [Self.evil])
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 5)
        h.model.openFixAll()
        #expect(h.model.fixAll?.batches.map(\.line) == ["global npm: Remove evil", "global npm: 4 packages"])
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        #expect(launcher.runs[0].invocation.arguments == ["uninstall", "-g", "evil"])
        #expect(h.model.fixAll?.progressLine == "Batch 1 of 2 · global npm: Remove evil")
        try await Task.sleep(for: .milliseconds(150))
        #expect(launcher.runs.count == 1)                                                           // the next waits
        try FileManager.default.removeItem(at: h.npm.deletingLastPathComponent().appendingPathComponent("v-evil"))
        launcher.runs[0].end(.exited(0))
        try await waitUntil { launcher.runs.count == 2 }
        #expect(launcher.runs[1].invocation.arguments == ["install", "-g", "minimist@1.2.6", "chalk@4.1.2", "lodash@4.17.21", "debug@2.6.9"])
        #expect(h.model.fixAll?.progressLine == "Batch 2 of 2 · global npm: 4 packages")
        #expect(Set(Self.four.map { h.id($0.name) }).allSatisfy { h.model.fixes[$0]?.isBusy == true })
        for p in Self.four { try h.installed(p.name, p.fixed) }
        launcher.runs[1].end(.exited(0))
        try await waitUntil { done(h) }
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 5")
        for p in Self.four { #expect(h.model.fixes[h.id(p.name)]?.outcome == .fixed(now: p.fixed), "\(p.name)") }
        #expect(h.model.fixes[h.id("evil")]?.outcome == .removed)
    }

    /// One command for several findings: twins that share a command are one item, run once, each checked on its own.
    @Test func oneCommandForSeveralFindingsRunsOnce() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21")], twin: true)
        let (lodash, twin) = (h.findings[0].id, h.findings[1].id)
        try await assessed(h)
        h.model.openFixAll()
        #expect(h.model.fixAll?.batches.count == 1 && h.model.fixAll?.batches[0].items.count == 1
                && h.model.fixAll?.batches[0].findings.map(\.id) == [lodash, twin])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.npmInstalls == ["lodash@4.17.21"])                                               // once
        #expect(h.model.fixes[lodash]?.outcome == .fixed(now: "4.17.21") && h.model.fixes[twin]?.outcome == .fixed(now: "4.17.21"))
        #expect(h.model.fixAll?.summary == "Fixed 2")
    }

    /// An earlier batch can change the picture: removing evil also brings chalk 4.1.2. The npm batch checks its findings
    /// again first: chalk is done, and only lodash is in its command.
    @Test func aFindingAnEarlierBatchFixedIsLeftOut() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21"), Package(name: "chalk", installed: "4.0.0", fixed: "4.1.2"),
                           Self.evil])
        try Data("chalk@4.1.2".utf8).write(to: h.npm.deletingLastPathComponent().appendingPathComponent("also-evil"))
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.npmInstalls == ["uninstall evil", "lodash@4.17.21"])
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .fixed(now: "4.1.2"))
        #expect(h.model.fixAll?.summary == "Fixed 3")
    }

    /// One item of a batch fails: the others are fixed, each finding keeps its own outcome, and the failed one counts
    /// (and offers Retry). Run by the stand-in npm, which goes on past the failing item.
    @Test func eachFindingKeepsItsOwnOutcomeAfterABatch() async throws {
        let h = try setUp(Array(Self.four.prefix(3)))
        try Data().write(to: h.npm.deletingLastPathComponent().appendingPathComponent("fail-chalk"))
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.npmInstalls == ["chalk@4.1.2 lodash@4.17.21 debug@2.6.9"])
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .exitedWithError(1))
        #expect(h.model.fixes[h.id("lodash")]?.outcome == .fixed(now: "4.17.21") && h.model.fixes[h.id("debug")]?.outcome == .fixed(now: "2.6.9"))
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 2 · 1 failed")
        try await waitUntil { h.model.fixes[h.id("chalk")]?.availability != .checking }
        #expect(h.model.fixAllPanel.count == 1)                                                   // chalk offers Retry, and counts again
    }

    /// A batch that asked for a password went on (the stand-in's log says whose step asked): that finding needs the
    /// person, the one that was not fixed for another reason failed, the rest are fixed. Nothing opens Terminal while Fix
    /// all runs; the summary lists the one that needs a password with its Terminal button, which works once it ended.
    @Test func aPasswordInABatchIsTheItemsAloneAndTerminalWaitsForTheSummary() async throws {
        let terminal = CountingTerminal()
        let h = try setUp(Array(Self.four.prefix(3)), terminal: terminal)
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].print("==> Installing lodash@4.17.21\nsudo: a terminal is required to read the password\n==> Installing debug@2.6.9\n")
        try h.installed("debug", "2.6.9")
        launcher.runs[0].end(.needsPassword)
        try await waitUntil { done(h) }
        #expect(h.model.fixes[h.id("lodash")]?.outcome == .needsPassword)
        #expect(h.model.fixes[h.id("chalk")]?.outcome == .exitedWithError(1))                   // not its step that asked
        #expect(h.model.fixes[h.id("debug")]?.outcome == .fixed(now: "2.6.9"))
        #expect(h.model.fixAll?.summary == "Fixed 1 · 1 failed · 1 needs you")
        #expect(h.model.fixAll?.needYou.map(\.finding.title) == ["lodash"])
        #expect(terminal.lock.withLock { terminal.opened } == 0)
        h.model.runFixInTerminal(h.finding("lodash"))                                            // the summary's button
        try await waitUntil { terminal.lock.withLock { terminal.opened } == 1 }
        #expect(terminal.lock.withLock { terminal.opened } == 1)
        // the review and the run offer no Terminal; only the summary's list does, through the one TerminalButton
        let views = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/FixAllViews.swift"), encoding: .utf8)
        for view in ["FixAllReview", "FixAllBatchLine", "FixAllProposalLine", "FixAllProgress"] {
            let body = views.components(separatedBy: "struct \(view)")[1].components(separatedBy: "\nstruct ")[0]
            #expect(!body.contains("Terminal"), "\(view) offers Terminal")
        }
        #expect(views.components(separatedBy: "struct FixAllNeedLine")[1].contains("TerminalButton("))
    }

    /// Stop ends the batch under way, as its own Stop does, and no other starts.
    @Test func stopEndsTheBatchAndCancelsTheRest() async throws {
        let h = try setUp(Array(Self.four.prefix(2)) + [Self.evil])
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 && h.model.fixAllPanel.run?.step == .running }
        h.model.stopFixAll()
        #expect(launcher.runs[0].stopAsked)
        try await waitUntil { done(h) }
        #expect(launcher.runs.count == 1)
        #expect(h.model.fixes[h.id("evil")]?.outcome == .stopped("still 1.0.0"))
        #expect(h.model.fixAll?.ending == .stopped && h.model.fixAll?.batches[1].status == .notRun)
        #expect(h.model.fixAll?.summary == "3 not run")
        #expect(h.model.fixes[h.id("lodash")]?.progress == nil)                                    // untouched
    }

    /// One at a time: while a row's own fix runs, Fix all waits and says why; while Fix all runs, no row's fix starts.
    @Test func fixAllAndASingleFixWaitForEachOther() async throws {
        let h = try setUp(Array(Self.four.prefix(3)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.beginFix(h.finding("debug"))
        try await waitUntil { h.model.fixes[h.id("debug")]?.preview != .loading }
        h.model.runFix(h.finding("debug"))
        try await waitUntil { launcher.runs.count == 1 }
        #expect(h.model.fixAllPanel.waitingFor == "debug" && h.model.fixAllPanel.why == "One fix at a time: debug is running.")
        h.model.openFixAll()
        #expect(h.model.fixAll == nil)
        try h.installed("debug", "2.6.9")
        launcher.runs[0].end(.exited(0))
        try await waitUntil { h.model.activeFix == nil }

        h.model.beginFix(h.finding("lodash"))                                                    // its review open before Fix all starts
        try await waitUntil { h.model.fixes[h.id("lodash")]?.preview != .loading }
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 2 }
        #expect(h.model.rowFixes.values.filter { !$0.isBusy && $0.waitingFor != nil }.allSatisfy { $0.waitingFor == "global npm" })
        h.model.runFix(h.finding("lodash"))                                                      // waits: nothing starts
        h.model.openFixAll()                                                                     // and the batch stays as it is
        #expect(launcher.runs.count == 2 && h.model.fixAll?.phase == .running)
        launcher.runs[1].end(.exited(0))
        try await waitUntil { done(h) }
    }

    /// The batch lives in the model: a panel opened again draws it from there, as it draws a row's run.
    @Test func thePanelDrawsFixAllFromTheModel() async throws {
        let h = try setUp(Array(Self.four.prefix(2)))
        let launcher = FakeLauncher()
        h.model.launcher = launcher
        try await assessed(h)
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { launcher.runs.count == 1 }
        launcher.runs[0].print("step one\n")
        try await waitUntil { h.model.fixAllPanel.run?.log.lines == ["step one"] }
        let panel = h.model.fixAllPanel                                                          // what a new panel gets
        #expect(panel.batch?.phase == .running && panel.batch?.progressLine == "global npm: 2 packages" && panel.run?.log.lines == ["step one"])
        launcher.runs[0].end(.exited(0))
        try await waitUntil { done(h) }
        h.model.closeFixAll()
        #expect(h.model.fixAll == nil)
    }

    /// The row draws its button from the same decision Fix all counts (FixRowState.offeredFix), so the two cannot
    /// differ; and the header's button is the rows' own FixButton.
    @Test func theRowAndTheCountShareOneDecision() throws {
        let row = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/FindingRow.swift"), encoding: .utf8)
        #expect(row.contains("if let offer = fix.offeredFix {") && row.contains("canRetry: fix.offeredFix != nil"))
        #expect(!row.contains("case let .offered(offer)?:"))
        let panel = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/PopoverView.swift"), encoding: .utf8)
        #expect(panel.contains("FixButton(title: \"Fix all ("))
    }

    // MARK: pip batches

    /// Python 3.11's two upgrades together bring anyio 5 (which their dry run did not show), and httpx breaks: the whole
    /// batch is put back at once, its items run one at a time with the single fix's own gates, alpha lands, and beta,
    /// which breaks it again on its own, is put back too. Fix all goes on, and nothing is left broken.
    @Test func aBatchThatBreaksSomethingIsPutBackThenRunOneAtATime() async throws {
        let h = try setUp([], pip: [Package(name: "alpha", installed: "1.0", fixed: "1.1", severity: .critical),
                                    Package(name: "beta", installed: "2.0", fixed: "2.1")])
        try h.pipFile("drags-beta", "anyio 5.0.0")
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 2)
        h.model.openFixAll()
        #expect(h.model.fixAll?.batches.map(\.line) == ["Python 3.11: 2 packages"])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        let changes = h.pipChanges.map { $0.filter { $0.contains("==") || $0 == "--no-deps" } }
        #expect(changes == [["alpha==1.1", "beta==2.1"],                         // together
                            ["--no-deps", "alpha==1.0", "anyio==4.0.0", "beta==2.0"],   // put back
                            ["alpha==1.1"],                                      // one at a time
                            ["beta==2.1"],
                            ["--no-deps", "anyio==4.0.0", "beta==2.0"]])        // beta put back on its own
        #expect(h.model.fixes[h.id("alpha")]?.outcome == .fixed(now: "1.1"))
        #expect(h.model.fixes[h.id("beta")]?.outcome == .putBack("httpx 0.27.0"))
        #expect(h.site == ["alpha": "1.1", "beta": "2.0", "anyio": "4.0.0", "httpx": "0.27.0"])
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 1 · 1 failed")
        #expect(h.model.fixAll?.isolatedBatches.map(\.why) == ["it broke httpx 0.27.0"])
    }

    /// A pair fine alone and conflicting together: alpha 1.1 needs beta below 2.1, which beta's own fix is. Each passes
    /// its own gate; the batch's end state does not, so nothing runs as one: alpha runs alone, and beta, checked again
    /// against what is installed now, is left with why.
    @Test func theBatchsEndStateIsCheckedAsAWhole() async throws {
        let h = try setUp([], pip: [Package(name: "alpha", installed: "1.0", fixed: "1.1", severity: .critical),
                                    Package(name: "beta", installed: "2.0", fixed: "2.1")])
        try h.pipFile("meta/alpha-1.1", "beta<2.1\n")
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 2)                                                   // each alone is fine
        h.model.openFixAll()
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(!h.pipChanges.contains { $0.contains("alpha==1.1") && $0.contains("beta==2.1") })  // never together
        #expect(h.model.fixes[h.id("alpha")]?.outcome == .fixed(now: "1.1"))
        #expect(h.model.fixes[h.id("beta")]?.outcome == .blocked("alpha 1.1 needs beta < 2.1 — nothing installed needs alpha: removing it would clear the way"))
        #expect(h.site["beta"] == "2.0")
        #expect(h.model.fixAll?.isolatedBatches.map(\.why) == ["alpha 1.1 needs beta < 2.1"])
    }

    /// A single pip upgrade that breaks something is put back at once, and Fix all goes on to the next batch.
    @Test func aSingleUpgradeThatBreaksSomethingIsPutBackAndFixAllGoesOn() async throws {
        let h = try setUp([Package(name: "lodash", installed: "4.17.20", fixed: "4.17.21")],
                          pip: [Package(name: "starlette", installed: "0.48.0", fixed: "1.3.1", group: .exploited, exploited: true)])
        try h.pipFile("drags-starlette", "anyio 5.0.0")
        try await assessed(h)
        h.model.openFixAll()
        #expect(h.model.fixAll?.batches.map(\.label) == ["Python 3.11", "global npm"])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.model.fixes[h.id("starlette")]?.outcome == .putBack("httpx 0.27.0"))
        #expect(h.site["starlette"] == "0.48.0" && h.site["anyio"] == "4.0.0")
        #expect(h.npmInstalls == ["lodash@4.17.21"])                                              // went on
        #expect(h.model.fixAll?.ending == .finished && h.model.fixAll?.summary == "Fixed 1 · 1 failed")
    }

    // MARK: Proposals

    /// A proposal is listed unticked and runs only when ticked, in its Python's batch.
    @Test func aProposalRunsOnlyWhenTicked() async throws {
        let h = try setUp([], pip: [Package(name: "alpha", installed: "1.0", fixed: "1.1", severity: .critical),
                                    Package(name: "gamma", installed: "3.0", fixed: "3.4")], alsoVulnerable: [("PyPI", "gamma", "3.1", "3.4")])
        // something installed pins gamma below 3.2: the full fix is blocked; the site's plan within that is 3.1
        try h.pipFile("meta/pinner-1.0", "gamma<3.2\n")
        let py = h.python!
        let p = Process(); p.executableURL = py; p.arguments = ["--put", "pinner", "1.0"]; try p.run(); p.waitUntilExit()
        h.model.fixServer = PartialServer(target: "3.1")
        try await assessed(h)
        #expect(h.model.fixAllPanel.count == 1)                                                   // the proposal is not counted
        guard let proposal = h.model.fixes[h.id("gamma")]?.offeredProposal else { Issue.record("no proposal"); return }
        #expect(proposal.plan.target == "3.1")
        h.model.openFixAll()
        #expect(h.model.fixAll?.proposals.map(\.ticked) == [false] && h.model.fixAll?.batches.flatMap(\.findings).map(\.title) == ["alpha"])
        h.model.tickProposal(h.id("gamma"), true)
        #expect(h.model.fixAll?.batches.map(\.line) == ["Python 3.11: 2 packages"])
        h.model.runFixAll()
        try await waitUntil { done(h) }
        #expect(h.pipChanges.map { $0.filter { $0.contains("==") } } == [["alpha==1.1", "gamma==3.1"]])
        #expect(h.model.fixAll?.batches[0].outcomes[h.id("gamma")] == .partlyFixed(now: "3.1", remain: 1))
        let now = try #require(h.model.report?.findings.first { $0.title == "gamma" })              // still found, at 3.1
        #expect(now.installedVersion == "3.1" && h.model.fixes[now.id]?.outcome == .partlyFixed(now: "3.1", remain: 1))
        #expect(h.model.fixAll?.summary == "Fixed 1 · 1 partly fixed")
        #expect(h.site["gamma"] == "3.1")
    }

    /// The site, for the test above: gamma's answer within its constraint, at 3.0, plans `target`, which the core finds
    /// leaves one of its two flaws (GHSA-x, fixed in it) and not the other (GHSA-y, fixed in 3.4).
    struct PartialServer: FixServer {
        let target: String
        func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Result?, FixServerError> {
            .success(try! JSONDecoder().decode(BatchResponse.Result.self, from: Data(
                (#"{"ecosystem":"PyPI","name":"gamma","version":"3.0","distinct_flaws":2,"worst_severity":"HIGH","advisories":["GHSA-x","GHSA-y"],"#
                 + #""flaws":[{"id":"GHSA-x","severity":"HIGH","fixed_in":["\#(target)"],"ranges":[{"fixed":"\#(target)"}]},"#
                 + #"{"id":"GHSA-y","severity":"HIGH","fixed_in":["3.4"],"ranges":[{"fixed":"3.4"}]}],"#
                 + #""plan":{"target":"\#(target)","fixes":["GHSA-x"],"remaining":[{"id":"GHSA-y","reason":"blocked-by-constraint","constraint":"\#(constraints[0])"}]}}"#).utf8)))
        }
        func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: BatchResponse.Result], FixServerError> {
            .success([:])
        }
    }

    /// An upgrade together runs in Fix all only if pip's version of its package, in the batch's own dry run, fixes what
    /// its fix fixes, as the core judges it. starlette 0.48.0 has a flaw 1.3.1 leaves and that comes back from 1.3.2 to
    /// 1.4. pip picks 1.3.5: the batch is skipped, says why, and pip changes nothing. pip picks no starlette at all: the
    /// same. pip picks 1.4: it runs.
    @Test func anUpgradeTogetherRunsOnlyIfPipsVersionFixesWhatTheFixFixes() async throws {
        func run(pipPicks starlette: String?) async throws -> Home {
            let h = try setUp([], pip: [Package(name: "starlette", installed: "0.48.0", fixed: "1.3.1", group: .exploited, exploited: true)])
            try h.pipFile("meta/fastapi-0.120.0", "starlette<0.49.0,>=0.40.0\n")
            try h.pipFile("meta/fastapi-0.135.2", "starlette<2.0.0,>=0.46.0\n")
            let p = Process(); p.executableURL = h.python; p.arguments = ["--put", "fastapi", "0.120.0"]; try p.run(); p.waitUntilExit()
            if let starlette { try h.pipFile("resolve-starlette", starlette) }
            try h.pipFile("resolve-fastapi", "0.135.2")
            h.model.fixServer = TogetherServer()
            try await assessed(h)
            h.model.openFixAll()
            h.model.tickProposal(h.id("starlette"), true)
            h.model.runFixAll()
            try await waitUntil { done(h) }
            return h
        }
        let refused = try await run(pipPicks: "1.3.5")
        #expect(refused.pipChanges.isEmpty && refused.site["starlette"] == "0.48.0")
        let why = "pip's set would install starlette 1.3.5, which the core does not confirm fixes what 1.3.1 fixes"
        #expect(refused.model.fixAll?.batches.map(\.status) == [.skipped(why)])
        #expect(refused.model.fixes[refused.id("starlette")]?.outcome == .blocked(why))
        let none = try await run(pipPicks: nil)
        #expect(none.pipChanges.isEmpty && none.model.fixAll?.batches.map(\.status) == [.skipped("pip's set would not update starlette to 1.3.1 or later")])
        let ran = try await run(pipPicks: "1.4")
        #expect(ran.pipChanges.map { $0.filter { $0.contains("==") } } == [["starlette==1.4", "fastapi==0.135.2"]])
        #expect(ran.site["starlette"] == "1.4" && ran.site["fastapi"] == "0.135.2")
    }

    /// The site, for the test above: nothing to plan within constraints, and starlette's flaw at 0.48.0 and at what pip
    /// picks, with its two ranges.
    struct TogetherServer: FixServer {
        func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Result?, FixServerError> { .success(nil) }
        func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: BatchResponse.Result], FixServerError> {
            .success(Dictionary(uniqueKeysWithValues: versions.filter { $0.name == "starlette" && $0.version != "1.4" }.map { v in
                (v, try! JSONDecoder().decode(BatchResponse.Result.self, from: Data(
                    (#"{"ecosystem":"PyPI","name":"starlette","version":"\#(v.version)","distinct_flaws":1,"worst_severity":"HIGH","advisories":["GHSA-x"],"#
                     + #""flaws":[{"id":"GHSA-x","severity":"HIGH","fixed_in":["1.3.1","1.4"],"#
                     + #""ranges":[{"fixed":"1.3.1"},{"introduced":"1.3.2","fixed":"1.4"}]}]}"#).utf8)))
            }))
        }
    }

    // MARK: Refused rows

    /// A row refused because its command would break something installed shows no command at all: not to copy, not in
    /// its reason, not in what it offers instead. A dependent's specifier (with the upgrade together it offers, and, with
    /// no site to check it, nothing instead), a runtime boundary, a project of the person's. A command the app only does
    /// not run, and one that needs a password, are still there to copy.
    @Test func aRefusedRowShowsNoCommand() async throws {
        /// starlette under fastapi, torch under whisperx, werkzeug under blooper (a project installed for development).
        func scene(site withSite: Bool) async throws -> Home {
            let h = try setUp([], pip: [Package(name: "starlette", installed: "0.48.0", fixed: "1.3.1", group: .exploited, exploited: true),
                                        Package(name: "torch", installed: "2.7.0", fixed: "2.13.0", severity: .critical),
                                        Package(name: "werkzeug", installed: "3.0.1", fixed: "3.0.6")])
            try h.pipFile("meta/fastapi-0.120.0", "starlette<0.49.0,>=0.40.0\n")
            try h.pipFile("meta/whisperx-3.3.4", "torch>=2\n")
            try h.pipFile("meta/blooper-0.1.0", "werkzeug<3.0.2\n")
            for (name, version) in [("fastapi", "0.120.0"), ("whisperx", "3.3.4"), ("blooper", "0.1.0")] {
                let p = Process(); p.executableURL = h.python; p.arguments = ["--put", name, version]; try p.run(); p.waitUntilExit()
            }
            let site = h.python!.deletingLastPathComponent().appendingPathComponent("site")
            try Data(#"{"url": "file:///Users/ana/code/blooper", "dir_info": {"editable": true}}"#.utf8)
                .write(to: site.appendingPathComponent("blooper-0.1.0.dist-info/direct_url.json"))
            if !withSite { h.model.fixServer = nil }
            try await assessed(h)
            return h
        }
        var h = try await scene(site: true)
        /// Every text the row can show about its fix, besides the command block itself.
        func texts(_ f: Finding) -> [String] {
            let s = h.model.fixes[f.id]
            var out = [f.note].compactMap { $0 }
            if case let .withheld(why?)? = s?.availability { out.append(why) }
            if let p = s?.offeredProposal { out += [p.proposal?.line(p.plan), p.proposal?.asks].compactMap { $0 } }
            return out
        }
        func refusedWithNoCommand(_ name: String, _ line: String) {
            let f = h.finding(name), row = h.model.fixes[f.id] ?? FixRowState()
            #expect(row.hold == .blocked && row.offeredFix == nil, "\(name)")
            #expect(FindingRow.copyable(f, row) == nil, "\(name) offers its refused command to copy")
            #expect(!texts(f).contains { $0.contains("pip install") || $0.contains(f.upgradeCommand!) }, "\(name)")
            #expect(texts(f).first { $0.hasPrefix(line) } != nil, "\(name): \(texts(f))")
        }

        // with the site: starlette is offered together with fastapi instead
        refusedWithNoCommand("starlette", "fastapi 0.120.0 needs starlette < 0.49.0")
        #expect(h.model.fixes[h.id("starlette")]?.offeredProposal?.proposal?.line(h.model.fixes[h.id("starlette")]!.offeredProposal!.plan)
                == "Update starlette with fastapi (fixes the exploited flaw)")
        refusedWithNoCommand("torch", "torch 2.9 goes with torchaudio 2.9")
        refusedWithNoCommand("werkzeug", "blooper 0.1.0 needs werkzeug < 3.0.2 — it is a project installed for development")
        #expect(h.model.fixes[h.id("werkzeug")]?.offeredProposal == nil)                          // nothing safe instead

        // without the site, nothing is proposed: the reason alone
        h = try await scene(site: false)
        refusedWithNoCommand("starlette", "fastapi 0.120.0 needs starlette < 0.49.0")
        #expect(h.model.fixes[h.id("starlette")]?.offeredProposal == nil)

        // what the app only does not run, and what needs a password, keep their commands to copy
        let starlette = h.finding("starlette")
        #expect(FindingRow.copyable(starlette, FixRowState(availability: .withheld("Not run for you: it changes the project's dependencies."), hold: .yours))
                == starlette.upgradeCommand)
        let offer = FixOffer(plan: try FixPlan.make(for: starlette, tools: ToolEnvironment(base: [:], isExecutable: { _ in true })).get())
        #expect(FindingRow.copyable(starlette, FixRowState(availability: .terminal(offer, "Needs your administrator password."))) == starlette.upgradeCommand)

        // and the row draws a command only through that one decision
        let row = try String(contentsOf: StyleGuardTests.app.appendingPathComponent("Sources/OSVAMonitorUI/FindingRow.swift"), encoding: .utf8)
        #expect(row.components(separatedBy: "commandBlock(command)").count - 1 == 2 && row.contains("let command = Self.copyable(finding, fix)")
                && row.contains("canCopy: command != nil"))
    }

    // MARK: The header

    /// What "N need action" is made of: every finding that needs action in one bucket, the buckets adding up to N.
    @Test func theHeaderSaysWhatNeedActionIsMadeOf() {
        let rows = PreviewData.fixAllRows
        let findings = PreviewData.fixAllFindings
        let b = FixAll.breakdown(findings, fixes: rows)
        #expect(b?.total == findings.filter(\.group.needsAction).count)
        #expect(b?.withOK == 2 && b?.password == 1 && b?.fixable == FixAll.offered(findings, fixes: rows).filter { $0.0.group.needsAction }.count)
        #expect(b?.lower == 1)                                                                    // jinja2, lower, which Fix all fixes too
        #expect(b?.line?.hasPrefix("\(b!.fixable) fixable here (+1 lower) · 2 need your OK · 1 need a password · ") == true)
        #expect(b!.fixable + b!.lower == FixAll.offered(findings, fixes: rows).count)            // the button's count
        var checking = rows
        checking[PreviewData.FixID.nginx]?.availability = .checking
        #expect(FixAll.breakdown(findings, fixes: checking) == nil)                               // not while rows are decided
    }
}
