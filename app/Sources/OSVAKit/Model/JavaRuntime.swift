import Foundation

/// Who built a Java runtime, as its `release` file, its bundle's Info.plist and its folder's name tell. Decides the
/// name it is shown by, and what it is checked against (`JavaCheck.route`): a record of its own when the public index
/// has one (a `C jre <vendor> <product>` line, `rawValue` being the vendor), else OpenJDK's advisories for the builds of
/// OpenJDK, else nothing.
public enum JavaVendor: String, Codable, Sendable, CaseIterable {
    case temurin, zulu, corretto, microsoft, homebrew, redhat, liberica, sapmachine, jetbrains
    /// Oracle's JDK (Java SE), not the OpenJDK builds Oracle publishes on jdk.java.net (`openjdk`).
    case oracle
    /// A build of OpenJDK whose builder is not told (jdk.java.net's, or one with no IMPLEMENTOR).
    case openjdk
    case graalvm
    /// IBM Semeru: OpenJDK's class library on the OpenJ9 virtual machine.
    case semeru

    public var title: String {
        switch self {
        case .temurin: return "Temurin"
        case .zulu: return "Zulu"
        case .corretto: return "Corretto"
        case .microsoft: return "Microsoft"
        case .homebrew: return "Homebrew"
        case .redhat: return "Red Hat"
        case .liberica: return "Liberica"
        case .sapmachine: return "SapMachine"
        case .jetbrains: return "JetBrains Runtime"
        case .oracle: return "Oracle"
        case .openjdk: return "OpenJDK"
        case .graalvm: return "GraalVM"
        case .semeru: return "Semeru"
        }
    }

    /// A build of OpenJDK, HotSpot and all, so OpenJDK's advisories are about its code. Oracle's JDK is built from
    /// the same sources and is checked against them too, when the index has no record of Oracle Java SE of its own.
    public var sharesOpenJDK: Bool { self != .graalvm && self != .semeru }

    /// How the vendor numbers its own builds, when it patches without moving JAVA_VERSION (Corretto 27.0.1.1.4 still says
    /// 27.0.1): the distributor's name in an advisory's `fixed_builds`, and IMPLEMENTOR_VERSION's prefix before the build.
    public var buildScheme: (dist: String, prefix: String)? {
        self == .corretto ? ("Amazon Corretto", "Corretto-") : nil
    }

    /// Why it is not checked against OpenJDK's advisories.
    public var notOpenJDK: String? {
        switch self {
        case .graalvm: return "GraalVM's advisories are published apart from OpenJDK's, and its versions are not compared with OpenJDK's"
        case .semeru: return "Semeru runs the OpenJ9 virtual machine, not OpenJDK's HotSpot"
        default: return nil
        }
    }

    /// Where the vendor offers its builds, to be read, not opened: no command downloads an installer. Domains without a
    /// path where the vendor has one, so a wrapped note never breaks one at its "/".
    public var download: String? {
        switch self {
        case .temurin: return "adoptium.net"
        case .zulu: return "azul.com"
        case .corretto: return "corretto.aws"
        case .microsoft: return "microsoft.com/openjdk"
        case .redhat: return "developers.redhat.com"
        case .liberica: return "bell-sw.com"
        case .sapmachine: return "sapmachine.io"
        case .oracle: return "oracle.com"
        case .openjdk: return "jdk.java.net"
        case .graalvm: return "graalvm.org"
        case .semeru: return "developer.ibm.com/languages/java/semeru-runtimes"
        case .homebrew, .jetbrains: return nil
        }
    }

    /// The vendor, from what a runtime says about itself, most specific first: GraalVM by its own keys (it says
    /// IMPLEMENTOR="Oracle Corporation" and carries Oracle's bundle identifier), then the release file's IMPLEMENTOR,
    /// the Info.plist's JVMVendor (Java 8's release files often have no IMPLEMENTOR), the bundle identifier, the folder's
    /// name (SDKMAN's "17.0.9-tem", IntelliJ's "corretto-21.0.5"). Anything else is a build of OpenJDK by someone unnamed.
    static func identify(release: [String: String], plist: [String: Any], folder: String) -> JavaVendor {
        let implementor = (release["IMPLEMENTOR"] ?? "").lowercased()
        let javaVM = plist["JavaVM"] as? [String: Any] ?? [:]
        let jvmVendor = ((javaVM["JVMVendor"] as? String) ?? "").lowercased()
        let bundleID = ((plist["CFBundleIdentifier"] as? String) ?? "").lowercased()
        let bundleName = ((plist["CFBundleName"] as? String) ?? "").lowercased()
        let name = folder.lowercased()
        let runtime = (release["JAVA_RUNTIME_VERSION"] ?? "").lowercased()

        if release["GRAALVM_VERSION"] != nil || runtime.contains("jvmci") || implementor.contains("graalvm") || bundleName.contains("graalvm")
            || name.contains("graalvm") || hasSuffix(name, ["-graal", "-graalce", "-nik", "-mandrel"]) { return .graalvm }
        if (release["JVM_VARIANT"] ?? "").lowercased().contains("openj9") { return .semeru }
        for said in [implementor, jvmVendor] where !said.isEmpty {
            if let v = byName(said) {
                return v == .oracle ? oracleOrOpenJDK(bundleID: bundleID, folder: name, runtime: runtime, release: release) : v
            }
        }
        let ids: [(String, JavaVendor)] = [("com.azulsystems.", .zulu), ("com.azul.", .zulu), ("com.amazon.corretto", .corretto),
                                           ("com.microsoft.", .microsoft), ("com.oracle.java", .oracle), ("net.temurin", .temurin),
                                           ("net.adoptopenjdk", .temurin), ("com.sap.", .sapmachine), ("com.bellsoft", .liberica),
                                           ("com.jetbrains", .jetbrains)]
        if let (_, v) = ids.first(where: { bundleID.hasPrefix($0.0) }) { return v }
        if release["BUILD_TYPE"]?.lowercased() == "commercial" { return .oracle }          // Oracle's JDK 8 says only this
        let folders: [(String, JavaVendor)] = [("temurin", .temurin), ("adoptopenjdk", .temurin), ("zulu", .zulu), ("corretto", .corretto),
                                               ("microsoft", .microsoft), ("liberica", .liberica), ("sapmachine", .sapmachine),
                                               ("jbr", .jetbrains), ("semeru", .semeru), ("openj9", .semeru), ("oracle", .oracle)]
        if let (_, v) = folders.first(where: { name.contains($0.0) }) { return v }
        let sdkman: [(String, JavaVendor)] = [("-tem", .temurin), ("-zulu", .zulu), ("-amzn", .corretto), ("-ms", .microsoft),
                                              ("-librca", .liberica), ("-sapmchn", .sapmachine), ("-sem", .semeru), ("-oracle", .oracle)]
        if let (_, v) = sdkman.first(where: { name.hasSuffix($0.0) }) { return v }
        return .openjdk
    }

    private static func hasSuffix(_ name: String, _ suffixes: [String]) -> Bool { suffixes.contains { name.hasSuffix($0) } }

    /// The vendor an IMPLEMENTOR or a JVMVendor names.
    private static func byName(_ s: String) -> JavaVendor? {
        let names: [(String, JavaVendor)] = [("adoptium", .temurin), ("adoptopenjdk", .temurin), ("eclipse foundation", .temurin),
                                             ("azul", .zulu), ("amazon", .corretto), ("microsoft", .microsoft), ("homebrew", .homebrew),
                                             ("red hat", .redhat), ("bellsoft", .liberica), ("sap se", .sapmachine), ("jetbrains", .jetbrains),
                                             ("international business machines", .semeru), ("ibm", .semeru), ("oracle", .oracle)]
        if s == "sap" { return .sapmachine }
        return names.first { s.contains($0.0) }?.1
    }

    /// Oracle signs both its JDK and the OpenJDK builds on jdk.java.net as "Oracle Corporation". Its JDK's bundle is
    /// com.oracle.java.*; jdk.java.net's is net.java.openjdk.jdk. Without a bundle: SDKMAN's "-open" and a folder named
    /// openjdk are jdk.java.net's, an LTS build or a commercial one Oracle's.
    private static func oracleOrOpenJDK(bundleID: String, folder: String, runtime: String, release: [String: String]) -> JavaVendor {
        if bundleID.hasPrefix("com.oracle.java") { return .oracle }
        if bundleID.hasPrefix("net.java.openjdk") || folder.hasSuffix("-open") || folder.contains("openjdk") { return .openjdk }
        if folder.contains("oracle") || runtime.contains("-lts") || release["BUILD_TYPE"]?.lowercased() == "commercial" { return .oracle }
        return .openjdk
    }
}

/// A Java runtime installed on this Mac (a JDK, or a JRE), from its `release` file. Stays on this Mac: neither its
/// path, its folder's name nor its vendor is ever sent; only the project or product it is checked as, when the index
/// lists that, may be.
public struct JavaRuntime: Hashable, Codable, Sendable {
    /// Where it was found, which says who put it there and how it is updated.
    public enum Place: String, Codable, Sendable {
        /// /Library/Java/JavaVirtualMachines: an installer's (or a cask's), for every user.
        case system
        /// ~/Library/Java/JavaVirtualMachines: IntelliJ IDEA's downloads on a Mac, or the person's own.
        case user
        /// ~/.jdks: IntelliJ IDEA's downloads.
        case intellij
        case sdkman, asdf, mise
        /// A Homebrew formula's keg (openjdk, openjdk@17).
        case homebrew
    }

    /// The bundle (".jdk") or folder, as found: what the row shows and Finder reveals.
    public var path: String
    /// Its Home, where the `release` file is.
    public var home: String
    /// The Home with every link resolved: two finds of one runtime (a link in /Library/Java/JavaVirtualMachines to a
    /// Homebrew keg, SDKMAN's "current") are one runtime.
    public var realPath: String
    public var place: Place
    public var vendor: JavaVendor
    /// The version as the runtime writes it: JAVA_VERSION ("17.0.20", "1.8.0_511"), else its Info.plist's JVMVersion.
    public var version: String
    /// The version the advisories use (`JavaVersion.canonical`): "17.0.20", "8.0.511".
    public var canonical: String
    /// What its builder calls it: JAVA_RUNTIME_VERSION or IMPLEMENTOR_VERSION ("17.0.20+8", "Zulu21.36+17-CA").
    public var build: String?
    /// IMPLEMENTOR (or the Info.plist's JVMVendor), as written.
    public var implementor: String?
    /// IMPLEMENTOR_VERSION, as written ("Corretto-27.0.1.1.4", "Temurin-17.0.20+8").
    public var implementorVersion: String? = nil
    /// "JDK" or "JRE" (the release file's IMAGE_TYPE; a JDK unless it says otherwise).
    public var image: String
    /// The Homebrew formula whose keg it is.
    public var formula: String?
    /// The Homebrew cask that installed it, when the cask's own record says it put this folder there.
    public var cask: String?

    public init(path: String, home: String, realPath: String, place: Place, vendor: JavaVendor, version: String, canonical: String,
                build: String? = nil, implementor: String? = nil, image: String = "JDK", formula: String? = nil, cask: String? = nil) {
        self.path = path; self.home = home; self.realPath = realPath; self.place = place; self.vendor = vendor; self.version = version
        self.canonical = canonical; self.build = build; self.implementor = implementor; self.image = image; self.formula = formula
        self.cask = cask
    }

    /// The vendor's own build, when it numbers builds its own way (`JavaVendor.buildScheme`): "27.0.1.1.4".
    public var vendorBuild: String? {
        guard let scheme = vendor.buildScheme, let v = implementorVersion, v.hasPrefix(scheme.prefix) else { return nil }
        return JavaRelease.plausible(String(v.dropFirst(scheme.prefix.count)))
    }

    /// The version as Java names it: "17.0.20", "8u511".
    public var shownVersion: String { JavaVersion.shown(canonical) }
    /// The feature release: "17", "8".
    public var major: String { String(canonical.prefix { $0.isNumber }) }
    /// The row's title: "Java (Temurin)".
    public var title: String { "Java (\(vendor.title))" }
    /// The folder it is in: "/Library/Java/JavaVirtualMachines".
    public var folder: String { (path as NSString).deletingLastPathComponent }

    /// For a list, one short line: "GraalVM 21.0.12 (graalvm-21.jdk)", its own folder's name telling it from another.
    public var listItem: String { "\(vendor.title) \(shownVersion) (\((path as NSString).lastPathComponent))" }

    /// Where, for the line under a finding: "JDK in /Library/Java/JavaVirtualMachines · Homebrew cask".
    var location: String {
        if let formula, place == .homebrew { return "Homebrew \(formula)" }
        let managers: [Place: String] = [.sdkman: "SDKMAN", .asdf: "asdf", .mise: "mise"]
        let tool = cask != nil ? "Homebrew cask" : managers[place]
        return "\(image) in \(Paths.abbreviatingHome(folder))" + (tool.map { " · \($0)" } ?? "")
    }
}

/// Java's versions, in the one form the site's ranges for OpenJDK use (its server normalises the issuer's versions the
/// same way, fi/ranges.java_version). The verified core's order is not changed; the data is:
///   - Java 8 and earlier, "update N": `F.0.N`. "1.8.0_511", "1.8.0_511-b33", "8u511", "8u511b33-perf" are 8.0.511;
///     "1.8.0" and "1.8" are 8.0.0; Homebrew's openjdk@8 "1.8.0-472" is 8.0.472. (Adoptium's "semantic" version, and
///     what SDKMAN, Zulu and Corretto write for 8.)
///   - Java 9 and later (JEP 223, 322): as JAVA_VERSION writes it, "17", "17.0.20", "17.0.21.0.3", without a `+build`.
/// Under the core's order 8 < 8.0.0 < 8.0.511 and 17.0.21 < 17.0.21.0.3 < 17.0.22, which the ranges rely on. Anything
/// else ("17-ea", "27-ea", a year-numbered version) has no canonical form: it is never guessed.
public enum JavaVersion {
    private static let legacy = Regex("^1\\.([1-8])(?:\\.0)?(?:[_-]([0-9]{1,4}))?(?:-b[0-9]{1,4})?$")
    private static let update = Regex("^([1-8])u([0-9]{1,4})(?:-?b[0-9]{1,4})?(?:-perf)?$")
    private static let modern = Regex("^([0-9]{1,2}(?:\\.[0-9]{1,9}){0,5})(?:\\+[0-9A-Za-z.+-]{0,40})?$")
    private static let updateForm = Regex("^([1-8])\\.0\\.([0-9]{1,4})$")

    /// The canonical form, or nil when the text is no Java version this knows.
    public static func canonical(_ raw: String) -> String? {
        let v = raw.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty, v.utf8.count <= 64 else { return nil }
        if let m = legacy.firstMatch(v), let feature = m[1] { return "\(feature).0.\(Int(m[2] ?? "0") ?? 0)" }
        if let m = update.firstMatch(v), let feature = m[1], let n = m[2].flatMap({ Int($0) }) { return "\(feature).0.\(n)" }
        if let m = modern.firstMatch(v), let core = m[1], let major = Int(core.prefix { $0.isNumber }), major >= 2 { return core }
        return nil
    }

    /// How Java names a version, for the row: "8u511" for 8.0.511 ("8" for 8.0.0), the canonical form from 9 on. Text
    /// that is no Java version is shown as written.
    public static func shown(_ version: String) -> String {
        guard let c = canonical(version) else { return version }
        if let m = updateForm.firstMatch(c), let feature = m[1], let n = m[2].flatMap({ Int($0) }) { return n == 0 ? feature : "\(feature)u\(n)" }
        return c
    }

    /// A Homebrew formula of OpenJDK ("openjdk", "openjdk@8"), whose versions are Java's.
    public static func isHomebrewFormula(_ name: String) -> Bool { name == "openjdk" || name.hasPrefix("openjdk@") }
}
