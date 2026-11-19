import Foundation
@testable import OSVAKit

/// Builds what the bundle and extension readers read: app bundles, frameworks, Mach-O libraries, extension folders.
enum Make {
    /// The recorded index with the bundle records (Fixtures/bundles/index-lines.tsv) after it.
    static let indexData: Data = Fixture.data("api/app-index.tsv") + Fixture.data("bundles/index-lines.tsv")
    static let index: PublicIndex = try! PublicIndex.decode(indexData)

    static func plist(_ values: [String: Any], to url: URL) {
        let data = try! PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
        try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! data.write(to: url)
    }

    static func json(_ value: Any, to url: URL) {
        let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! data.write(to: url)
    }

    static func bytes(_ data: Data, to url: URL) {
        try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! data.write(to: url)
    }

    /// An app bundle with an Info.plist.
    @discardableResult
    static func app(_ root: URL, _ name: String, id: String?, short: String?, build: String? = nil) -> URL {
        let bundle = root.appendingPathComponent(name + ".app")
        var info: [String: Any] = ["CFBundleName": name]
        if let id { info["CFBundleIdentifier"] = id }
        if let short { info["CFBundleShortVersionString"] = short }
        if let build { info["CFBundleVersion"] = build }
        plist(info, to: bundle.appendingPathComponent("Contents/Info.plist"))
        write("x", to: bundle.appendingPathComponent("Contents/MacOS/\(name)"))
        return bundle
    }

    /// A versioned framework (Versions/A, Current and the top-level links, as Xcode lays them out), with an
    /// Info.plist and, when `binary` is given, its executable.
    @discardableResult
    static func framework(_ app: URL, _ name: String, short: String?, build: String?, binary: Data? = nil, folder: String = "Contents/Frameworks") -> URL {
        let fw = app.appendingPathComponent(folder).appendingPathComponent(name + ".framework")
        let a = fw.appendingPathComponent("Versions/A")
        var info: [String: Any] = ["CFBundleExecutable": name]
        if let short { info["CFBundleShortVersionString"] = short }
        if let build { info["CFBundleVersion"] = build }
        plist(info, to: a.appendingPathComponent("Resources/Info.plist"))
        if let binary { bytes(binary, to: a.appendingPathComponent(name)) }
        let fm = FileManager.default
        try! fm.createSymbolicLink(atPath: fw.appendingPathComponent("Versions/Current").path, withDestinationPath: "A")
        try! fm.createSymbolicLink(atPath: fw.appendingPathComponent("Resources").path, withDestinationPath: "Versions/Current/Resources")
        if binary != nil { try! fm.createSymbolicLink(atPath: fw.appendingPathComponent(name).path, withDestinationPath: "Versions/Current/\(name)") }
        return fw
    }

    /// A 64-bit Mach-O dynamic library: LC_ID_DYLIB with these versions, and a __TEXT,__cstring section holding the
    /// strings (each NUL-terminated).
    static func dylib(current: String, compatibility: String, strings: [String] = [], cpu: UInt32 = 0x0100_000C) -> Data {
        func version(_ s: String) -> UInt32 {
            let p = s.split(separator: ".").map { UInt32($0)! } + [0, 0, 0]
            return p[0] << 16 | p[1] << 8 | p[2]
        }
        var d = Data()
        func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { d.append(contentsOf: $0) } }
        func u64(_ v: UInt64) { withUnsafeBytes(of: v.littleEndian) { d.append(contentsOf: $0) } }
        func name16(_ s: String) { var b = Array(s.utf8); b += Array(repeating: 0, count: 16 - b.count); d.append(contentsOf: b) }
        let installName = Array("@rpath/libx.dylib".utf8) + [0]
        let idSize = (24 + installName.count + 7) / 8 * 8
        let segSize = 72 + 80
        let sizeofcmds = idSize + segSize
        let text = Data(strings.flatMap { Array($0.utf8) + [0] })
        let textOffset = 32 + sizeofcmds
        // mach_header_64
        u32(0xFEED_FACF); u32(cpu); u32(0); u32(6); u32(2); u32(UInt32(sizeofcmds)); u32(0); u32(0)
        // LC_ID_DYLIB
        u32(0xD); u32(UInt32(idSize)); u32(24); u32(0); u32(version(current)); u32(version(compatibility))
        d.append(contentsOf: installName); d.append(contentsOf: [UInt8](repeating: 0, count: idSize - 24 - installName.count))
        // LC_SEGMENT_64 __TEXT with one section, __cstring
        u32(0x19); u32(UInt32(segSize)); name16("__TEXT"); u64(0); u64(UInt64(textOffset + text.count)); u64(0); u64(UInt64(textOffset + text.count))
        u32(5); u32(5); u32(1); u32(0)
        name16("__cstring"); name16("__TEXT"); u64(UInt64(textOffset)); u64(UInt64(text.count)); u32(UInt32(textOffset)); u32(0); u32(0); u32(0); u32(2); u32(0); u32(0); u32(0)
        d.append(text)
        return d
    }

    /// A universal binary of these slices, each at a 4 KB boundary.
    static func fat(_ slices: [(cpu: UInt32, data: Data)]) -> Data {
        var d = Data()
        func be(_ v: UInt32) { withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) } }
        be(0xCAFE_BABE); be(UInt32(slices.count))
        var offset = 4096
        var offsets: [Int] = []
        for s in slices {
            offsets.append(offset)
            be(s.cpu); be(0); be(UInt32(offset)); be(UInt32(s.data.count)); be(12)
            offset += (s.data.count + 4095) / 4096 * 4096
        }
        for (s, o) in zip(slices, offsets) {
            d.append(Data(count: o - d.count))
            d.append(s.data)
        }
        return d
    }

    /// A VS Code-family extension folder with its package.json.
    @discardableResult
    static func editorExtension(_ folder: URL, publisher: String, name: String, version: String, displayName: String? = nil,
                                dependencies: [(String, String)] = []) -> URL {
        let dir = folder.appendingPathComponent("\(publisher).\(name)-\(version)")
        var manifest: [String: Any] = ["publisher": publisher, "name": name, "version": version]
        if let displayName { manifest["displayName"] = displayName }
        json(manifest, to: dir.appendingPathComponent("package.json"))
        for (dep, v) in dependencies { json(["name": dep, "version": v], to: dir.appendingPathComponent("node_modules/\(dep)/package.json")) }
        return dir
    }

    /// A Chromium profile's extension: <profile>/Extensions/<id>/<folder>/manifest.json.
    @discardableResult
    static func chromiumExtension(_ userData: URL, profile: String, id: String, folder: String, manifest: [String: Any]) -> URL {
        let dir = userData.appendingPathComponent(profile).appendingPathComponent("Extensions").appendingPathComponent(id).appendingPathComponent(folder)
        json(manifest, to: dir.appendingPathComponent("manifest.json"))
        return dir
    }

    static func product(_ key: String) -> ProductResponse {
        try! JSONDecoder().decode(ProductResponse.self, from: Fixture.data("bundles/product-\(key).json"))
    }

    static var cpython: ProjectResponse { try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-cpython.json")) }
}

extension RecordedTransport {
    /// The site, with the bundle records in its index and the product records in Fixtures/bundles.
    static func bundleSite(batch: String = "api/check-batch-malicious.json") -> RecordedTransport {
        RecordedTransport { request, _ in
            let path = request.url!.path
            switch path {
            case "/data/app-index.tsv": return Reply(status: 200, body: Make.indexData)
            case "/api/v1/check/batch": return Reply(status: 200, body: Fixture.data(batch))
            case "/api/v1/state": return Reply(status: 200, body: Fixture.data("api/state.json"))
            default:
                for (prefix, folder) in [("/api/v1/project/", "api/project-"), ("/api/v1/product/", "bundles/product-")] where path.hasPrefix(prefix) {
                    if let data = try? Data(contentsOf: Fixture.url(folder + path.dropFirst(prefix.count) + ".json")) { return Reply(status: 200, body: data) }
                }
                return Reply(status: 404, body: Data(#"{"error":"not found"}"#.utf8))
            }
        }
    }
}
