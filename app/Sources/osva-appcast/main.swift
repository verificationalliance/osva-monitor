// osva-appcast: the parts of scripts/release.sh that are better done in Swift than in shell, each tested in
// Tests/OSVAReleaseTests. It never signs: Sparkle's sign_update does that. It never prints a private key.
//
//   osva-appcast add --appcast FILE --version 0.1.1 --build 1001 --url URL --length BYTES --signature BASE64
//                    --minimum-system 26.0 [--notes FILE.md|FILE.txt] [--date 2026-11-19T12:00:00Z]
//       Adds the release to FILE (made if missing), or puts it in place of the same version; writes FILE unsigned.
//   osva-appcast public-key --key-file FILE
//       Prints the public key (as in SUPublicEDKey) of the private key in FILE.
//   osva-appcast verify-archive --public-key BASE64 --signature BASE64 FILE
//   osva-appcast verify-feed --public-key BASE64 FILE
//       Exit 0 when the signature is the key's, 1 when it is not.
import Foundation
import OSVARelease

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("osva-appcast: \(message)\n".utf8))
    exit(code)
}

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { fail("usage: osva-appcast add|public-key|verify-archive|verify-feed …", code: 2) }
args.removeFirst()

var options: [String: String] = [:], positional: [String] = []
while !args.isEmpty {
    let a = args.removeFirst()
    if a.hasPrefix("--") {
        guard !args.isEmpty else { fail("\(a) needs a value", code: 2) }
        options[String(a.dropFirst(2))] = args.removeFirst()
    } else {
        positional.append(a)
    }
}
@MainActor func option(_ name: String) -> String {
    guard let v = options[name], !v.isEmpty else { fail("--\(name) is required", code: 2) }
    return v
}
@MainActor func read(_ path: String) -> Data {
    guard let d = FileManager.default.contents(atPath: path) else { fail("cannot read \(path)") }
    return d
}

do {
    switch command {
    case "add":
        let path = option("appcast")
        let existing = FileManager.default.fileExists(atPath: path) ? try Appcast.parse(read(path)) : Appcast()
        guard let length = Int(option("length")), length > 0 else { fail("--length must be a positive number of bytes", code: 2) }
        let date: Date
        if let d = options["date"] {
            guard let parsed = ISO8601DateFormatter().date(from: d) else { fail("--date must be ISO 8601, like 2026-11-19T12:00:00Z", code: 2) }
            date = parsed
        } else {
            date = Date()
        }
        let version = option("version")
        var notes: Appcast.Notes?
        if let file = options["notes"] {
            let text = String(decoding: read(file), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            notes = Appcast.Notes(text, format: file.hasSuffix(".md") || file.hasSuffix(".markdown") ? .markdown : .plainText)
        }
        let item = Appcast.Item(version: option("build"), shortVersion: version, published: date, url: option("url"), length: length,
                                edSignature: option("signature"), minimumSystemVersion: Appcast.threePartVersion(option("minimum-system")),
                                notes: notes ?? Appcast.defaultNotes(version: version))
        try UpdateKey.checkSignatureShape(item.edSignature)
        let updated = try existing.adding(item)
        try Data(updated.xml().utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
        print("\(path): \(updated.items.count) release\(updated.items.count == 1 ? "" : "s"), newest \(updated.items[0].shortVersion)")
    case "public-key":
        print(try UpdateKey.publicKey(ofKeyFile: read(option("key-file"))))
    case "verify-archive":
        guard positional.count == 1 else { fail("verify-archive takes one file", code: 2) }
        let ok = try UpdateKey.verify(read(positional[0]), signature: option("signature"), publicKey: option("public-key"))
        if !ok { fail("\(positional[0]): the signature is not the update key's") }
    case "verify-feed":
        guard positional.count == 1 else { fail("verify-feed takes one file", code: 2) }
        if try !FeedSignature.verify(read(positional[0]), publicKey: option("public-key")) {
            fail("\(positional[0]): the feed is not signed by the update key (or was changed after signing)")
        }
    default:
        fail("unknown command \(command)", code: 2)
    }
} catch {
    fail("\(error)")
}
