import CryptoKit
import Foundation

/// The update key's two uses, checked here with CryptoKit, apart from Sparkle's own `sign_update`: the release script
/// signs with Sparkle's tool, then checks the result against the public key inside the app it is releasing.
///
/// The private key is a file holding the base64 of a 32-byte Ed25519 seed (CryptoKit's
/// `Curve25519.Signing.PrivateKey().rawRepresentation`), the form `sign_update --ed-key-file` reads.
public enum UpdateKey {
    public enum Problem: Error, Equatable, CustomStringConvertible {
        case notBase64Seed
        case badPublicKey
        case badSignature

        public var description: String {
            switch self {
            case .notBase64Seed: return "the key file does not hold the base64 of a 32-byte Ed25519 seed"
            case .badPublicKey: return "not the base64 of a 32-byte Ed25519 public key"
            case .badSignature: return "not the base64 of a 64-byte Ed25519 signature"
            }
        }
    }

    /// The public key (base64, as in SUPublicEDKey) of the seed in a key file's contents. The seed is only held in
    /// memory, and no error repeats it.
    public static func publicKey(ofKeyFile contents: Data) throws -> String {
        let text = String(decoding: contents, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard var seed = Data(base64Encoded: text), seed.count == 32 else { throw Problem.notBase64Seed }
        defer { seed.resetBytes(in: 0..<seed.count) }
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { throw Problem.notBase64Seed }
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    public static func publicKey(base64: String) throws -> Curve25519.Signing.PublicKey {
        guard let raw = Data(base64Encoded: base64.trimmingCharacters(in: .whitespacesAndNewlines)), raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { throw Problem.badPublicKey }
        return key
    }

    /// Whether `signature` (base64) is the key's signature of `data`: an archive, as in `sparkle:edSignature`.
    public static func verify(_ data: Data, signature: String, publicKey: String) throws -> Bool {
        let key = try Self.publicKey(base64: publicKey)
        return key.isValidSignature(try signatureBytes(signature), for: data)
    }

    /// Throws unless `signature` is the base64 of 64 bytes, the size of every Ed25519 signature.
    public static func checkSignatureShape(_ signature: String) throws { _ = try signatureBytes(signature) }

    private static func signatureBytes(_ base64: String) throws -> Data {
        guard let sig = Data(base64Encoded: base64.trimmingCharacters(in: .whitespacesAndNewlines)), sig.count == 64 else {
            throw Problem.badSignature
        }
        return sig
    }
}

/// A signed feed: the appcast's bytes, then the block `sign_update` appends after `</rss>`:
///
///     <!-- sparkle-signatures:
///     edSignature: <base64 Ed25519 signature of every byte before the block>
///     length: <how many bytes that is>
///     -->
///
/// Read the way Sparkle reads it (`SPUExtractAppcastContent` in Sparkle 2.10.1): the last such block, its lines.
public enum FeedSignature {
    static let prefix = Data("<!-- sparkle-signatures:\n".utf8)
    static let suffix = Data("-->".utf8)

    /// The signed part of a feed: everything before its signature block (the whole feed when it has none).
    public static func content(of feed: Data) -> Data {
        block(of: feed)?.content ?? feed
    }

    /// The signature and signed length the block names, if the feed has one.
    public static func signature(of feed: Data) -> (edSignature: String, length: Int)? {
        guard let b = block(of: feed), let signature = b.signature else { return nil }
        return (signature, b.length)
    }

    /// Whether the feed is signed, the length matches, and the signature is the key's.
    public static func verify(_ feed: Data, publicKey: String) throws -> Bool {
        guard let b = block(of: feed), let signature = b.signature, b.length == b.content.count else { return false }
        return try UpdateKey.verify(b.content, signature: signature, publicKey: publicKey)
    }

    private static func block(of feed: Data) -> (content: Data, signature: String?, length: Int)? {
        guard let start = feed.range(of: prefix, options: .backwards),
              let end = feed.range(of: suffix, in: start.upperBound..<feed.endIndex) else { return nil }
        let text = String(decoding: feed[start.upperBound..<end.lowerBound], as: UTF8.self)
        var signature: String?, length = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("edSignature:") {
                signature = line.dropFirst("edSignature:".count).trimmingCharacters(in: .whitespacesAndNewlines)
            } else if line.hasPrefix("length:") {
                length = Int(line.dropFirst("length:".count).trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
        }
        return (Data(feed[feed.startIndex..<start.lowerBound]), signature, length)
    }
}
