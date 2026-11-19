import CryptoKit
import Foundation
import Testing
@testable import OSVARelease

@Suite struct SignatureTests {
    /// The fixtures were signed by Sparkle 2.10.1's sign_update with a throwaway key made for them and then deleted;
    /// this is its public half.
    static let fixtureKey = "fIel3RnIs8ffBDaORRrsutuOlUuV6lIcsDBAlunegMk="
    static let fixtureArchiveSignature = "jvyyZtwH/QZupCSk04n5EJJOz/rg/ZVZSYBKRBOODAAN0pcPyEi7Kt7/RQbILOkZT/8d0BvHgbPxLqEK0oNbDA=="

    /// The key file's form, the base64 of CryptoKit's 32-byte seed, gives the same public key as CryptoKit.
    @Test func keyFileGivesItsPublicKey() throws {
        let key = Curve25519.Signing.PrivateKey()
        let file = Data((key.rawRepresentation.base64EncodedString() + "\n").utf8)
        #expect(try UpdateKey.publicKey(ofKeyFile: file) == key.publicKey.rawRepresentation.base64EncodedString())
    }

    @Test func aKeyFileOfAnotherShapeIsRefusedWithoutRepeatingIt() {
        for contents in ["", "not base64!", Data(count: 64).base64EncodedString(), Data(count: 31).base64EncodedString()] {
            #expect(throws: UpdateKey.Problem.notBase64Seed) { try UpdateKey.publicKey(ofKeyFile: Data(contents.utf8)) }
        }
        #expect(!UpdateKey.Problem.notBase64Seed.description.contains("="))
    }

    @Test func signUpdatesArchiveSignatureVerifies() throws {
        let archive = Fixture.data("archive.txt")
        #expect(try UpdateKey.verify(archive, signature: Self.fixtureArchiveSignature, publicKey: Self.fixtureKey))
        var changed = archive; changed[0] ^= 1
        #expect(try !UpdateKey.verify(changed, signature: Self.fixtureArchiveSignature, publicKey: Self.fixtureKey))
        let other = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        #expect(try !UpdateKey.verify(archive, signature: Self.fixtureArchiveSignature, publicKey: other))
        #expect(throws: UpdateKey.Problem.badSignature) { try UpdateKey.verify(archive, signature: "AAAA", publicKey: Self.fixtureKey) }
        #expect(throws: UpdateKey.Problem.badPublicKey) { try UpdateKey.verify(archive, signature: Self.fixtureArchiveSignature, publicKey: "AAAA") }
    }

    /// The feed sign_update signed verifies here, the way Sparkle reads it; one changed byte, a wrong key, a wrong
    /// length or no block at all do not.
    @Test func signUpdatesFeedSignatureVerifies() throws {
        let feed = Fixture.data("signed-by-sign_update.xml")
        #expect(try FeedSignature.verify(feed, publicKey: Self.fixtureKey))
        let content = FeedSignature.content(of: feed)
        #expect(String(decoding: content, as: UTF8.self).hasSuffix("</rss>\n"))
        #expect(FeedSignature.signature(of: feed)?.length == content.count)

        var changed = feed; changed[100] ^= 1
        #expect(try !FeedSignature.verify(changed, publicKey: Self.fixtureKey))
        let other = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        #expect(try !FeedSignature.verify(feed, publicKey: other))
        #expect(try !FeedSignature.verify(content, publicKey: Self.fixtureKey))
        let longer = Data(String(decoding: feed, as: UTF8.self).replacingOccurrences(of: "length: \(content.count)", with: "length: \(content.count + 1)").utf8)
        #expect(try !FeedSignature.verify(longer, publicKey: Self.fixtureKey))
    }

    /// A block written the way sign_update writes it, over a feed written here.
    @Test func ourFeedSignedLikeSignUpdate() throws {
        let key = Curve25519.Signing.PrivateKey()
        let content = Data(Appcast(items: [AppcastTests.item("0.1.1", build: "1001")]).xml().utf8)
        let signature = try key.signature(for: content).base64EncodedString()
        let feed = content + Data("<!-- sparkle-signatures:\nedSignature: \(signature)\nlength: \(content.count)\n-->\n".utf8)
        #expect(try FeedSignature.verify(feed, publicKey: key.publicKey.rawRepresentation.base64EncodedString()))
        #expect(try Appcast.parse(feed).items.count == 1)
    }
}
