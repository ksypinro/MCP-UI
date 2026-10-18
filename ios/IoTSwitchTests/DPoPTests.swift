import CryptoKit
import XCTest
@testable import IoTSwitch

/// DPoP proofs (RFC 9449) as the app builds them.
final class DPoPTests: XCTestCase {

    func testTheThumbprintMatchesTheRFCExample() {
        // RFC 9449 section 4.1's example key, and the cnf.jkt section 6.1 binds to it.
        XCTAssertEqual(
            DPoPKey.thumbprint(x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                               y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        )
    }

    private func parts(_ jws: String) throws -> (header: [String: Any], payload: [String: Any], input: Data, signature: Data) {
        let segments = jws.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(segments.count, 3)
        let decode = { (segment: String) throws -> [String: Any] in
            try JSONSerialization.jsonObject(with: Data(base64URLEncoded: segment)!) as! [String: Any]
        }
        return (try decode(segments[0]), try decode(segments[1]),
                Data("\(segments[0]).\(segments[1])".utf8), Data(base64URLEncoded: segments[2])!)
    }

    func testAProofNamesTheRequestAndVerifiesWithItsOwnKey() throws {
        let key = try DPoPKey.generate()
        let url = URL(string: "http://localhost:4000/v1/devices?page=2#x")!
        let proof = try key.proof(method: "get", url: url, accessToken: "iotsw_at_token", nonce: "n-1")
        let (header, payload, input, signature) = try parts(proof)

        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header["alg"] as? String, "ES256")
        let jwk = try XCTUnwrap(header["jwk"] as? [String: String])
        XCTAssertNil(jwk["d"], "never the private key")
        XCTAssertEqual(DPoPKey.thumbprint(x: jwk["x"]!, y: jwk["y"]!), key.thumbprint)

        XCTAssertEqual(payload["htm"] as? String, "GET")
        XCTAssertEqual(payload["htu"] as? String, "http://localhost:4000/v1/devices", "no query, no fragment")
        XCTAssertEqual(payload["nonce"] as? String, "n-1")
        XCTAssertEqual(payload["ath"] as? String, Data(SHA256.hash(data: Data("iotsw_at_token".utf8))).base64URLEncoded)
        XCTAssertNotNil(payload["jti"])

        let publicKey = try P256.Signing.PublicKey(
            rawRepresentation: Data(base64URLEncoded: jwk["x"]!)! + Data(base64URLEncoded: jwk["y"]!)!)
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: input))
    }

    func testEveryProofIsUnique() throws {
        let key = try DPoPKey.generate()
        let url = URL(string: "http://localhost:4000/token")!
        let first = try parts(key.proof(method: "POST", url: url, accessToken: nil, nonce: nil)).payload["jti"] as? String
        let second = try parts(key.proof(method: "POST", url: url, accessToken: nil, nonce: nil)).payload["jti"] as? String
        XCTAssertNotEqual(first, second)
    }

    func testTheKeyringKeepsOneKeyUntilReset() throws {
        let store = InMemoryDPoPKeyStore()
        let keyring = DPoPKeyring(store: store)
        let first = try keyring.key().thumbprint
        XCTAssertEqual(try DPoPKeyring(store: store).key().thumbprint, first, "restored after a relaunch")
        keyring.reset()
        XCTAssertNotEqual(try keyring.key().thumbprint, first)
    }
}
