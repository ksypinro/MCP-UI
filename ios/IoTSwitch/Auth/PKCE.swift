import CryptoKit
import Foundation

/// A PKCE pair (RFC 7636), S256 only. A fresh one for every sign-in, held in
/// memory until the code is redeemed and never written anywhere.
struct PKCE: Sendable {
    let verifier: String
    let challenge: String

    init() {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        verifier = Data(bytes).base64URLEncoded
        challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded
    }

    /// A random value for `state`, compared exactly when the browser returns.
    static func randomState() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncoded
    }
}
