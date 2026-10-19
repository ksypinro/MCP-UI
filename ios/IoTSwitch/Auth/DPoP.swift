import CryptoKit
import Foundation
import Security

/// DPoP (RFC 9449): every token the app holds is bound to a key it alone has.
///
/// On a device the key is generated inside the Secure Enclave and can never
/// be read out — only an encrypted handle that this one chip can use is
/// stored. A refresh token copied out of the Keychain of a jailbroken phone
/// is therefore useless: redeeming it needs a proof signed by a key that does
/// not exist anywhere else. The Simulator has no Secure Enclave, so there the
/// key is an ordinary P-256 key in the Keychain; that path exists for
/// development and tests only.
final class DPoPKey: @unchecked Sendable {
    private enum Backing {
        case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)
    }

    private let backing: Backing

    private init(_ backing: Backing) { self.backing = backing }

    /// A new key: in the Secure Enclave when there is one.
    static func generate() throws -> DPoPKey {
        if SecureEnclave.isAvailable {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
            ) else { throw error!.takeRetainedValue() as Error }
            return DPoPKey(.secureEnclave(try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)))
        }
        return DPoPKey(.software(P256.Signing.PrivateKey()))
    }

    /// What is persisted: for the Secure Enclave, an encrypted handle only
    /// that chip can use; for the Simulator fallback, the key itself.
    var storedRepresentation: Data {
        switch backing {
        case .secureEnclave(let key): return Data([1]) + key.dataRepresentation
        case .software(let key): return Data([2]) + key.rawRepresentation
        }
    }

    static func restore(_ data: Data) throws -> DPoPKey {
        guard let tag = data.first else { throw CocoaError(.coderInvalidValue) }
        let body = data.dropFirst()
        switch tag {
        case 1: return DPoPKey(.secureEnclave(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: body)))
        case 2: return DPoPKey(.software(try P256.Signing.PrivateKey(rawRepresentation: body)))
        default: throw CocoaError(.coderInvalidValue)
        }
    }

    private var publicKey: P256.Signing.PublicKey {
        switch backing {
        case .secureEnclave(let key): return key.publicKey
        case .software(let key): return key.publicKey
        }
    }

    private func sign(_ data: Data) throws -> Data {
        switch backing {
        case .secureEnclave(let key): return try key.signature(for: data).rawRepresentation
        case .software(let key): return try key.signature(for: data).rawRepresentation
        }
    }

    /// The public key as a JWK's coordinates.
    private var coordinates: (x: String, y: String) {
        let raw = publicKey.rawRepresentation // x ‖ y, 32 bytes each
        return (Data(raw.prefix(32)).base64URLEncoded, Data(raw.suffix(32)).base64URLEncoded)
    }

    /// RFC 7638 thumbprint: what the server binds tokens to (cnf.jkt) and what
    /// the authorization request commits to (dpop_jkt).
    var thumbprint: String { DPoPKey.thumbprint(x: coordinates.x, y: coordinates.y) }

    static func thumbprint(x: String, y: String) -> String {
        // Members in lexicographic order, no whitespace: RFC 7638 section 3.
        let canonical = #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#
        return Data(SHA256.hash(data: Data(canonical.utf8))).base64URLEncoded
    }

    /// A proof for one request: the method, the URL without query, the hash
    /// of the access token being sent (if any), and the server's nonce.
    func proof(method: String, url: URL, accessToken: String?, nonce: String?, now: Date = Date()) throws -> String {
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        components?.query = nil
        components?.fragment = nil
        let htu = components?.url?.absoluteString ?? url.absoluteString

        let (x, y) = coordinates
        let header: [String: Any] = [
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": ["kty": "EC", "crv": "P-256", "x": x, "y": y]
        ]
        var payload: [String: Any] = [
            "jti": UUID().uuidString, "htm": method.uppercased(), "htu": htu, "iat": Int(now.timeIntervalSince1970)
        ]
        if let accessToken {
            payload["ath"] = Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncoded
        }
        if let nonce { payload["nonce"] = nonce }

        let options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        let signingInput = try JSONSerialization.data(withJSONObject: header, options: options).base64URLEncoded
            + "." + JSONSerialization.data(withJSONObject: payload, options: options).base64URLEncoded
        // CryptoKit's raw ECDSA signature is r ‖ s, exactly the JWS ES256 form.
        return signingInput + "." + (try sign(Data(signingInput.utf8))).base64URLEncoded
    }
}

/// Where the key handle is kept. A protocol so tests do not touch the Keychain.
protocol DPoPKeyStore: Sendable {
    func load() -> Data?
    func save(_ data: Data)
    func clear()
}

struct KeychainDPoPKeyStore: DPoPKeyStore {
    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.IoTSwitch.dpop",
            kSecAttrAccount as String: "dpop-key"
        ]
    }

    func load() -> Data? {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        return SecItemCopyMatching(lookup as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
    }

    func save(_ data: Data) {
        clear()
        var insert = query
        insert[kSecValueData as String] = data
        // This device only, never in iCloud Keychain or a backup.
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        insert[kSecAttrSynchronizable as String] = false
        SecItemAdd(insert as CFDictionary, nil)
    }

    func clear() {
        SecItemDelete(query as CFDictionary)
    }
}

final class InMemoryDPoPKeyStore: DPoPKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    func load() -> Data? { lock.withLock { data } }
    func save(_ data: Data) { lock.withLock { self.data = data } }
    func clear() { lock.withLock { data = nil } }
}

/// The app's current DPoP key, created on first use and replaced on sign-out,
/// so a new sign-in never reuses the key of the last one.
final class DPoPKeyring: @unchecked Sendable {
    private let store: DPoPKeyStore
    private let lock = NSLock()
    private var cached: DPoPKey?

    init(store: DPoPKeyStore) { self.store = store }

    func key() throws -> DPoPKey {
        try lock.withLock {
            if let cached { return cached }
            if let data = store.load(), let restored = try? DPoPKey.restore(data) {
                cached = restored
                return restored
            }
            let fresh = try DPoPKey.generate()
            store.save(fresh.storedRepresentation)
            cached = fresh
            return fresh
        }
    }

    func reset() {
        lock.withLock {
            cached = nil
            store.clear()
        }
    }
}

/// The most recent DPoP-Nonce the server sent. Every response may carry one.
final class DPoPNonceCache: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    var current: String? { lock.withLock { value } }
    func update(_ nonce: String?) {
        guard let nonce, !nonce.isEmpty else { return }
        lock.withLock { value = nonce }
    }
}
