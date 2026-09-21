import Foundation
import Security

struct StoredSession: Codable, Sendable, Equatable {
    var accessToken: String
    var refreshToken: String
    var account: Account
}

/// Where the session lives between launches. A protocol so tests do not touch
/// the real Keychain, which is shared process-wide and outlives a test run.
protocol TokenStorage: Sendable {
    func load() -> StoredSession?
    /// Returns whether the session was actually persisted. A storage layer
    /// that silently fails to save looks identical to one that works until the
    /// app is relaunched, which is the worst time to find out.
    @discardableResult func save(_ session: StoredSession) -> Bool
    func clear()
}

/// Spec section 7.2: native credentials belong in the Keychain, never in
/// UserDefaults, which is a plain file inside the app container.
struct KeychainTokenStorage: TokenStorage {
    let service: String

    init(service: String = "com.example.IoTSwitch.session") {
        self.service = service
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "session"
        ]
    }

    func load() -> StoredSession? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(StoredSession.self, from: data)
    }

    @discardableResult
    func save(_ session: StoredSession) -> Bool {
        guard let data = try? JSONEncoder().encode(session) else { return false }

        // The search query must not carry attributes that are not part of the
        // item's identity, or an update can silently match nothing.
        let update: [String: Any] = [
            kSecValueData as String: data,
            // Without this the session is readable while the device is locked
            // and is included in unencrypted backups.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        var status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var insert = baseQuery
            insert.merge(update) { current, _ in current }
            status = SecItemAdd(insert as CFDictionary, nil)
        }

        if status != errSecSuccess {
            // errSecMissingEntitlement (-34018) here means the build has no
            // keychain entitlement, which happens when code signing is off.
            assertionFailure("Keychain save failed with OSStatus \(status)")
            return false
        }
        return true
    }

    func clear() {
        SecItemDelete(baseQuery as CFDictionary)
    }
}

/// For tests and previews.
final class InMemoryTokenStorage: TokenStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: StoredSession?

    init(_ initial: StoredSession? = nil) { stored = initial }

    func load() -> StoredSession? { lock.withLock { stored } }
    @discardableResult
    func save(_ session: StoredSession) -> Bool {
        lock.withLock { stored = session }
        return true
    }
    func clear() { lock.withLock { stored = nil } }
}
