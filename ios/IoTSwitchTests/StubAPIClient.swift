import Foundation
@testable import IoTSwitch

/// A scriptable APIClient. Each method pops the next queued outcome, and every
/// call is recorded so a test can assert on what was *not* sent — which is how
/// "never issue the inverse operation" is checked.
final class StubAPIClient: APIClient, @unchecked Sendable {
    enum Call: Equatable {
        case push(AuthorizationRequest)
        case exchange(code: String, verifier: String)
        case refresh(String)
        case revoke(String)
        case me(String)
        case list
        case get(String)
        case control(id: String, state: DeviceState, expectedVersion: Int)
        case add(name: String, key: String)
    }

    private let lock = NSLock()
    private(set) var calls: [Call] = []

    var pushResults: [Result<URL, Error>] = []
    var exchangeResults: [Result<TokenResponse, Error>] = []
    var meResults: [Result<Account, Error>] = []
    var refreshResults: [Result<TokenResponse, Error>] = []
    var revokeError: Error?
    var listResults: [Result<[Device], Error>] = []
    var getResults: [Result<Device, Error>] = []
    var controlResults: [Result<Device, Error>] = []
    var addResults: [Result<Device, Error>] = []
    var readGate: (@Sendable () async -> Void)?

    /// Blocks every call until released. Used to observe in-flight behaviour.
    var gate: (@Sendable () async -> Void)?

    private func record(_ call: Call) {
        lock.withLock { calls.append(call) }
    }

    private func next<T>(_ queue: inout [Result<T, Error>], _ label: String) throws -> T {
        let result: Result<T, Error>? = lock.withLock {
            queue.isEmpty ? nil : queue.removeFirst()
        }
        guard let result else {
            XCTFailFromStub("StubAPIClient ran out of queued results for \(label)")
            throw APIError.network(message: "no stubbed result for \(label)")
        }
        return try result.get()
    }

    func callCount(_ predicate: (Call) -> Bool) -> Int {
        lock.withLock { calls.filter(predicate).count }
    }

    // MARK: APIClient

    func pushAuthorization(_ request: AuthorizationRequest) async throws -> URL {
        record(.push(request)); await gate?()
        return try next(&pushResults, "pushAuthorization")
    }

    func exchangeCode(code: String, verifier: String, redirectURI: String) async throws -> TokenResponse {
        record(.exchange(code: code, verifier: verifier)); await gate?()
        return try next(&exchangeResults, "exchangeCode")
    }

    func refresh(refreshToken: String) async throws -> TokenResponse {
        record(.refresh(refreshToken)); await gate?()
        return try next(&refreshResults, "refresh")
    }

    func revoke(refreshToken: String) async throws {
        record(.revoke(refreshToken))
        if let revokeError { throw revokeError }
    }

    func me(accessToken: String) async throws -> Account {
        record(.me(accessToken))
        return try next(&meResults, "me")
    }

    func listDevices(accessToken: String) async throws -> [Device] {
        record(.list); await readGate?(); await gate?()
        return try next(&listResults, "listDevices")
    }

    func getDevice(id: String, accessToken: String) async throws -> Device {
        record(.get(id)); await readGate?(); await gate?()
        return try next(&getResults, "getDevice")
    }

    func controlDevice(
        id: String, state: DeviceState, expectedVersion: Int, accessToken: String
    ) async throws -> Device {
        record(.control(id: id, state: state, expectedVersion: expectedVersion)); await gate?()
        return try next(&controlResults, "controlDevice")
    }

    func addDevice(name: String, idempotencyKey: String, accessToken: String) async throws -> Device {
        record(.add(name: name, key: idempotencyKey)); await gate?()
        return try next(&addResults, "addDevice")
    }
}

import XCTest
private func XCTFailFromStub(_ message: String) { XCTFail(message) }

// MARK: - Fixtures

extension Device {
    static func fixture(
        id: String = "dev_01", name: String = "Bedroom Lamp",
        state: DeviceState = .off, version: Int = 1,
        createdAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        updatedAt: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> Device {
        Device(id: id, name: name, state: state, version: version,
               createdAt: createdAt, updatedAt: updatedAt)
    }
}

extension Account {
    static func fixture(id: String = "acc_01", username: String = "sam") -> Account {
        Account(id: id, username: username)
    }
}

extension TokenResponse {
    static func fixture(access: String = "access-2", refresh: String? = "refresh-2", expiresIn: Int = 600) -> TokenResponse {
        TokenResponse(accessToken: access, tokenType: "DPoP", expiresIn: expiresIn, refreshToken: refresh, scope: nil)
    }
}

/// A signed-in session whose access token is still fresh, so a test starts
/// from "signed in and working" without a refresh being queued first.
@MainActor
func makeSignedInSession(_ api: StubAPIClient, storage: InMemoryTokenStorage? = nil) -> SessionController {
    SessionController(
        api: api,
        storage: storage ?? InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture())),
        initialAccess: (token: "access-1", expiresIn: 600)
    )
}

/// The system browser, scripted: answers with whatever callback the test
/// builds from the authorization URL it was asked to open.
@MainActor
final class StubWebAuthenticator: WebAuthenticator {
    var respond: (URL) throws -> URL = { _ in throw AuthError.cancelled }
    private(set) var opened: [URL] = []

    func authenticate(url: URL, callback: AuthCallback) async throws -> URL {
        opened.append(url)
        return try respond(url)
    }
}

/// Holds a call open until a test releases it, so in-flight behaviour can be
/// observed rather than inferred from timing.
actor AsyncGate {
    private var isOpen = false
    func hasWaiter() -> Bool { !waiters.isEmpty }
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }
}
