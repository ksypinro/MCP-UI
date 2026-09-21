import Foundation
@testable import IoTSwitch

/// A scriptable APIClient. Each method pops the next queued outcome, and every
/// call is recorded so a test can assert on what was *not* sent — which is how
/// "never issue the inverse operation" is checked.
final class StubAPIClient: APIClient, @unchecked Sendable {
    enum Call: Equatable {
        case signUp(String)
        case logIn(String)
        case refresh(String)
        case logOut
        case list
        case get(String)
        case control(id: String, state: DeviceState, expectedVersion: Int)
        case add(name: String, key: String)
    }

    private let lock = NSLock()
    private(set) var calls: [Call] = []

    var sessionResults: [Result<SessionResponse, Error>] = []
    var refreshResults: [Result<RefreshResponse, Error>] = []
    var listResults: [Result<[Device], Error>] = []
    var getResults: [Result<Device, Error>] = []
    var controlResults: [Result<Device, Error>] = []
    var addResults: [Result<Device, Error>] = []
    var logOutError: Error?

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

    func signUp(username: String, password: String) async throws -> SessionResponse {
        record(.signUp(username)); await gate?()
        return try next(&sessionResults, "signUp")
    }

    func logIn(username: String, password: String) async throws -> SessionResponse {
        record(.logIn(username)); await gate?()
        return try next(&sessionResults, "logIn")
    }

    func refresh(refreshToken: String) async throws -> RefreshResponse {
        record(.refresh(refreshToken)); await gate?()
        return try next(&refreshResults, "refresh")
    }

    func logOut(accessToken: String) async throws {
        record(.logOut)
        if let logOutError { throw logOutError }
    }

    func listDevices(accessToken: String) async throws -> [Device] {
        record(.list); await gate?()
        return try next(&listResults, "listDevices")
    }

    func getDevice(id: String, accessToken: String) async throws -> Device {
        record(.get(id)); await gate?()
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

extension SessionResponse {
    static func fixture(access: String = "access-1", refresh: String = "refresh-1") -> SessionResponse {
        SessionResponse(account: .fixture(), accessToken: access, refreshToken: refresh, expiresIn: 900)
    }
}

extension RefreshResponse {
    static func fixture(access: String = "access-2", refresh: String = "refresh-2") -> RefreshResponse {
        RefreshResponse(accessToken: access, refreshToken: refresh, expiresIn: 900)
    }
}

@MainActor
func makeSignedInSession(_ api: StubAPIClient) -> SessionController {
    SessionController(
        api: api,
        storage: InMemoryTokenStorage(
            StoredSession(accessToken: "access-1", refreshToken: "refresh-1", account: .fixture())
        )
    )
}

/// Holds a call open until a test releases it, so in-flight behaviour can be
/// observed rather than inferred from timing.
actor AsyncGate {
    private var isOpen = false
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
