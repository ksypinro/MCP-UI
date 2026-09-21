import XCTest
@testable import IoTSwitch

/// Spec sections 7.2 and 10.4.
@MainActor
final class SessionControllerTests: XCTestCase {

    func testSignUpStoresTheSessionForNextLaunch() async throws {
        let api = StubAPIClient()
        api.sessionResults = [.success(.fixture())]
        let storage = InMemoryTokenStorage()
        let session = SessionController(api: api, storage: storage)

        try await session.signUp(username: "sam", password: "correct horse battery staple")

        XCTAssertTrue(session.isSignedIn)
        XCTAssertEqual(storage.load()?.accessToken, "access-1")
        XCTAssertEqual(session.account?.username, "sam")
    }

    func testAStoredSessionIsRestoredOnLaunch() {
        let api = StubAPIClient()
        let session = makeSignedInSession(api)

        XCTAssertTrue(session.isSignedIn)
        XCTAssertEqual(session.account?.username, "sam")
    }

    func testAnExpiredAccessTokenIsRefreshedOnceAndTheCallRetried() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = makeSignedInSession(api)

        var tokensSeen: [String] = []
        var hasFailedOnce = false
        let result: String = try await session.authorized { token in
            tokensSeen.append(token)
            if !hasFailedOnce {
                hasFailedOnce = true
                throw APIError.unauthenticated
            }
            return "ok"
        }

        XCTAssertEqual(result, "ok")
        XCTAssertEqual(tokensSeen, ["access-1", "access-2"], "the retry uses the renewed token")
        XCTAssertTrue(session.isSignedIn)
    }

    func testTheRotatedRefreshTokenIsStored() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let storage = InMemoryTokenStorage(
            StoredSession(accessToken: "access-1", refreshToken: "refresh-1", account: .fixture())
        )
        let session = SessionController(api: api, storage: storage)

        var first = true
        _ = try? await session.authorized { _ -> String in
            if first { first = false; throw APIError.unauthenticated }
            return "ok"
        }

        // The old refresh token is dead the moment it is exchanged. Losing the
        // new one would strand the session until the access token expires.
        XCTAssertEqual(storage.load()?.refreshToken, "refresh-2")
    }

    /// The backend revokes the whole family when a refresh token is replayed,
    /// so two concurrent refreshes would log the user out everywhere.
    func testConcurrentFailuresRefreshExactlyOnce() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = makeSignedInSession(api)

        let gate = AsyncGate()
        api.gate = { await gate.wait() }

        var attempts = 0
        func work() async -> String? {
            try? await session.authorized { token in
                attempts += 1
                if token == "access-1" { throw APIError.unauthenticated }
                return "ok"
            }
        }

        async let a = work()
        async let b = work()
        async let c = work()
        // Let all three discover the stale token before any refresh resolves.
        try await Task.sleep(nanoseconds: 50_000_000)
        await gate.open()
        let results = await [a, b, c]

        XCTAssertEqual(results.compactMap { $0 }.count, 3)
        XCTAssertEqual(
            api.callCount { if case .refresh = $0 { return true }; return false }, 1,
            "a replayed refresh token is treated as theft by the backend"
        )
        XCTAssertGreaterThanOrEqual(attempts, 4)
    }

    func testAFailedRefreshSignsTheUserOut() async {
        let api = StubAPIClient()
        api.refreshResults = [.failure(APIError.unauthenticated)]
        let storage = InMemoryTokenStorage(
            StoredSession(accessToken: "access-1", refreshToken: "refresh-1", account: .fixture())
        )
        let session = SessionController(api: api, storage: storage)

        do {
            _ = try await session.authorized { _ -> String in throw APIError.unauthenticated }
            XCTFail("expected the call to fail")
        } catch {
            XCTAssertEqual(error as? APIError, .unauthenticated)
        }

        XCTAssertFalse(session.isSignedIn)
        XCTAssertNil(storage.load(), "the stored session is cleared, not left to fail again")
    }

    func testLogOutClearsLocalStateEvenIfTheServerCallFails() async {
        let api = StubAPIClient()
        api.logOutError = APIError.network(message: "offline")
        let storage = InMemoryTokenStorage(
            StoredSession(accessToken: "access-1", refreshToken: "refresh-1", account: .fixture())
        )
        let session = SessionController(api: api, storage: storage)

        await session.logOut()

        // Otherwise a user who taps Log Out while offline stays in a shell
        // they cannot use and cannot leave.
        XCTAssertFalse(session.isSignedIn)
        XCTAssertNil(storage.load())
    }
}

/// The storage contract the session depends on. A silent save failure looks
/// identical to a working one until the app is relaunched.
final class TokenStorageTests: XCTestCase {
    func testTheKeychainRoundTripsASession() {
        let storage = KeychainTokenStorage(service: "com.example.IoTSwitch.tests.\(UUID().uuidString)")
        let session = StoredSession(
            accessToken: "access-1", refreshToken: "refresh-1", account: .fixture()
        )

        XCTAssertTrue(storage.save(session), "save must report success, not fail silently")
        XCTAssertEqual(storage.load(), session)

        // Saving again must update in place rather than fail as a duplicate.
        let rotated = StoredSession(
            accessToken: "access-2", refreshToken: "refresh-2", account: .fixture()
        )
        XCTAssertTrue(storage.save(rotated))
        XCTAssertEqual(storage.load(), rotated)

        storage.clear()
        XCTAssertNil(storage.load())
    }
}
