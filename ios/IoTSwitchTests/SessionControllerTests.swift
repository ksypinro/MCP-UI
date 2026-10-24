import CryptoKit
import XCTest
@testable import IoTSwitch

/// Spec sections 7.2 and 10.4, with sign-in in the system browser (OAuth 2.1:
/// PAR, PKCE, DPoP), never a native password form.
@MainActor
final class SessionControllerTests: XCTestCase {

    private let auth = AuthConfiguration.development(URL(string: "http://localhost:4000")!)
    private let authorizeURL = URL(string: "http://localhost:4000/authorize?client_id=iot-switch-ios&request_uri=urn:x")!

    private final class Clock {
        var date = Date(timeIntervalSince1970: 1_800_000_000)
    }

    private func signInSession(_ api: StubAPIClient, web: StubWebAuthenticator, storage: InMemoryTokenStorage = InMemoryTokenStorage(),
                               keyring: DPoPKeyring = DPoPKeyring(store: InMemoryDPoPKeyStore())) -> SessionController {
        SessionController(api: api, storage: storage, auth: auth, web: web, keyring: keyring)
    }

    /// The callback the authorization server would send for the request the app pushed.
    private func callback(for api: StubAPIClient, code: String = "iotsw_ac_code", issuer: String? = nil,
                          state: String? = nil, extra: [URLQueryItem] = []) -> (URL) throws -> URL {
        { _ in
            guard case let .push(request)? = api.calls.last(where: { if case .push = $0 { return true }; return false }) else {
                throw AuthError.missingCode
            }
            var components = URLComponents(string: "com.example.iotswitch:/oauth/callback")!
            components.queryItems = [
                URLQueryItem(name: "code", value: code),
                URLQueryItem(name: "state", value: state ?? request.state),
                URLQueryItem(name: "iss", value: issuer ?? "http://localhost:4000")
            ] + extra
            return components.url!
        }
    }

    // MARK: - Signing in

    func testSigningInPushesTheRequestAndKeepsOnlyTheRefreshToken() async throws {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        let storage = InMemoryTokenStorage()
        let keyring = DPoPKeyring(store: InMemoryDPoPKeyStore())
        api.pushResults = [.success(authorizeURL)]
        api.exchangeResults = [.success(.fixture(access: "access-1", refresh: "refresh-1"))]
        api.meResults = [.success(.fixture())]
        web.respond = callback(for: api)
        let session = signInSession(api, web: web, storage: storage, keyring: keyring)

        try await session.signIn(signUp: true)

        XCTAssertTrue(session.isSignedIn)
        XCTAssertEqual(session.account?.username, "sam")
        XCTAssertEqual(storage.load(), StoredSession(refreshToken: "refresh-1", account: .fixture()),
                       "the access token is never persisted")
        XCTAssertEqual(web.opened, [authorizeURL], "the browser opens only the request_uri form")

        guard case let .push(request) = api.calls[0], case let .exchange(code, verifier) = api.calls[1] else {
            return XCTFail("expected push, then exchange: \(api.calls)")
        }
        XCTAssertTrue(request.signUp)
        XCTAssertEqual(request.redirectURI, "com.example.iotswitch:/oauth/callback")
        XCTAssertEqual(request.dpopThumbprint, try keyring.key().thumbprint, "the code is bound to this app's key")
        XCTAssertEqual(code, "iotsw_ac_code")
        XCTAssertEqual(Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded, request.codeChallenge,
                       "the verifier redeemed is the one the challenge was made from")
    }

    func testAResponseFromAnotherIssuerIsRefused() async {
        // RFC 9207: a mix-up attack hands the app a code from a server it
        // never asked. The response's issuer gives it away.
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(authorizeURL)]
        web.respond = callback(for: api, issuer: "https://attacker.example")
        let session = signInSession(api, web: web)

        await XCTAssertThrowsErrorAsync(try await session.signIn(signUp: false)) {
            XCTAssertEqual($0 as? AuthError, .issuerMismatch)
        }
        XCTAssertFalse(api.calls.contains { if case .exchange = $0 { return true }; return false }, "nothing is redeemed")
        XCTAssertFalse(session.isSignedIn)
    }

    func testAResponseToAnotherRequestIsRefused() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(authorizeURL)]
        web.respond = callback(for: api, state: "someone-elses-state")
        let session = signInSession(api, web: web)

        await XCTAssertThrowsErrorAsync(try await session.signIn(signUp: false)) {
            XCTAssertEqual($0 as? AuthError, .stateMismatch)
        }
        XCTAssertFalse(session.isSignedIn)
    }

    func testClosingTheSheetOrDecliningSignsNobodyIn() async {
        let api = StubAPIClient()
        let web = StubWebAuthenticator()
        api.pushResults = [.success(authorizeURL), .success(authorizeURL)]
        let session = signInSession(api, web: web)

        web.respond = { _ in throw AuthError.cancelled }
        await XCTAssertThrowsErrorAsync(try await session.signIn(signUp: false)) {
            XCTAssertEqual($0 as? AuthError, .cancelled)
        }

        web.respond = callback(for: api, extra: [URLQueryItem(name: "error", value: "access_denied")])
        await XCTAssertThrowsErrorAsync(try await session.signIn(signUp: false)) {
            XCTAssertEqual($0 as? AuthError, .cancelled)
        }
        XCTAssertFalse(session.isSignedIn)
    }

    func testAStoredSessionIsRestoredOnLaunch() {
        let session = makeSignedInSession(StubAPIClient())
        XCTAssertTrue(session.isSignedIn)
        XCTAssertEqual(session.account?.username, "sam")
    }

    // MARK: - Refreshing

    func testAColdStartRefreshesBeforeTheFirstCall() async throws {
        // The access token is never stored, so a relaunch begins with a refresh.
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = SessionController(api: api, storage: InMemoryTokenStorage(
            StoredSession(refreshToken: "refresh-1", account: .fixture())))

        let token = try await session.authorized { $0 }
        XCTAssertEqual(token, "access-2")
    }

    func testATokenNearExpiryIsRefreshedBeforeItIsUsed() async throws {
        let clock = Clock()
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = SessionController(
            api: api, storage: InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture())),
            initialAccess: (token: "access-1", expiresIn: 600), now: { clock.date }
        )

        let fresh = try await session.authorized { $0 }
        XCTAssertEqual(fresh, "access-1", "fresh: used as is")
        clock.date.addTimeInterval(500) // under a quarter of its life left
        let renewed = try await session.authorized { $0 }
        XCTAssertEqual(renewed, "access-2", "nearly expired: refreshed first")
    }

    func testAnExpiredAccessTokenIsRefreshedOnceAndTheCallRetried() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = makeSignedInSession(api)

        var tokensSeen: [String] = []
        let result: String = try await session.authorized { token in
            tokensSeen.append(token)
            if tokensSeen.count == 1 { throw APIError.unauthenticated }
            return "ok"
        }

        XCTAssertEqual(result, "ok")
        XCTAssertEqual(tokensSeen, ["access-1", "access-2"], "the retry uses the renewed token")
        XCTAssertTrue(session.isSignedIn)
    }

    func testTheRotatedRefreshTokenIsStored() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = makeSignedInSession(api, storage: storage)

        _ = try? await session.authorized { token -> String in
            if token == "access-1" { throw APIError.unauthenticated }
            return "ok"
        }

        // The old refresh token is spent the moment it is exchanged. Losing the
        // new one would strand the session.
        XCTAssertEqual(storage.load()?.refreshToken, "refresh-2")
    }

    /// The backend treats a replayed refresh token outside a short window as
    /// theft and revokes the grant, so concurrent callers must share one refresh.
    func testConcurrentFailuresRefreshExactlyOnce() async throws {
        let api = StubAPIClient()
        api.refreshResults = [.success(.fixture())]
        let session = makeSignedInSession(api)

        let gate = AsyncGate()
        api.gate = { await gate.wait() }

        func work() async -> String? {
            try? await session.authorized { token in
                if token == "access-1" { throw APIError.unauthenticated }
                return "ok"
            }
        }

        async let a = work()
        async let b = work()
        async let c = work()
        try await Task.sleep(nanoseconds: 50_000_000)
        await gate.open()
        let results = await [a, b, c]

        XCTAssertEqual(results.compactMap { $0 }.count, 3)
        XCTAssertEqual(api.callCount { if case .refresh = $0 { return true }; return false }, 1)
    }

    func testARejectedRefreshSignsTheUserOut() async {
        let api = StubAPIClient()
        api.refreshResults = [.failure(APIError.unauthenticated)]
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = makeSignedInSession(api, storage: storage)

        await XCTAssertThrowsErrorAsync(try await session.authorized { _ -> String in throw APIError.unauthenticated }) {
            XCTAssertEqual($0 as? APIError, .unauthenticated)
        }
        XCTAssertFalse(session.isSignedIn)
        XCTAssertNil(storage.load(), "the stored session is cleared, not left to fail again")
    }

    func testANetworkFailureDuringRefreshKeepsTheSession() async {
        let api = StubAPIClient()
        api.refreshResults = [.failure(APIError.network(message: "offline"))]
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = makeSignedInSession(api, storage: storage)

        await XCTAssertThrowsErrorAsync(try await session.authorized { _ -> String in throw APIError.unauthenticated }) {
            XCTAssertEqual($0 as? APIError, .network(message: "offline"), "the transport error is surfaced")
        }
        XCTAssertTrue(session.isSignedIn, "being offline is not being signed out")
        XCTAssertEqual(storage.load()?.refreshToken, "refresh-1", "the refresh token is kept for the next attempt")
    }

    func testARateLimitedRefreshKeepsTheSession() async {
        let api = StubAPIClient()
        api.refreshResults = [.failure(APIError.api(code: "RATE_LIMITED", message: "Too many requests.", field: nil, status: 429))]
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = makeSignedInSession(api, storage: storage)

        _ = try? await session.authorized { _ -> String in throw APIError.unauthenticated }

        XCTAssertTrue(session.isSignedIn)
        XCTAssertNotNil(storage.load())
    }

    // MARK: - Signing out

    func testLogOutRevokesTheGrantAndForgetsTheKey() async throws {
        let api = StubAPIClient()
        let keyring = DPoPKeyring(store: InMemoryDPoPKeyStore())
        let before = try keyring.key().thumbprint
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = SessionController(api: api, storage: storage, keyring: keyring,
                                        initialAccess: (token: "access-1", expiresIn: 600))

        await session.logOut()

        XCTAssertEqual(api.calls, [.revoke("refresh-1")])
        XCTAssertFalse(session.isSignedIn)
        XCTAssertNil(storage.load())
        XCTAssertNotEqual(try keyring.key().thumbprint, before, "the next sign-in gets a new key")
    }

    func testLogOutClearsLocalStateEvenIfRevocationFails() async {
        let api = StubAPIClient()
        api.revokeError = APIError.network(message: "offline")
        let storage = InMemoryTokenStorage(StoredSession(refreshToken: "refresh-1", account: .fixture()))
        let session = makeSignedInSession(api, storage: storage)

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
        let session = StoredSession(refreshToken: "refresh-1", account: .fixture())

        XCTAssertTrue(storage.save(session), "save must report success, not fail silently")
        XCTAssertEqual(storage.load(), session)

        // Saving again must update in place rather than fail as a duplicate.
        let rotated = StoredSession(refreshToken: "refresh-2", account: .fixture())
        XCTAssertTrue(storage.save(rotated))
        XCTAssertEqual(storage.load(), rotated)

        storage.clear()
        XCTAssertNil(storage.load())
    }
}

/// XCTAssertThrowsError for async expressions.
func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath, line: UInt = #line,
    _ handler: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {
        handler(error)
    }
}
