import Foundation

/// Owns the session and is the only thing that touches a token.
///
/// Everything that needs an authenticated call goes through `authorized`, which
/// refreshes once on a 401 and signs out if that fails. Spec section 10.4.
@MainActor
final class SessionController: ObservableObject {
    @Published private(set) var account: Account?
    @Published private(set) var isSignedIn: Bool = false

    private let api: APIClient
    private let storage: TokenStorage
    private var session: StoredSession?

    /// The in-flight refresh, if any.
    ///
    /// Refresh must be single-flight. The backend rotates refresh tokens and
    /// treats a replayed one as theft, revoking the whole family — so two
    /// requests racing to refresh would not merely duplicate work, they would
    /// log the user out and invalidate every other device.
    private var refreshTask: Task<String, Error>?

    init(api: APIClient, storage: TokenStorage) {
        self.api = api
        self.storage = storage
        if let restored = storage.load() {
            session = restored
            account = restored.account
            isSignedIn = true
        }
    }

    // MARK: - Entering and leaving

    func signUp(username: String, password: String) async throws {
        adopt(try await api.signUp(username: username, password: password))
    }

    func logIn(username: String, password: String) async throws {
        adopt(try await api.logIn(username: username, password: password))
    }

    func logOut() async {
        // Tell the backend if we can, but a failure here must not strand the
        // user in a signed-in shell they cannot use.
        if let token = session?.accessToken {
            try? await api.logOut(accessToken: token)
        }
        clearSession()
    }

    /// Drops local state without calling the backend. Used when the session is
    /// already gone: spec section 10.4 step 3.
    func sessionExpired() {
        clearSession()
    }

    // MARK: - Authorized work

    /// Runs `operation` with a valid access token, refreshing once if the
    /// backend rejects the one we hold.
    func authorized<T>(_ operation: (String) async throws -> T) async throws -> T {
        guard let token = session?.accessToken else {
            sessionExpired()
            throw APIError.unauthenticated
        }

        do {
            return try await operation(token)
        } catch APIError.unauthenticated {
            let renewed: String
            do {
                renewed = try await refreshOnce()
            } catch {
                sessionExpired()
                throw APIError.unauthenticated
            }
            do {
                return try await operation(renewed)
            } catch APIError.unauthenticated {
                // Refreshed and still refused: the session is genuinely gone.
                sessionExpired()
                throw APIError.unauthenticated
            }
        }
    }

    private func refreshOnce() async throws -> String {
        // A caller that arrives while a refresh is already running waits for
        // that one rather than starting a second. Two refreshes with the same
        // token is a replay, and the backend revokes the entire family on a
        // replay — so a race here would log the user out of every device.
        if let existing = refreshTask {
            return try await existing.value
        }

        guard let refreshToken = session?.refreshToken else {
            throw APIError.unauthenticated
        }

        let task = Task<String, Error> { @MainActor [api] in
            let renewed = try await api.refresh(refreshToken: refreshToken)
            // Store the rotated refresh token immediately. The old one is dead
            // the moment this returns, so losing the new one strands the
            // session until the access token expires.
            self.store(accessToken: renewed.accessToken, refreshToken: renewed.refreshToken)
            return renewed.accessToken
        }

        refreshTask = task
        defer { refreshTask = nil }
        return try await task.value
    }

    // MARK: - Storage

    private func adopt(_ response: SessionResponse) {
        let stored = StoredSession(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            account: response.account
        )
        session = stored
        storage.save(stored)
        account = response.account
        isSignedIn = true
    }

    private func store(accessToken: String, refreshToken: String) {
        guard var current = session else { return }
        current.accessToken = accessToken
        current.refreshToken = refreshToken
        session = current
        storage.save(current)
    }

    private func clearSession() {
        refreshTask?.cancel()
        refreshTask = nil
        session = nil
        storage.clear()
        account = nil
        isSignedIn = false
    }
}
