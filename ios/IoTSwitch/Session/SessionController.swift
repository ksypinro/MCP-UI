import Foundation

/// Owns the session and is the only thing that touches a token.
///
/// Signing in happens in the system browser on the authorization server's own
/// page (RFC 8252): the app never sees a password. The request is pushed over
/// the back channel first (PAR), carries a fresh PKCE challenge and commits
/// to the app's DPoP key, so the code that comes back can only be redeemed by
/// this app, with that key.
///
/// Everything that needs an authenticated call goes through `authorized`,
/// which refreshes early and once on a 401, and signs out only when the
/// server rejects the refresh token. Spec section 10.4.
@MainActor
final class SessionController: ObservableObject {
    @Published private(set) var account: Account?
    @Published private(set) var isSignedIn: Bool = false

    private let api: APIClient
    private let storage: TokenStorage
    private let auth: AuthConfiguration
    private let web: WebAuthenticator?
    private let keyring: DPoPKeyring?
    private let now: () -> Date

    private var refreshToken: String?
    private var access: (token: String, issuedAt: Date, expiresAt: Date)?

    /// The in-flight refresh, if any.
    ///
    /// Refresh must be single-flight. The backend rotates refresh tokens and
    /// treats a replay outside a short grace window as theft, revoking the
    /// whole grant — so two requests racing to refresh could log the user out.
    private var refreshTask: Task<String, Error>?

    init(
        api: APIClient, storage: TokenStorage, auth: AuthConfiguration = .development(URL(string: "http://localhost:4000")!),
        web: WebAuthenticator? = nil, keyring: DPoPKeyring? = nil,
        initialAccess: (token: String, expiresIn: TimeInterval)? = nil, now: @escaping () -> Date = Date.init
    ) {
        self.api = api
        self.storage = storage
        self.auth = auth
        self.web = web
        self.keyring = keyring
        self.now = now
        if let restored = storage.load() {
            refreshToken = restored.refreshToken
            account = restored.account
            isSignedIn = true
            if let initialAccess {
                access = (initialAccess.token, now(), now().addingTimeInterval(initialAccess.expiresIn))
            }
        }
    }

    // MARK: - Entering and leaving

    /// Signs in (or up) in the system browser. Throws `AuthError.cancelled`
    /// if the person closes the sheet; that is not worth an error message.
    func signIn(signUp: Bool) async throws {
        guard let web else { throw AuthError.couldNotStart }
        let pkce = PKCE()
        let state = PKCE.randomState()
        let thumbprint = try keyring?.key().thumbprint ?? ""

        let authorizeURL = try await api.pushAuthorization(AuthorizationRequest(
            codeChallenge: pkce.challenge, state: state, redirectURI: auth.redirectURI,
            dpopThumbprint: thumbprint, signUp: signUp
        ))
        let callback = try await web.authenticate(url: authorizeURL, callback: auth.callback)
        let code = try Self.code(from: callback, state: state, issuer: auth.issuer)

        let tokens = try await api.exchangeCode(code: code, verifier: pkce.verifier, redirectURI: auth.redirectURI)
        guard let refresh = tokens.refreshToken else { throw APIError.decoding(message: "No refresh token was issued.") }
        let account = try await api.me(accessToken: tokens.accessToken)
        adopt(tokens, refresh: refresh, account: account)
    }

    /// Reads the authorization response, refusing anything that is not the
    /// answer to this request from this server.
    static func code(from callback: URL, state: String, issuer: String) throws -> String {
        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let value = { (name: String) in items.first(where: { $0.name == name })?.value }

        // RFC 9207: an authorization server names itself in every response. A
        // response naming another, or none, is refused before anything else
        // is read from it — including its error text.
        guard value("iss") == issuer else { throw AuthError.issuerMismatch }
        guard value("state") == state else { throw AuthError.stateMismatch }
        if let error = value("error") {
            if error == "access_denied" { throw AuthError.cancelled }
            throw AuthError.denied(value("error_description") ?? "Sign-in was refused.")
        }
        guard let code = value("code"), !code.isEmpty else { throw AuthError.missingCode }
        return code
    }

    func logOut() async {
        // Revoke at the authorization server if we can; a failure must not
        // strand the user in a signed-in shell they cannot use.
        if let refreshToken {
            try? await api.revoke(refreshToken: refreshToken)
        }
        clearSession()
        // A new key for the next sign-in: nothing carries over.
        keyring?.reset()
    }

    /// Drops local state without calling the backend. Used when the session is
    /// already gone: spec section 10.4 step 3.
    func sessionExpired() {
        clearSession()
    }

    // MARK: - Authorized work

    /// Runs `operation` with a valid access token: refreshing first if there
    /// is none in memory or it has under a quarter of its life left, and once
    /// more if the backend still rejects it.
    func authorized<T>(_ operation: (String) async throws -> T) async throws -> T {
        guard refreshToken != nil else {
            sessionExpired()
            throw APIError.unauthenticated
        }
        let token = try await currentAccessToken()

        do {
            return try await operation(token)
        } catch APIError.unauthenticated {
            let renewed = try await refreshOnce()
            do {
                return try await operation(renewed)
            } catch APIError.unauthenticated {
                // Refreshed and still refused: the session is genuinely gone.
                sessionExpired()
                throw APIError.unauthenticated
            }
        }
    }

    private func currentAccessToken() async throws -> String {
        if let access {
            let lifetime = access.expiresAt.timeIntervalSince(access.issuedAt)
            if access.expiresAt.timeIntervalSince(now()) > lifetime * 0.25 { return access.token }
        }
        return try await refreshOnce()
    }

    /// Single-flight refresh. Signs out only when the server rejects the
    /// refresh token; being offline or rate-limited keeps the session.
    private func refreshOnce() async throws -> String {
        if let existing = refreshTask {
            return try await existing.value
        }
        guard let refreshToken else { throw APIError.unauthenticated }

        let task = Task<String, Error> { @MainActor [api] in
            let renewed = try await api.refresh(refreshToken: refreshToken)
            // Store the rotated refresh token before anything else. The old
            // one is spent the moment this returns.
            self.store(renewed)
            return renewed.accessToken
        }

        refreshTask = task
        defer { refreshTask = nil }
        do {
            return try await task.value
        } catch APIError.unauthenticated {
            sessionExpired()
            throw APIError.unauthenticated
        }
    }

    // MARK: - Storage

    private func adopt(_ tokens: TokenResponse, refresh: String, account: Account) {
        refreshToken = refresh
        access = (tokens.accessToken, now(), now().addingTimeInterval(TimeInterval(tokens.expiresIn)))
        storage.save(StoredSession(refreshToken: refresh, account: account))
        self.account = account
        isSignedIn = true
    }

    private func store(_ tokens: TokenResponse) {
        guard let account else { return }
        if let rotated = tokens.refreshToken {
            refreshToken = rotated
            storage.save(StoredSession(refreshToken: rotated, account: account))
        }
        access = (tokens.accessToken, now(), now().addingTimeInterval(TimeInterval(tokens.expiresIn)))
    }

    private func clearSession() {
        refreshTask?.cancel()
        refreshTask = nil
        refreshToken = nil
        access = nil
        storage.clear()
        account = nil
        isSignedIn = false
    }
}
